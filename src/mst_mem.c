#include <malloc.h>
#include <stdlib.h>
#define __USE_GNU
#include <dlfcn.h>

#include "mstunnel.h"
#include "memmgmt.h"
#include "mstrb.h"

#ifdef __USE_MM__
static void *(*def_malloc_hook)(size_t size, const void *caller);
static void (*def_free_hook)(void *ptr, const void *caller);
static void *(*def_realloc_hook)(void *ptr, size_t size, const void *caller);
static void *(*def_memalign_hook)(size_t alignment, size_t size, const void *caller);
#endif

void *os_malloc(size_t size);
void os_free(void *);

mst_mpool_bucket_t gmpool_slabs[mpool_slab_max];
mst_mpool_bucket_t gmpool_table[D_MPOOL_TABLE_SIZE];

mst_mpool_size_map_t gmpool_size_map[] = {
    {32, "size32"},
    {64, "size64"},
    {128, "size128"},
    {256, "size256"},
    {512, "size512"},
    {1024, "size1024"},
    {2048, "size2048"},
    {4096, "size4096"},
};

int mst_do_fbs_byte(int ival)
{
    int index = 0;
    int nval = 0;

    if (ival & 0xF0) {
        index += 4;
        nval = (ival & 0xF0) >> 4;
    }
    else {
        nval = ival & 0x0F;
    }

    if (nval & 0xC) {
        index += 2;
        nval = (nval & 0xC) >> 2;
    }
    else {
        nval = (nval & 0x3);
    }

    if (nval & 0x2) {
        index += 2;
    }
    else if (nval) {
        index += 1;
    }

    //fprintf(stderr, "Given val: %d, index: %d\n", ival, index);

    return (index)?(index - 1):index;
}

int mst_do_fbs_dw(int inval)
{
    int index = 0;
    int temp = 0;

    temp = mst_do_fbs_byte(inval & 0xFF);

    if ((inval >> 8) && ((inval >> 8) & 0xFF)) {
        index += 8;
    }
    else {
        index += temp;
    }
    temp = mst_do_fbs_byte((inval >> 8) & 0xFF);

    if ((inval >> 16) && ((inval >> 16) & 0xFF)) {
        index += 16;
    }
    else {
        index += temp;
    }
    temp = mst_do_fbs_byte((inval >> 16) & 0xFF);

    if ((inval >> 24) && ((inval >> 24) & 0xFF)) {
        index += 24;
    }
    else {
        index += temp;
    }
    temp = mst_do_fbs_byte((inval >> 24) & 0xFF);

    index += temp;

    //fprintf(stderr, "First bit is at index: %d\n", index);

    return index;
}

static void mst_mpool_table_insert(mst_mpool_buf_t *mp_node)
{
    struct rb_node **new;
    struct rb_root *rbr = NULL;
    struct rb_node *parent = NULL;
    unsigned int key = (unsigned)mp_node->buffer;
    unsigned int sval = 0;
    mst_mpool_bucket_t *mp_bucket;

    mp_bucket = &gmpool_table[(key & 0xFFC00000) >> 22];

    pthread_mutex_lock(&mp_bucket->b_lock);
    rbr = &mp_bucket->rbr;

    new = &rbr->rb_node;

    while(*new) {
        parent = *new;
        sval = (unsigned)((mst_mpool_buf_t *)(rb_entry(parent, struct mst_mpool_buf, rbn)))->buffer;
        sval = ((sval & 0xFFC00000) >> 22);
        if (key < sval) {
            new = &parent->rb_left;
        }
        else {
            new = &parent->rb_right;
        }
    }

    rb_link_node(&mp_node->rbn, parent, new);
    rb_insert_color(&mp_node->rbn, rbr);
    atomic_inc(&mp_bucket->count);
    
    pthread_mutex_unlock(&mp_bucket->b_lock);

    return;
}

//static void mst_mpool_insert(mst_mpool_buf_t *mp_node, struct rb_root *rbr)
static void mst_mpool_insert(mst_mpool_buf_t *mp_node)
{
    struct rb_node **new;// = &rbr->rb_node;
    struct rb_node *parent = NULL;
    unsigned int key = (unsigned)mp_node->buffer;
    unsigned int sval = 0;
    mst_mpool_bucket_t *mp_bucket;
    struct rb_root *rbr;
    
    mp_bucket = &gmpool_slabs[mp_node->slab_type];

    pthread_mutex_lock(&mp_bucket->b_lock);
    rbr = &mp_bucket->rbr;

    new = &rbr->rb_node;

    while(*new) {
        parent = *new;
        sval = (unsigned)((mst_mpool_buf_t *)(rb_entry(parent, struct mst_mpool_buf, rbn)))->buffer;
        if (key < sval) {
            new = &parent->rb_left;
        }
        else {
            new = &parent->rb_right;
        }
    }

    rb_link_node(&mp_node->rbn, parent, new);
    rb_insert_color(&mp_node->rbn, rbr);
    atomic_inc(&mp_bucket->count);
    pthread_mutex_unlock(&mp_bucket->b_lock);

    return;
}

void mst_mpool_rework_buf(struct rb_node *rb_node, int size)
{
    mst_mpool_buf_t *mp_node;
    int given_size = 0;
    int delta = 0;
    int fbs = 0;
    void *p = NULL;
    mst_mpool_buf_t *new_node;

    mp_node = rb_entry(rb_node, struct mst_mpool_buf, rbn);

    if (!mp_node->head) {
        // Do not split, fragments or buddies
        mp_node->given_size = mp_node->size;
        return;
    }

    given_size = mp_node->size;
    p = mp_node->buffer;

rework:

    if (given_size > size) {
        //fprintf(stderr, "Given size: %d, size: %d\n", given_size, size);
        // Try to reclaim as much buffer as possible
        delta = given_size - size;

        fbs = mst_do_fbs_dw(delta);
        //fprintf(stderr, "Fbs: %d, delta: %d\n", fbs, delta);
        if ((1 << fbs) >= gmpool_size_map[0].size) {
            new_node = (mst_mpool_buf_t *)os_malloc(sizeof(mst_mpool_buf_t));
            assert(new_node);
            rb_init_node(&new_node->rbn);
            new_node->size = (1 << fbs);
            new_node->buffer = (p + given_size - new_node->size);
            new_node->head = 0;
            new_node->parent = (int)mp_node;
            atomic_set(&new_node->tot_child, 0);
            new_node->slab_type = mst_do_fbs_dw(((1 << fbs) / gmpool_size_map[0].size));

            atomic_inc(&mp_node->tot_child);
            given_size -= (1 << fbs);

            //mst_mpool_insert(new_node, &gmpool_slabs[new_node->slab_type].rbr);
            mst_mpool_insert(new_node);
            //gmpool_slabs[new_node->slab_type].count++;

            goto rework;
        }
        else {
            mp_node->given_size = given_size;
            return;
        }
    }

    mp_node->given_size = given_size;

    return;
}

static mst_mpool_buf_t *
mst_lookup_mpool_buf(void *ptr)
{
    mst_mpool_buf_t *mp_node = NULL;
    struct rb_node *rb_node;
    struct rb_root *rbr = NULL;
    unsigned int key = (unsigned)ptr;
    mst_mpool_bucket_t *mp_bucket;

    mp_bucket = &gmpool_table[(key & 0xFFC00000) >> 22]; // Key is MSB 10-bits of 32-bit address

    pthread_mutex_lock(&mp_bucket->b_lock);
    rbr = &mp_bucket->rbr;
    rb_node = rb_first(rbr);

    while(rb_node) {
        mp_node = rb_entry(rb_node, struct mst_mpool_buf, rbn);
        if (mp_node && (mp_node->buffer == ptr)) {
            rb_erase(rb_node, rbr);
            break;
        }
        rb_node = rb_next(rb_node);
    }
    
    pthread_mutex_unlock(&mp_bucket->b_lock);
    return mp_node;
}

void
mst_free(void *ptr, const void *caller)
{
    mst_mpool_buf_t *mp_node;
    //struct rb_node *rb_node;
    //struct rb_root *rbr = NULL;
    //unsigned int key = (unsigned)ptr;

    if (!ptr) {
        return;
    }

    mp_node = mst_lookup_mpool_buf(ptr);

    if (mp_node) {
        if (!atomic_read(&mp_node->tot_child) && mp_node->head) {
            mp_node->given_size = 0;
            mp_node->who = 0;
            fprintf(stderr, "Added %p back to pool, caller: %p\n", ptr, caller);
            //mst_mpool_insert(mp_node, &gmpool_slabs[mp_node->slab_type].rbr);
            mst_mpool_insert(mp_node);
            //gmpool_slabs[mp_node->slab_type].count++;
        }
        else if(!mp_node->head) {
            mst_mpool_buf_t *parent = (mst_mpool_buf_t *)mp_node->parent;
            os_free(mp_node);
            if (atomic_dec_and_test(&parent->tot_child) && !atomic_read(&parent->in_use)) {
                mst_free(parent->buffer, caller);
            }
        }
        return;
    }
    //fprintf(stderr, "Perhaps %p belongs to OS. Freeing it\n", ptr);
    os_free(ptr);
    return;
}

void *
mst_malloc(size_t size, const void *caller)
{
    int slab = 0;
    int fbs = 0;
    int rechk_cnt = 0;
    mst_mpool_buf_t *mp_node;
    struct rb_node *rb_node;

    //fprintf(stderr, "Caller is %p\n", caller);
    if (size <= gmpool_size_map[0].size) {
        slab = 0;
    }
    else if (size > gmpool_size_map[mpool_slab_max - 1].size) {
        void *p = NULL;
        // We dnt have large buffers. Ask OS
        p = os_malloc(size);
        //fprintf(stderr, "Got buffer %p of size %d bytes from OS\n", p, size);
        return p;
    }
    else {
        fbs = mst_do_fbs_dw(size);
        slab = (((1 << fbs) / gmpool_size_map[0].size)); // find slab-slot
        slab = mst_do_fbs_dw(slab);

        //fprintf(stderr, "Slab index is %d\n", slab);

        if (size > gmpool_size_map[slab].size) {
            slab = ((slab + 1) % mpool_slab_max);
        }
        //fprintf(stderr, "Corrected Slab index is %d\n", slab);
    }

recheck:
    if (rechk_cnt >= mpool_slab_max) {
        void *p = NULL;
        // We have done a full cycle of unavailable slots. Ask OS.
        p = os_malloc (size);
        //fprintf(stderr, "[max_rechk] Got buffer %p of size %d bytes from OS\n", p, size);
        return p;
    }

    if (atomic_read(&gmpool_slabs[slab].count)) {
        if (size > gmpool_size_map[slab].size) {
            void *p = NULL;
            // We have done a full cycle of unavailable slots. Ask OS.
            p = os_malloc (size);
            //fprintf(stderr, "[unavlbl] Got buffer %p of size %d bytes from OS\n", p, size);
            return p;
        }

        pthread_mutex_lock(&gmpool_slabs[slab].b_lock);
        rb_node = rb_first(&gmpool_slabs[slab].rbr);
        rb_erase(rb_node, &gmpool_slabs[slab].rbr);
        atomic_dec(&gmpool_slabs[slab].count);
        pthread_mutex_unlock(&gmpool_slabs[slab].b_lock);
        mp_node = rb_entry(rb_node, struct mst_mpool_buf, rbn);
        atomic_inc(&mp_node->in_use);
        mst_mpool_rework_buf(rb_node, size);
        mst_mpool_table_insert(mp_node);

        mp_node->who = (int)caller;
        return mp_node->buffer;
    }
    else {
        slab = ((slab + 1) % mpool_slab_max);
        rechk_cnt++;
        goto recheck;
    }

    return NULL;
}

void mst_print_mpool_slabs(void)
{
    int index = 0;
    mst_mpool_buf_t *mp_node;
    struct rb_node *rb_node;
    struct rb_root *rbr;

    for(index = 0; index < mpool_slab_max; index++) {
        rbr = &gmpool_slabs[index].rbr;

        rb_node = rb_first(rbr);
        while(rb_node) {
            mp_node = rb_entry(rb_node, struct mst_mpool_buf, rbn);
            if(mp_node) {
                fprintf(stderr, "Slab-> %s, size: %d, buffer: %p, given_size: %d, head: %d, parent: 0x%0X, tot_child: %d, slab_type: %d\n", 
                        gmpool_size_map[mp_node->slab_type].slab_name, mp_node->size, mp_node->buffer, mp_node->given_size, 
                        mp_node->head, mp_node->parent, atomic_read(&mp_node->tot_child), mp_node->slab_type);
            }
            rb_node = rb_next(rb_node);
        }
        fprintf(stderr, "\n");
    }

    return;
}

void mst_print_mpool_table(void)
{
    int index = 0;
    mst_mpool_buf_t *mp_node;
    struct rb_node *rb_node;
    struct rb_root *rbr;

    for(index = 0; index < D_MPOOL_TABLE_SIZE; index++) {
        rbr = &gmpool_table[index].rbr;

        rb_node = rb_first(rbr);
        while(rb_node) {
            mp_node = rb_entry(rb_node, struct mst_mpool_buf, rbn);
            if(mp_node) {
                fprintf(stderr, "Slab-> %s, size: %d, buffer: %p, given_size: %d, head: %d, parent: 0x%0X, tot_child: %d, slab_type: %d\n", 
                        gmpool_size_map[mp_node->slab_type].slab_name, mp_node->size, mp_node->buffer, mp_node->given_size, 
                        mp_node->head, mp_node->parent, atomic_read(&mp_node->tot_child), mp_node->slab_type);
            }
            rb_node = rb_next(rb_node);
        }
    }
}

#define D_MEM_PER_SLAB (2 * 1024 * 10240) // 20 M

int mst_init_mpool(void)
{
    int index = 0;
    int index_y = 0;
    mst_mpool_buf_t *mp_node;

    for(index = 0; index < mpool_slab_max; index++) {
        pthread_mutex_init(&gmpool_slabs[index].b_lock, NULL);

        //for(index_y = 0; index_y < D_MPOOL_NODES_PER_SLAB; index_y++) {
        for(index_y = 0; index_y < (D_MEM_PER_SLAB/gmpool_size_map[index].size); index_y++) {
            mp_node = (mst_mpool_buf_t *)malloc(sizeof(mst_mpool_buf_t));
            assert(mp_node);
            rb_init_node(&mp_node->rbn);
            mp_node->size = gmpool_size_map[index].size;
            mp_node->buffer = (void *)malloc(mp_node->size);
            mp_node->given_size = 0;
            mp_node->head = 1;
            mp_node->parent = 0;
            atomic_set(&mp_node->tot_child, 0);
            mp_node->slab_type = index;

            //mst_mpool_insert(mp_node, &gmpool_slabs[index].rbr);
            mst_mpool_insert(mp_node);
            //gmpool_slabs[index].count++;
        }
    }
    for(index = 0; index < D_MPOOL_TABLE_SIZE; index++) {
        pthread_mutex_init(&gmpool_table[index].b_lock, NULL);
    }

    fprintf(stderr, "%s() done\n", __func__);

    return 0;
}


/**
 * Overload malloc init hook. This is declared in malloc.h
 */
//__malloc_initialize_hook = mst_memmgmt_init;

void
os_free(void *ptr)
{
    __free_hook = def_free_hook;
    free(ptr);
    __free_hook = mst_free;
}

void *
os_malloc(size_t size)
{
    void *p;

    __malloc_hook = def_malloc_hook;
    p = malloc(size);
    __malloc_hook = mst_malloc;

    return p;
}

void 
mst_memmgmt_init(void)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);

#ifndef __USE_MM__
    __mst_malloc = dlsym(RTLD_NEXT, "malloc");
    __mst_free = dlsym(RTLD_NEXT, "free");
    __mst_realloc = dlsym(RTLD_NEXT, "realloc");
    __mst_memalign = dlsym(RTLD_NEXT, "memalign");

    if (!__mst_malloc || !__mst_free || !__mst_realloc || !__mst_memalign) {
        return;
    }
    fprintf (stderr, "%p, %p, %p, %p\n", __mst_malloc, __mst_free, __mst_realloc, __mst_memalign);
#else
    mst_init_mpool();

    def_malloc_hook = __malloc_hook;
    def_free_hook = __free_hook;
    def_realloc_hook = __realloc_hook;
    def_memalign_hook = __memalign_hook;

    // Only malloc and free are over-loaded
    __malloc_hook = mst_malloc;
    __free_hook = mst_free;
    //__realloc_hook = mst_realloc;
    //__memalign_hook = mst_memalign;
#endif

    return;
}

void *
mst_realloc(void *ptr, size_t size, const void *caller)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
    // TODO: Fill in this place with MM/BM functions
    return __mst_realloc(ptr, size);
}
   
void *
mst_memalign(size_t alignment, size_t size, const void *caller)
{
    // TODO: Fill in this place with MM/BM functions
    return __mst_memalign(alignment, size);
}

#ifdef __SELF_TEST__
int main(int argc, char **argv)
{
    char *buff = NULL;
    int size = 0;
    int count = 0;
    int ptrs[512];
    int index = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <buf_size>\n", argv[0]);
        return 0;
    }

    size = atoi(argv[1]);

    mst_init_mpool();

    do {
        buff = mst_malloc(size);
        fprintf(stderr, "buff %p of size %d bytes\n", buff, size);
        fprintf(stderr, "Printing slabs\n");
        mst_print_mpool_slabs();
        fprintf(stderr, "============\nPrinting table\n");
        mst_print_mpool_table();
        ptrs[count] = (int)buff;
        count++;
    } while(buff);

    fprintf(stderr, "%d * %d bytes\n", (count - 1), size);

    for(index = 0; index < count; index++) {
        mst_free((void *)ptrs[index]);
    }

    fprintf(stderr, "Printing slabs\n");
    mst_print_mpool_slabs();
    fprintf(stderr, "============\nPrinting table\n");
    mst_print_mpool_table();

    return 0;
}
#endif //__SELF_TEST__


