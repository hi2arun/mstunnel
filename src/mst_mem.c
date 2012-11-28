#include <malloc.h>
#include <stdlib.h>
#define __USE_GNU
#include <dlfcn.h>

#include "mstunnel.h"
#include "memmgmt.h"

#ifdef __USE_MM__
static void *(*def_malloc_hook)(size_t size, const void *caller);
static void (*def_free_hook)(void *ptr, const void *caller);
static void *(*def_realloc_hook)(void *ptr, size_t size, const void *caller);
static void *(*def_memalign_hook)(size_t alignment, size_t size, const void *caller);
#endif

/**
 * Overload malloc init hook. This is declared in malloc.h
 */
//__malloc_initialize_hook = mst_memmgmt_init;

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
    def_malloc_hook = __malloc_hook;
    def_free_hook = __free_hook;
    def_realloc_hook = __realloc_hook;
    def_memalign_hook = __memalign_hook;

    __malloc_hook = mst_malloc;
    __free_hook = mst_free;
    __realloc_hook = mst_realloc;
    __memalign_hook = mst_memalign;
#endif

    return;
}

void *
mst_malloc(size_t size, const void *caller)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
    // TODO: Fill in this place with MM/BM functions
    return __mst_malloc(size);
}

void
mst_free(void *ptr, const void *caller)
{
    fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
    // TODO: Fill in this place with MM/BM functions
    __mst_free(ptr);
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


mst_mem_config_t mst_mbuf_inuse_slots[mst_buf_unk];
mst_mem_config_t mst_mbuf_free_slots[mst_buf_unk];

typedef struct mem_slot_details {
    char mem_slot_name[D_NAME_SIZ + 1];
    int size_in_bytes;
} mem_slot_details_t;

mem_slot_details_t msd[mst_buf_unk] = {
    {"mst_buf32", 32},
    {"mst_buf64", 64},
    {"mst_buf128", 128},
    {"mst_buf256", 256},
    {"mst_buf512", 512},
    {"mst_buf1024", 1024},
    {"mst_buf2048", 2048},
    {"mst_buf4096", 4096},
};

#define D_MEM_SIZE_PER_CHAIN (1024 * 10240) // 10 M

int mst_add_mbuf_to_inuse(int slot, mst_buffer_t *__mbuf)
{
    mst_buf_head_t *__mbuf_head = &(mst_mbuf_inuse_slots[slot].__mbuf_chain);

    __mbuf->__prev = NULL;
    __mbuf->__next = __mbuf_head->mbuf_list;
    __mbuf_head->mbuf_list = __mbuf;
    __mbuf_head->mbuf_available += (__mbuf->frags_count + 1);
    return 0;
}

#define D_MEM_BLK_MIN 64 // 64 bytes is the min we have

int mst_get_slot(int factor)
{
    int count = 1;

chk:
    if (1 == factor) {
        return count;
    }

    factor >>= 1;
    count++;
    goto chk;

    return 0; // i knw.. h ehe
}
//
// block_type:
//  0 - fragmented first, linear next
//  1 - linear first, fragmented next
mst_buffer_t *mst_alloc_mbuf(size_t size, int block_type, int module)
{
    int slot = -1;
    int frag_size = 0;
    unsigned int index = 0;
    int new_slot = -1;
    int frags_count = 0;

    if (!size) {
        return NULL;
    }

    if (block_type) {
        frag_size = size;
    }
    else {
        frag_size = size / 4;
    }

    if (frag_size < msd[0].size_in_bytes) {
        slot = 0;
    }
    else {
        // msd[0]/size_in_bytes always points to the least mem block size we support
        // size / least_size points to the slot the blocks to be fetched from.
        slot = mst_get_slot(frag_size / msd[0].size_in_bytes) - 1;
        if(frag_size % msd[0].size_in_bytes) {
            // Handle over-boundary case
            // Eg. size = 70, least = 64, size/least = 1; size % least = 6, thus slot + 1 = 1 => slot_128
            // This is a wastage of bytes. Thus ask for properly sized blocks in 2^n, where 4 > n <= 12.
            slot += 1;
        }
        fprintf(stderr, "Requested size: %d, frag_size: %d, slot: %d\n", size, frag_size, slot);
    }
    assert((slot >= mst_buf32) && (slot < mst_buf_unk));
    
    if (mst_mbuf_free_slots[slot].__mbuf_chain.mbuf_available) {
        new_slot = slot;
    }
    else {
        for (index = (slot + 1)%mst_buf_unk; index != slot; index = (index + 1)%mst_buf_unk) {
            if (mst_mbuf_free_slots[index].__mbuf_chain.mbuf_available) {
                new_slot = index;
                break;
            }
        }
    }
    fprintf(stderr, "Requested size: %d, frag_size: %d, slot: %d, new_slot: %d\n", size, frag_size, slot, new_slot);

    if (size < mst_mbuf_free_slots[new_slot].size_per_block) {
        // TODO: Check with OS for the asked memory
        fprintf(stderr, "Assert size < size_per_block\n");
        return NULL;
    }

    frags_count = size / mst_mbuf_free_slots[new_slot].size_per_block;
    fprintf(stderr, "Frags count: %d, spb: %d\n", frags_count, mst_mbuf_free_slots[new_slot].size_per_block);
    if (frags_count > mst_mbuf_free_slots[new_slot].__mbuf_chain.mbuf_available) {
        // TODO: Check with OS for the asked memory
        fprintf(stderr, "Assert frags_count > mbuf_available\n");
        return NULL;
    }
    // frags_count should at least be 1
    assert(frags_count);

    {
        mst_buf_head_t *__mbuf_head = &(mst_mbuf_free_slots[new_slot].__mbuf_chain);
        mst_buffer_t *__mbuf = NULL;
        mst_buffer_t *mbuf_temp = NULL;

        __mbuf = __mbuf_head->mbuf_list;

        __mbuf->frags_count = frags_count - 1;
        for(index = 0, mbuf_temp = __mbuf; index < (frags_count - 1) && mbuf_temp; index++) {
            mbuf_temp = mbuf_temp->__next;
        }
        if (frags_count) {
            __mbuf->mfrags = __mbuf->__next;
        }
        __mbuf_head->mbuf_list = mbuf_temp->__next;
        mbuf_temp->__next = NULL;
        //__mbuf_head->mbuf_list = __mbuf->__next;
        __mbuf_head->mbuf_list->__prev = NULL;
        __mbuf->__next = NULL;
        __mbuf->__prev = NULL;
        __mbuf_head->mbuf_available -= frags_count;
        
        mst_add_mbuf_to_inuse(slot, __mbuf);
        return __mbuf;
    }

    return NULL;
}

int
mst_membuf_init()
{
    int index = 0;
    int cntr = 0;

    for (index = 0; index < mst_buf_unk; index++) {
        memcpy(mst_mbuf_free_slots[index].mem_blk_name, msd[index].mem_slot_name, D_NAME_SIZ);
        memcpy(mst_mbuf_inuse_slots[index].mem_blk_name, msd[index].mem_slot_name, D_NAME_SIZ);
        
        mst_mbuf_free_slots[index].size_per_block = msd[index].size_in_bytes;
        mst_mbuf_inuse_slots[index].size_per_block = msd[index].size_in_bytes;
        
        mst_mbuf_free_slots[index].__mbuf_chain.mbuf_count = D_MEM_SIZE_PER_CHAIN/mst_mbuf_free_slots[index].size_per_block;
        mst_mbuf_inuse_slots[index].__mbuf_chain.mbuf_count = D_MEM_SIZE_PER_CHAIN/mst_mbuf_inuse_slots[index].size_per_block;
        
        mst_mbuf_free_slots[index].__mbuf_chain.mbuf_available = mst_mbuf_free_slots[index].__mbuf_chain.mbuf_count;
        mst_mbuf_inuse_slots[index].__mbuf_chain.mbuf_available = 0;
        
        mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list = NULL;
        mst_mbuf_inuse_slots[index].__mbuf_chain.mbuf_list = NULL;

        for (cntr = 0; cntr < mst_mbuf_free_slots[index].__mbuf_chain.mbuf_count; cntr++) {
            mst_buffer_t *node = (mst_buffer_t *)__mst_malloc(sizeof(mst_buffer_t));
            if (!node) {
                fprintf(stderr, "FATAL: malloc failed\n");
                assert(node);
            }
            node->buf_type = index;
            node->__which = &mst_mbuf_free_slots[index];
            node->buffer = (void *)__mst_malloc(mst_mbuf_free_slots[index].size_per_block);
            node->buf_len = mst_mbuf_free_slots[index].size_per_block;
            node->__prev = NULL;
            node->__next = mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list;
            mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list = node;
        }
    }

    fprintf(stderr, "Membuf slots initialized successfully\n");

    return 0;
}
