#include "mstunnel.h"
#include "memmgmt.h"

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

    pthread_mutex_lock(&mst_mbuf_inuse_slots[slot].mem_lock);
    __mbuf->__prev = NULL;
    __mbuf->__next = __mbuf_head->mbuf_list;
    if (__mbuf_head->mbuf_list) {
        __mbuf_head->mbuf_list->__prev = __mbuf;
    }
    __mbuf_head->mbuf_list = __mbuf;
    __mbuf_head->mbuf_available += (__mbuf->frags_count + 1);
    pthread_mutex_unlock(&mst_mbuf_inuse_slots[slot].mem_lock);
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

void mst_free_iov(struct iovec *iov)
{
    __mst_free(iov);
    return;
}

struct iovec *
mst_mbuf_rework_iov(mst_buffer_t *mbuf, int rlen, int *iov_len)
{
    int tot_iovs = mbuf->iov_len;
    struct iovec *iov = mbuf->iov;
    int buf_len = mbuf->buf_len;
    int needed_iovs = 0;


    // Calculate how many iovs are needed and number of mbufs to be reclaimed
    if (rlen > buf_len) {
        // rlen > buf_len - we need more than one iovs
        needed_iovs = (rlen / buf_len) + ((rlen % buf_len)?1:0); // number of iovs to be preserved
        //fprintf(stderr, "rlen > buf_len: needed_iovs: %d\n", needed_iovs);
    }
    else {
        needed_iovs = 1; // number of iovs to be preserved
    }

    assert(tot_iovs >= needed_iovs);

    // Now return excess mbufs to pool
    iov[needed_iovs - 1].iov_len = (rlen % buf_len);
    //fprintf(stderr, "Needed iovs: %d, rlen: %d, buf_len: %d\n", needed_iovs, rlen, buf_len);

    *iov_len = needed_iovs;
    return iov;
}

struct iovec *
mst_mbuf_to_iov(mst_buffer_t *mbuf, int *iov_len) 
{
    struct iovec *iov;
    int index = 0;
    mst_buffer_t *mbuf_temp;

    //iov = (struct iovec*)__mst_malloc(sizeof(struct iovec) * (mbuf->frags_count + 1));
    mbuf->iov = (struct iovec*)__mst_malloc(sizeof(struct iovec) * (mbuf->frags_count + 1));
    //if (!iov) {
    if (!mbuf->iov) {
        return NULL;
    }

    iov = mbuf->iov;

    iov[0].iov_len = mbuf->buf_len;
    iov[0].iov_base = mbuf->buffer;

    for(mbuf_temp = mbuf->mfrags, index = 1; mbuf->frags_count && mbuf_temp; mbuf_temp = mbuf_temp->__next, index++) {

        iov[index].iov_len = mbuf_temp->buf_len;
        iov[index].iov_base = mbuf_temp->buffer;
        //fprintf(stderr, "mbuf: %p, ftail: %p, mbuf_temp: %p\n", mbuf, mbuf->mfrags_tail, mbuf_temp);
    }

    //fprintf(stderr, "Frags_count: %d, index: %d\n", mbuf->frags_count, index);

    assert(index == (mbuf->frags_count + 1));

    mbuf->iov_len = index;

    *iov_len = index;

    return iov;
}

void mst_dealloc_mbuf(mst_buffer_t *mbuf)
{
    //mst_mem_config_t *mbuf_inuse_slot = mbuf->__which;
    mst_mem_config_t *mbuf_inuse_slot = &mst_mbuf_inuse_slots[mbuf->buf_type];
    mst_mem_config_t *mbuf_free_slot = NULL;
    mst_buffer_t *mbuf_temp = NULL;

    //fprintf(stderr, "%s() called: size: %d, frags_count: %d\n", __func__, mbuf->buf_type, mbuf->frags_count);

    assert((mbuf->buf_type >= mst_buf32) && (mbuf->buf_type < mst_buf_unk));

#if 0
    // Acquire inuse list lock here
    pthread_mutex_lock(&mbuf_inuse_slot->mem_lock);

    // it is the first element
    if (!mbuf->__prev) {
        mbuf_inuse_slot->__mbuf_chain.mbuf_list = mbuf->__next;
    }
    else {
        mbuf_temp = mbuf->__prev;
        mbuf_temp->__next = mbuf->__next;
    }
    mbuf_inuse_slot->__mbuf_chain.mbuf_available -= (mbuf->frags_count + 1);
    mbuf->__prev = NULL;
    mbuf->__next = NULL;
    
    // Release inuse list lock here
    pthread_mutex_unlock(&mbuf_inuse_slot->mem_lock);

#endif

    mbuf_free_slot = &mst_mbuf_free_slots[mbuf->buf_type];
    
    // Acquire free list lock here
    pthread_mutex_lock(&mbuf_free_slot->mem_lock);

    // Now that mbuf is removed from 'inuse' slots, add it to 'free' slots
    mbuf_temp = mbuf_free_slot->__mbuf_chain.mbuf_list;
    // Make mbuf at head and the existing chain follows it
    mbuf->__next = mbuf_temp;
    mbuf_temp->__prev = mbuf;
    if (mbuf->frags_count) {
        // Make mfrags at the head of the list
        mbuf->mfrags_tail->__next = mbuf;
        mbuf->__prev = mbuf->mfrags_tail;
        mbuf_free_slot->__mbuf_chain.mbuf_list = mbuf->mfrags;
    }
    else {
        // Make mbuf at the head of the list
        mbuf_free_slot->__mbuf_chain.mbuf_list = mbuf;
    }
    mbuf_free_slot->__mbuf_chain.mbuf_available += (mbuf->frags_count + 1);
    // Now do the cleanup of mbuf
    mbuf->frags_count = 0;
    mbuf->mfrags = NULL;
    mbuf->mfrags_tail = NULL;
    if (mbuf->iov) {
        __mst_free(mbuf->iov);
        mbuf->iov = NULL;
    }
    mbuf->iov_len = 0;

    // Release free list lock here
    pthread_mutex_unlock(&mbuf_free_slot->mem_lock);
    return;
    
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
        //fprintf(stderr, "Requested size: %d, frag_size: %d, slot: %d\n", size, frag_size, slot);
    }
    assert((slot >= mst_buf32) && (slot < mst_buf_unk));
    
    pthread_mutex_lock(&mst_mbuf_free_slots[slot].mem_lock);
    if (mst_mbuf_free_slots[slot].__mbuf_chain.mbuf_available) {
        new_slot = slot;
    }
    else {
        pthread_mutex_unlock(&mst_mbuf_free_slots[slot].mem_lock);
        for (index = (slot + 1)%mst_buf_unk; index != slot; index = (index + 1)%mst_buf_unk) {
            pthread_mutex_lock(&mst_mbuf_free_slots[index].mem_lock);
            if (mst_mbuf_free_slots[index].__mbuf_chain.mbuf_available) {
                new_slot = index;
                break;
            }
            pthread_mutex_unlock(&mst_mbuf_free_slots[index].mem_lock);
        }
    }
    //fprintf(stderr, "Requested size: %d, frag_size: %d, slot: %d, new_slot: %d\n", size, frag_size, slot, new_slot);

    if (size < mst_mbuf_free_slots[new_slot].size_per_block) {
        // TODO: Check with OS for the asked memory
        fprintf(stderr, "Assert size < size_per_block\n");
        
        pthread_mutex_unlock(&mst_mbuf_free_slots[new_slot].mem_lock);
        return NULL;
    }

    frags_count = size / mst_mbuf_free_slots[new_slot].size_per_block;
    //fprintf(stderr, "Frags count: %d, spb: %d\n", frags_count, mst_mbuf_free_slots[new_slot].size_per_block);
    if (frags_count > mst_mbuf_free_slots[new_slot].__mbuf_chain.mbuf_available) {
        // TODO: Check with OS for the asked memory
        fprintf(stderr, "Assert frags_count > mbuf_available\n");
        
        pthread_mutex_unlock(&mst_mbuf_free_slots[new_slot].mem_lock);
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
        if (frags_count - 1) {
            __mbuf->mfrags = __mbuf->__next;
            __mbuf->mfrags->__prev = NULL;
            __mbuf->mfrags_tail = mbuf_temp;
        }
        __mbuf_head->mbuf_list = mbuf_temp->__next;
        mbuf_temp->__next = NULL;
        __mbuf_head->mbuf_list->__prev = NULL;
        __mbuf->__next = NULL;
        __mbuf->__prev = NULL;
        __mbuf_head->mbuf_available -= frags_count;
        
        pthread_mutex_unlock(&mst_mbuf_free_slots[new_slot].mem_lock);
        
        //mst_add_mbuf_to_inuse(new_slot, __mbuf);
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
        
        pthread_mutex_init(&mst_mbuf_free_slots[index].mem_lock, NULL);
        pthread_mutex_init(&mst_mbuf_inuse_slots[index].mem_lock, NULL);

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
            node->mfrags_tail = node->mfrags = NULL;
            node->iov = NULL;
            node->iov_len = 0;
            node->__prev = NULL;
            node->__next = mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list;
            if (mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list) {
                mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list->__prev = node;
            }
            mst_mbuf_free_slots[index].__mbuf_chain.mbuf_list = node;
        }
    }

    //fprintf(stderr, "Membuf slots initialized successfully\n");

    return 0;
}
