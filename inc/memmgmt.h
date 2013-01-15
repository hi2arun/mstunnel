#ifndef __MST_MEMMGMT_H__
#define __MST_MEMMGMT_H__

#include "mstrb.h"

typedef enum mst_mpool_slab {
    mpool_slab32 = 0,
    mpool_slab64,
    mpool_slab128,
    mpool_slab256,
    mpool_slab512,
    mpool_slab1024,
    mpool_slab2048,
    mpool_slab4096,
    mpool_slab_max // nothing after this
} mst_mpool_slab_t;

typedef struct mst_mpool_size_map {
    int size;
    char *slab_name;
} mst_mpool_size_map_t;

typedef struct mst_mpool_buf {
    struct rb_node rbn;
    void *buffer;
    int size;
    int head; // 0/1
    int given_size;
    int parent; // Address of parent node, if head = 0
    atomic_t tot_child;
    atomic_t in_use;
    int who; // Owner of this memory
    mst_mpool_slab_t slab_type;
} mst_mpool_buf_t;

typedef struct mst_mpool_bucket {
    atomic_t count;
    struct rb_root rbr;
    pthread_mutex_t b_lock;
} mst_mpool_bucket_t;

#define D_MPOOL_TABLE_SIZE 1024 // 2^10 - MSB 10 bits of the address is key
#define D_MPOOL_NODES_PER_SLAB 8192

void mst_memmgmt_init(void);
void *mst_malloc(size_t size, const void *caller);
void mst_free(void *ptr, const void *caller);
void *mst_realloc(void *ptr, size_t size, const void *caller);
void *mst_memalign(size_t alignment, size_t size, const void *caller);

void *(*__mst_malloc)(size_t size);
void (*__mst_free)(void *ptr);
void *(*__mst_realloc)(void *ptr, size_t size);
void *(*__mst_memalign)(size_t alignment, size_t size);


extern int mst_membuf_init(void);
extern mst_buffer_t *mst_alloc_mbuf(size_t size, int, int module);
extern void mst_dealloc_mbuf(mst_buffer_t *);
extern struct iovec * mst_mbuf_to_iov(mst_buffer_t *mbuf, int *iov_len, int); 
extern struct iovec * mst_mbuf_rework_iov(mst_buffer_t *mbuf, int rlen, int *iov_len, int); 

#endif //!__MST_MEMMGMT_H__
