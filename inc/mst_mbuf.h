#ifndef __MST_MBUF_H__
#define __MST_MBUF_H__

typedef enum mst_buf_type {
    mst_buf32,
    mst_buf64,
    mst_buf128,
    mst_buf256,
    mst_buf512,
    mst_buf1024,
    mst_buf2048,
    mst_buf4096,
    mst_buf_unk //Shud be the last one
} mst_buf_t;

struct mst_buf_head;
struct mst_buffer;

typedef struct mst_buf_head {
    int mbuf_count;
    int mbuf_available;
    struct mst_buffer *mbuf_list;
} mst_buf_head_t;

#define D_NAME_SIZ 15
typedef struct mst_mem_config {
    char mem_blk_name[D_NAME_SIZ + 1];
    int size_per_block; // in bytes
    struct mst_buf_head __mbuf_chain;
    pthread_mutex_t mem_lock;
} mst_mem_config_t;

typedef struct mst_buffer {
    struct mst_buffer *__prev;
    struct mst_buffer *__next;
    struct mst_mem_config *__which;
    mst_buf_t buf_type;
    void *buffer;
    unsigned sid; // SCTP flow id
    int buf_len;
    struct iovec *iov;
    int iov_len;
    int frags_count; // frags_len = frags_count * buf_len
    struct mst_buffer *mfrags;
    struct mst_buffer *mfrags_tail;
} mst_buffer_t;

typedef struct mst_buf_q {
    mst_buffer_t *mbuf;
    int wlen;
    TAILQ_ENTRY(mst_buf_q) q_field;
} mst_buf_q_t;

#endif //!__MST_MBUF_H__
