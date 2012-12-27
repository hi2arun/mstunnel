#ifndef __MST_NW_QUEUE_H__
#define __MST_NW_QUEUE_H__

extern int mst_init_nw_queue(void);
extern int mst_init_tun_queue(void);
extern int mst_insert_nw_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp);
extern int mst_insert_tun_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp);
extern int mst_init_epoll_queue(void);
extern int mst_insert_epoll_queue(mst_nw_q_t *qelm);
extern mst_nw_q_t *mst_epoll_dequeue_tail(void);
extern int mst_insert_mbuf_q(mst_nw_peer_t *pmnp, mst_buffer_t *mbuf, int len);
extern mst_buf_q_t *mst_mbuf_dequeue_tail(mst_nw_peer_t *pmnp);


#endif // !__MST_NW_QUEUE_H__
