#ifndef __MST_NETWORK_H__
#define __MST_NETWORK_H__

#include "ds/mst_list.h"
#include "ds/mst_jhash.h"

#define D_NW_CONN_TABLE_SIZE 512
#define D_NW_TOT_LINKS 2
// MSB(16 bytes): Major version
// LSB(16 bytes): Minor version
#define D_NW_VERSION_1_0 0x00010000

typedef struct mst_nw_header {
    int nw_id;
    int nw_version;
} __attribute__((__packed__)) mst_nw_header_t;

typedef struct mst_mnp {
    int slot_available;
    int mnp_id;
//    TAILQ_ENTRY(mst_mnp) q_field;
} mst_mnp_t;

typedef struct mst_nw_conn {
    struct hlist_node hnode;
    int nw_id;
    atomic_t ref_cnt;
    mst_mnp_t mnp_slots[D_NW_TOT_LINKS];
    int curr_slot;
    int mnp_pair;
    pthread_mutex_t n_lock; // node lock
//    TAILQ_HEAD(mst_mnp_q, mst_mnp) mnp_list;
} mst_nw_conn_t;

typedef struct mst_nw_conn_table {
    struct hlist_head bucket;
    pthread_mutex_t b_lock; // bucket lock
} mst_nw_conn_table_t;

extern int mst_setup_network(void);
extern int mst_loop_network(void);
extern int mst_setup_tunnel(mst_nw_peer_t *pmnp);
extern int mst_cleanup_mnp(mst_nw_peer_t *pmnp);
extern int mst_do_tun_read(mst_nw_peer_t *pmnp);
extern int mst_do_nw_read(mst_nw_peer_t *pmnp);
extern int mst_do_nw_write(mst_nw_peer_t *pmnp, mst_buffer_t *, int rlen);
extern int mst_do_tun_write(mst_nw_peer_t *pmnp, mst_buffer_t *, int rlen);
extern int mst_init_network(void);
extern inline void mst_epoll_events(mst_nw_peer_t *pmnp, int ev_cmd, int events);
extern void mst_nw_write(mst_nw_peer_t *pmnp);
extern void mst_tun_write(mst_nw_peer_t *pmnp);

extern mst_nw_conn_t *mst_mnp_by_nw_id (int nw_id);
extern int mst_lookup_nw_id (int nw_id);
extern int mst_lookup_mnp_by_nw_id (int nw_id, int mnp_id);
extern int mst_insert_mnp_by_nw_id (int nw_id, int mnp_id);
extern int mst_remove_mnp_by_nw_id (int nw_id, int mnp_id);
extern mst_nw_peer_t *mst_get_next_fd(int nw_id);

#endif //!__MST_NETWORK_H__
