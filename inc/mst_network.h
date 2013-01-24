#ifndef __MST_NETWORK_H__
#define __MST_NETWORK_H__

#include <netinet/ip.h>

#include "ds/mst_list.h"
#include "ds/mst_jhash.h"

#define D_IPV4 4
#define D_IPV4_STR_FMT "%u.%u.%u.%u"
#define M_NIPQUAD(x) \
    (unsigned char)*((char *)x + 0), \
    (unsigned char)*((char *)x + 1), \
    (unsigned char)*((char *)x + 2), \
    (unsigned char)*((char *)x + 3)

#define D_NW_CONN_TABLE_SIZE 512
#define D_NW_TOT_LINKS 2
// MSB(16 bytes): Major version
// LSB(16 bytes): Minor version
#define D_NW_VERSION_1_0 0x00010000

typedef struct mst_nw_header {
    int nw_version;
    int nw_id;
} __attribute__((__packed__)) mst_nw_header_t;

#define D_MIN_SND_CNT 4 
#define D_MAX_SND_CNT 100
#define D_SAMPLE_CNT 10 

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
    int link_type; // 0 - similar, 1 - dissimilar
    pthread_mutex_t n_lock; // node lock
//    TAILQ_HEAD(mst_mnp_q, mst_mnp) mnp_list;
} mst_nw_conn_t;

typedef struct mst_nw_conn_table {
    struct hlist_head bucket;
    pthread_mutex_t b_lock; // bucket lock
} mst_nw_conn_table_t;

#define D_IP_FLOW_TABLE_SIZE 512
#define D_IP_SLOTS_PER_FLOW 32

typedef enum mst_ip_dir {
    E_NW_IN = 100,
    E_TUN_IN,
} mst_ip_dir_t;

typedef struct mst_ip_tuple {
    struct mst_ip_tuple *next;
    struct mst_ip_tuple *prev;
    unsigned sip;
    unsigned dip;
    unsigned sid; // SCTP flow ID
    unsigned hits;
    // perhaps, will think of adding L4 info later
} mst_ip_tuple_t;

typedef struct mst_nw_ip_flow {
    mst_ip_tuple_t *head;
    mst_ip_tuple_t *tail;
    int slots;
    pthread_mutex_t b_lock; // bucket lock
} mst_nw_ip_flow_t;

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


extern int mst_init_ip_flow_table(void);
extern int mst_insert_ip_tuple(unsigned sip, unsigned dip, mst_ip_dir_t ip_dir, unsigned sid);
extern int mst_lookup_ip_tuple(unsigned sip, unsigned dip, mst_ip_dir_t ip_dir, int sid);
extern int mst_get_ip_info(char *data, int rlen, unsigned *sip, unsigned *dip);
extern void mst_dump_ip_flow_table(void);

extern int mst_calculate_tput(mst_nw_peer_t *pmnp);

#endif //!__MST_NETWORK_H__
