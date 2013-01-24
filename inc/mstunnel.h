#ifndef __MST_MSTUNNEL_H__
#define __MST_MSTUNNEL_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <unistd.h>
#include <syslog.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <assert.h>
#include <string.h>
#include <sys/uio.h>
#include <netdb.h>
#include <net/if.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <sys/queue.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/mman.h>

#include "mst_mbuf.h"
#include "mst_constants.h"
#include "mst_atomic.h"

#define M_MNP_REF_UP(x) \
        atomic_inc(&(x)->ref_cnt)

#define M_MNP_REF_DOWN(x) \
        atomic_dec(&(x)->ref_cnt)

#define M_MNP_REF_DOWN_AND_FREE(x) \
    {\
        if (atomic_dec_and_test(&(x)->ref_cnt)) { \
            mst_cleanup_mnp(x); \
        }\
    }

typedef struct mst_node_info {
    char *host_name;
    char *host_addr;
    unsigned host_ipv4;
    int port;
    int policy_mark; // applicable for clients 
} mst_node_info_t;

typedef struct mst_configuration {
    struct event_config *ev_cfg;
    struct sctp_event_subscribe sctp_ev_subsc;
    int mst_mode; // 0 - client, 1 - server
    int log_level;
} mst_config_t;

typedef struct mst_nw_parms {
    float link_nice; // ~ 1/(avg SRTT) of the link
    int xmit_factor; // default 10
    atomic_t xmit_max_pkts; // link_nice * xmit_factor
    atomic_t xmit_curr_pkts; 
    int xmit_curr_cnt; // Current cnt transmitted
    int xmit_curr_stream; // Current stream #
    //TODO: Extend this to have all conn/tunn specific config and placeholders
} mst_nw_parms_t;

// client-server info
typedef struct mst_clisvr_info {
    // multiple Interfaces/links to one/multiple servers
    struct mst_clisvr_info *__next;
    unsigned short num_ostreams; // number of out streams
    unsigned short max_instreams; // Max instreams that we support
    mst_nw_parms_t nw_parms;
    mst_node_info_t *client;
    mst_node_info_t *server;
} mst_csi_t;

typedef struct mst_opts {
    char *config_db; // points to config file
    
    char *ifconfig; // points to ifconfig command with abs path
    char *route; // points to route binary
    char *iproute; // points to ip route command
    char *iprule; // points to ip rule command for policy routing

    mst_config_t mst_config;
    mst_csi_t *mst_tuple;
    int mst_tuple_cnt;
    int mst_sk_backlog;
    pthread_rwlock_t rwlock;
} mst_opts_t;


struct mst_timer_data;

typedef enum mst_link_color {
    MST_LINK_GREEN = 0x1001,
    MST_LINK_YELLOW,
    MST_LINK_RED,
} mst_link_color_t;

typedef struct mst_stat {
    unsigned smf_1; // smoothing factor - 1
    unsigned smf_2; // smoothing factor - 2
    
    int *pkts_in;
    int *pkts_out;
    int last_pkts_in;
    int last_pkts_out;
    int *bytes_in;
    int *bytes_out;
    int last_bytes_in;
    int last_bytes_out;
    int tx_error;
    int rx_error;

    int *unack_cnt;
    int *pending_cnt;
    int *srtt;
    int *min_srtt;
    int *max_srtt;
    int *avg_srtt;

    int *min_rx_bw;
    int *max_rx_bw;
    int *rx_bw;
    unsigned rx_time;
    unsigned last_rx_time;
    
    int *min_tx_bw;
    int *max_tx_bw;
    int *tx_bw;
    unsigned tx_time;
    unsigned last_tx_time;
    unsigned last_tx_clog;

    int curr_sample_cnt;
    int sample_cnt;
    int *snd_cnt;
    int min_snd_cnt;
    int max_snd_cnt;

    mst_link_color_t link_color;
} mst_stat_t;
    
TAILQ_HEAD(mst_mbuf_q, mst_buf_q);

typedef struct mst_conn {
    evutil_socket_t conn_fd;
    struct event *read_event; // read
    struct event *write_event; // write
    struct sockaddr_in ip_tuple;
    mst_csi_t *mst_tuple;
    struct mst_timer_data *timer_data; 
    mst_stat_t mst_conn_stat;
    mst_nw_parms_t nw_parms;
    mst_buffer_t *mbuf;
    struct iovec *iov;
    struct mst_mbuf_q mbuf_wq; // write_queue
    pthread_mutex_t wq_lock;
    int event_flags;
    int curr_state;
} mst_conn_t;

typedef struct mst_event_base {
    // epoll infra
    int epfd;
    int ev_cnt; // total number of events
    struct epoll_event ev;
    struct epoll_event *evb;
    pthread_mutex_t ev_lock;

    // Timer_event_base
    struct event_base *Teb;
} mst_event_base_t;

// MNP - FLAGs - 4 bytes
// MSB 2-bytes: MNP Type (max 16 types)
// 0x1 - MNP_LISTEN
// 0x2 - MNP_CONNECT
// 0x4 - MNP_PEER
// 0x8 - MNP_TUN
//
// LSB 2-bytes: MNP State (max 16 states)
// 0x1 - LISTEN
// 0x2 - CONNECTING
// 0x4 - CONNECTED
// 0x8 - TUNNEL (Applicable only when MNP Type is MNP_TUN
// 0x10 - ERROR
//

// MNP Types
#define D_MNP_TYPE_TUN 0x1
#define D_MNP_TYPE_NW 0x2

#define M_MNP_TYPE(x) (((x) & 0xFFFF0000) >> 16)
#define M_MNP_SET_TYPE(x, state) (((x) & 0x0000FFFF) | (state << 16))

// MNP State
#define D_MNP_STATE_LISTEN 0x1
#define D_MNP_STATE_CONNECTING 0x2
#define D_MNP_STATE_CONNECTED 0x4
#define D_MNP_STATE_ESTABLISHED 0x8
#define D_MNP_STATE_TUNNEL 0x10
#define D_MNP_STATE_ERROR 0x20

#define M_MNP_STATE(x) ((x) & 0x0000FFFF)
#define M_MNP_SET_STATE(x, state) (((x) & 0xFFFF0000) | state)
#define M_MNP_UNSET_STATE(x, state) (((x) & 0xFFFFFFFF) & ~state)

typedef struct mst_nw_peer {
    int mnp_flags;
    mst_conn_t *mst_connection;
    int mnp_pair; //holds a pointer to its pair FD. conn <-> tunn pair
    int nw_id;
    unsigned short num_ostreams; // number of out streams
    unsigned short max_instreams; // Max instreams that we support
    mst_config_t *mst_config;
    pthread_mutex_t ref_lock;
    atomic_t ref_cnt;

    void (*mst_epoll_write)(struct mst_nw_peer *pmnp);
    void (*mst_epoll_read)(struct mst_nw_peer *pmnp);
    int (*mst_data_write)(struct mst_nw_peer *pmnp, mst_buffer_t *mbuf, int rlen);
    int (*mst_data_read)(struct mst_nw_peer *pmnp);
} mst_nw_peer_t;

typedef enum mst_nw_q_type {
    MST_SCTP_Q = 10,
    MST_TUN_Q,
} mst_nw_q_type_t;

typedef struct mst_nw_q {
    mst_nw_q_type_t q_type;
    mst_nw_peer_t *pmnp; // this is mnp
    TAILQ_ENTRY(mst_nw_q) q_field;
} mst_nw_q_t;

typedef enum mst_timer_priv_type {
    MST_SYS = 10, // system timer - 1s
    MST_MNP,
} mst_timer_priv_type_t;

typedef struct mst_timer_data {
    int type;
    struct timeval timeo;
    struct event *te; // Event to track FD status
    void *data;
} mst_timer_data_t;

typedef struct mst_timer {
    struct event_base *teb;
    mst_timer_data_t *sys_td; // system timer data 
} mst_timer_t;

#define mst_fd mst_connection->conn_fd
#define mst_ceb mst_connection->conn_event_base
#define mst_re mst_connection->read_event
#define mst_we mst_connection->write_event
#define mst_td mst_connection->timer_data
#define mst_ipt mst_connection->ip_tuple
#define mst_mt mst_connection->mst_tuple
#define mst_cs mst_connection->mst_conn_stat
#define mst_cbuf mst_connection->mbuf
#define mst_ciov mst_connection->iov
#define mst_wq mst_connection->mbuf_wq
#define mst_wql mst_connection->wq_lock
#define mst_rc mst_connection->ref_cnt
#define mst_ef mst_connection->event_flags
#define mst_curr mst_connection->curr_state
#define mst_nwp mst_connection->nw_parms

#define mst_ec mst_config.ev_cfg
#define mst_ses mst_config.sctp_ev_subsc
#define pmst_ses mst_config->sctp_ev_subsc

#define pmst_mt mst_config->mst_tuple

extern mst_opts_t mst_global_opts;

extern int mst_process_message(mst_nw_peer_t *mnp, struct msghdr *rmsg, int rlen);
extern int mst_link_status(mst_nw_peer_t *mnp);

extern inline mst_csi_t * mst_get_tuple_config(void);
extern inline mst_config_t * mst_get_mst_config(void);

extern inline int mst_get_mnp_state(mst_nw_peer_t *pmnp); 

#endif //!__MST_MSTUNNEL_H__
