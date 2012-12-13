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
#include <glib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <sys/queue.h>

#include "mst_mbuf.h"
#include "mst_constants.h"

#define M_MNP_REF_UP(x) \
    {\
        pthread_mutex_lock(&(x)->ref_lock); \
        (x)->ref_cnt++; \
        pthread_mutex_unlock(&(x)->ref_lock); \
    }

#define M_MNP_REF_DOWN(x) \
    {\
        pthread_mutex_lock(&(x)->ref_lock); \
        if ((x)->ref_cnt) { \
            (x)->ref_cnt--; \
        }\
        pthread_mutex_unlock(&(x)->ref_lock); \
    }

#define M_MNP_REF_DOWN_AND_FREE(x) \
    {\
        pthread_mutex_lock(&(x)->ref_lock); \
        if ((x)->ref_cnt) { \
            (x)->ref_cnt--; \
        }\
        if (0 == (x)->ref_cnt) { \
            mst_cleanup_mnp(x); \
        }\
        pthread_mutex_unlock(&(x)->ref_lock); \
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
    unsigned short num_ostreams; // number of out streams
    unsigned short max_instreams; // Max instreams that we support
    float link_nice; // ~ 1/(avg SRTT) of the link
    int xmit_factor; // default 10
    int xmit_max_pkts; // link_nice * xmit_factor
    int xmit_curr_cnt; // Current cnt transmitted
    int xmit_curr_stream; // Current stream #
    //TODO: Extend this to have all conn/tunn specific config and placeholders
} mst_nw_parms_t;


// client-server info
typedef struct mst_clisvr_info {
    // multiple Interfaces/links to one/multiple servers
    struct mst_clisvr_info *__next;
    mst_node_info_t *client;
    mst_node_info_t *server;
    mst_nw_parms_t nw_parms;
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

typedef struct mst_stat {
    unsigned long pkts_in;
    unsigned long pkts_out;
    unsigned long bytes_in;
    unsigned long bytes_out;
    unsigned long tx_error;
    unsigned long rx_error;
} mst_stat_t;

typedef struct mst_tunn {
    evutil_socket_t tunn_fd;
    struct event *tunn_read_event; // read
    struct event *tunn_write_event; // write
    struct mst_timer_data *timer_data;
    mst_stat_t mst_tunn_stat;
    mst_buffer_t *mbuf;
    struct iovec *iov;
    //mst_buffer_queue_t write_queue;
    int ref_cnt;
    pthread_mutex_t tunn_lock;
} mst_tunn_t;

typedef struct mst_conn {
    evutil_socket_t conn_fd;
    struct event *read_event; // read
    struct event *write_event; // write
    struct sockaddr_in ip_tuple;
    mst_csi_t *mst_tuple;
    struct mst_timer_data *timer_data; 
    mst_stat_t mst_conn_stat;
    mst_buffer_t *mbuf;
    struct iovec *iov;
    //mst_buffer_queue_t write_queue;
    int ref_cnt;
    pthread_mutex_t conn_lock;
} mst_conn_t;

typedef struct mst_event_base {
    // connection_event_base
    struct event_base *ceb;
    pthread_mutex_t ceb_lock;
    pthread_cond_t ceb_cond;
    
    // tunnel_event_base
    struct event_base *teb;
    pthread_mutex_t teb_lock;
    pthread_cond_t teb_cond;
    
    // Timer_event_base
    struct event_base *Teb;
} mst_event_base_t;

typedef struct mst_nw_peer {
    mst_conn_t *mst_connection;
    mst_tunn_t *mst_tunnel;
    mst_config_t *mst_config;
    pthread_mutex_t ref_lock;
    int ref_cnt;
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
#define mst_wq mst_connection->write_queue
#define mst_cl mst_connection->conn_lock
#define mst_rc mst_connection->ref_cnt

#define mst_tfd mst_tunnel->tunn_fd
#define mst_teb mst_tunnel->tunn_event_base
#define mst_tre mst_tunnel->tunn_read_event
#define mst_twe mst_tunnel->tunn_write_event
#define mst_ttd mst_tunnel->timer_data
#define mst_tcs mst_tunnel->mst_tunn_stat
#define mst_tbuf mst_tunnel->mbuf
#define mst_tiov mst_tunnel->iov
#define mst_twq mst_tunnel->write_queue
#define mst_tcl mst_tunnel->tunn_lock
#define mst_trc mst_tunnel->ref_cnt


#define mst_ec mst_config.ev_cfg
#define mst_ses mst_config.sctp_ev_subsc
#define pmst_ses mst_config->sctp_ev_subsc

#define pmst_mt mst_config->mst_tuple

extern mst_opts_t mst_global_opts;

extern int mst_process_message(mst_nw_peer_t *mnp, struct msghdr *rmsg, int rlen);
extern int mst_link_status(mst_nw_peer_t *mnp);

extern inline mst_csi_t * mst_get_tuple_config(void);
extern inline mst_config_t * mst_get_mst_config(void);

#endif //!__MST_MSTUNNEL_H__
