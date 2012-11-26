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

typedef struct mst_globals {
    int alpha;

} mst_globals_t;

typedef struct mst_configuration {
    struct event_config *ev_cfg;
    struct sctp_event_subscribe sctp_ev_subsc;
} mst_config_t;

typedef struct mst_conn {
    evutil_socket_t conn_fd;
    struct event_base *conn_event_base;
    struct event *read_event; // read
    struct event *write_event; // write
    struct sockaddr_in ip_tuple;
} mst_conn_t;

typedef struct mst_network {
    char *if_name;
    int mode;
    mst_conn_t mst_connection;
    mst_config_t mst_config;
} mst_network_t;

typedef enum mst_buf_type {
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
} mst_mem_config_t;

typedef struct mst_buffer {
    struct mst_buffer *__prev;
    struct mst_buffer *__next;
    struct mst_mem_config *__which;
    mst_buf_t buf_type;
    void *buffer;
    int buf_len;
} mst_buffer_t;


typedef struct mst_nw_peer {
    mst_conn_t mst_connection;
    mst_config_t mst_config;
    mst_buffer_t *__mbuf;
} mst_nw_peer_t;

#define mst_fd mst_connection.conn_fd
#define mst_ceb mst_connection.conn_event_base
#define mst_re mst_connection.read_event
#define mst_we mst_connection.write_event
#define mst_ipt mst_connection.ip_tuple

#define mst_ec mst_config.ev_cfg
#define mst_ses mst_config.sctp_ev_subsc

#endif //!__MST_MSTUNNEL_H__
