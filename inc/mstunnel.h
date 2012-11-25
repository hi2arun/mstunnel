#ifndef __MST_MSTUNNEL_H__
#define __MST_MSTUNNEL_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <unistd.h>
#include <syslog.h>

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
    struct event *conn_event;
    struct sockaddr_in ip_tuple;
} mst_conn_t;

typedef struct mst_network {
    char *if_name;
    int mode;
    mst_conn_t mst_connection;
    mst_config_t mst_config;
} mst_network_t;

#endif //!__MST_MSTUNNEL_H__
