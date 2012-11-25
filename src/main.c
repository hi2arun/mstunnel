#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <event2/event.h>
#include <assert.h>

#include "memmgmt.h"
#include "mstunnel.h"

//mst_events_t mst_events;
//mst_conn_t mst_conn[D_MST_MAX_CONN];
mst_network_t mst_network_base;

#define mnb mst_network_base

#define mnb_mode mst_network_base.mode

#define mnb_fd mst_network_base.mst_connection.conn_fd
#define mnb_ceb mst_network_base.mst_connection.conn_event_base
#define mnb_ce mst_network_base.mst_connection.conn_event
#define mnb_ipt mst_network_base.mst_connection.ip_tuple

#define mnb_ec mst_network_base.mst_config.ev_cfg
#define mnb_ses mst_network_base.mst_config.sctp_ev_subsc

void mst_log_event_cb(int severity, const char *msg);

void mst_log_event_cb(int severity, const char *msg)
{
    syslog(LOG_WARNING, "[MST] %s\n", msg);
}

int mst_log_init(void)
{
    event_set_log_callback(mst_log_event_cb);
    return 0;
}

int mst_mm_init(void)
{
    event_set_mem_functions(__mst_malloc, __mst_realloc, __mst_free);
    return 0;
}

int mst_event_init(void)
{
}

int mst_create_socket(void)
{
    int rv = -1;
    mnb_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if (mnb_fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    mnb_ses.sctp_data_io_event = 1;
    mnb_ses.sctp_association_event = 1;
    mnb_ses.sctp_shutdown_event = 1;

    rv = setsockopt(mnb_fd, SOL_SCTP, SCTP_EVENTS, (char *)&mnb_ses, sizeof(mnb_ses));
    if (rv < 0) {
        fprintf(stderr, "SCTP_EVENTS subscribe failure: %s\n", strerror (errno));
    }

    return mnb_fd;
}

int mst_bind_socket(char *ipaddr, unsigned short port)
{
    int rv = -1;
    mnb_ipt.sin_family = AF_INET;
    mnb_ipt.sin_addr.s_addr = inet_addr(ipaddr);
    mnb_ipt.sin_port = htons(port);

    rv = bind(mnb_fd, (struct sockaddr *)&mnb_ipt, sizeof(mnb_ipt));

    if (rv < 0) {
        fprintf(stderr, "Bind error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

void mst_do_accept(evutil_socket_t fd, short event, void *arg)
{
    struct sockaddr_in client;
    socklen_t sk_len = sizeof(client);
    evutil_socket_t cfd;

    assert(mnb_fd == fd);
    memset(&client, 0, sk_len);

    fprintf(stderr, "Got a call\n");
    cfd = accept(fd, (struct sockaddr *)&client, sk_len);

    fprintf(stderr, "CFD: %d, %s\n", cfd, strerror(errno));

    if (cfd > 0) {
        fprintf(stderr, "Accepted conn from '%s:%hu'\n", inet_ntoa(client.sin_addr), client.sin_port);
        evutil_make_socket_nonblocking(cfd);
    }

    return;
}

int mst_listen_socket(int backlog)
{
    int rv = -1;

    rv = listen(mnb_fd, backlog);

    if (rv < 0) {
        fprintf(stderr, "Listen call failed: %s\n", strerror(errno));
        return -1;
    }

    mnb_ce = event_new(mnb_ceb, mnb_fd, EV_READ|EV_PERSIST, mst_do_accept, (void *)mnb_ceb);
    event_add(mnb_ce, NULL);

    return 0;
}

#define D_SRV_BACKLOG 100

int mst_setup_network(int mode, char *ipaddr, unsigned short port)
{
    int sk;

    sk = mst_create_socket();
    if (mode) {
        mst_bind_socket(ipaddr, port);
    }
    else {
        mst_bind_socket(ipaddr, (port - 1));
    }

    // Create event base here - root
    mnb_ceb = event_base_new ();
    if (!mnb_ceb) {
        fprintf(stderr, "Failed to create event base: %s\n", strerror(errno));
        return -1;
    }

    evutil_make_socket_nonblocking(mnb_fd);

    if (mode) {
        mst_listen_socket(D_SRV_BACKLOG);
    }
    else {
        //mst_connect_socket(sk, ipaddr, port);
    }

    event_base_dispatch(mnb_ceb);


    //mst_process_loop(mode);

    //mst_cleanup_socket(sk);

    return 0;
}

void printhelp(void)
{
    fprintf(stderr, "Usage: \n");
    return;
}

int main(int argc, char **argv)
{
    int opt;
    int mode = 0; // 0 - client, 1 - server
    char *ipaddr = NULL;
    unsigned short port = 0;

    memset(&mnb, 0, sizeof(mnb));
    while((opt = getopt(argc, argv, "sP:D:h")) != EOF) {
        switch(opt) {
            case 's':
                mnb_mode = mode = 1;
                break;
            case 'P':
                port = (unsigned short)atoi(optarg);
                break;
            case 'D':
                ipaddr = strdup(optarg);
                break;
            case 'h':
            default:
                printhelp();
                exit(EXIT_FAILURE);
        }
    }

    if (!ipaddr) {
        printhelp();
        exit(EXIT_FAILURE);
    }

    mst_log_init();
    mst_mm_init();
    mst_event_init();
    mst_setup_network(mode, ipaddr, port);

    return 0;
}
