#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <event2/event.h>
#include <assert.h>

#include "mstunnel.h"
#include "mst_network.h"
#include "memmgmt.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"

mst_opts_t mst_global_opts; 

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
    mst_memmgmt_init();
    mst_membuf_init();
    event_set_mem_functions(__mst_malloc, __mst_realloc, __mst_free);
    return 0;
}

int mst_levent_init(void)
{
    //evthread_use_pthreads();
    return 0;
}

void printhelp(char *prgname)
{
    fprintf(stderr, "Usage: %s [-s] <-P port> <-D IPv4 address> [-h]\n", prgname);
    return;
}

inline mst_csi_t *
mst_get_tuple_config(void)
{
    return mst_global_opts.mst_tuple;
}

#ifdef __DEV_TEST__
int mst_init_test_tuple(mst_csi_t **mt)
{
    mst_csi_t *pmt = NULL;
    *mt = (mst_csi_t *)__mst_malloc(sizeof(mst_csi_t));
    if (!(*mt)) {
        fprintf(stderr, "%d: Malloc failed\n", __LINE__);
        return -1;
    }

    pmt = *mt;

    pmt->__next = NULL;
    pmt->client = (mst_node_info_t *)__mst_malloc(sizeof(mst_node_info_t));
    if (!pmt->client) {
        fprintf(stderr, "%d: Malloc failed\n", __LINE__);
        return -1;
    }
    pmt->server = (mst_node_info_t *)__mst_malloc(sizeof(mst_node_info_t));
    if (!pmt->server) {
        fprintf(stderr, "%d: Malloc failed\n", __LINE__);
        return -1;
    }
    pmt->client->host_name = NULL; // letz go by IP address
    pmt->client->host_addr = "14.1.1.2";
    pmt->client->port = 0; // leave it to OS for port assign
    pmt->client->policy_mark = 0; // Disable policy mark

    pmt->server->host_name = NULL; // letz go by IP address
    pmt->server->host_addr = "14.1.1.1";
    pmt->server->port = 40400; 
    pmt->server->policy_mark = 0; // Disable policy mark

    pmt->nw_parms.num_ostreams = 10;
    pmt->nw_parms.max_instreams = 10;
    pmt->nw_parms.link_nice = 1.0;
    pmt->nw_parms.xmit_factor = 1000;
    pmt->nw_parms.xmit_max_pkts = (int)(pmt->nw_parms.link_nice * pmt->nw_parms.xmit_factor);
    pmt->nw_parms.xmit_curr_cnt = 0;
    pmt->nw_parms.xmit_curr_stream = 0;

    return 0;
}
#endif //__DEV_TEST__

inline mst_config_t *
mst_get_mst_config(void)
{
    return &mst_global_opts.mst_config;
}

int mst_config_init(void)
{
    int rv = -1;
    mst_global_opts.ifconfig = "/sbin/ifconfig ";
    mst_global_opts.route = "/sbin/route ";
    mst_global_opts.iproute = "/sbin/ip route ";
    mst_global_opts.iprule = "/sbin/ip rule ";

    mst_global_opts.mst_ses.sctp_data_io_event = 1;
    mst_global_opts.mst_ses.sctp_association_event = 1;
    mst_global_opts.mst_ses.sctp_shutdown_event = 1;

    mst_global_opts.mst_tuple_cnt = 1;
    mst_global_opts.mst_sk_backlog = D_SRV_BACKLOG; 

#ifdef __DEV_TEST__
    mst_init_test_tuple(&mst_global_opts.mst_tuple);
#endif // __DEV_TEST__
    
    rv = pthread_rwlock_init(&mst_global_opts.rwlock, NULL);

    assert(rv >= 0);

    return 0;
}

int main(int argc, char **argv)
{
    int opt;

    while((opt = getopt(argc, argv, "sh")) != EOF) {
        switch(opt) {
            case 's':
                fprintf(stderr, "Server mode\n");
                mst_global_opts.mst_config.mst_mode = 1;
                break;
            case 'h':
            default:
                printhelp(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    mst_mm_init();

    mst_config_init();

    mst_log_init();
    mst_levent_init();
    //mst_timer_init();
    mst_tun_init();
    mst_timer_init();
    mst_init_epoll_queue();
    mst_init_nw_queue();
    mst_init_tun_queue();
    if (mst_setup_network()) {
        exit(EXIT_FAILURE);
    }
    //mst_loop_network();
    mst_init_network();

    mst_loop_timer(NULL);

    fprintf(stderr, "Something caused exit....\n");

    return 0;
}
