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

mst_opts_t mst_global_opts; 

extern mst_network_t mst_network_base;

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

int main(int argc, char **argv)
{
    int opt;
    int mode = 0; // 0 - client, 1 - server
    char *ipaddr = NULL;
    int rv = -1;
    unsigned short port = 0;

    memset(&mst_network_base, 0, sizeof(mst_network_t));
    while((opt = getopt(argc, argv, "sP:D:h")) != EOF) {
        switch(opt) {
            case 's':
                mst_network_base.mode = mode = 1;
                break;
            case 'P':
                port = (unsigned short)atoi(optarg);
                break;
            case 'D':
                ipaddr = strdup(optarg);
                break;
            case 'h':
            default:
                printhelp(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!ipaddr) {
        printhelp(argv[0]);
        exit(EXIT_FAILURE);
    }

    mst_global_opts.ifconfig = "/sbin/ifconfig ";
    mst_global_opts.route = "/sbin/route ";
    mst_global_opts.iproute = "/sbin/ip route ";
    mst_global_opts.iprule = "/sbin/ip rule ";

    //mst_global_opts.mst_config;
    //mst_global_opts.mst_tuple;
    rv = pthread_rwlock_init(&mst_global_opts.rwlock, NULL);
    if (rv < 0) {
        fprintf(stderr, "Global opts rwlock failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    mst_log_init();
    mst_mm_init();
    mst_levent_init();
    mst_timer_init();
    if (mst_setup_network(mode, ipaddr, port)) {
        exit(EXIT_FAILURE);
    }
    mst_loop_network(mode);

    return 0;
}
