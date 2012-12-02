#include "mstunnel.h"
#include "mst_network.h"
#include "memmgmt.h"
#include "mst_timer.h"

mst_timer_t mst_timer_base;

void mst_timer(evutil_socket_t fd, short event, void *arg)
{
    mst_timer_data_t *td = (mst_timer_data_t *)arg;
//    fprintf(stderr, "Timer triggered\n======================\n");
    if (!arg) {
        return;
    }
    switch(td->type) {
        case MST_SYS:
            fprintf(stderr, "System timer\n");
            break;
        case MST_MNP:
            fprintf(stderr, "MNP timer\n");
            mst_link_status(td->data);
            break;
        default:
            fprintf(stderr, "Unknown timer\n");
            return;
    }

    evtimer_add(td->te, &td->timeo);
    return;
}

void *mst_loop_timer(void *arg)
{
    int rv = -1;
    rv = event_base_dispatch(mtb.teb);
    fprintf(stderr, "exit status timer... base: %p, rv: %d\n", mtb.teb, rv);
    return NULL;
}

int mst_timer_init(void)
{
    pthread_t pt_status_timer;

    mtb.sys_td = (mst_timer_data_t *)__mst_malloc(sizeof(mst_timer_data_t));
    if (!mtb.sys_td) {
        fprintf(stderr, "Mem allocation for sys timer - failed\n");
        return -1;
    }
    mtb.sys_td->type = MST_SYS;
    mtb.sys_td->timeo.tv_sec = 1;
    mtb.sys_td->timeo.tv_usec = 0;
    mtb.sys_td->data = NULL;

    // Create event base here for all timers - root
    mtb.teb = event_base_new ();
    if (!mtb.teb) {
        fprintf(stderr, "Failed to create timer event base: %s\n", strerror(errno));
        return -1;
    }

    mtb.sys_td->te = evtimer_new(mtb.teb, mst_timer, mtb.sys_td);
    fprintf(stderr, "Looping timer... base: %p\n", mtb.teb);
    evtimer_add(mtb.sys_td->te, &mtb.sys_td->timeo);

    fprintf(stderr, "status timer... base: %p\n", mtb.teb);
    pthread_create(&pt_status_timer, NULL, mst_loop_timer, NULL);

    return 0;
}
