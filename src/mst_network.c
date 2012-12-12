#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"

mst_event_base_t meb;
mst_nw_peer_t *mnp; // For peers
mst_nw_peer_t *mnp_l; // For local socket inits 

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

inline void mst_wakeup_tun_base(void)
{
    pthread_mutex_lock(&meb.teb_lock);
    pthread_cond_signal(&meb.teb_cond);
    pthread_mutex_unlock(&meb.teb_lock);
}

inline void mst_wakeup_conn_base(void)
{
    pthread_mutex_lock(&meb.ceb_lock);
    pthread_cond_signal(&meb.ceb_cond);
    pthread_mutex_unlock(&meb.ceb_lock);
}

int mst_create_socket(void)
{
    int rv = -1;
    int fd = -1;
    mst_config_t *mc = NULL;
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if (fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
    }

    assert(fd > 0);

    // This call won't return NULL
    mc = mst_get_mst_config();

    rv = setsockopt(fd, SOL_SCTP, SCTP_EVENTS, (char *)&mc->sctp_ev_subsc, sizeof(mc->sctp_ev_subsc));
    if (rv < 0) {
        fprintf(stderr, "SCTP_EVENTS subscribe failure: %s\n", strerror (errno));
    }
    // Make the socket non-blocking
    evutil_make_socket_nonblocking(fd);

    return fd;
}

int mst_bind_socket(mst_nw_peer_t *pmnp, int mode)
{
    int rv = -1;
    mst_csi_t *mc;
    mst_node_info_t *mni;
    struct sockaddr_in skaddr;

    memset(&skaddr, 0, sizeof(skaddr));

    mc = pmnp->mst_mt;
    
    mni = (mode)?mc->server:mc->client;
    
    skaddr.sin_family = AF_INET;
    skaddr.sin_addr.s_addr = inet_addr(mni->host_addr);
    skaddr.sin_port = htons(mni->port);

    rv = bind(pmnp->mst_fd, (struct sockaddr *)&skaddr, sizeof(skaddr));

    assert(!rv);

    return 0;
}

void mst_tun_do_write(evutil_socket_t fd, short event, void *arg)
{
    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    return;
}

void mst_tun_do_read(evutil_socket_t fd, short event, void *arg)
{
    mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;

    fprintf(stderr, "%s(): __ENTRY__: %s\n", __func__, "Added to MST_TUN_Q\n");
    mst_insert_nw_queue(MST_TUN_Q, pmnp);
    return;
}

//void mst_tun_do_read(evutil_socket_t fd, short event, void *arg)
int mst_do_tun_read(mst_nw_peer_t *pmnp)
{
    //mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;
    struct iovec *iov = NULL;
    mst_buffer_t *mbuf = NULL;
    mst_tunn_t *pmtun = pmnp->mst_tunnel;
    int rlen = 0;
    int iov_len = 0;

    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    mbuf = mst_alloc_mbuf(D_MST_READ_SIZE, 0, 0 /*fill module info later*/);
    assert(mbuf);

    iov = mst_mbuf_to_iov(mbuf, &iov_len);

    //rlen = recvmsg(fd, &rmsg, MSG_WAITALL); // change it to NOWAIT later
    //rlen = readv(fd, iov, iov_len); // change it to NOWAIT later
    rlen = readv(pmtun->tunn_fd, iov, iov_len); // change it to NOWAIT later
    fprintf(stderr, "Received %d bytes. Decode TUNN here\n", rlen);
    if (rlen < 0 && rlen != EAGAIN) {
        fprintf(stderr, "Read error: %s\n", strerror(errno));
        mst_cleanup_mnp(pmnp);
        mst_dealloc_mbuf(mbuf);
        __mst_free(iov);
        return -1;
    }
    if (rlen == 0) {
        fprintf(stderr, "TUNN cleanup - 2\n");
        mst_cleanup_mnp(pmnp);
        mst_dealloc_mbuf(mbuf);
        __mst_free(iov);
        return -1;
    }
    fprintf(stderr, "Wake up TUN base\n");
    mst_wakeup_tun_base();

    event_add(pmnp->mst_tre, NULL);
    mst_dealloc_mbuf(mbuf);

    return 0;
}

void mst_do_write(evutil_socket_t fd, short event, void *arg)
{
    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    return;
}

int mst_destroy_mbuf_q(mst_buffer_queue_t *mbuf_q)
{
    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    return 0;
}

int mst_cleanup_mnp(mst_nw_peer_t *pmnp)
{
    if (pmnp->mst_connection) {
        close(pmnp->mst_fd);
        event_free(pmnp->mst_re);
        event_free(pmnp->mst_we);
        event_free(pmnp->mst_td->te);
        __mst_free(pmnp->mst_td);
        mst_dealloc_mbuf(pmnp->mst_cbuf);
        __mst_free(pmnp->mst_ciov);
        //mst_destroy_mbuf_q(&pmnp->mst_wq);
        pmnp->mst_fd = -1;
    }
    if (pmnp->mst_tunnel) {
        close(pmnp->mst_tfd);
        event_free(pmnp->mst_tre);
        event_free(pmnp->mst_twe);
        if (pmnp->mst_ttd) {
            event_free(pmnp->mst_ttd->te);
            __mst_free(pmnp->mst_ttd);
        }
        //mst_destroy_mbuf_q(&pmnp->mst_twq);
        pmnp->mst_tfd = -1;
        mst_tun_dev_name_rel();
    }
    pmnp->mst_config = NULL;

    fprintf(stderr, "Cleaning up mnp %p\n", pmnp);

    return 0;

}

void mst_do_read(evutil_socket_t fd, short event, void *arg)
{
    mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;

    fprintf(stderr, "%s(): __ENTRY__: %s\n", __func__, "Added to MST_SCTP_Q\n");
    mst_insert_nw_queue(MST_SCTP_Q, pmnp);
    return;
}

//void mst_do_nw_read(evutil_socket_t fd, short event, void *arg)
int mst_do_nw_read(mst_nw_peer_t *pmnp)
{
    //mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;
    mst_conn_t *pmconn = pmnp->mst_connection;
    char ctrlmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
    struct iovec *iov = NULL;
    struct msghdr rmsg;
    mst_buffer_t *mbuf = NULL;
    int rlen = 0;
    int iov_len = 0;

    memset(&rmsg, 0, sizeof(rmsg));
    mbuf = mst_alloc_mbuf(D_MST_READ_SIZE, 0, 0 /*fill module info later*/);
    assert(mbuf);

    iov = mst_mbuf_to_iov(mbuf, &iov_len);

    rmsg.msg_iov = iov;
    rmsg.msg_iovlen = iov_len;
    rmsg.msg_control = ctrlmsg;
    rmsg.msg_controllen = sizeof(ctrlmsg);

    pmnp->mst_cbuf = mbuf;
    pmnp->mst_ciov = iov;

    //rlen = recvmsg(fd, &rmsg, MSG_WAITALL); // change it to NOWAIT later
    rlen = recvmsg(pmconn->conn_fd, &rmsg, MSG_WAITALL); // change it to NOWAIT later
    fprintf(stderr, "Received %d bytes. Decode SCTP here\n", rlen);
    if (rlen < 0 && rlen != EAGAIN) {
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        //mst_cleanup_mnp(pmnp);
        //mst_dealloc_mbuf(mbuf);
        //__mst_free(iov);
        return -1;
    }
    if (rlen == 0) {
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        //mst_cleanup_mnp(pmnp);
        //mst_dealloc_mbuf(mbuf);
        //__mst_free(iov);
        return -1;
    }
    mst_process_message(pmnp, &rmsg, rlen);

    event_add(pmnp->mst_re, NULL);
    mst_dealloc_mbuf(mbuf);
    __mst_free(iov);
    pmnp->mst_cbuf = NULL;
    pmnp->mst_ciov = NULL;
    
    mst_wakeup_conn_base();

    return 0;
}

int mst_setup_tunnel(mst_nw_peer_t *pmnp)
{
    char dev_name[IFNAMSIZ + 1] = {0};
    int rv = 0;

    rv = mst_tun_dev_name(dev_name, IFNAMSIZ);
    fprintf(stderr, "New dev name: %s\n", dev_name);

    if(!pmnp->mst_tunnel) {
        pmnp->mst_tunnel = (mst_tunn_t *) __mst_malloc(sizeof(mst_tunn_t));
        assert(pmnp->mst_tunnel);
    }
    else {
        memset(pmnp->mst_tunnel, 0, sizeof(mst_tunn_t));
    }
    pmnp->mst_tfd = mst_tun_open(dev_name);
    assert(pmnp->mst_tfd > 0);
    pmnp->mst_tre = event_new(meb.teb, pmnp->mst_tfd, EV_READ, mst_tun_do_read, (void *)pmnp);
    pmnp->mst_twe = event_new(meb.teb, pmnp->mst_tfd, EV_WRITE, mst_tun_do_write, (void *)pmnp);
    
    evutil_make_socket_nonblocking(pmnp->mst_tfd);
    event_add(pmnp->mst_tre, NULL);
   
    mst_wakeup_tun_base();

    return rv;
}

void mst_do_accept(evutil_socket_t fd, short event, void *arg)
{
    int rv = -1;
    struct sockaddr_in client;
    socklen_t sk_len = sizeof(client);
    evutil_socket_t cfd;
    mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;

    assert(pmnp->mst_fd == fd);
    memset(&client, 0, sk_len);

    fprintf(stderr, "Got a call\n");
    cfd = accept(fd, (struct sockaddr *)&client, &sk_len);

    if ((cfd > 0) && (cfd <= D_MAX_PEER_CNT)) {
        fprintf(stderr, "Accepted conn[%d] from '%s:%hu'\n", cfd, inet_ntoa(client.sin_addr), client.sin_port);

        if(!mnp[cfd].mst_connection) {
            mnp[cfd].mst_connection = (mst_conn_t *) __mst_malloc(sizeof(mst_conn_t));
            assert(mnp[cfd].mst_connection);
        }
        else {
            memset(mnp[cfd].mst_connection, 0, sizeof(mst_conn_t));
        }

        mnp[cfd].mst_fd = cfd;
        mnp[cfd].mst_re = event_new(meb.ceb, cfd, EV_READ, mst_do_read, (void *)&mnp[cfd]);
        mnp[cfd].mst_we = event_new(meb.ceb, cfd, EV_WRITE, mst_do_write, (void *)&mnp[cfd]);

        if (!mnp[cfd].mst_td) {
            mnp[cfd].mst_td = (mst_timer_data_t *)__mst_malloc(sizeof(mst_timer_data_t));
            assert(mnp[cfd].mst_td);
        }
        mnp[cfd].mst_td->type = MST_MNP;
        mnp[cfd].mst_td->timeo.tv_sec = 1;
        mnp[cfd].mst_td->timeo.tv_usec = 0;
        mnp[cfd].mst_td->te = evtimer_new(meb.Teb, mst_timer, mnp[cfd].mst_td);
        mnp[cfd].mst_td->data = &mnp[cfd];

        rv = setsockopt(mnp[cfd].mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&pmnp->pmst_ses, sizeof(pmnp->pmst_ses));

        fprintf(stderr, "SSO: RV: %d\n", rv);

        assert(rv >= 0);

        M_MNP_REF_UP(&mnp[cfd]);
        evutil_make_socket_nonblocking(cfd);
        event_add(mnp[cfd].mst_re, NULL);
        evtimer_add(mnp[cfd].mst_td->te, &mnp[cfd].mst_td->timeo);
    }
    else {
        fprintf(stderr, "CFD: %d, %s\n", cfd, strerror(errno));
    }

    return;
}

int mst_listen_socket(void)
{
    int rv = -1;
    int index = 0;
    
    for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
        rv = listen(mnp_l[index].mst_fd, mst_global_opts.mst_sk_backlog);
        assert(!rv);

        M_MNP_REF_UP(&mnp_l[index]);
        mnp_l[index].mst_re = event_new(meb.ceb, mnp_l[index].mst_fd, EV_READ|EV_PERSIST, mst_do_accept, (void *)&mnp_l[index]);
        event_add(mnp_l[index].mst_re, NULL);
    }

    return 0;
}

int mst_setup_network(void)
{
    mst_csi_t *mt = NULL;
    int index = 0;

    mt = mst_get_tuple_config();

    mnp_l = (mst_nw_peer_t *)__mst_malloc(sizeof(mst_nw_peer_t) * mst_global_opts.mst_tuple_cnt);
    
    assert(mnp_l);

    memset(mnp_l, 0, sizeof(mst_nw_peer_t) * mst_global_opts.mst_tuple_cnt);

    for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
        mnp_l[index].mst_connection = (mst_conn_t *)__mst_malloc(sizeof(mst_conn_t));
        assert(mnp_l[index].mst_connection);
        memset(mnp_l[index].mst_connection, 0, sizeof(mst_conn_t));
        mnp_l[index].mst_fd = mst_create_socket();
        mnp_l[index].mst_mt = &mt[index];

        mnp_l[index].mst_config = &mst_global_opts.mst_config;
        
        mnp_l[index].mst_tunnel = (mst_tunn_t *)__mst_malloc(sizeof(mst_tunn_t));
        assert(mnp_l[index].mst_tunnel);
        memset(mnp_l[index].mst_tunnel, 0, sizeof(mst_tunn_t));
        
        assert(!mst_bind_socket(&mnp_l[index], mst_global_opts.mst_config.mst_mode));
    }

    return 0;
}

int
mst_connect_socket(void)
{
    int rv = -1;
    int index = 0;
    struct sockaddr_in skaddr;
    mst_csi_t *mc;
    mst_node_info_t *mni;
    mst_nw_peer_t *pmnp = NULL;


    for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
        mc = mnp_l[index].mst_mt;
        mni = mc->server;
        
        memset(&skaddr, 0, sizeof(skaddr));

        skaddr.sin_family = AF_INET;
        skaddr.sin_addr.s_addr = inet_addr(mni->host_addr);
        skaddr.sin_port = htons(mni->port);

        rv = connect(mnp_l[index].mst_fd, (struct sockaddr *)&skaddr, sizeof(skaddr));

        if ((rv < 0) && (EINPROGRESS != errno)) {
            fprintf(stderr, "Connect error: %d:%s\n", errno, strerror(errno));
            continue;
        }

        pmnp = &mnp_l[index];
        pmnp->mst_re = event_new(meb.ceb, pmnp->mst_fd, EV_READ, mst_do_read, (void *)pmnp);
        pmnp->mst_we = event_new(meb.ceb, pmnp->mst_fd, EV_WRITE, mst_do_write, (void *)pmnp);

        //TODO: Create tun interface and setup tunn_events

        pmnp->mst_td = (mst_timer_data_t *)__mst_malloc(sizeof(mst_timer_data_t));
        assert(pmnp->mst_td);
        pmnp->mst_td->type = MST_MNP;
        pmnp->mst_td->timeo.tv_sec = 1;
        pmnp->mst_td->timeo.tv_usec = 0;
        pmnp->mst_td->te = evtimer_new(meb.Teb, mst_timer, pmnp->mst_td);
        pmnp->mst_td->data = pmnp;

        rv = setsockopt(pmnp->mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&pmnp->pmst_ses, sizeof(pmnp->pmst_ses));

        assert(rv >= 0);

        M_MNP_REF_UP(pmnp);

        evutil_make_socket_nonblocking(pmnp->mst_fd);
        event_add(pmnp->mst_re, NULL);
        evtimer_add(pmnp->mst_td->te, &pmnp->mst_td->timeo);
    }

    return 0;
}

int mst_loop_network(void)
{
    int rv = -1;
    // Create event base here for all connections - root
    meb.ceb = event_base_new();
    assert(meb.ceb);
    
    pthread_mutex_init(&meb.ceb_lock, NULL);
    pthread_cond_init(&meb.ceb_cond, NULL);

    if (mst_global_opts.mst_config.mst_mode) {
        mnp = (mst_nw_peer_t *) __mst_malloc(D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));

        assert(mnp);

        memset(mnp, 0, D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));
        mst_listen_socket();
    }
    else {
        mst_connect_socket();
    }

client_loop:
    rv = event_base_dispatch(meb.ceb);

    fprintf(stderr, "RV: %d\n", rv);
    if (!mst_global_opts.mst_config.mst_mode) {
        pthread_mutex_lock(&meb.teb_lock);
        pthread_cond_wait(&meb.teb_cond, &meb.teb_lock);
        pthread_mutex_unlock(&meb.teb_lock);

        goto client_loop;
    }

    //mst_cleanup_network();

    return 0;
}

