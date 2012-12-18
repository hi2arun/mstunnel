#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"

mst_event_base_t meb;
mst_nw_peer_t *mnp; // For peers
mst_nw_peer_t *mnp_l; // For local socket inits 

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

//void mst_tun_do_read(evutil_socket_t fd, short event, void *arg)
void mst_tun_do_read(mst_nw_peer_t *pmnp)
{
    fprintf(stderr, "%s(): __ENTRY__: %s\n", __func__, "Added to MST_TUN_Q\n");
    pthread_mutex_lock(&meb.ev_lock);
    epoll_ctl(meb.epfd, EPOLL_CTL_DEL, pmnp->mst_fd, NULL);
    pthread_mutex_unlock(&meb.ev_lock);
    mst_insert_nw_queue(MST_TUN_Q, pmnp);
    return;
}

int mst_do_tunn_write(mst_nw_peer_t *pmnp, int rlen)
{
    struct iovec *iov = NULL;
    int iov_len = 0;
    int rv = -1;
    mst_buffer_t *mbuf = pmnp->mst_cbuf;
    mst_nw_peer_t *pmnp_conn = (mst_nw_peer_t *)pmnp->mnp_pair;

    iov = mst_mbuf_rework_iov(mbuf, rlen, &iov_len);
    assert(iov && iov_len);

    rv = writev(pmnp_conn->mst_fd, iov, iov_len);
    fprintf(stderr, "Wrote %d bytes on tun dev\n", rv);
    if (rv < 0) {
        fprintf(stderr, "WriteV error: %s\n", strerror(errno));
    }

    return 0;
}

//void mst_tun_do_read(evutil_socket_t fd, short event, void *arg)
int mst_do_tun_read(mst_nw_peer_t *pmnp)
{
    struct iovec *iov = NULL;
    mst_buffer_t *mbuf = NULL;
    int rlen = 0;
    int iov_len = 0;

    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);
    mbuf = mst_alloc_mbuf(D_MST_READ_SIZE, 0, 0 /*fill module info later*/);
    assert(mbuf);

    iov = mst_mbuf_to_iov(mbuf, &iov_len);

    pmnp->mst_cbuf = mbuf;
    //pmnp->mst_tiov = iov;
    
    rlen = readv(pmnp->mst_fd, iov, iov_len); // change it to NOWAIT later
    fprintf(stderr, "Received %d bytes. Decode TUNN here\n", rlen);
    if (rlen < 0 && rlen != EAGAIN) {
        fprintf(stderr, "Read error - 1: %s\n", strerror(errno));
        mst_cleanup_mnp(pmnp);
        return -1;
    }
    if (rlen == 0) {
        fprintf(stderr, "TUNN cleanup - 2\n");
        mst_cleanup_mnp(pmnp);
        return -1;
    }

    if (rlen > 0) {
        mst_do_conn_write(pmnp, rlen);
    }

    mst_dealloc_mbuf(mbuf);
    pmnp->mst_cbuf = NULL;
    pthread_mutex_lock(&meb.ev_lock);
    meb.ev.events = EPOLLIN;
    meb.ev.data.ptr = pmnp;
    assert(!epoll_ctl(meb.epfd, EPOLL_CTL_ADD, pmnp->mst_fd, &meb.ev));
    pthread_mutex_unlock(&meb.ev_lock);
    
    return 0;
}

int mst_do_conn_write(mst_nw_peer_t *pmnp, int rlen)
{
    int rv = -1;
    struct msghdr omsg;
    char ctrlmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct cmsghdr *cmsg;
    struct sctp_sndrcvinfo *sinfo;
    mst_csi_t *mt = NULL;
    struct iovec *iov = NULL;
    int iov_len = 0;
    mst_nw_peer_t *pmnp_pair = (mst_nw_peer_t *)pmnp->mnp_pair;
    
    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);
    mt = pmnp_pair->mst_mt;
    memset(&omsg, 0, sizeof(omsg));

    iov = mst_mbuf_rework_iov(pmnp->mst_cbuf, rlen, &iov_len);

    assert(iov && iov_len);

    omsg.msg_iov = iov;
    omsg.msg_iovlen = iov_len;
    omsg.msg_control = ctrlmsg;
    omsg.msg_controllen = sizeof(ctrlmsg);
    omsg.msg_flags = 0;

    cmsg = CMSG_FIRSTHDR(&omsg);
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDRCV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

    omsg.msg_controllen = cmsg->cmsg_len;
    sinfo = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
    memset(sinfo, 0, sizeof(struct sctp_sndrcvinfo));

    sinfo->sinfo_ppid = rand();
    sinfo->sinfo_stream = mt->nw_parms.xmit_curr_stream;
    sinfo->sinfo_flags = 0;

    rv = sendmsg(pmnp_pair->mst_fd, &omsg, MSG_WAITALL);

    fprintf(stderr, "SendMSG: %d --- on stream ID: %d, (%s)\n", rv, sinfo->sinfo_stream, strerror(errno));

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
        if (pmnp->mst_td) {
            event_free(pmnp->mst_td->te);
            __mst_free(pmnp->mst_td);
            pmnp->mst_td = NULL;
        }
        mst_dealloc_mbuf(pmnp->mst_cbuf);
        //__mst_free(pmnp->mst_ciov);

        if(0 && pmnp->mst_mt) {
            if(pmnp->mst_mt->client) {
                __mst_free(pmnp->mst_mt->client);
            }
            if(pmnp->mst_mt->server) {
                __mst_free(pmnp->mst_mt->server);
            }
            __mst_free(pmnp->mst_mt);
        }
        //mst_destroy_mbuf_q(&pmnp->mst_wq);
        pmnp->mst_fd = -1;
    }
    fprintf(stderr, "Cleaning up mnp %p\n", pmnp);

    return 0;

}

//void mst_do_read(evutil_socket_t fd, short event, void *arg)
void mst_do_read(mst_nw_peer_t *pmnp)
{
    fprintf(stderr, "%s(): __ENTRY__: %s\n", __func__, "Added to MST_SCTP_Q\n");
    fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);
    pthread_mutex_lock(&meb.ev_lock);
    epoll_ctl(meb.epfd, EPOLL_CTL_DEL, pmnp->mst_fd, NULL);
    pthread_mutex_unlock(&meb.ev_lock);
    mst_insert_nw_queue(MST_SCTP_Q, pmnp);
    return;
}

int mst_do_nw_read(mst_nw_peer_t *pmnp)
{
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

    fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);

    iov = mst_mbuf_to_iov(mbuf, &iov_len);

    rmsg.msg_iov = iov;
    rmsg.msg_iovlen = iov_len;
    rmsg.msg_control = ctrlmsg;
    rmsg.msg_controllen = sizeof(ctrlmsg);

    pmnp->mst_cbuf = mbuf;

    rlen = recvmsg(pmconn->conn_fd, &rmsg, MSG_WAITALL); // change it to NOWAIT later
    fprintf(stderr, "Received %d bytes. Decode SCTP here\n", rlen);
    if (rlen < 0 && rlen != EAGAIN) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        exit(0);
        return -1;
    }
    if (rlen == 0) {
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }
    if (rlen > 0) {
        mst_process_message(pmnp, &rmsg, rlen);
    }

    mst_dealloc_mbuf(mbuf);
    pmnp->mst_cbuf = NULL;
    
    pthread_mutex_lock(&meb.ev_lock);
    meb.ev.events = EPOLLIN;
    meb.ev.data.ptr = pmnp;
    assert(!epoll_ctl(meb.epfd, EPOLL_CTL_ADD, pmnp->mst_fd, &meb.ev));
    pthread_mutex_unlock(&meb.ev_lock);
    
    return 0;
}

int mst_setup_tunnel(mst_nw_peer_t *pmnp)
{
    char dev_name[IFNAMSIZ + 1] = {0};
    int rv = 0;
    int tunfd = -1;

    rv = mst_tun_dev_name(dev_name, IFNAMSIZ);
    fprintf(stderr, "New dev name: %s\n", dev_name);

    tunfd = mst_tun_open(dev_name);
    //pmnp->mst_tfd = mst_tun_open(dev_name);
    assert(tunfd > 0);
    evutil_make_socket_nonblocking(tunfd);
    
    if(!mnp[tunfd].mst_connection) {
        mnp[tunfd].mst_connection = (mst_conn_t *) __mst_malloc(sizeof(mst_conn_t));
        assert(mnp[tunfd].mst_connection);
    }
    else {
        memset(mnp[tunfd].mst_connection, 0, sizeof(mst_conn_t));
    }

    mnp[tunfd].mst_fd = tunfd;
    mnp[tunfd].mst_mt = NULL;

    mnp[tunfd].mnp_flags ^= mnp[tunfd].mnp_flags;
    mnp[tunfd].mnp_flags = M_MNP_SET_TYPE(mnp[tunfd].mnp_flags, D_MNP_TYPE_TUN);
    mnp[tunfd].mnp_flags = M_MNP_SET_STATE(mnp[tunfd].mnp_flags, D_MNP_STATE_TUNNEL);

    mnp[tunfd].mst_td = NULL;
    mnp[tunfd].mnp_pair = (int)pmnp;
    pmnp->mnp_pair = (int)&mnp[tunfd];
    M_MNP_REF_UP(&mnp[tunfd]);
    
    pthread_mutex_lock(&meb.ev_lock);
    meb.ev.events = EPOLLIN;
    meb.ev.data.ptr = &mnp[tunfd];
    assert(!epoll_ctl(meb.epfd, EPOLL_CTL_ADD, tunfd, &meb.ev));
    pthread_mutex_unlock(&meb.ev_lock);

    return rv;
}

//void mst_do_accept(evutil_socket_t fd, short event, void *arg)
int mst_do_accept(mst_nw_peer_t *pmnp)
{
    int rv = -1;
    struct sockaddr_in client;
    socklen_t sk_len = sizeof(client);
    evutil_socket_t cfd;
    //mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;

    memset(&client, 0, sk_len);

    fprintf(stderr, "Got a call\n");
    cfd = accept(pmnp->mst_fd, (struct sockaddr *)&client, &sk_len);

    if ((cfd > 0) && (cfd <= D_MAX_PEER_CNT)) {
        fprintf(stderr, "Accepted conn[%d] from '%s:%hu'\n", cfd, inet_ntoa(client.sin_addr), client.sin_port);

        if(!mnp[cfd].mst_connection) {
            mnp[cfd].mst_connection = (mst_conn_t *) __mst_malloc(sizeof(mst_conn_t));
            assert(mnp[cfd].mst_connection);
        }
        else {
            memset(mnp[cfd].mst_connection, 0, sizeof(mst_conn_t));
        }

        mnp[cfd].mst_mt = (mst_csi_t *)__mst_malloc(sizeof(mst_csi_t));
        assert(mnp[cfd].mst_mt);
        memset(mnp[cfd].mst_mt, 0, sizeof(mst_csi_t));
        mnp[cfd].mst_mt->client = (mst_node_info_t *)__mst_malloc(sizeof(mst_node_info_t));
        assert(mnp[cfd].mst_mt->client);
        mnp[cfd].mst_mt->client->host_ipv4 = client.sin_addr.s_addr;
        mnp[cfd].mst_mt->client->port = client.sin_port;
        mnp[cfd].mst_mt->nw_parms = pmnp->mst_mt->nw_parms;

        mnp[cfd].mst_fd = cfd;
        mnp[cfd].mnp_flags ^= mnp[cfd].mnp_flags;
        mnp[cfd].mnp_flags = M_MNP_SET_TYPE(mnp[cfd].mnp_flags, D_MNP_TYPE_PEER);
        mnp[cfd].mnp_flags = M_MNP_SET_STATE(mnp[cfd].mnp_flags, D_MNP_STATE_CONNECTED);
        
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
        evtimer_add(mnp[cfd].mst_td->te, &mnp[cfd].mst_td->timeo);

        pthread_mutex_lock(&meb.ev_lock);
        meb.ev.events = EPOLLIN;
        meb.ev.data.ptr = &mnp[cfd];
        assert(!epoll_ctl(meb.epfd, EPOLL_CTL_ADD, cfd, &meb.ev));
        pthread_mutex_unlock(&meb.ev_lock);

    }
    else {
        fprintf(stderr, "CFD: %d, %s\n", cfd, strerror(errno));
    }

    return 0;
}

int mst_listen_socket(void)
{
    int rv = -1;
    int index = 0;
    
    for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
        rv = listen(mnp_l[index].mst_fd, mst_global_opts.mst_sk_backlog);
        assert(!rv);

        M_MNP_REF_UP(&mnp_l[index]);
    }

    return 0;
}

int mst_setup_network(void)
{
    mst_csi_t *mt = NULL;
    int index = 0;

    mt = mst_get_tuple_config();

    pthread_mutex_init(&meb.ev_lock, NULL);
    meb.epfd = epoll_create(1/* Any +ve number shud do here*/);

    assert(meb.epfd > 0);
    meb.ev.events = EPOLLIN;
    
    meb.evb = (struct epoll_event *)__mst_malloc(sizeof(struct epoll_event) * (D_MAX_PEER_CNT + mst_global_opts.mst_tuple_cnt));
    assert(meb.evb);
    meb.ev_cnt = (D_MAX_PEER_CNT + mst_global_opts.mst_tuple_cnt);

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
        
        assert(!mst_bind_socket(&mnp_l[index], mst_global_opts.mst_config.mst_mode));

        if (mst_global_opts.mst_config.mst_mode) {
            mnp_l[index].mnp_flags = M_MNP_SET_TYPE(mnp_l[index].mnp_flags, D_MNP_TYPE_LISTEN);
            mnp_l[index].mnp_flags = M_MNP_SET_STATE(mnp_l[index].mnp_flags, D_MNP_STATE_LISTEN);
        }
        else {
            mnp_l[index].mnp_flags = M_MNP_SET_TYPE(mnp_l[index].mnp_flags, D_MNP_TYPE_CONNECT);
        }

        fprintf(stderr, "MNP flags: %0X, %p\n", mnp_l[index].mnp_flags, &mnp_l[index]);

        pthread_mutex_lock(&meb.ev_lock);
        meb.ev.events = EPOLLIN;
        meb.ev.data.ptr = &mnp_l[index];
        assert(!epoll_ctl(meb.epfd, EPOLL_CTL_ADD, mnp_l[index].mst_fd, &meb.ev));
        pthread_mutex_unlock(&meb.ev_lock);
    }

    return 0;
}

int
mst_do_connect(mst_nw_peer_t *pmnp)
{
    fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    pmnp->mst_td = (mst_timer_data_t *)__mst_malloc(sizeof(mst_timer_data_t));
    assert(pmnp->mst_td);
    pmnp->mst_td->type = MST_MNP;
    pmnp->mst_td->timeo.tv_sec = 1;
    pmnp->mst_td->timeo.tv_usec = 0;
    pmnp->mst_td->te = evtimer_new(meb.Teb, mst_timer, pmnp->mst_td);
    pmnp->mst_td->data = pmnp;

    M_MNP_REF_UP(pmnp);
    fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);

    pmnp->mnp_flags = M_MNP_SET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTED);

    evtimer_add(pmnp->mst_td->te, &pmnp->mst_td->timeo);
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
    mst_config_t *mst_conf = mst_get_mst_config();


    for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
        mc = mnp_l[index].mst_mt;
        mni = mc->server;
        
        memset(&skaddr, 0, sizeof(skaddr));

        skaddr.sin_family = AF_INET;
        skaddr.sin_addr.s_addr = inet_addr(mni->host_addr);
        skaddr.sin_port = htons(mni->port);
        
        pmnp = &mnp_l[index];
        pmnp->mst_config = mst_conf;
        
        rv = setsockopt(pmnp->mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&pmnp->pmst_ses, sizeof(pmnp->pmst_ses));
        assert(rv >= 0);

        rv = connect(mnp_l[index].mst_fd, (struct sockaddr *)&skaddr, sizeof(skaddr));

        if ((rv < 0) && (EINPROGRESS != errno)) {
            fprintf(stderr, "Connect error: %d:%s\n", errno, strerror(errno));
            continue;
        }
        pmnp->mnp_flags = M_MNP_SET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTING);
    }

    return 0;
}

void *mst_nw_thread(void *arg)
{
    int rv = -1;
    int nfds = -1;
    int index = 0;
    mst_nw_peer_t *pmnp = NULL;

    while(1) {

        fprintf(stderr, "EPOLL Wait loop\n");

        nfds = epoll_wait(meb.epfd, meb.evb, meb.ev_cnt, -1);
        fprintf(stderr, "nfds: %d\n", nfds);
        assert(!(nfds < 0));

        for(index = 0; index < nfds; index++) {

            if ((meb.evb[index].events & EPOLLERR) ||
                (meb.evb[index].events & EPOLLHUP) ||
                !(meb.evb[index].events & EPOLLIN)) {
                fprintf (stderr, "EPOLL ERROR: closing socket\n");
                M_MNP_REF_DOWN_AND_FREE((mst_nw_peer_t *)&meb.evb[index].data);
                continue;
            }

            pmnp = (mst_nw_peer_t *)meb.evb[index].data.ptr;
            pthread_mutex_lock(&pmnp->mst_cl);
            fprintf(stderr, "EPOLL loop, pmnp: %p, flags: %0X\n", pmnp, pmnp->mnp_flags);
            switch(M_MNP_TYPE(pmnp->mnp_flags)) {
                case D_MNP_TYPE_LISTEN:
                    mst_do_accept(pmnp);
                    break;
                case D_MNP_TYPE_CONNECT:
                    if (D_MNP_STATE_CONNECTING == M_MNP_STATE(pmnp->mnp_flags)) {
                        mst_do_connect(pmnp);
                    }
                    else {
                        mst_do_read(pmnp);
                    }
                    break;
                case D_MNP_TYPE_PEER:
                    mst_do_read(pmnp);
                    break;
                case D_MNP_TYPE_TUN:
                    mst_tun_do_read(pmnp);
                    break;
                default:
                    fprintf(stderr, "Unknown MNP_TYPE %0X received\n", pmnp->mnp_flags);
            }
            pthread_mutex_unlock(&pmnp->mst_cl);
        }
    }

    fprintf(stderr, "NW thread RV: %d\n", rv);

    return NULL;
}

int mst_init_network(void)
{
    pthread_t pt_nw_thread;
    //int rv = -1;

    pthread_create(&pt_nw_thread, NULL, mst_nw_thread, NULL);
    sleep(2);

    mnp = (mst_nw_peer_t *) __mst_malloc(D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));
    assert(mnp);
    if (mst_global_opts.mst_config.mst_mode) {
        memset(mnp, 0, D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));
        mst_listen_socket();
    }
    else {
        mst_connect_socket();
    }

    return 0;
}

