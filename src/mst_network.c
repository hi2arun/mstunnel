#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"

mst_event_base_t meb;
mst_nw_peer_t *mnp; // For peers
mst_nw_peer_t *mnp_l; // For local socket inits 

#define D_MAX_LISTEN_CNT 2
#define D_MAX_CONNECT_CNT 2
#define D_MAX_PEER_CNT 1024

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

void mst_do_write(evutil_socket_t fd, short event, void *arg)
{
    return;
}

void mst_do_read(evutil_socket_t fd, short event, void *arg)
{
    mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;
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

    rlen = recvmsg(fd, &rmsg, MSG_WAITALL); // change it to NOWAIT later
    fprintf(stderr, "Received %d bytes. Decode SCTP here\n", rlen);
    if (rlen < 0 && rlen != EAGAIN) {
        close(fd);
        event_free(pmnp->mst_re);
        event_free(pmnp->mst_we);
        event_free(pmnp->mst_td->te);
        mst_dealloc_mbuf(mbuf);
        return;
    }
    if (rlen == 0) {
        close(fd);
        event_free(pmnp->mst_re);
        event_free(pmnp->mst_we);
        event_free(pmnp->mst_td->te);
        mst_dealloc_mbuf(mbuf);
        return;
    }
    //mst_process_message(pmnp, &rmsg, rlen);

    event_add(pmnp->mst_re, NULL);
    mst_dealloc_mbuf(mbuf);

    return;
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

    // Create event base for tunn side
    meb.teb = event_base_new();
    assert(meb.teb);


    if (mst_global_opts.mst_config.mst_mode) {
        mnp = (mst_nw_peer_t *) __mst_malloc(D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));

        assert(mnp);

        memset(mnp, 0, D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));
        mst_listen_socket();
    }
    else {
        mst_connect_socket();
    }

    rv = event_base_dispatch(meb.ceb);

    fprintf(stderr, "RV: %d\n", rv);

    //mst_cleanup_network();

    return 0;
}

