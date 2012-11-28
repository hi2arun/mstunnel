#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"

mst_network_t mst_network_base;
mst_nw_peer_t *mnp;

#define mnb mst_network_base
#define D_MAX_PEER_CNT 1024

int mst_create_socket(void)
{
    int rv = -1;
    mnb.mst_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

    if (mnb.mst_fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    mnb.mst_ses.sctp_data_io_event = 1;
    mnb.mst_ses.sctp_association_event = 1;
    mnb.mst_ses.sctp_shutdown_event = 1;

    rv = setsockopt(mnb.mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&mnb.mst_ses, sizeof(mnb.mst_ses));
    if (rv < 0) {
        fprintf(stderr, "SCTP_EVENTS subscribe failure: %s\n", strerror (errno));
    }

    return mnb.mst_fd;
}

int mst_bind_socket(char *ipaddr, unsigned short port)
{
    int rv = -1;
    mnb.mst_ipt.sin_family = AF_INET;
    mnb.mst_ipt.sin_addr.s_addr = inet_addr(ipaddr);
    mnb.mst_ipt.sin_port = htons(port);

    rv = bind(mnb.mst_fd, (struct sockaddr *)&mnb.mst_ipt, sizeof(mnb.mst_ipt));

    if (rv < 0) {
        fprintf(stderr, "Bind error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

void mst_do_write(evutil_socket_t fd, short event, void *arg)
{
    return;
}

void mst_do_read(evutil_socket_t fd, short event, void *arg)
{
    mst_nw_peer_t *mnp = (mst_nw_peer_t *)arg;
    char ctrlmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
    //struct iovec iov;
    struct iovec *iov = NULL;
    struct msghdr rmsg;
    mst_buffer_t *mbuf = NULL;
    int rlen = 0;
    int iov_len = 0;

    memset(&rmsg, 0, sizeof(rmsg));
    mbuf = mst_alloc_mbuf(D_MST_READ_SIZE, 0, 0 /*fill module info later*/);
    assert(mbuf);

    iov = mst_mbuf_to_iov(mbuf, &iov_len);


    //iov.iov_len = D_MST_READ_SIZE;
    //iov.iov_base = mbuf->buffer;
    rmsg.msg_iov = iov;
    rmsg.msg_iovlen = iov_len;
    rmsg.msg_control = ctrlmsg;
    rmsg.msg_controllen = sizeof(ctrlmsg);

    rlen = recvmsg(fd, &rmsg, MSG_WAITALL); // change it to NOWAIT later
    fprintf(stderr, "Received %d bytes. Decode SCTP here\n", rlen);
    if (rlen < 0 && rlen != EAGAIN) {
        event_free(mnp->mst_re);
        event_free(mnp->mst_we);
        mst_dealloc_mbuf(mbuf);
        return;
    }
    if (rlen == 0) {
        event_free(mnp->mst_re);
        event_free(mnp->mst_we);
        mst_dealloc_mbuf(mbuf);
        return;
    }

    mst_process_message(mnp, &rmsg, rlen);

    event_add(mnp->mst_re, NULL);
    mst_dealloc_mbuf(mbuf);

    return;
}

void mst_do_accept(evutil_socket_t fd, short event, void *arg)
{
    int rv = -1;
    struct sockaddr_in client;
    socklen_t sk_len = sizeof(client);
    evutil_socket_t cfd;

    assert(mnb.mst_fd == fd);
    memset(&client, 0, sk_len);

    fprintf(stderr, "Got a call\n");
    cfd = accept(fd, (struct sockaddr *)&client, &sk_len);

    if ((cfd > 0) && (cfd <= D_MAX_PEER_CNT)) {
        fprintf(stderr, "Accepted conn from '%s:%hu'\n", inet_ntoa(client.sin_addr), client.sin_port);

        mnp[cfd].mst_fd = cfd;
        mnp[cfd].mst_ceb = mnb.mst_ceb;
        mnp[cfd].mst_re = event_new(mnb.mst_ceb, cfd, EV_READ, mst_do_read, (void *)&mnp[cfd]);
        mnp[cfd].mst_we = event_new(mnb.mst_ceb, cfd, EV_WRITE, mst_do_write, (void *)&mnp[cfd]);

        mnp[cfd].mst_ses.sctp_data_io_event = 1;
        mnp[cfd].mst_ses.sctp_association_event = 1;
        mnp[cfd].mst_ses.sctp_shutdown_event = 1;

        rv = setsockopt(mnp[cfd].mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&mnp[cfd].mst_ses, sizeof(mnp[cfd].mst_ses));

        if (rv < 0) {
            fprintf(stderr, "Setsockopt failed @[%d]:%s\n", __LINE__, strerror(errno));
        }
        evutil_make_socket_nonblocking(cfd);
        event_add(mnp[cfd].mst_re, NULL);
    }
    else {
        fprintf(stderr, "CFD: %d, %s\n", cfd, strerror(errno));
    }

    return;
}

int mst_listen_socket(int backlog)
{
    int rv = -1;

    rv = listen(mnb.mst_fd, backlog);

    if (rv < 0) {
        fprintf(stderr, "Listen call failed: %s\n", strerror(errno));
        return -1;
    }

    mnb.mst_re = event_new(mnb.mst_ceb, mnb.mst_fd, EV_READ|EV_PERSIST, mst_do_accept, (void *)mnb.mst_ceb);
    event_add(mnb.mst_re, NULL);

    return 0;
}

#define D_SRV_BACKLOG 100

int mst_setup_network(int mode, char *ipaddr, unsigned short port)
{
    int rv = -1;
    int sk;

    sk = mst_create_socket();
    if (sk < 0) {
        return rv;
    }

    if (mode) {
        rv = mst_bind_socket(ipaddr, port);
    }
    else {
        rv = mst_bind_socket(ipaddr, (port - 1));
    }

    return rv;
}

int mst_loop_network(int mode)
{
    // Create event base here - root
    mnb.mst_ceb = event_base_new ();
    if (!mnb.mst_ceb) {
        fprintf(stderr, "Failed to create event base: %s\n", strerror(errno));
        return -1;
    }

    evutil_make_socket_nonblocking(mnb.mst_fd);

    if (mode) {
        mnp = (mst_nw_peer_t *) __mst_malloc(D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));

        if (!mnp) {
            fprintf(stderr, "Failed to alloc memory: %s\n", strerror(errno));
            return -1;
        }

        mst_listen_socket(D_SRV_BACKLOG);
    }
    else {
        //mst_connect_socket(sk, ipaddr, port);
    }

    event_base_dispatch(mnb.mst_ceb);

    //mst_cleanup_socket(sk);

    return 0;
}

