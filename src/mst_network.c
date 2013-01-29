#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"
#include "mst_cntrs.h"

extern mst_nw_conn_table_t mst_nw_ct[D_NW_CONN_TABLE_SIZE];

mst_event_base_t meb;
mst_nw_peer_t *mnp; // For peers
mst_nw_peer_t *mnp_l; // For local socket inits 

extern mst_conf_t g_mst_conf;
extern pthread_mutex_t mst_eq_lock;
extern pthread_cond_t mst_eq_cond;

void mst_nw_write(struct mst_nw_peer *pmnp);
void mst_tun_write(struct mst_nw_peer *pmnp);
void mst_nw_read(struct mst_nw_peer *pmnp);
void mst_tun_read(struct mst_nw_peer *pmnp);
int mst_do_nw_write(struct mst_nw_peer *pmnp, mst_buffer_t *mbuf, int rlen);
int mst_do_tun_write(struct mst_nw_peer *pmnp, mst_buffer_t *mbuf, int rlen);
int mst_do_nw_read(struct mst_nw_peer *pmnp);
int mst_do_tun_read(struct mst_nw_peer *pmnp);

atomic_t tun_reads, tun_writes;
atomic_t nw_reads, nw_writes;

#define D_TUN_READ 0
#define D_NW_READ 1

inline time_t mst_jiffies(void)
{
    return time(NULL);
}

inline int mst_get_mnp_state(mst_nw_peer_t *pmnp) 
{
    int state = 0;
    pthread_mutex_lock(&pmnp->ref_lock);
    state = M_MNP_STATE(pmnp->mnp_flags);
    pthread_mutex_unlock(&pmnp->ref_lock);

    return state;
}

int mst_init_mnp(mst_nw_peer_t *pmnp)
{
    char cntr_name[D_MST_CNTR_LEN + 1] = {0};
    memset(&pmnp->mst_cs, 0, sizeof (pmnp->mst_cs));
    pmnp->mst_cs.sample_cnt = D_SAMPLE_CNT;
    pmnp->mst_cs.curr_sample_cnt = D_SAMPLE_CNT;

    if (D_MNP_TYPE_NW == M_MNP_TYPE(pmnp->mnp_flags)) {
        pmnp->mst_epoll_write = mst_nw_write;
        pmnp->mst_epoll_read = mst_nw_read;
        pmnp->mst_data_write = mst_do_nw_write;
        pmnp->mst_data_read = mst_do_nw_read;

        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.pkts_in", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.pkts_in);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.pkts_out", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.pkts_out);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.bytes_in", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.bytes_in);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.bytes_out", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.bytes_out);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.unack_cnt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.unack_cnt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.pending_cnt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.pending_cnt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.min_srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.min_srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.max_srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.max_srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.avg_srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.avg_srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.min_rx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.min_rx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.max_rx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.max_rx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.rx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.rx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.min_tx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.min_tx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.max_tx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.max_tx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.tx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.tx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.snd_cnt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.snd_cnt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "nw.%d.link_color", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.link_color);
        *(pmnp->mst_cs.link_color) = MST_LINK_YELLOW;
    }
    else {
        pmnp->mst_epoll_write = mst_tun_write;
        pmnp->mst_epoll_read = mst_tun_read;
        pmnp->mst_data_write = mst_do_tun_write;
        pmnp->mst_data_read = mst_do_tun_read;

        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.pkts_in", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.pkts_in);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.pkts_out", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.pkts_out);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.bytes_in", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.bytes_in);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.bytes_out", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.bytes_out);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.unack_cnt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.unack_cnt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.pending_cnt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.pending_cnt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.min_srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.min_srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.max_srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.max_srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.avg_srtt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.avg_srtt);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.min_rx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.min_rx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.max_rx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.max_rx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.rx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.rx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.min_tx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.min_tx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.max_tx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.max_tx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.tx_bw", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.tx_bw);
        snprintf(cntr_name, D_MST_CNTR_LEN, "tun.%d.snd_cnt", pmnp->mst_fd);
        mst_register_cntr(cntr_name, &pmnp->mst_cs.snd_cnt);
    }
    *(pmnp->mst_cs.snd_cnt) = D_MAX_SND_CNT;
    pmnp->mst_cs.min_snd_cnt = D_MIN_SND_CNT;
    pmnp->mst_cs.max_snd_cnt = D_MAX_SND_CNT;

    return 0;
}

inline void mst_epoll_events(mst_nw_peer_t *pmnp, int ev_cmd, int events)
{
    struct epoll_event ev;
    int epfd = meb.epfd;
    int rv = 0;

    ev.events = events;
    ev.data.ptr = pmnp;
    pthread_mutex_lock(&meb.ev_lock);
    rv = epoll_ctl(epfd, ev_cmd, pmnp->mst_fd, &ev);
    pthread_mutex_unlock(&meb.ev_lock);
    assert(!rv);
    pmnp->mst_ef = events;
    return;
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

//int mst_bind_socket(mst_nw_peer_t *pmnp, int mode)
int mst_bind_socket(mst_nw_peer_t *pmnp)
{
    int rv = -1;
    //mst_csi_t *mc;
    //mst_node_info_t *mni;
    struct sockaddr_in skaddr;
    mst_links_t *link = pmnp->link;

    memset(&skaddr, 0, sizeof(skaddr));

    skaddr.sin_family = AF_INET;
    skaddr.sin_addr.s_addr = inet_addr(link->leftip);
    skaddr.sin_port = htons(link->leftport);

    rv = bind(pmnp->mst_fd, (struct sockaddr *)&skaddr, sizeof(skaddr));

    assert(!rv);

    return 0;
}

void mst_tun_write(mst_nw_peer_t *pmnp)
{
    mst_buf_q_t *qelm;
    int count = 0;
    //fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    
    while (NULL != (qelm = mst_mbuf_dequeue_tail(pmnp))) {
        //mst_do_tun_write(pmnp, qelm->mbuf, qelm->wlen);
        pmnp->mst_data_write(pmnp, qelm->mbuf, qelm->wlen);
        mst_dealloc_mbuf(qelm->mbuf);
        mst_free(qelm, __func__);
        count++;
    }

    if (count > 1) {
        //fprintf(stderr, "%d continuous tun writes\n", count);
    }
    
    return;
}

void mst_tun_read(mst_nw_peer_t *pmnp)
{
    int i = 0;
    //fprintf(stderr, "%s(): __ENTRY__: %s\n", __func__, "Added to MST_TUN_Q\n");
    pthread_mutex_lock(&pmnp->ref_lock);
    if(!(pmnp->mst_curr & EPOLLIN)) { 
        M_MNP_REF_UP(pmnp);
        mst_epoll_events (pmnp, EPOLL_CTL_MOD, (pmnp->mst_ef & (~EPOLLIN)));
        pmnp->mst_curr |= EPOLLIN;
        mst_insert_tun_queue(MST_TUN_Q, pmnp);
        i = 1;
    }
    else {
        //fprintf(stderr, "Currently in epoll-tun read\n");
    }
    pthread_mutex_unlock(&pmnp->ref_lock);
    if (!i) {
        fprintf(stderr, "Spurious EPOLLIN for tun!!\n");
    }
    //fprintf(stderr, "%s(): __EXIT__: %s\n", __func__, "Added to MST_TUN_Q\n");
    return;
}

int mst_do_tun_write(mst_nw_peer_t *pmnp, mst_buffer_t *mbuf, int rlen)
{
    struct iovec *iov = NULL;
    int iov_len = 0;
    int rv = -1;

    assert(rlen > 0);

    iov = mst_mbuf_rework_iov(mbuf, rlen, &iov_len, D_NW_READ);
    assert(iov && iov_len);

    //fprintf(stderr, "%s:%d \n", __FILE__, __LINE__);
    // iov[0] is for nw_header. Data is available from iov[1]
    rv = writev(pmnp->mst_fd, &iov[1], iov_len);
    if ((rv < 0) || (0 == rv)) {
        fprintf(stderr, "WriteV error: %s - %d bytes, iov_len: %d\n", strerror(errno), rlen, iov_len);
    }
    else {
        atomic_inc(&tun_writes);
        
        pmnp->mst_cs.tx_time = mst_jiffies();
        *(pmnp->mst_cs.pkts_out)++;
        *(pmnp->mst_cs.bytes_out) += rv;
        //fprintf(stderr, "Wrote %d bytes on tun dev\n", rv);
    }
    //fprintf(stderr, "%s:%d unlock\n", __FILE__, __LINE__);

    return 0;
}

int mst_send_nw_init(mst_nw_peer_t *pmnp)
{
    struct iovec *iov = NULL;
    mst_buffer_t *mbuf = NULL;
    int iov_len = 0;

    mbuf = mst_alloc_mbuf(32 ,0, 0);
    assert(mbuf);

    iov = mst_mbuf_to_iov(mbuf, &iov_len, D_NW_READ);
    assert(iov);

    //mst_do_nw_write(pmnp, mbuf, 0);
    pmnp->mst_data_write(pmnp, mbuf, 0);
    fprintf(stderr, "%s(): Sent init message\n", __func__);

    if (!mst_lookup_nw_id(ntohl(pmnp->nw_id))) {
        mst_setup_tunnel(pmnp);
    }
    
    mst_insert_mnp_by_nw_id(ntohl(pmnp->nw_id), (int) pmnp);

    mst_dealloc_mbuf(mbuf);

    return 0;
}

int mst_get_ip_info(char *data, int rlen, unsigned *sip, unsigned *dip)
{
    struct ip *iph;

    iph = (struct ip *)data;

    if ((rlen < sizeof(struct ip)) || (D_IPV4 != iph->ip_v)) {
        fprintf(stderr, "[WARNING] Unknown IP version: %d or len: %d\n", iph->ip_v, rlen);
        return -1;
    }

    //fprintf(stderr, "SIP: "D_IPV4_STR_FMT", DIP: "D_IPV4_STR_FMT"\n", M_NIPQUAD(&iph->ip_src), M_NIPQUAD(&iph->ip_dst));
    *sip = iph->ip_src.s_addr;
    *dip = iph->ip_dst.s_addr;

    return 0;
}

int mst_get_new_sid(void)
{
    int sid = rand();

    return (sid % 10);
}

int mst_do_tun_read(mst_nw_peer_t *pmnp)
{
    struct iovec *iov = NULL;
    mst_buffer_t *mbuf = NULL;
    int rlen = 0;
    int iov_len = 0;
    mst_nw_peer_t *spmnp;
    int snd_cnt = 0;

tun_read_again:
    //fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    mbuf = mst_alloc_mbuf(D_MST_READ_SIZE, 0, 0 /*fill module info later*/);
    assert(mbuf);
    // D_NW_READ - Letz allocate room for nw_header in iov[0]. Will be populated by mst_do_nw_write
    iov = mst_mbuf_to_iov(mbuf, &iov_len, D_NW_READ);

    pmnp->mst_cbuf = mbuf;
    
    // iov[0] contains nw header. Tun read shud populate data from iov[1]
    rlen = readv(pmnp->mst_fd, &iov[1], (iov_len - 1)); // change it to NOWAIT later
    if ((rlen < 0) && ((EINTR != errno) && (errno != EAGAIN))) {
        fprintf(stderr, "Read error - 1: %s\n", strerror(errno));
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }
    if (rlen == 0) {
        fprintf(stderr, "TUNN cleanup - 2\n");
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }

    if ((rlen < 0) && ((EAGAIN == errno) || (EWOULDBLOCK == errno))) {
        mst_dealloc_mbuf(mbuf);
        pmnp->mst_cbuf = NULL;
        //fprintf(stderr, "[TUN]: EAGAIN\n");
        return 0;
    }

    if (rlen > 0) {
        unsigned sip = 0, dip = 0;
        int sid = -1;

        pmnp->mst_cs.rx_time = mst_jiffies();
        (*pmnp->mst_cs.pkts_in)++;
        *(pmnp->mst_cs.bytes_in) += rlen;

        if (!mst_get_ip_info(iov[1].iov_base, iov[1].iov_len, &sip, &dip)) {

            sid = mst_lookup_ip_tuple(sip, dip, E_TUN_IN, sid);
            if (sid < 0) {
                sid = mst_get_new_sid();
                fprintf(stderr, "New SID is %d\n",sid);
                mst_insert_ip_tuple(sip, dip, E_TUN_IN, sid);
            }
            pmnp->mst_cbuf->sid = sid;

            if (!snd_cnt) {
                spmnp = mst_get_next_fd(ntohl(pmnp->nw_id));
                snd_cnt = spmnp->mst_cs.snd_cnt;
            }
            //fprintf(stderr, "Received %d bytes. Decode TUNN here\n", rlen);
            
            if (!spmnp || (-1 == mst_insert_mbuf_q(spmnp, pmnp->mst_cbuf, rlen))) {
                mst_dealloc_mbuf(mbuf);
            }
            snd_cnt--;
            atomic_inc(&tun_reads);
        }
    }

    //mst_dealloc_mbuf(mbuf);
    pmnp->mst_cbuf = NULL;
    goto tun_read_again;

    return 0;
}

#define D_TEST_NW_ID htonl(0xDEADBEAF)

int mst_do_nw_write(mst_nw_peer_t *pmnp, mst_buffer_t *mbuf, int rlen)
{
    int rv = -1;
    struct msghdr omsg;
    char ctrlmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct cmsghdr *cmsg;
    struct sctp_sndrcvinfo *sinfo;
    //mst_csi_t *mt = NULL;
    struct iovec *iov = NULL;
    int iov_len = 0;
    int sid = -1;
    mst_nw_header_t nw_header = {.nw_id = D_TEST_NW_ID, .nw_version = htonl(D_NW_VERSION_1_0)};
    
    memset(&omsg, 0, sizeof(omsg));

    iov = mst_mbuf_rework_iov(mbuf, rlen, &iov_len, D_NW_READ);

    if (!rlen) {
        pmnp->nw_id = nw_header.nw_id;
        sid = mst_get_new_sid();
    }
    else {
        sid = mbuf->sid;
    }

    iov[0].iov_base = &nw_header;
    iov[0].iov_len = sizeof(mst_nw_header_t);

    assert(iov && iov_len);

    omsg.msg_iov = iov;
    omsg.msg_iovlen = (iov_len + 1);
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

    //sinfo->sinfo_ppid = rand();
    sinfo->sinfo_ppid = 0;
    sinfo->sinfo_stream = sid;
    sinfo->sinfo_flags = 0;

    rv = sendmsg(pmnp->mst_fd, &omsg, (rlen)?MSG_DONTWAIT:MSG_WAITALL);
    if ((rv < 0) && (EAGAIN == errno)) {
        return EAGAIN;
        //fprintf(stderr, "Sendmsg --> EAGAIN\n");
    }
    atomic_inc(&nw_writes);
    
    pmnp->mst_cs.tx_time = mst_jiffies();
    *(pmnp->mst_cs.pkts_out)++;
    *(pmnp->mst_cs.bytes_out) += rv;

    //fprintf(stderr, "%s:%d unlock\n", __FILE__, __LINE__);

    //fprintf(stderr, "SendMSG: %d --- on stream ID: %d, (%s)\n", rv, sinfo->sinfo_stream, strerror(errno));

    return 0;
}

void mst_nw_write(mst_nw_peer_t *pmnp)
{
    mst_buf_q_t *qelm;
    int count = 0;
    //fprintf(stderr, "%s(): __ENTRY__\n", __func__);

    
    while (NULL != (qelm = mst_mbuf_dequeue_tail(pmnp))) {
        //if (EAGAIN == mst_do_nw_write(pmnp, qelm->mbuf, qelm->wlen)) {
        if (EAGAIN == pmnp->mst_data_write(pmnp, qelm->mbuf, qelm->wlen)) {
            mst_insert_mbuf_q(pmnp, qelm->mbuf, qelm->wlen);
            pthread_mutex_lock(&pmnp->ref_lock);
            mst_epoll_events (pmnp, EPOLL_CTL_MOD, (pmnp->mst_ef | (EPOLLOUT)));
            pmnp->mst_curr &= ~EPOLLOUT;
            pthread_mutex_unlock(&pmnp->ref_lock);
            mst_free(qelm, __func__);
            return;
        }
        else {
            mst_dealloc_mbuf(qelm->mbuf);
            mst_free(qelm, __func__);
        }
        count++;
    }
    if (count > 1) {
        //fprintf(stderr, "%d continuous nw writes\n", count);
    }
    return;
}

int mst_cleanup_mnp(mst_nw_peer_t *pmnp)
{
    mst_nw_peer_t *mnp_pair = NULL;
    if (pmnp->mst_connection && (-1 != pmnp->mst_fd)) {
        close(pmnp->mst_fd);
        mnp_pair = (mst_nw_peer_t *)pmnp->mnp_pair;
        if (pmnp->mst_td) {
            event_free(pmnp->mst_td->te);
            mst_free(pmnp->mst_td, __func__);
            pmnp->mst_td = NULL;
        }
        if (pmnp->mst_cbuf) {
            mst_dealloc_mbuf(pmnp->mst_cbuf);
        }
        if (D_MNP_TYPE_NW == M_MNP_TYPE(pmnp->mnp_flags)) {
            mst_remove_mnp_by_nw_id(ntohl(pmnp->nw_id), (int)pmnp);
        }
        //mst_destroy_mbuf_q(&pmnp->mst_wq);
        pmnp->mst_fd = -1;
        mst_cleanup_mnp(mnp_pair);
        fprintf(stderr, "Cleaning up mnp %p\n", pmnp);
    }

    return 0;

}

void mst_nw_read(mst_nw_peer_t *pmnp)
{
    int i = 0;
    //fprintf(stderr, "%s(): __ENTRY__: %s\n", __func__, "Added to MST_SCTP_Q\n");
    //fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);
    pthread_mutex_lock(&pmnp->ref_lock);
    if (!(pmnp->mst_curr & EPOLLIN)) {
        M_MNP_REF_UP(pmnp);
        mst_epoll_events (pmnp, EPOLL_CTL_MOD, (pmnp->mst_ef & (~EPOLLIN)));
        pmnp->mst_curr |= EPOLLIN;
        mst_insert_nw_queue(MST_SCTP_Q, pmnp);
        i = 1;
    }
    else {
        //fprintf(stderr, "Currently in epoll-nw read\n");
    }
    pthread_mutex_unlock(&pmnp->ref_lock);
    if (!i) {
        fprintf(stderr, "Spurious EPOLLIN for nw!!\n");
    }
    //fprintf(stderr, "%s(): __EXIT__: %s\n", __func__, "Added to MST_SCTP_Q\n");
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
    int rv = 0;
    mst_nw_header_t *nw_header;
    //int rx_nw_id = 0;

read_again:
    memset(&rmsg, 0, sizeof(rmsg));
    mbuf = mst_alloc_mbuf(D_MST_READ_SIZE, 0, 0 /*fill module info later*/);
    assert(mbuf);

    //fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);

    nw_header = (mst_nw_header_t *) mst_malloc(sizeof(mst_nw_header_t), __func__);
    assert(nw_header);

    memset(nw_header, 0, sizeof(mst_nw_header_t));

    iov = mst_mbuf_to_iov(mbuf, &iov_len, D_NW_READ);

    iov[0].iov_base = nw_header;
    iov[0].iov_len = sizeof(mst_nw_header_t);

    rmsg.msg_iov = iov;
    rmsg.msg_iovlen = iov_len;
    rmsg.msg_control = ctrlmsg;
    rmsg.msg_controllen = sizeof(ctrlmsg);

    pmnp->mst_cbuf = mbuf;

    rlen = recvmsg(pmconn->conn_fd, &rmsg, MSG_DONTWAIT); // change it to NOWAIT later
    if (rlen < 0 && errno != EAGAIN) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }
    if ((rlen < 0) && ((EAGAIN == errno) || (EWOULDBLOCK == errno))) {
        mst_dealloc_mbuf(mbuf);
        pmnp->mst_cbuf = NULL;
        return 0;
    }
    if (rlen == 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }
    if (rlen > 0) {
        pmnp->mst_cs.rx_time = mst_jiffies();
        (*pmnp->mst_cs.pkts_in)++;
        *(pmnp->mst_cs.bytes_in) += rlen;
        
        //fprintf(stderr, "Received %d bytes. Decode SCTP here.\n", rlen);
        rv = mst_process_message(pmnp, &rmsg, rlen);
        atomic_inc(&nw_reads);
    }

    if (rv != 5) {
        mst_free(nw_header, __func__);
        mst_dealloc_mbuf(mbuf);
    }
    else {
        //fprintf(stderr, "SCTP -> mbuf queue\n");
    }
    pmnp->mst_cbuf = NULL;

    goto read_again;

    return 0;
}

int mst_setup_tunnel(mst_nw_peer_t *pmnp)
{
    char dev_name[IFNAMSIZ + 1] = {0};
    int rv = 0;
    int tunfd = -1;
    mst_nw_peer_t *tmnp;

    rv = mst_tun_dev_name(dev_name, IFNAMSIZ);
    fprintf(stderr, "New dev name: %s\n", dev_name);

    tunfd = mst_tun_open(dev_name);
    assert(tunfd > 0);
    evutil_make_socket_nonblocking(tunfd);

    if (g_mst_conf.mst_type) {
        tmnp = &mnp[tunfd];
    }
    else {
        tmnp = &mnp_l[g_mst_conf.links_cnt];
    }
    
    if(!tmnp->mst_connection) {
        tmnp->mst_connection = (mst_conn_t *) mst_malloc(sizeof(mst_conn_t), __func__);
        assert(tmnp->mst_connection);
        pthread_mutex_init(&tmnp->ref_lock, NULL);
        TAILQ_INIT(&tmnp->mst_wq);
        pthread_mutex_init(&tmnp->mst_wql, NULL);
    }
    else {
        memset(tmnp->mst_connection, 0, sizeof(mst_conn_t));
    }

    tmnp->mst_fd = tunfd;
    tmnp->mst_curr = 0;

    tmnp->mnp_flags ^= tmnp->mnp_flags;
    tmnp->mnp_flags = M_MNP_SET_TYPE(tmnp->mnp_flags, D_MNP_TYPE_TUN);
    tmnp->mnp_flags = M_MNP_SET_STATE(tmnp->mnp_flags, D_MNP_STATE_TUNNEL);

    tmnp->mst_td = NULL;
    tmnp->mnp_pair = (int)pmnp;
    tmnp->nw_id = pmnp->nw_id;
    
    M_MNP_REF_UP(tmnp);
    mst_init_mnp(tmnp);
    
    mst_epoll_events (tmnp, EPOLL_CTL_ADD, (EPOLLIN|EPOLLET));
    //mst_epoll_events (&mnp[tunfd], EPOLL_CTL_ADD, (EPOLLIN));
    
    pthread_mutex_lock(&pmnp->ref_lock);
    fprintf(stderr, "NW<->TUN pair: %d <-> %d: NWID 0x%X\n", pmnp->mst_fd, tunfd, ntohl(tmnp->nw_id));
    pmnp->mnp_pair = (int)tmnp;
    pthread_mutex_unlock(&pmnp->ref_lock);

    return rv;
}

int mst_do_accept(mst_nw_peer_t *pmnp)
{
    int rv = -1;
    struct sockaddr_in client;
    socklen_t sk_len = sizeof(client);
    evutil_socket_t cfd;
    
    //mst_nw_peer_t *pmnp = (mst_nw_peer_t *)arg;

    memset(&client, 0, sk_len);

    //fprintf(stderr, "Got a call\n");
    cfd = accept(pmnp->mst_fd, (struct sockaddr *)&client, &sk_len);

    if ((cfd > 0) && (cfd <= D_MAX_PEER_CNT)) {
        fprintf(stderr, "Accepted conn[%d] from '%s:%hu'\n", cfd, inet_ntoa(client.sin_addr), ntohs(client.sin_port));

        if(!mnp[cfd].mst_connection) {
            mnp[cfd].mst_connection = (mst_conn_t *) mst_malloc(sizeof(mst_conn_t), __func__);
            assert(mnp[cfd].mst_connection);
            pthread_mutex_init(&mnp[cfd].ref_lock, NULL);
            TAILQ_INIT(&mnp[cfd].mst_wq);
        }
        else {
            memset(mnp[cfd].mst_connection, 0, sizeof(mst_conn_t));
        }

        mnp[cfd].mst_nwp = pmnp->mst_nwp;
        mnp[cfd].num_ostreams = pmnp->num_ostreams;
        mnp[cfd].max_instreams = pmnp->max_instreams;

        mnp[cfd].mst_curr = 0;
        mnp[cfd].mst_fd = cfd;
        mnp[cfd].mnp_flags ^= mnp[cfd].mnp_flags;
        mnp[cfd].mnp_flags = M_MNP_SET_TYPE(mnp[cfd].mnp_flags, D_MNP_TYPE_NW);
        mnp[cfd].mnp_flags = M_MNP_SET_STATE(mnp[cfd].mnp_flags, D_MNP_STATE_CONNECTED);
        
        if (!mnp[cfd].mst_td) {
            mnp[cfd].mst_td = (mst_timer_data_t *)mst_malloc(sizeof(mst_timer_data_t), __func__);
            assert(mnp[cfd].mst_td);
        }
        mnp[cfd].mst_td->type = MST_MNP;
        mnp[cfd].mst_td->timeo.tv_sec = 5;
        mnp[cfd].mst_td->timeo.tv_usec = 0;
        mnp[cfd].mst_td->te = evtimer_new(meb.Teb, mst_timer, mnp[cfd].mst_td);
        mnp[cfd].mst_td->data = &mnp[cfd];

        rv = setsockopt(mnp[cfd].mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&pmnp->pmst_ses, sizeof(pmnp->pmst_ses));

        //fprintf(stderr, "SSO: RV: %d\n", rv);

        assert(rv >= 0);

        M_MNP_REF_UP(&mnp[cfd]);
        mst_init_mnp(&mnp[cfd]);

        evutil_make_socket_nonblocking(cfd);
        evtimer_add(mnp[cfd].mst_td->te, &mnp[cfd].mst_td->timeo);
        
        mst_epoll_events (&mnp[cfd], EPOLL_CTL_ADD, (EPOLLIN|EPOLLET));
        fprintf(stderr, "Added fd '%d' to epoll\n", mnp[cfd].mst_fd);
        //mst_epoll_events (&mnp[cfd], EPOLL_CTL_ADD, (EPOLLIN));
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
    
    //for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
    for(index = 0; index < g_mst_conf.links_cnt; index++) {
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
    //meb.epfd = epoll_create(1/* Any +ve number shud do here*/);
    //meb.epfd = epoll_create(2 * D_MAX_PEER_CNT/* Any +ve number shud do here*/);
    meb.epfd = epoll_create(2 * g_mst_conf.links_cnt/* Any +ve number shud do here*/);

    assert(meb.epfd > 0);
    meb.ev.events = EPOLLIN;

    if (g_mst_conf.mst_type) /*server*/ {
        meb.evb = (struct epoll_event *)mst_malloc(sizeof(struct epoll_event) * (D_MAX_PEER_CNT + g_mst_conf.links_cnt), __func__);
        assert(meb.evb);
        meb.ev_cnt = (D_MAX_PEER_CNT + g_mst_conf.links_cnt);
    }
    else /*client*/ {
        meb.evb = (struct epoll_event *)mst_malloc(sizeof(struct epoll_event) * (g_mst_conf.links_cnt + 1 /* for tunfd */), __func__);
        assert(meb.evb);
        meb.ev_cnt = (g_mst_conf.links_cnt + 1);
    }

    //mnp_l = (mst_nw_peer_t *)mst_malloc(sizeof(mst_nw_peer_t) * mst_global_opts.mst_tuple_cnt, __func__);
    mnp_l = (mst_nw_peer_t *)mst_malloc(sizeof(mst_nw_peer_t) * g_mst_conf.links_cnt, __func__);
    
    assert(mnp_l);

    //memset(mnp_l, 0, sizeof(mst_nw_peer_t) * mst_global_opts.mst_tuple_cnt);
    memset(mnp_l, 0, sizeof(mst_nw_peer_t) * (g_mst_conf.links_cnt + 1));

    //for(index = 0; index < mst_global_opts.mst_tuple_cnt; index++) {
    for(index = 0; index < g_mst_conf.links_cnt; index++) {
        mnp_l[index].mst_connection = (mst_conn_t *)mst_malloc(sizeof(mst_conn_t), __func__);
        assert(mnp_l[index].mst_connection);
        memset(mnp_l[index].mst_connection, 0, sizeof(mst_conn_t));
        mnp_l[index].mst_fd = mst_create_socket();
        mnp_l[index].mst_nwp = mt[index].nw_parms;
        mnp_l[index].num_ostreams = mt[index].num_ostreams;
        mnp_l[index].max_instreams = mt[index].max_instreams;
        mnp_l[index].mst_curr = 0;
        mnp_l[index].link = &(g_mst_conf.links[index]);
        
        TAILQ_INIT(&mnp_l[index].mst_wq);
        pthread_mutex_init(&mnp_l[index].mst_wql, NULL);

        //pthread_mutex_init(&mnp_l[index].mst_cl, NULL);
        pthread_mutex_init(&mnp_l[index].ref_lock, NULL);
        mnp_l[index].mst_config = &mst_global_opts.mst_config;
        
        //assert(!mst_bind_socket(&mnp_l[index], mst_global_opts.mst_config.mst_mode));
        assert(!mst_bind_socket(&mnp_l[index]));

        //if (mst_global_opts.mst_config.mst_mode) {
        if (g_mst_conf.mst_type) {
            mnp_l[index].mnp_flags = M_MNP_SET_STATE(mnp_l[index].mnp_flags, D_MNP_STATE_LISTEN);
        }

        mnp_l[index].mnp_flags = M_MNP_SET_TYPE(mnp_l[index].mnp_flags, D_MNP_TYPE_NW);

        mst_init_mnp(&mnp_l[index]);
        //fprintf(stderr, "MNP flags: %0X, %p\n", mnp_l[index].mnp_flags, &mnp_l[index]);

        mst_epoll_events (&mnp_l[index], EPOLL_CTL_ADD, (EPOLLIN|EPOLLET));
        //mst_epoll_events (&mnp_l[index], EPOLL_CTL_ADD, (EPOLLIN));
    }

    return 0;
}

int
mst_do_connect(mst_nw_peer_t *pmnp)
{
    //fprintf(stderr, "%s(): __ENTRY__\n", __func__);
    pmnp->mst_td = (mst_timer_data_t *)mst_malloc(sizeof(mst_timer_data_t), __func__);
    assert(pmnp->mst_td);
    pmnp->mst_td->type = MST_MNP;
    pmnp->mst_td->timeo.tv_sec = 5;
    pmnp->mst_td->timeo.tv_usec = 0;
    pmnp->mst_td->te = evtimer_new(meb.Teb, mst_timer, pmnp->mst_td);
    pmnp->mst_td->data = pmnp;

    M_MNP_REF_UP(pmnp);
    fprintf(stderr, "%s(): pmnp: %p, fd: %d\n", __func__, pmnp, pmnp->mst_fd);

    pmnp->mnp_flags = M_MNP_UNSET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTING);
    pmnp->mnp_flags = M_MNP_SET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTED);

    evtimer_add(pmnp->mst_td->te, &pmnp->mst_td->timeo);
    
    mst_send_nw_init(pmnp);

    pmnp->mnp_flags = M_MNP_UNSET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTED);
    pmnp->mnp_flags = M_MNP_SET_STATE(pmnp->mnp_flags, D_MNP_STATE_ESTABLISHED);
    pmnp->mst_td->timeo.tv_sec = 0;
    pmnp->mst_td->timeo.tv_usec = 50000;

    //mst_nw_read(pmnp);
    pmnp->mst_epoll_read(pmnp);
    
    return 0;
}

int
//mst_connect_socket(void)
mst_connect_socket(mst_nw_peer_t *pmnp)
{
    int rv = -1;
    int index = 0;
    struct sockaddr_in skaddr;
    mst_links_t *link = pmnp->link;
    mst_config_t *mst_conf = mst_get_mst_config();

    memset(&skaddr, 0, sizeof(skaddr));

    skaddr.sin_family = AF_INET;
    skaddr.sin_addr.s_addr = inet_addr(link->rightip);
    skaddr.sin_port = htons(link->rightport);

    pmnp->mst_config = mst_conf;

    rv = setsockopt(pmnp->mst_fd, SOL_SCTP, SCTP_EVENTS, (char *)&pmnp->pmst_ses, sizeof(pmnp->pmst_ses));
    assert(rv >= 0);

    rv = connect(pmnp->mst_fd, (struct sockaddr *)&skaddr, sizeof(skaddr));

    if ((rv < 0) && (EINPROGRESS != errno)) {
        fprintf(stderr, "Connect error: %d:%s\n", errno, strerror(errno));
        return -1;
    }
    pmnp->mnp_flags = M_MNP_SET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTING);

    return 0;
}

void *mst_nw_thread(void *arg)
{
    int rv = -1;
    int nfds = -1;
    int index = 0;
    int epoll_delay = 1;
    mst_nw_peer_t *pmnp = NULL;

    while(1) {

        //fprintf(stderr, "EPOLL Wait loop\n");

        nfds = epoll_wait(meb.epfd, meb.evb, meb.ev_cnt, epoll_delay /*100 ms*/);
        //fprintf(stderr, "nfds: %d\n", nfds);
        if (nfds < 0) {
            //fprintf(stderr, "epoll_wait error: %s\n", strerror(errno));
        }
        //assert(!(nfds < 0));

        if (0 == nfds) {
            mst_nw_q_t *qelm = NULL;
            int count = 0;
            //fprintf(stderr, "Epoll wait returned 0. Add back FDs to epoll\n");

            while(NULL != (qelm = mst_epoll_dequeue_tail())) {
                count++;
                pthread_mutex_lock(&qelm->pmnp->ref_lock);
                mst_epoll_events (qelm->pmnp, EPOLL_CTL_MOD, (qelm->pmnp->mst_ef | (EPOLLIN | EPOLLET)));
                //mst_epoll_events (qelm->pmnp, EPOLL_CTL_MOD, (qelm->pmnp->mst_ef | (EPOLLIN)));
                qelm->pmnp->mst_curr &= ~EPOLLIN;
                pthread_mutex_unlock(&qelm->pmnp->ref_lock);
                mst_free(qelm, __func__);
            }
            if (!count) {
            }
        }

        for(index = 0; index < nfds; index++) {

            if ((meb.evb[index].events & EPOLLERR) ||
                (meb.evb[index].events & EPOLLHUP) ||
                !((meb.evb[index].events & EPOLLIN) || 
                (meb.evb[index].events & EPOLLOUT))) {
                fprintf (stderr, "EPOLL ERROR: closing socket\n");
                M_MNP_REF_DOWN_AND_FREE((mst_nw_peer_t *)&meb.evb[index].data);
                continue;
            }

            pmnp = (mst_nw_peer_t *)meb.evb[index].data.ptr;

            if (meb.evb[index].events & EPOLLOUT) {
                //fprintf(stderr, "EPOLLOUT events\n");
                switch(M_MNP_TYPE(pmnp->mnp_flags)) {
                    case D_MNP_TYPE_TUN:
                        pthread_mutex_lock(&pmnp->ref_lock);
                        if (!(pmnp->mst_curr & EPOLLOUT)) {
                            mst_epoll_events (pmnp, EPOLL_CTL_MOD, (pmnp->mst_ef & (~EPOLLOUT)));
                            pmnp->mst_curr |= EPOLLOUT;
                            mst_insert_tun_wq(MST_TUN_Q, pmnp);
                        }
                        pthread_mutex_unlock(&pmnp->ref_lock);

                        //mst_tun_write(pmnp);
                        break;
                    default:
                        pthread_mutex_lock(&pmnp->ref_lock);
                        if (!(pmnp->mst_curr & EPOLLOUT)) {
                            mst_epoll_events (pmnp, EPOLL_CTL_MOD, (pmnp->mst_ef & (~EPOLLOUT)));
                            pmnp->mst_curr |= EPOLLOUT;
                            mst_insert_nw_wq(MST_SCTP_Q, pmnp);
                        }
                        pthread_mutex_unlock(&pmnp->ref_lock);

                        //mst_nw_write(pmnp);
                }
            }
            if (!(meb.evb[index].events & EPOLLIN)) {
                continue;
            }

            //fprintf(stderr, "EPOLL loop, pmnp: %p, flags: %0X\n", pmnp, pmnp->mnp_flags);
            //switch(M_MNP_STATE(pmnp->mnp_flags)) {
            switch(mst_get_mnp_state(pmnp)) {
                case D_MNP_STATE_LISTEN:
                    mst_do_accept(pmnp);
                    break;
                case D_MNP_STATE_CONNECTING:
                    fprintf(stderr, "State is connecting\n");
                    mst_do_connect(pmnp);
                    break;
                case D_MNP_STATE_CONNECTED:
                case D_MNP_STATE_ESTABLISHED:
                    //mst_nw_read(pmnp);
                    pmnp->mst_epoll_read(pmnp);
                    break;
                case D_MNP_STATE_TUNNEL:
                    //mst_tun_read(pmnp);
                    pmnp->mst_epoll_read(pmnp);
                    break;
                default:
                    fprintf(stderr, "Unknown MNP_TYPE %0X received\n", pmnp->mnp_flags);
            }
        }
    }

    fprintf(stderr, "NW thread RV: %d\n", rv);

    return NULL;
}

int mst_init_network(void)
{
    pthread_t pt_nw_thread;
    int index = 0;
    //int rv = -1;
    //

    for(index = 0; index < D_NW_CONN_TABLE_SIZE; index++) {
        INIT_HLIST_HEAD(&mst_nw_ct[index].bucket);
        pthread_mutex_init(&mst_nw_ct[index].b_lock, NULL);
    }

    mst_init_ip_flow_table();

    pthread_create(&pt_nw_thread, NULL, mst_nw_thread, NULL);
    sleep(2);

    //if (mst_global_opts.mst_config.mst_mode) {
    if (g_mst_conf.mst_type) {
        mnp = (mst_nw_peer_t *) mst_malloc(D_MAX_PEER_CNT * sizeof(mst_nw_peer_t), __func__);
        assert(mnp);
        memset(mnp, 0, D_MAX_PEER_CNT * sizeof(mst_nw_peer_t));
        mst_listen_socket();
    }
    else {
        for(index = 0; index < g_mst_conf.links_cnt; index++) {
            mst_connect_socket(&mnp_l[index]);
        }
    }

    return 0;
}

