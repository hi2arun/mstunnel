#include "mstunnel.h"
#include "mst_network.h"
#include "memmgmt.h"
#include "mst_nw_queue.h"

#define D_CTRL_MSG_LEN 256 // 256 bytes is good enuf to hold control message

int
mst_process_ac(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    struct iovec *msg_iov = NULL;
    union sctp_notification *snp = NULL;
    struct sctp_assoc_change *sac;
    char ctrl_msg[D_CTRL_MSG_LEN];
    int mc_len = 0;
    int mc_tlen = 0;
    int index = 0;

    //fprintf(stderr, "ENTRY: %s()\n", __func__);
    assert(rlen <= D_CTRL_MSG_LEN);

    memset(ctrl_msg, 0, sizeof(ctrl_msg));
    fprintf(stderr, "Ctrl msg len: %d\n", sizeof(ctrl_msg));

    for (index = 0; index < rmsg->msg_iovlen; index++) {
        msg_iov = &(rmsg->msg_iov[index]);

        if ((mc_tlen + msg_iov->iov_len) < rlen) {
            mc_len = msg_iov->iov_len;
        }
        else {
            mc_len = (rlen - mc_tlen);
        }

        memcpy((ctrl_msg + mc_tlen), msg_iov->iov_base, mc_len);
        mc_tlen += mc_len;
        
        fprintf(stderr, "Copied: %d bytes\n", mc_len);

        if (mc_tlen >= rlen) {
            fprintf(stderr, "Total Copied: %d bytes\n", mc_tlen);
            break;
        }
    }

    // Notification should be in the first vector
    //snp = (union sctp_notification *)msg_iov->iov_base;
    snp = (union sctp_notification *)ctrl_msg;
    sac = &snp->sn_assoc_change;

    switch(sac->sac_state) {
        // Comm UP
        case 0:
            //fprintf(stderr, "COMM_UP - Setting up tunnel\n");
            atomic_set(&pmnp->mst_nwp.xmit_curr_pkts, 0);
            //mst_setup_tunnel(pmnp);
            break;
        // Comm RESTART
        case 2:
            //fprintf(stderr, "COMM_RESTART\n");
            break;
        // Shutdown COMPLETE
        case 3:
            //fprintf(stderr, "SHUTDOWN_COMPLETE\n");
            break;
        // Comm DOWN
        case 1:
            // Cant Start ASSOC
        case 4:
        default:
            fprintf(stderr, "Cleanup mnp: assoc_change to %d\n", sac->sac_state);
            mst_cleanup_mnp(pmnp);
    }
    
    return 0;
}
int
mst_process_pac(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    //fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}
int
mst_process_sf(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}
int
mst_process_re(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}
int
mst_process_se(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}
int
mst_process_pde(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}
int
mst_process_ai(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}
int
mst_process_auth_ind(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    //fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}


int
mst_process_notification(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen) 
{
    union sctp_notification *snp = NULL;
    struct iovec *msg_iov = NULL;

    //fprintf(stderr, "ENTRY: %s()\n", __func__);
    msg_iov = rmsg->msg_iov;
    // Notification should be in the first vector
    snp = (union sctp_notification *)msg_iov->iov_base;

    switch(snp->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            mst_process_ac(pmnp, rmsg, rlen);
            break;
        case SCTP_PEER_ADDR_CHANGE:
            mst_process_pac(pmnp, rmsg, rlen);
            break;
        case SCTP_SEND_FAILED:
            mst_process_sf(pmnp, rmsg, rlen);
            break;
        case SCTP_REMOTE_ERROR:
            mst_process_re(pmnp, rmsg, rlen);
            break;
        case SCTP_SHUTDOWN_EVENT:
            mst_process_se(pmnp, rmsg, rlen);
            break;
        case SCTP_PARTIAL_DELIVERY_EVENT:
            mst_process_pde(pmnp, rmsg, rlen);
            break;
        case SCTP_ADAPTATION_INDICATION:
            mst_process_ai(pmnp, rmsg, rlen);
            break;
        case SCTP_AUTHENTICATION_INDICATION:
            mst_process_auth_ind(pmnp, rmsg, rlen);
            break;
        default:
            fprintf(stderr, "Unknown notification type: %0x\n", snp->sn_header.sn_type);
    }

    return 0;
}

int
mst_get_sid(struct msghdr *rmsg)
{
    struct cmsghdr *scmsg = NULL;
    sctp_cmsg_data_t *rdata = NULL;
    
    for(scmsg = CMSG_FIRSTHDR(rmsg); scmsg != NULL; scmsg = CMSG_NXTHDR(rmsg, scmsg)) {
        rdata = (sctp_cmsg_data_t *)CMSG_DATA(scmsg);
        if (SCTP_SNDRCV == scmsg->cmsg_type) {
            return rdata->sndrcv.sinfo_stream;
        }
    }

    return -1;
}

int
mst_process_data(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    unsigned sip = 0, dip = 0;
    struct iovec *iov;
    int sid = -1;
    //fprintf(stderr, "ENTRY: %s()\n", __func__);
    //
    iov = rmsg->msg_iov;

    if (!mst_get_ip_info(iov[1].iov_base, iov[1].iov_len, &sip, &dip)) {
        sid = mst_get_sid(rmsg);
        if (mst_lookup_ip_tuple(sip, dip, E_NW_IN, sid) < 0) {
            mst_insert_ip_tuple(sip, dip, E_NW_IN, sid);
        }
        pmnp->mst_cbuf->sid = sid;
        
        mst_insert_mbuf_q((mst_nw_peer_t *)pmnp->mnp_pair, pmnp->mst_cbuf, rlen);
        return 5;
    }
    
   return 0;
}

int 
mst_dump_ctrlmsg(int type, sctp_cmsg_data_t *rdata)
{
    return 0;
    switch(type) {
        case SCTP_INIT:
            fprintf(stderr, "MSG TYPE: SCTP_INIT\n");
            fprintf(stderr, "sinit_num_ostreams: %hu, ", rdata->init.sinit_num_ostreams);
            fprintf(stderr, "sinit_max_instreams: %hu, ", rdata->init.sinit_max_instreams);
            fprintf(stderr, "sinit_max_attempts: %hu, ", rdata->init.sinit_max_attempts);
            fprintf(stderr, "sinit_max_init_timeo: %hu\n", rdata->init.sinit_max_init_timeo);
            break;
        case SCTP_SNDRCV:
            fprintf(stderr, "MSG TYPE: SCTP_SNDRCV\n");
            fprintf(stderr, "sinfo_assoc_id: 0x%0X, ", rdata->sndrcv.sinfo_assoc_id);
            fprintf(stderr, "sinfo_stream: 0x%0X, ", rdata->sndrcv.sinfo_stream);
            fprintf(stderr, "sinfo_ssn: 0x%0X, ", rdata->sndrcv.sinfo_ssn);
            fprintf(stderr, "sinfo_flags: 0x%0X, ", rdata->sndrcv.sinfo_flags);
            fprintf(stderr, "sinfo_ppid: 0x%0X, ", rdata->sndrcv.sinfo_ppid);
            fprintf(stderr, "sinfo_context: 0x%0X, ", rdata->sndrcv.sinfo_context);
            fprintf(stderr, "sinfo_timetolive: 0x%0X, ", rdata->sndrcv.sinfo_timetolive);
            fprintf(stderr, "sinfo_tsn: 0x%0X, ", rdata->sndrcv.sinfo_tsn);
            fprintf(stderr, "sinfo_cumtsn: 0x%0X\n", rdata->sndrcv.sinfo_cumtsn);
            break;
        default:
            fprintf(stderr, "Unknown CMSG-TYPE 0x%0X received\n", type);
    }

    return 0;
}

int
mst_process_message(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    struct cmsghdr *scmsg = NULL;
    sctp_cmsg_data_t *rdata = NULL;
    int rv = 0;
    int nm = 0;
    mst_nw_header_t *nw_header = NULL;

    if (!rlen || (rlen < 0)) {
        fprintf(stderr, "No data. Nothing to dump\n");
    }

    // Check if it is notification message or data

    if (MSG_NOTIFICATION & rmsg->msg_flags) {
        mst_process_notification(pmnp, rmsg, rlen);
        nm = 1;
    }
    else {
        nw_header = rmsg->msg_iov[0].iov_base;
        //fprintf(stderr, "NW ID: 0x%x, version: 0x%x\n", ntohl(nw_header->nw_id), ntohl(nw_header->nw_version));
        // TODO: Validate/add nw_id. If failed, process error
        if (rlen > sizeof(mst_nw_header_t)) {
            if (!mst_lookup_nw_id(ntohl(nw_header->nw_id))) {
                fprintf(stderr, "No NW ID is present in CT. Rejecting packet\n");
            }
            else {
                rv = mst_process_data(pmnp, rmsg, rlen);
                if (5 == rv) {
                    mst_free(nw_header, __func__);
                }
            }
        }
        else {
            int retval = 0;
            int retval_1 = 0;
            fprintf(stderr, "NW control message is received: NW ID: 0x%x\n", ntohl(nw_header->nw_id));
            pmnp->nw_id = nw_header->nw_id;
            if (!mst_lookup_nw_id(ntohl(nw_header->nw_id))) {
                mst_setup_tunnel(pmnp);
            }
            if (0 == (retval = mst_lookup_mnp_by_nw_id(ntohl(nw_header->nw_id), (int)pmnp))) {
                if (0 == (retval_1 = mst_insert_mnp_by_nw_id(ntohl(nw_header->nw_id), (int)pmnp))) {
                    pmnp->mnp_flags = M_MNP_UNSET_STATE(pmnp->mnp_flags, D_MNP_STATE_CONNECTED);
                    pmnp->mnp_flags = M_MNP_SET_STATE(pmnp->mnp_flags, D_MNP_STATE_ESTABLISHED);
                    pmnp->mst_td->timeo.tv_sec = 0;
                    pmnp->mst_td->timeo.tv_usec = 50000;
                }
            }
        }
    }

    for(scmsg = CMSG_FIRSTHDR(rmsg); scmsg != NULL; scmsg = CMSG_NXTHDR(rmsg, scmsg)) {
        rdata = (sctp_cmsg_data_t *)CMSG_DATA(scmsg);
        mst_dump_ctrlmsg(scmsg->cmsg_type, rdata);
    }

    if (!nm) {
        return rv;
    }

    return 0;
}

int
mst_print_sctp_paddrinfo(struct sctp_paddrinfo *sstat_primary)
{
    return 0;

    fprintf(stderr, "Spi assoc id: %d, ", sstat_primary->spinfo_assoc_id);
    fprintf(stderr, "Spi state: %d, ", sstat_primary->spinfo_state);
    fprintf(stderr, "Spi cwnd: %d, ", sstat_primary->spinfo_cwnd);
    fprintf(stderr, "Spi srtt: %d, ", sstat_primary->spinfo_srtt);
    fprintf(stderr, "Spi rto: %d, ", sstat_primary->spinfo_rto);
    fprintf(stderr, "Spi mtu: %d\n", sstat_primary->spinfo_mtu);

    return 0;
}

int
mst_calculate_tput(mst_nw_peer_t *pmnp)
{
    unsigned time_delta = 0;
    
    time_delta = (pmnp->mst_cs.rx_time - pmnp->mst_cs.last_rx_time);

    if (time_delta) {
        *(pmnp->mst_cs.rx_bw) = (*(pmnp->mst_cs.bytes_in) - pmnp->mst_cs.last_bytes_in)/time_delta;
        *(pmnp->mst_cs.rx_bw) *= 8; // in bits
        pmnp->mst_cs.last_bytes_in = *(pmnp->mst_cs.bytes_in);
        pmnp->mst_cs.last_rx_time = pmnp->mst_cs.rx_time;
    }
    else if (!(*(pmnp->mst_cs.bytes_in) - pmnp->mst_cs.last_bytes_in)) {
        *(pmnp->mst_cs.rx_bw) = 0;
    }
    time_delta = (pmnp->mst_cs.tx_time - pmnp->mst_cs.last_tx_time);

    if (time_delta) {
        *(pmnp->mst_cs.tx_bw) = (*(pmnp->mst_cs.bytes_out) - pmnp->mst_cs.last_bytes_out)/time_delta;
        *(pmnp->mst_cs.tx_bw) *= 8; // in bits
        pmnp->mst_cs.last_bytes_out = *(pmnp->mst_cs.bytes_out);
        pmnp->mst_cs.last_tx_time = pmnp->mst_cs.tx_time;
    }
    else if (!(*(pmnp->mst_cs.bytes_out) - pmnp->mst_cs.last_bytes_out)) {
        *(pmnp->mst_cs.tx_bw) = 0;
    }

    return;
}

typedef struct mst_pkts_watermark {
    int min;
    int max;
} mst_pkts_wm_t;

#define D_LINK_COLOR_CNT 3 // Red, Yellow, Green

// Link congestion matrix
typedef struct mst_link_cmtx {
    int srtt;
    mst_pkts_wm_t link_wm[D_LINK_COLOR_CNT];
} mst_link_cmtx_t;

mst_link_cmtx_t link_mtx[] = {
    //srtt, Green, Yellow, Red
    {100, {0, 15, 16, 30, 31, -1}},
    {300, {0, 30, 31, 50, 51, -1}},
    {700, {0, 70, 71, 100, 101, -1}},
    {1000, {0, 100, 101, 150, 151, -1}},
    {-1},
};

int
mst_color_link(int srtt, int unack_cnt)
{
    int index = 0;
    int y = 0;

    for(index = 0; link_mtx[index].srtt != -1; index++) {
        if (srtt <= link_mtx[index].srtt) {
            for (y = 0; y < D_LINK_COLOR_CNT; y++) {
                if ((unack_cnt >= link_mtx[index].link_wm[y].min) && (unack_cnt <= link_mtx[index].link_wm[y].max)) {
                    switch(y) {
                        case 0:
                            return MST_LINK_GREEN;
                        case 1:
                            return MST_LINK_YELLOW;
                        case 2:
                        default:
                            return MST_LINK_RED;
                    }
                }
            }
        }
    }

    // Larger RTT cases
    fprintf(stderr, "Large RTT %d\n", srtt);

    for (y = 0; y < D_LINK_COLOR_CNT; y++) {
        if ((unack_cnt >= link_mtx[index - 1].link_wm[y].min) && (unack_cnt <= link_mtx[index - 1].link_wm[y].max)) {
            switch(y) {
                case 0:
                    return MST_LINK_GREEN;
                case 1:
                    return MST_LINK_YELLOW;
                case 2:
                default:
                    return MST_LINK_RED;
            }
        }
    }

    return MST_LINK_RED;
}

inline int
max(int a, int b) {
    return (a >= b)?a:b;
}

inline int
min(int a, int b) {
    return (a <= b)?a:b;
}

int 
mst_compute_congestion(mst_nw_peer_t *pmnp, struct sctp_status *ls)
{
    if (!(pmnp->mst_cs.curr_sample_cnt % pmnp->mst_cs.sample_cnt)) {
        mst_link_color_t link_color = MST_LINK_YELLOW;

        pmnp->mst_cs.curr_sample_cnt = 0;
        *(pmnp->mst_cs.avg_srtt) /= pmnp->mst_cs.sample_cnt;

        link_color = mst_color_link(*(pmnp->mst_cs.avg_srtt), *(pmnp->mst_cs.unack_cnt));
        if (MST_LINK_GREEN == link_color) {
            *(pmnp->mst_cs.snd_cnt) = max((*(pmnp->mst_cs.snd_cnt))/2, pmnp->mst_cs.min_snd_cnt);
        }
        else if ((MST_LINK_YELLOW == link_color) && (MST_LINK_RED != pmnp->mst_cs.link_color)) {
            *(pmnp->mst_cs.snd_cnt) = min((*(pmnp->mst_cs.snd_cnt))*2, pmnp->mst_cs.max_snd_cnt);
        }
        else if (MST_LINK_YELLOW == link_color) {
            *(pmnp->mst_cs.snd_cnt) = pmnp->mst_cs.max_snd_cnt;
        }
        else {
            *(pmnp->mst_cs.snd_cnt) = 1;;
        }
        pmnp->mst_cs.link_color = link_color;

        *(pmnp->mst_cs.unack_cnt) = 0;
        *(pmnp->mst_cs.pending_cnt) = 0;
    }
    else {
        *(pmnp->mst_cs.avg_srtt) += ls->sstat_primary.spinfo_srtt;
    }
    if (ls->sstat_primary.spinfo_srtt < *(pmnp->mst_cs.min_srtt)) {
        *(pmnp->mst_cs.min_srtt) = ls->sstat_primary.spinfo_srtt;
    }
    if (!(*(pmnp->mst_cs.min_srtt))) {
        *(pmnp->mst_cs.min_srtt) = ls->sstat_primary.spinfo_srtt;
    }
    if (ls->sstat_primary.spinfo_srtt > *(pmnp->mst_cs.max_srtt)) {
        *(pmnp->mst_cs.max_srtt) = ls->sstat_primary.spinfo_srtt;
    }

    *(pmnp->mst_cs.srtt) = ls->sstat_primary.spinfo_srtt;
    *(pmnp->mst_cs.unack_cnt) += ls->sstat_unackdata;
    *(pmnp->mst_cs.pending_cnt) += ls->sstat_penddata;

    return 0;
}

int
mst_link_status(mst_nw_peer_t *pmnp)
{
    struct sctp_status link_status;
    mst_csi_t *mst_tuple;
    socklen_t optlen = sizeof(struct sctp_status);

    if (D_MNP_STATE_ESTABLISHED != M_MNP_STATE(pmnp->mnp_flags)) {
        fprintf(stderr, "pmnp[%p] state is not D_MNP_STATE_ESTABLISHED\n", pmnp);
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }

    M_MNP_REF_UP(pmnp);

    if (getsockopt(pmnp->mst_fd, IPPROTO_SCTP, SCTP_STATUS, &link_status, &optlen) < 0) {
        fprintf(stderr, "Getsockopt failed: %s for fd: %d\n", strerror(errno), pmnp->mst_fd);
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }

    mst_tuple = pmnp->mst_mt;
#if 0
    fprintf(stderr, "Link status for fd: %d, ", pmnp->mst_fd);
    fprintf(stderr, "Assoc ID: %d, ", link_status.sstat_assoc_id);
    fprintf(stderr, "State: %d, ", link_status.sstat_state);
    fprintf(stderr, "Rwnd: %d, ", link_status.sstat_rwnd);
    fprintf(stderr, "Unackdata: %d, ", link_status.sstat_unackdata);
    fprintf(stderr, "Pend data: %d, ", link_status.sstat_penddata);
    fprintf(stderr, "InStrms: %d, ", link_status.sstat_instrms);
    fprintf(stderr, "OutStrms: %d, ", link_status.sstat_outstrms);
    fprintf(stderr, "FragPoint: %d, ", link_status.sstat_fragmentation_point);
#endif

    mst_print_sctp_paddrinfo(&link_status.sstat_primary);


    pmnp->mst_cs.curr_sample_cnt++;
    mst_calculate_tput(pmnp);
    mst_compute_congestion(pmnp, &link_status);

    M_MNP_REF_DOWN_AND_FREE(pmnp);

    return 0;
}

mst_nw_peer_t *mst_get_next_fd(int nw_id)
{
    mst_nw_conn_t *nw_conn = mst_mnp_by_nw_id(nw_id);
    mst_nw_peer_t *pmnp;
    mst_nw_peer_t *curr_pmnp;
    int curr_slot = 0;
    int index = 0;
    int curr_pkts = 0;
    int avbl_link = 0;

    if (!nw_conn) {
        fprintf(stderr, "[WARNING] No NW-CONN available for nw id 0x%X\n", nw_id);
        return NULL;
    }
    curr_slot = nw_conn->curr_slot;
    curr_pmnp = (mst_nw_peer_t *)(nw_conn->mnp_slots[curr_slot].mnp_id);

    curr_slot = (curr_slot + 1)%D_NW_TOT_LINKS;
    
    for (index = 0; index < D_NW_TOT_LINKS; index++) {
        if (!nw_conn->mnp_slots[curr_slot].slot_available) {
            pmnp = (mst_nw_peer_t *)(nw_conn->mnp_slots[curr_slot].mnp_id);
            avbl_link++;
            if (MST_LINK_RED != pmnp->mst_cs.link_color) {
                nw_conn->curr_slot = curr_slot;
                pthread_mutex_unlock(&nw_conn->n_lock); // lock was acquired by mst_mnp_by_nw_id()
                return pmnp;
            }
        }

        //fprintf(stderr, "Moving from slot %d to next\n", curr_slot);
        curr_slot = (curr_slot + 1)%D_NW_TOT_LINKS;
    }
        
    pthread_mutex_unlock(&nw_conn->n_lock); // lock was acquired by mst_mnp_by_nw_id()

    fprintf(stderr, "Returning curr pmnp\n");
    
    return curr_pmnp;
}
