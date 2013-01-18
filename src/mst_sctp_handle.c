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

    pmnp->mst_nwp.link_nice = (link_status.sstat_primary.spinfo_srtt)?((float)1.0/link_status.sstat_primary.spinfo_srtt):1.0;
    pmnp->mst_nwp.link_nice += (link_status.sstat_unackdata)?((float)1/link_status.sstat_unackdata):1.0;
    pmnp->mst_nwp.link_nice += (link_status.sstat_penddata)?((float)1/link_status.sstat_penddata):1.0;

    if (0 == atomic_read(&pmnp->mst_nwp.xmit_curr_pkts)) 
    {
        atomic_set(&pmnp->mst_nwp.xmit_max_pkts, (int)(pmnp->mst_nwp.link_nice * pmnp->mst_nwp.xmit_factor));
        atomic_set(&pmnp->mst_nwp.xmit_curr_pkts, atomic_read(&pmnp->mst_nwp.xmit_max_pkts));
    }

    pmnp->mst_nwp.xmit_curr_stream = (pmnp->mst_nwp.xmit_curr_stream + 1) % pmnp->num_ostreams;
    //mst_tuple->nw_parms.xmit_curr_stream = 0;

    //fprintf(stderr, "Unackdata: %f, ", (link_status.sstat_unackdata)?1/(link_status.sstat_unackdata):0.0);
    //fprintf(stderr, "Pend data: %f, ", (link_status.sstat_penddata)?1/(link_status.sstat_penddata):0.0);
    //fprintf(stderr, "[%p] Link nice: %f, xmit_max_pkts: %d\n", pmnp, pmnp->mst_nwp.link_nice, atomic_read(&pmnp->mst_nwp.xmit_max_pkts));
    
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

    for (index = 0; index < D_NW_TOT_LINKS; index++) {
        if (!nw_conn->mnp_slots[curr_slot].slot_available) {
            pmnp = (mst_nw_peer_t *)(nw_conn->mnp_slots[curr_slot].mnp_id);
            curr_pkts = atomic_read(&pmnp->mst_nwp.xmit_curr_pkts);
            avbl_link++;
            if (curr_pkts) {
                atomic_dec(&pmnp->mst_nwp.xmit_curr_pkts);
                nw_conn->curr_slot = curr_slot;
                pthread_mutex_unlock(&nw_conn->n_lock); // lock was acquired by mst_mnp_by_nw_id()
                return pmnp;
            }
        }

        //fprintf(stderr, "Moving from slot %d to next\n", curr_slot);
        curr_slot = (curr_slot + 1)%D_NW_TOT_LINKS;
    }
        
    pthread_mutex_unlock(&nw_conn->n_lock); // lock was acquired by mst_mnp_by_nw_id()
    if (avbl_link > 1) {
        fprintf(stderr, "[WARNING] exit No NW-CONN available for nw id 0x%X\n", nw_id);
    }
    else {
        return curr_pmnp;
    }
    return NULL;
}
