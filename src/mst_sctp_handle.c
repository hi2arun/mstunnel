#include <glib.h>
#include "mstunnel.h"
#include "mst_network.h"
#include "memmgmt.h"

int
mst_process_ac(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    struct iovec *msg_iov = NULL;
    union sctp_notification *snp = NULL;
    struct sctp_assoc_change *sac;

    fprintf(stderr, "ENTRY: %s()\n", __func__);
    msg_iov = rmsg->msg_iov;
    // Notification should be in the first vector
    snp = (union sctp_notification *)msg_iov->iov_base;
    sac = &snp->sn_assoc_change;

    switch(sac->sac_state) {
        // Comm UP
        case 0:
            fprintf(stderr, "COMM_UP - Setting up tunnel\n");
            mst_setup_tunnel(pmnp);
            break;
        // Comm RESTART
        case 2:
            fprintf(stderr, "COMM_RESTART\n");
            break;
        // Shutdown COMPLETE
        case 3:
            fprintf(stderr, "SHUTDOWN_COMPLETE\n");
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
    fprintf(stderr, "ENTRY: %s()\n", __func__);
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
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    return 0;
}


int
mst_process_notification(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen) 
{
    union sctp_notification *snp = NULL;
    struct iovec *msg_iov = NULL;

    fprintf(stderr, "ENTRY: %s()\n", __func__);
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
mst_process_data(mst_nw_peer_t *pmnp, struct msghdr *rmsg, int rlen)
{
    fprintf(stderr, "ENTRY: %s()\n", __func__);
    mst_do_tunn_write(pmnp, rlen);
    return 0;
}

int 
mst_dump_ctrlmsg(int type, sctp_cmsg_data_t *rdata)
{
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

    if (!rlen || (rlen < 0)) {
        fprintf(stderr, "No data. Nothing to dump\n");
    }

    // Check if it is notification message or data

    if (MSG_NOTIFICATION & rmsg->msg_flags) {
        mst_process_notification(pmnp, rmsg, rlen);
    }
    else {
        mst_process_data(pmnp, rmsg, rlen);
    }

    for(scmsg = CMSG_FIRSTHDR(rmsg); scmsg != NULL; scmsg = CMSG_NXTHDR(rmsg, scmsg)) {
        rdata = (sctp_cmsg_data_t *)CMSG_DATA(scmsg);
        mst_dump_ctrlmsg(scmsg->cmsg_type, rdata);
    }

    return 0;
}

int
mst_print_sctp_paddrinfo(struct sctp_paddrinfo *sstat_primary)
{
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

    M_MNP_REF_UP(pmnp);

    if (getsockopt(pmnp->mst_fd, IPPROTO_SCTP, SCTP_STATUS, &link_status, &optlen) < 0) {
        fprintf(stderr, "Getsockopt failed: %s for fd: %d\n", strerror(errno), pmnp->mst_fd);
        M_MNP_REF_DOWN_AND_FREE(pmnp);
        return -1;
    }

    mst_tuple = pmnp->mst_mt;
    fprintf(stderr, "Link status for fd: %d, ", pmnp->mst_fd);
    fprintf(stderr, "Assoc ID: %d, ", link_status.sstat_assoc_id);
    fprintf(stderr, "State: %d, ", link_status.sstat_state);
    fprintf(stderr, "Rwnd: %d, ", link_status.sstat_rwnd);
    fprintf(stderr, "Unackdata: %d, ", link_status.sstat_unackdata);
    fprintf(stderr, "Pend data: %d, ", link_status.sstat_penddata);
    fprintf(stderr, "InStrms: %d, ", link_status.sstat_instrms);
    fprintf(stderr, "OutStrms: %d, ", link_status.sstat_outstrms);
    fprintf(stderr, "FragPoint: %d, ", link_status.sstat_fragmentation_point);

    mst_print_sctp_paddrinfo(&link_status.sstat_primary);

    mst_tuple->nw_parms.link_nice = (link_status.sstat_primary.spinfo_srtt)?((float)1.0/link_status.sstat_primary.spinfo_srtt):1.0;
    mst_tuple->nw_parms.xmit_max_pkts = (int)(mst_tuple->nw_parms.link_nice * mst_tuple->nw_parms.xmit_factor);

    mst_tuple->nw_parms.xmit_curr_stream = (mst_tuple->nw_parms.xmit_curr_stream + 1) % mst_tuple->nw_parms.num_ostreams;

    fprintf(stderr, "Link nice: %f, xmit_max_pkts: %d\n", mst_tuple->nw_parms.link_nice, mst_tuple->nw_parms.xmit_max_pkts);
    
    M_MNP_REF_DOWN_AND_FREE(pmnp);

    return 0;
}
