#ifndef __MST_NETWORK_H__
#define __MST_NETWORK_H__

#if 0 // Use native sctp_cmsg_data_t instead of this
typedef union {
    struct sctp_initmsg init;
    struct sctp_sndrcvinfo sndrcvinfo;
} _sctp_cmsg_data_t;
#endif


extern int mst_setup_network(void);
extern int mst_loop_network(void);

#endif //!__MST_NETWORK_H__
