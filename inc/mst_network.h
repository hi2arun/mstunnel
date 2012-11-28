#ifndef __MST_NETWORK_H__
#define __MST_NETWORK_H__

#if 0 // Use native sctp_cmsg_data_t instead of this
typedef union {
    struct sctp_initmsg init;
    struct sctp_sndrcvinfo sndrcvinfo;
} _sctp_cmsg_data_t;
#endif


extern int mst_setup_network(int mode, char *ipaddr, unsigned short port);
extern int mst_loop_network(int mode);

#endif //!__MST_NETWORK_H__
