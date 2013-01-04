#ifndef __MST_NETWORK_H__
#define __MST_NETWORK_H__

// MSB(16 bytes): Major version
// LSB(16 bytes): Minor version
#define D_NW_VERSION_1_0 0x00010000

typedef struct mst_nw_header {
    int nw_id;
    int nw_version;
} __attribute__((__packed__)) mst_nw_header_t;

extern int mst_setup_network(void);
extern int mst_loop_network(void);
extern int mst_setup_tunnel(mst_nw_peer_t *pmnp);
extern int mst_cleanup_mnp(mst_nw_peer_t *pmnp);
extern int mst_do_tun_read(mst_nw_peer_t *pmnp);
extern int mst_do_nw_read(mst_nw_peer_t *pmnp);
extern int mst_do_nw_write(mst_nw_peer_t *pmnp, mst_buffer_t *, int rlen);
extern int mst_do_tun_write(mst_nw_peer_t *pmnp, mst_buffer_t *, int rlen);
extern int mst_init_network(void);
extern inline void mst_epoll_events(mst_nw_peer_t *pmnp, int ev_cmd, int events);
extern void mst_nw_write(mst_nw_peer_t *pmnp);
extern void mst_tun_write(mst_nw_peer_t *pmnp);

#endif //!__MST_NETWORK_H__
