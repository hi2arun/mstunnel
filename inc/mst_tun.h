#ifndef __MST_TUNNEL_H__
#define __MST_TUNNEL_H__

typedef struct mst_dev_mngr {
    // mstc - mst_client
    // msts - mst_server
    char *dev_prefix;
    int dev_count;
    pthread_mutex_t mdm_mutex;
} mst_dev_mngr_t;

extern mst_dev_mngr_t g_mdm;

extern int mst_tun_open(char *);
extern int mst_tun_dev_name(char *, int name_size);
extern int mst_tun_dev_name_rel(void);
extern int mst_tun_init(void);

#endif //!__MST_TUNNEL_H__
