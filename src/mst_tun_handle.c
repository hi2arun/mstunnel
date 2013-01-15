#include "mstunnel.h"
#include "mst_network.h"
#include "mst_tun.h"
#include "memmgmt.h"

mst_dev_mngr_t g_mdm;

#define D_TUN_DEV "/dev/net/tun"

extern mst_event_base_t meb;

int mst_tun_init(void)
{
    // server
    if(mst_global_opts.mst_config.mst_mode) {
        g_mdm.dev_prefix = "msts";
    }
    else {
        g_mdm.dev_prefix = "mstc";
    }

    pthread_mutex_init(&g_mdm.mdm_mutex, NULL);

    return 0;
}

int mst_tun_dev_name_rel(void)
{
    pthread_mutex_lock(&g_mdm.mdm_mutex);
    g_mdm.dev_count -= 1;
    // This can't go negative
    assert(g_mdm.dev_count >= 0);
    pthread_mutex_unlock(&g_mdm.mdm_mutex);
    return 0;
}

int mst_tun_dev_name(char *dev_name, int name_size)
{
    int rv = -1;

    pthread_mutex_lock(&g_mdm.mdm_mutex);
    if(mst_global_opts.mst_config.mst_mode) {
        if (g_mdm.dev_count >= D_MAX_PEER_CNT) {
            fprintf(stderr, "Tun limit reached\n");
            goto ret_here;
        }
        snprintf(dev_name, name_size, "%s%d", g_mdm.dev_prefix, ++g_mdm.dev_count);
        rv = 0;
    }
    else {
        if (g_mdm.dev_count >= D_MAX_CONNECT_CNT) {
            fprintf(stderr, "Tun limit reached\n");
            goto ret_here;
        }
        snprintf(dev_name, name_size, "%s%d", g_mdm.dev_prefix, ++g_mdm.dev_count);
        rv = 0;
    }

ret_here:
    pthread_mutex_unlock(&g_mdm.mdm_mutex);

    return rv;
}

int mst_tun_open(char *dev_name)
{
    struct ifreq ifr;
    int tun_fd;
    int rv = -1;
    int dummy_fd = socket(AF_INET, SOCK_DGRAM, 0);

    assert(dummy_fd > 0);

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
    //ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    strncpy(ifr.ifr_name, dev_name, sizeof(ifr.ifr_name));

    tun_fd = open(D_TUN_DEV, O_RDWR);

    assert(tun_fd > 0);

    rv = ioctl(tun_fd, TUNSETIFF, (void *)&ifr);
    assert(rv >= 0);
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev_name, sizeof(ifr.ifr_name));
    ifr.ifr_flags = IFF_UP;
    rv = ioctl(dummy_fd, SIOCSIFFLAGS, (void *)&ifr);
    assert(rv >= 0);
    close(dummy_fd);

    fprintf(stderr, "Created interface '%s' successfully\n", dev_name);

    return tun_fd;
}
