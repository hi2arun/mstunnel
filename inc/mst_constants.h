#ifndef __MST_CONSTANTS_H__
#define __MST_CONSTANTS_H__

#define MST_SERVER_PORT 11100

#define MST_CLIENT_PORT_BASE 10100

#define D_MST_READ_SIZE 2048 // will ask for 2K buffer

#define D_SRV_BACKLOG 100
#define D_MAX_LISTEN_CNT 2
#define D_MAX_CONNECT_CNT 2
#define D_MAX_PEER_CNT 1024

typedef enum {
    MST_MAX_STREAMS = 0xffff,
    // Default Active output streams
    MST_DEF_ACT_OSTREAMS = 256,
    // Default Redundant output streams
    MST_DEF_RED_OSTREAMS = 256,
    MST_DEF_ISTREAMS = MST_MAX_STREAMS
} mst_streams_cnt_t;

#endif //!__MST_CONSTANTS_H__
