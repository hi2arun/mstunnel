#ifndef __MST_CONSTANTS_H__
#define __MST_CONSTANTS_H__

#define MST_SERVER_PORT 11100

#define MST_CLIENT_PORT_BASE 10100

typedef enum {
    MST_MAX_STREAMS = 0xffff,
    // Default Active output streams
    MST_DEF_ACT_OSTREAMS = 256,
    // Default Redundant output streams
    MST_DEF_RED_OSTREAMS = 256,
    MST_DEF_ISTREAMS = MST_MAX_STREAMS
} mst_streams_cnt_t;

#endif //!__MST_CONSTANTS_H__