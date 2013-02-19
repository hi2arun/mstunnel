#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <assert.h>

typedef unsigned __be32;
typedef unsigned short __be16;

// udp-epoll support - begin
struct udp_peer_info {
    __be32 sip;
    __be32 dip;
    __be16  sport;
    __be16  dport;
};
#define UDP_ADD_PEER_INFO   500 /* Add new UDP socket to UDP connected table */
#define UDP_DEL_PEER_INFO   501 /* Del UDP socket from UDP connected table */
// udp-epoll support - end

#define M_NIPQUAD(x) (unsigned char)(((char *)&(x))[0]), \
    (unsigned char)(((char *)&(x))[1]), \
    (unsigned char)(((char *)&(x))[2]), \
    (unsigned char)(((char *)&(x))[3])

#define D_IP_FMT "%u.%u.%u.%u"

int main(int argc, char **argv)
{
    int sd = -1;
    struct sockaddr_in udps;
    struct sockaddr_in udpc;
    char tbuf[512] = {"test buffer\n"};
    char tbuf_r[512] = {"test buffer - reply\n"};
    int rv = -1;
    int csd = -1;
    int slen = sizeof(udpc);
    struct udp_peer_info upi;

    memset(&udps, 0, sizeof(udps));
    udps.sin_family = AF_INET;
    udps.sin_addr.s_addr = inet_addr("14.1.1.2");
    udps.sin_port = htons(10000);

    memset(&udpc, 0, sizeof(udpc));


    sd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sd > 0);

    rv = bind(sd, (struct sockaddr *)&udps, sizeof(udps));

    if (rv < 0) {
        fprintf(stderr, "Bind error: %s\n", strerror(errno));
        return -1;
    }

do_again:
    rv = recvfrom(sd, tbuf, sizeof(tbuf), 0, (struct sockaddr *)&udpc, &slen);

    //fprintf(stderr, "Got '%d' bytes from "D_IP_FMT":%hu\n", rv, M_NIPQUAD(udpc.sin_addr.s_addr), ntohs(udpc.sin_port));

    memset(&upi, 0, sizeof(upi));

    upi.sip = udps.sin_addr.s_addr;
    upi.sport = udps.sin_port;
    upi.dip = udpc.sin_addr.s_addr;
    upi.dport = udpc.sin_port;
    csd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(csd > 0);
    //fprintf(stderr, "Created new socket '%d' for client\n", csd);

    rv = setsockopt(csd, SOL_UDP, UDP_ADD_PEER_INFO, (char *)&upi, sizeof(upi));
    fprintf(stderr, "UDP_ADD_PEER_INFO status: %d: %s\n", rv, strerror(errno));
    assert(!rv);

    rv = sendto(csd, tbuf_r, sizeof(tbuf_r), 0, (struct sockaddr *)&udpc, sizeof(udpc));
    fprintf(stderr, "Sent '%d' bytes to server on csd: %d\n", rv, csd);

    memset(&udpc, 0, slen);
    memset(tbuf_r, 0, sizeof(tbuf_r));
#if 1
    fprintf(stderr, "Waiting for a message...\n");
    rv = recvfrom(csd, tbuf_r, sizeof(tbuf_r), 0, (struct sockaddr *)&udpc, &slen);
    if (rv) {
        tbuf_r[rv] = '\0';
    }
    fprintf(stderr, "Read '%d' bytes '%s' on csd: %d\n", rv, tbuf_r, csd);
#endif
    //sleep(1);
    rv = setsockopt(csd, SOL_UDP, UDP_DEL_PEER_INFO, (char *)&upi, sizeof(upi));
    //fprintf(stderr, "UDP_DEL_PEER_INFO status: %d: %s\n", rv, strerror(errno));

    close(csd);

    goto do_again;

    return 0;
}
