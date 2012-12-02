#ifndef __MST_TIMER_H__
#define __MST_TIMER_H__

#define mtb mst_timer_base
extern mst_timer_t mst_timer_base;
extern void mst_timer(evutil_socket_t fd, short event, void *arg);
extern int mst_timer_init(void);

#endif // !__MST_TIMER_H__
