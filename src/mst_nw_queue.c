#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"

TAILQ_HEAD(mst_nw_queue, mst_nw_q) mnq_head;
pthread_mutex_t mst_q_lock;
pthread_cond_t mst_q_cond;

TAILQ_HEAD(mst_tun_queue, mst_nw_q) tunq_head;
pthread_mutex_t mst_tq_lock;
pthread_cond_t mst_tq_cond;

TAILQ_HEAD(mst_epoll_queue, mst_nw_q) epollq_head;
pthread_mutex_t mst_eq_lock;

mst_nw_q_t *mst_tun_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    fprintf(stderr, "Insert deTQ lock\n");
    pthread_mutex_lock(&mst_tq_lock);
    qelm = TAILQ_LAST(&tunq_head, mst_tun_queue);
    if (qelm) {
        TAILQ_REMOVE(&tunq_head, qelm, q_field);
    }
    pthread_mutex_unlock(&mst_tq_lock);
    fprintf(stderr, "Release deTQ lock: %p\n", qelm);

    return qelm;
}

mst_nw_q_t *mst_nw_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    fprintf(stderr, "Insert deQ lock\n");
    pthread_mutex_lock(&mst_q_lock);
    qelm = TAILQ_LAST(&mnq_head, mst_nw_queue);
    if (qelm) {
        TAILQ_REMOVE(&mnq_head, qelm, q_field);
    }
    pthread_mutex_unlock(&mst_q_lock);
    fprintf(stderr, "Release deQ lock: %p\n", qelm);

    return qelm;
}

mst_nw_q_t *mst_epoll_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    qelm = TAILQ_LAST(&epollq_head, mst_epoll_queue);
    if (qelm) {
        TAILQ_REMOVE(&epollq_head, qelm, q_field);
    }
    return qelm;
}

int mst_insert_tun_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = __mst_malloc(sizeof(mst_nw_q_t));
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    fprintf(stderr, "Insert TQ lock\n");
    pthread_mutex_lock(&mst_tq_lock);
    TAILQ_INSERT_HEAD(&tunq_head, qelm, q_field);
    pthread_cond_signal(&mst_tq_cond);
    pthread_mutex_unlock(&mst_tq_lock);
    fprintf(stderr, "Release TQ lock\n");

    return 0;
}

int mst_insert_nw_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = __mst_malloc(sizeof(mst_nw_q_t));
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    fprintf(stderr, "Insert Q lock\n");
    pthread_mutex_lock(&mst_q_lock);
    TAILQ_INSERT_HEAD(&mnq_head, qelm, q_field);
    pthread_cond_signal(&mst_q_cond);
    pthread_mutex_unlock(&mst_q_lock);
    fprintf(stderr, "Release Q lock\n");

    return 0;
}

int mst_insert_epoll_queue(mst_nw_q_t *qelm)
{
    assert(qelm);
    
    pthread_mutex_lock(&mst_eq_lock);
    TAILQ_INSERT_HEAD(&epollq_head, qelm, q_field);
    pthread_mutex_unlock(&mst_eq_lock);

    return 0;
}

void *mst_loop_tun_queue(void *arg)
{
    mst_nw_q_t *qelm = NULL;

    while (1) {
        qelm = mst_tun_dequeue_tail();
        if (!qelm) {
            fprintf(stderr, "Waiting for Tqelm\n");
            pthread_mutex_lock(&mst_tq_lock);
            fprintf(stderr, "Waiting for Tqelm - condWAIT\n");
            pthread_cond_wait(&mst_tq_cond, &mst_tq_lock);
            pthread_mutex_unlock(&mst_tq_lock);
            continue;
        }

        fprintf(stderr, "Dequeued %p\n", qelm);

        fprintf(stderr, "%s:%d: lock\n", __FILE__, __LINE__);
        pthread_mutex_lock(&qelm->pmnp->mst_cl);
        mst_do_tun_read(qelm->pmnp);
        pthread_mutex_unlock(&qelm->pmnp->mst_cl);
        fprintf(stderr, "%s:%d: unlock\n", __FILE__, __LINE__);

        mst_insert_epoll_queue(qelm);
    }

}

void *mst_loop_nw_queue(void *arg)
{
    mst_nw_q_t *qelm = NULL;

    while (1) {
        qelm = mst_nw_dequeue_tail();
        if (!qelm) {
            fprintf(stderr, "Waiting for qelm\n");
            pthread_mutex_lock(&mst_q_lock);
            fprintf(stderr, "Waiting for qelm - condWAIT\n");
            pthread_cond_wait(&mst_q_cond, &mst_q_lock);
            pthread_mutex_unlock(&mst_q_lock);
            continue;
        }

        fprintf(stderr, "Dequeued %p\n", qelm);

        fprintf(stderr, "%s:%d: lock\n", __FILE__, __LINE__);
        pthread_mutex_lock(&qelm->pmnp->mst_cl);
        mst_do_nw_read(qelm->pmnp);
        pthread_mutex_unlock(&qelm->pmnp->mst_cl);
        fprintf(stderr, "%s:%d: unlock\n", __FILE__, __LINE__);

        mst_insert_epoll_queue(qelm);
    }

}

int mst_init_nw_queue(void)
{
    int index;
    pthread_t pt_nw_queue[5];

    TAILQ_INIT(&mnq_head);
    pthread_mutex_init(&mst_q_lock, NULL);
    pthread_cond_init(&mst_q_cond, NULL);

    for (index = 0; index < 5; index++) {
        pthread_create(&pt_nw_queue[index], NULL, mst_loop_nw_queue, NULL);
    }
    return 0;
}

int mst_init_tun_queue(void)
{
    int index;
    pthread_t pt_tun_queue[5];

    TAILQ_INIT(&tunq_head);
    pthread_mutex_init(&mst_tq_lock, NULL);
    pthread_cond_init(&mst_tq_cond, NULL);

    for (index = 0; index < 5; index++) {
        pthread_create(&pt_tun_queue[index], NULL, mst_loop_tun_queue, NULL);
    }
    return 0;
}

int mst_init_epoll_queue(void)
{
    TAILQ_INIT(&epollq_head);
    pthread_mutex_init(&mst_eq_lock, NULL);
    return 0;
}
 
