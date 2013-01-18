#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"

extern mst_event_base_t meb;

TAILQ_HEAD(mst_nw_queue, mst_nw_q) nw_rq_head;
pthread_mutex_t nw_rq_lock;
pthread_cond_t nw_rq_cond;

struct mst_nw_queue nw_wq_head;
pthread_mutex_t nw_wq_lock;
pthread_cond_t nw_wq_cond;

TAILQ_HEAD(mst_tun_queue, mst_nw_q) tun_rq_head;
pthread_mutex_t tun_rq_lock;
pthread_cond_t tun_rq_cond;

struct mst_tun_queue tun_wq_head;
pthread_mutex_t tun_wq_lock;
pthread_cond_t tun_wq_cond;

TAILQ_HEAD(mst_epoll_queue, mst_nw_q) epollq_head;
pthread_mutex_t mst_eq_lock;
pthread_cond_t mst_eq_cond;

#define D_COND_WAIT_TO 5
#define D_COND_WAIT_W_TO 1

atomic_t tun_in, tun_out;
atomic_t nw_in, nw_out;

mst_nw_q_t *mst_tun_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    //fprintf(stderr, "Insert deTQ lock\n");
    //pthread_mutex_lock(&tun_rq_lock);
    qelm = TAILQ_LAST(&tun_rq_head, mst_tun_queue);
    if (qelm) {
        TAILQ_REMOVE(&tun_rq_head, qelm, q_field);
    }
    //pthread_mutex_unlock(&tun_rq_lock);
    //fprintf(stderr, "Release deTQ lock: %p\n", qelm);

    return qelm;
}

mst_nw_q_t *mst_tun_wq_tail(void)
{
    mst_nw_q_t *qelm;
    //pthread_mutex_lock(&tun_wq_lock);
    qelm = TAILQ_LAST(&tun_wq_head, mst_tun_queue);
    if (qelm) {
        TAILQ_REMOVE(&tun_wq_head, qelm, q_field);
    }
    //pthread_mutex_unlock(&tun_wq_lock);

    return qelm;
}

mst_nw_q_t *mst_nw_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    //fprintf(stderr, "Insert deQ lock\n");
    //pthread_mutex_lock(&nw_rq_lock);
    qelm = TAILQ_LAST(&nw_rq_head, mst_nw_queue);
    if (qelm) {
        TAILQ_REMOVE(&nw_rq_head, qelm, q_field);
    }
    //pthread_mutex_unlock(&nw_rq_lock);
    //fprintf(stderr, "Release deQ lock: %p\n", qelm);

    return qelm;
}

mst_nw_q_t *mst_nw_wq_tail(void)
{
    mst_nw_q_t *qelm;
    //pthread_mutex_lock(&nw_wq_lock);
    qelm = TAILQ_LAST(&nw_wq_head, mst_nw_queue);
    if (qelm) {
        TAILQ_REMOVE(&nw_wq_head, qelm, q_field);
    }
    //pthread_mutex_unlock(&nw_wq_lock);

    return qelm;
}

mst_nw_q_t *mst_epoll_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    pthread_mutex_lock(&mst_eq_lock);
    qelm = TAILQ_LAST(&epollq_head, mst_epoll_queue);
    if (qelm) {
        TAILQ_REMOVE(&epollq_head, qelm, q_field);
    }
    pthread_mutex_unlock(&mst_eq_lock);
    
    return qelm;
}

mst_buf_q_t *mst_mbuf_dequeue_tail(mst_nw_peer_t *pmnp)
{
    mst_buf_q_t *qelm;
    pthread_mutex_lock(&pmnp->ref_lock);
    qelm = TAILQ_LAST(&pmnp->mst_wq, mst_mbuf_q);
    if (qelm) {
        TAILQ_REMOVE(&pmnp->mst_wq, qelm, q_field);
    }
    pthread_mutex_unlock(&pmnp->ref_lock);

    return qelm;
}

int mst_insert_tun_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = mst_malloc(sizeof(mst_nw_q_t), __func__);
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    //fprintf(stderr, "Insert TQ lock\n");
    pthread_mutex_lock(&tun_rq_lock);
    TAILQ_INSERT_HEAD(&tun_rq_head, qelm, q_field);
    pthread_cond_signal(&tun_rq_cond);
    pthread_mutex_unlock(&tun_rq_lock);
    //fprintf(stderr, "Release TQ lock\n");
    atomic_inc(&tun_in);

    return 0;
}

int mst_insert_tun_wq(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = mst_malloc(sizeof(mst_nw_q_t), __func__);
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    pthread_mutex_lock(&tun_wq_lock);
    TAILQ_INSERT_HEAD(&tun_wq_head, qelm, q_field);
    pthread_cond_signal(&tun_wq_cond);
    pthread_mutex_unlock(&tun_wq_lock);

    return 0;
}

int mst_insert_mbuf_q(mst_nw_peer_t *pmnp, mst_buffer_t *mbuf, int len)
{
    mst_buf_q_t *qelm;

    if (-1 == pmnp->mst_fd) {
        return -1;
    }
    
    qelm = mst_malloc(sizeof(mst_buf_q_t), __func__);
    assert(qelm);
    memset(qelm, 0, sizeof(mst_buf_q_t));
    qelm->wlen = len;
    qelm->mbuf = mbuf;

    //fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);

    pthread_mutex_lock(&pmnp->ref_lock);
    TAILQ_INSERT_HEAD(&pmnp->mst_wq, qelm, q_field);
    mst_epoll_events (pmnp, EPOLL_CTL_MOD, (pmnp->mst_ef | EPOLLOUT));
    pmnp->mst_curr &= ~EPOLLOUT;
    pthread_mutex_unlock(&pmnp->ref_lock);

    return 0;
}

int mst_insert_nw_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = mst_malloc(sizeof(mst_nw_q_t), __func__);
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    //fprintf(stderr, "Insert Q lock\n");
    pthread_mutex_lock(&nw_rq_lock);
    TAILQ_INSERT_HEAD(&nw_rq_head, qelm, q_field);
    pthread_cond_signal(&nw_rq_cond);
    pthread_mutex_unlock(&nw_rq_lock);
    //fprintf(stderr, "Release Q lock\n");
    //
    atomic_inc(&nw_in);

    return 0;
}

int mst_insert_nw_wq(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = mst_malloc(sizeof(mst_nw_q_t), __func__);
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    pthread_mutex_lock(&nw_wq_lock);
    TAILQ_INSERT_HEAD(&nw_wq_head, qelm, q_field);
    pthread_cond_signal(&nw_wq_cond);
    pthread_mutex_unlock(&nw_wq_lock);

    return 0;
}

int mst_insert_epoll_queue(mst_nw_q_t *qelm)
{
    assert(qelm);

    if (-1 == qelm->pmnp->mst_fd) {
        return -1;
    }
    
    pthread_mutex_lock(&mst_eq_lock);
    TAILQ_INSERT_HEAD(&epollq_head, qelm, q_field);
    pthread_cond_signal(&mst_eq_cond);
    pthread_mutex_unlock(&mst_eq_lock);

    return 0;
}

void *mst_loop_tun_queue(void *arg)
{
    mst_nw_q_t *qelm = NULL;
    //struct timespec cond_wait_ts;

    while (1) {
        pthread_mutex_lock(&tun_rq_lock);
        qelm = mst_tun_dequeue_tail();
        if (!qelm) {
            //cond_wait_ts.tv_sec = time(NULL) + D_COND_WAIT_TO;
            //cond_wait_ts.tv_nsec = 0;
            pthread_cond_wait(&tun_rq_cond, &tun_rq_lock);
            //pthread_cond_timedwait(&tun_rq_cond, &tun_rq_lock, &cond_wait_ts);
            pthread_mutex_unlock(&tun_rq_lock);
            continue;
        }
        pthread_mutex_unlock(&tun_rq_lock);

        mst_do_tun_read(qelm->pmnp);
        M_MNP_REF_DOWN_AND_FREE(qelm->pmnp);
        
        if (-1 == mst_insert_epoll_queue(qelm)) {
            fprintf(stderr, "[TUN] Freeing qelm...\n");
            mst_free(qelm, __func__);
        }
        atomic_inc(&tun_out);
    }

}

void *mst_loop_tun_wq(void *arg)
{
    mst_nw_q_t *qelm = NULL;
    //struct timespec cond_wait_ts;

    while (1) {
        pthread_mutex_lock(&tun_wq_lock);
        qelm = mst_tun_wq_tail();
        if (!qelm) {
            //cond_wait_ts.tv_sec = time(NULL) + D_COND_WAIT_W_TO;
            //cond_wait_ts.tv_nsec = 0;
            pthread_cond_wait(&tun_wq_cond, &tun_wq_lock);
            //pthread_cond_timedwait(&tun_wq_cond, &tun_wq_lock, &cond_wait_ts);
            pthread_mutex_unlock(&tun_wq_lock);
            continue;
        }
        pthread_mutex_unlock(&tun_wq_lock);

        mst_tun_write(qelm->pmnp);
        //M_MNP_REF_DOWN_AND_FREE(qelm->pmnp);
        
        mst_free(qelm, __func__);
    }

}


void *mst_loop_nw_queue(void *arg)
{
    mst_nw_q_t *qelm = NULL;
    //struct timespec cond_wait_ts;

    while (1) {
        pthread_mutex_lock(&nw_rq_lock);
        qelm = mst_nw_dequeue_tail();
        if (!qelm) {
            //cond_wait_ts.tv_sec = time(NULL) + D_COND_WAIT_TO;
            //cond_wait_ts.tv_nsec = 0;
            pthread_cond_wait(&nw_rq_cond, &nw_rq_lock);
            //pthread_cond_timedwait(&nw_rq_cond, &nw_rq_lock, &cond_wait_ts);
            pthread_mutex_unlock(&nw_rq_lock);
            continue;
        }
        pthread_mutex_unlock(&nw_rq_lock);

        mst_do_nw_read(qelm->pmnp);
        M_MNP_REF_DOWN_AND_FREE(qelm->pmnp);

        if (-1 == mst_insert_epoll_queue(qelm)) {
            fprintf(stderr, "[NW] Freeing qelm...\n");
            mst_free(qelm, __func__);
        }
        atomic_inc(&nw_out);
    }
}

void *mst_loop_nw_wq(void *arg)
{
    mst_nw_q_t *qelm = NULL;
    //struct timespec cond_wait_ts;

    while (1) {
        pthread_mutex_lock(&nw_wq_lock);
        qelm = mst_nw_wq_tail();
        if (!qelm) {
            //cond_wait_ts.tv_sec = time(NULL) + D_COND_WAIT_W_TO;
            //cond_wait_ts.tv_nsec = 0;
            pthread_cond_wait(&nw_wq_cond, &nw_wq_lock);
            //pthread_cond_timedwait(&nw_wq_cond, &nw_wq_lock, &cond_wait_ts);
            pthread_mutex_unlock(&nw_wq_lock);
            continue;
        }
        pthread_mutex_unlock(&nw_wq_lock);

        mst_nw_write(qelm->pmnp);
        //M_MNP_REF_DOWN_AND_FREE(qelm->pmnp);
        mst_free(qelm, __func__);
    }
}

int mst_init_nw_queue(void)
{
    int index;
    pthread_t pt_nw_rq[5];
    pthread_t pt_nw_wq[5];

    TAILQ_INIT(&nw_rq_head);
    pthread_mutex_init(&nw_rq_lock, NULL);
    pthread_cond_init(&nw_rq_cond, NULL);

    for (index = 0; index < 1; index++) {
        pthread_create(&pt_nw_rq[index], NULL, mst_loop_nw_queue, NULL);
    }

    TAILQ_INIT(&nw_wq_head);
    pthread_mutex_init(&nw_wq_lock, NULL);
    pthread_cond_init(&nw_wq_cond, NULL);
    
    for (index = 0; index < 1; index++) {
        pthread_create(&pt_nw_wq[index], NULL, mst_loop_nw_wq, NULL);
    }
    
    return 0;
}

int mst_init_tun_queue(void)
{
    int index;
    pthread_t pt_tun_rq[5];
    pthread_t pt_tun_wq[5];

    TAILQ_INIT(&tun_rq_head);
    pthread_mutex_init(&tun_rq_lock, NULL);
    pthread_cond_init(&tun_rq_cond, NULL);

    for (index = 0; index < 1; index++) {
        pthread_create(&pt_tun_rq[index], NULL, mst_loop_tun_queue, NULL);
    }

    TAILQ_INIT(&tun_wq_head);
    pthread_mutex_init(&tun_wq_lock, NULL);
    pthread_cond_init(&tun_wq_cond, NULL);
    
    for (index = 0; index < 1; index++) {
        pthread_create(&pt_tun_wq[index], NULL, mst_loop_tun_wq, NULL);
    }

    return 0;
}

int mst_init_epoll_queue(void)
{
    TAILQ_INIT(&epollq_head);
    pthread_mutex_init(&mst_eq_lock, NULL);
    pthread_cond_init(&mst_eq_cond, NULL);
    return 0;
}
 
