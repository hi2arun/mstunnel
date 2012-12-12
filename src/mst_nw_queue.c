#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"

TAILQ_HEAD(mst_nw_queue, mst_nw_q) mnq_head;
pthread_mutex_t mst_q_lock;
pthread_cond_t mst_q_cond;

mst_nw_q_t *mst_nw_dequeue_tail(void)
{
    mst_nw_q_t *qelm;
    pthread_mutex_lock(&mst_q_lock);
    qelm = TAILQ_LAST(&mnq_head, mst_nw_queue);
    TAILQ_REMOVE(&mnq_head, qelm, q_field);
    pthread_mutex_unlock(&mst_q_lock);

    return qelm;
}

int mst_insert_nw_queue(mst_nw_q_type_t q_type, mst_nw_peer_t *pmnp)
{
    mst_nw_q_t *qelm = __mst_malloc(sizeof(mst_nw_q_t));
    assert(qelm);
    memset(qelm, 0, sizeof(mst_nw_q_t));
    qelm->q_type = q_type;
    qelm->pmnp = pmnp;
    
    pthread_mutex_lock(&mst_q_lock);
    TAILQ_INSERT_HEAD(&mnq_head, qelm, q_field);
    pthread_cond_signal(&mst_q_cond);
    pthread_mutex_unlock(&mst_q_lock);

    return 0;
}

void *mst_loop_nw_queue(void *arg)
{
    mst_nw_q_t *qelm = NULL;

mst_wait:

    fprintf(stderr, "Waiting for qelm\n");
    pthread_mutex_lock(&mst_q_lock);
    pthread_cond_wait(&mst_q_cond, &mst_q_lock);
    pthread_mutex_unlock(&mst_q_lock);

    qelm = mst_nw_dequeue_tail();

    if (!qelm) {
        goto mst_wait;
    }
    fprintf(stderr, "Dequeued %p\n", qelm);

    switch(qelm->q_type) {
        case MST_SCTP_Q:
            mst_do_nw_read(qelm->pmnp);
            break;
        case MST_TUN_Q:
            mst_do_tun_read(qelm->pmnp);
            break;
        default:
            fprintf(stderr, "Unknown qelm->q_type\n");
    }

    __mst_free(qelm);
    goto mst_wait;

}

int mst_init_nw_queue(void)
{
    pthread_t pt_nw_queue;

    TAILQ_INIT(&mnq_head);
    pthread_mutex_init(&mst_q_lock, NULL);
    pthread_cond_init(&mst_q_cond, NULL);

    pthread_create(&pt_nw_queue, NULL, mst_loop_nw_queue, NULL);
    return 0;
}
    
