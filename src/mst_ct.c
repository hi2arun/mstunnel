#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"

mst_nw_conn_table_t mst_nw_ct[D_NW_CONN_TABLE_SIZE];

mst_nw_conn_t *mst_mnp_by_nw_id (int nw_id)
{
    u32 bucket_id = jhash_1word((u32) nw_id, 0);
    mst_nw_conn_table_t *mst_nw_conn_bkt;
    mst_nw_conn_t *nw_conn = NULL;
    mst_nw_conn_t *ret_conn = NULL;
    struct hlist_node *pos = NULL;
    struct hlist_node *temp = NULL;

    bucket_id %= D_NW_CONN_TABLE_SIZE;

    mst_nw_conn_bkt = &mst_nw_ct[bucket_id];
    
    pthread_mutex_lock(&mst_nw_conn_bkt->b_lock);
    if (hlist_empty(&mst_nw_conn_bkt->bucket)) {
        goto ret_here;
    }

    //hlist_for_each_entry(nw_conn, pos, &mst_nw_conn_bkt->bucket, hnode) {
    hlist_for_each_entry_safe(nw_conn, pos, temp, &mst_nw_conn_bkt->bucket, hnode) {
        if (nw_conn && (nw_id == nw_conn->nw_id)) {
            pthread_mutex_lock(&nw_conn->n_lock); // the callee of this function shud release lock
            ret_conn = nw_conn;
            goto ret_here;
        }
    }
ret_here:
    pthread_mutex_unlock(&mst_nw_conn_bkt->b_lock);
    return ret_conn;
}

int mst_lookup_nw_id (int nw_id)
{
    u32 bucket_id = jhash_1word((u32) nw_id, 0);
    mst_nw_conn_table_t *mst_nw_conn_bkt;
    mst_nw_conn_t *nw_conn = NULL;
    struct hlist_node *pos = NULL;
    int rv = 0;

    bucket_id %= D_NW_CONN_TABLE_SIZE;
    mst_nw_conn_bkt = &mst_nw_ct[bucket_id];

    pthread_mutex_lock(&mst_nw_conn_bkt->b_lock);
    if (hlist_empty(&mst_nw_conn_bkt->bucket)) {
        goto ret_here;
    }

    hlist_for_each_entry(nw_conn, pos, &mst_nw_conn_bkt->bucket, hnode) {
        if (nw_conn && (nw_id == nw_conn->nw_id)) {
            rv = 1;
            goto ret_here;
        }
    }

ret_here:
    pthread_mutex_unlock(&mst_nw_conn_bkt->b_lock);
    return rv;
}

int mst_lookup_mnp_by_nw_id (int nw_id, int mnp_id)
{
    u32 bucket_id = jhash_1word((u32) nw_id, 0);
    mst_nw_conn_table_t *mst_nw_conn_bkt;
    mst_nw_conn_t *nw_conn = NULL;
    struct hlist_node *pos = NULL;
    int rv = 0;
    int index = 0;

    bucket_id %= D_NW_CONN_TABLE_SIZE;
    mst_nw_conn_bkt = &mst_nw_ct[bucket_id];
    
    pthread_mutex_lock(&mst_nw_conn_bkt->b_lock);
    if (hlist_empty(&mst_nw_conn_bkt->bucket)) {
        goto ret_here;
    }

    hlist_for_each_entry(nw_conn, pos, &mst_nw_conn_bkt->bucket, hnode) {
        if (nw_conn && (nw_id == nw_conn->nw_id)) {
            pthread_mutex_lock(&nw_conn->n_lock); 
            for (index = 0; index < D_NW_TOT_LINKS; index++) {
                if (mnp_id == nw_conn->mnp_slots[index].mnp_id) {
                    rv = 1;
                    pthread_mutex_unlock(&nw_conn->n_lock); 
                    goto ret_here;
                }
            }
            pthread_mutex_unlock(&nw_conn->n_lock); 
        }
    }

ret_here:
    pthread_mutex_unlock(&mst_nw_conn_bkt->b_lock);
    return rv;
}

int mst_remove_mnp_by_nw_id (int nw_id, int mnp_id)
{
    mst_nw_conn_t *nw_conn = NULL;
    u32 bucket_id = jhash_1word((u32) nw_id, 0);
    mst_nw_conn_table_t *mst_nw_conn_bkt;
    int rv = 0; // ERROR
    int index = 0;
    
    bucket_id %= D_NW_CONN_TABLE_SIZE;
    mst_nw_conn_bkt = &mst_nw_ct[bucket_id];
    
    nw_conn = mst_mnp_by_nw_id(nw_id);

    if (nw_conn) {
        for(index = 0; index < D_NW_TOT_LINKS; index++) {
            if (nw_conn->mnp_slots[index].mnp_id == mnp_id) {
                nw_conn->mnp_slots[index].mnp_id = 0;
                nw_conn->mnp_slots[index].slot_available = 1;
                nw_conn->mnp_slots[index].snd_cnt = 0;
                rv = 1;
                atomic_dec(&nw_conn->ref_cnt);
                fprintf(stderr, "mnp 0x%X removed from bucket %d for nw_id 0x%X\n", mnp_id, bucket_id, nw_id);
                break;
            }
        }
        // Note: Lock was acquired in mst_mnp_by_nw_id()
        pthread_mutex_unlock(&nw_conn->n_lock);
        if (0 == atomic_read(&nw_conn->ref_cnt)) {
            pthread_mutex_lock(&mst_nw_conn_bkt->b_lock);
            hlist_del(&nw_conn->hnode);
            pthread_mutex_unlock(&mst_nw_conn_bkt->b_lock);
            mst_free(nw_conn, __func__);
            fprintf(stderr, "bucket %d freed\n", bucket_id);
        }
    }
    else {
        fprintf(stderr, "WARNING: Remove-mnp request for unavailable nw_conn\n");
    }

    return rv;
}

int mst_insert_mnp_by_nw_id (int nw_id, int mnp_id)
{
    mst_nw_conn_t *nw_conn = NULL;
    u32 bucket_id = jhash_1word((u32) nw_id, 0);
    mst_nw_conn_table_t *mst_nw_conn_bkt;
    int rv = 1; // ERROR
    int index = 0;
    
    bucket_id %= D_NW_CONN_TABLE_SIZE;
    mst_nw_conn_bkt = &mst_nw_ct[bucket_id];

    nw_conn = mst_mnp_by_nw_id(nw_id);

    if (!nw_conn) {
        nw_conn = mst_malloc(sizeof(mst_nw_conn_t), __func__);
        pthread_mutex_init(&nw_conn->n_lock, NULL);
        nw_conn->nw_id = nw_id;
        nw_conn->nw_lbmode = ntohs(((mst_nw_peer_t *)mnp_id)->lbmode);
        memset(nw_conn->mnp_slots, 0, sizeof(nw_conn->mnp_slots));
        INIT_HLIST_NODE(&nw_conn->hnode);
        nw_conn->mnp_slots[0].mnp_id = mnp_id;
        nw_conn->mnp_slots[0].slot_available = 0;
        nw_conn->mnp_slots[0].snd_cnt = 0;
        for(index = 1; index < D_NW_TOT_LINKS; index++) {
            nw_conn->mnp_slots[index].slot_available = 1;
            nw_conn->mnp_slots[index].snd_cnt = 0;
        }
        nw_conn->mnp_pair = ((mst_nw_peer_t *)mnp_id)->mnp_pair;
        atomic_inc(&nw_conn->ref_cnt);

        pthread_mutex_lock(&mst_nw_conn_bkt->b_lock);
        hlist_add_head(&nw_conn->hnode, &mst_nw_conn_bkt->bucket);
        pthread_mutex_unlock(&mst_nw_conn_bkt->b_lock);
        fprintf(stderr, "New mnp 0x%X added to bucket %d for nw_id 0x%X, slot: %d\n", mnp_id, bucket_id, 
            nw_id, atomic_read(&nw_conn->ref_cnt));
        rv = 0;
    }
    else {
        if (atomic_read(&nw_conn->ref_cnt) < D_NW_TOT_LINKS) {
            for(index = 0; index < D_NW_TOT_LINKS; index++) {
                if (nw_conn->mnp_slots[index].slot_available) {
                    nw_conn->mnp_slots[index].mnp_id = mnp_id;
                    nw_conn->mnp_slots[index].slot_available = 0;
                    nw_conn->mnp_slots[index].snd_cnt = 0;
                    rv = 0;
                    atomic_inc(&nw_conn->ref_cnt);
                    ((mst_nw_peer_t *)mnp_id)->mnp_pair = nw_conn->mnp_pair;
                    fprintf(stderr, "New mnp 0x%X updated to bucket %d for nw_id 0x%X, slot: %d\n", mnp_id, 
                            bucket_id, nw_id, atomic_read(&nw_conn->ref_cnt));
                    break;
                }
            }
        }
        // Lock was acquired by mst_mnp_by_nw_id()
        pthread_mutex_unlock(&nw_conn->n_lock);
    }

    return rv;
}
