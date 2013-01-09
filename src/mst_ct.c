#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"

mst_nw_conn_table_t mst_nw_ct[D_NW_CONN_TABLE_SIZE];

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
