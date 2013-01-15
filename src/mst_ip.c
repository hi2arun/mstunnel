#include "mstunnel.h"
#include "memmgmt.h"
#include "mst_network.h"
#include "mst_timer.h"
#include "mst_tun.h"
#include "mst_nw_queue.h"

mst_nw_ip_flow_t mst_ip_ct[D_IP_FLOW_TABLE_SIZE];

int mst_lookup_ip_tuple (unsigned sip, unsigned dip, mst_ip_dir_t ip_dir, int sid)
{
    unsigned l_sip;
    unsigned l_dip;
    int l_sid = -1;
    unsigned bucket_id = 0;
    mst_nw_ip_flow_t *mst_nw_ip_bkt;
    mst_ip_tuple_t *ip_tuple;
    mst_ip_tuple_t *temp_tuple;

    
    if (E_NW_IN == ip_dir) {
        l_sip = dip;
        l_dip = sip;
    }
    else {
        l_sip = sip;
        l_dip = dip;
    }

    bucket_id = jhash_2words(l_sip, l_dip, 0);
    bucket_id %= D_IP_FLOW_TABLE_SIZE;
    mst_nw_ip_bkt = &mst_ip_ct[bucket_id];
    
//    fprintf(stderr, "Lookup[%d] SIP: "D_IPV4_STR_FMT", DIP: "D_IPV4_STR_FMT"\n", ip_dir, M_NIPQUAD(&l_sip), M_NIPQUAD(&l_dip));

    pthread_mutex_lock(&mst_nw_ip_bkt->b_lock);
    for(ip_tuple = mst_nw_ip_bkt->head; ip_tuple; ip_tuple = ip_tuple->next) {
        if ((l_sip == ip_tuple->sip) && (l_dip == ip_tuple->dip)) {
            // Got a hit. Perform LRU now
            if (sid > -1) {
                // SID from NW side. Update local info.
                ip_tuple->sid = sid;
            }
            l_sid = ip_tuple->sid;
            ip_tuple->hits++;

            if (mst_nw_ip_bkt->head == ip_tuple) {
                // No LRU shifts. Head got a hit again.
            }
            else if (mst_nw_ip_bkt->tail == ip_tuple) {
                // Move tail to head and make tail->prev new tail
                temp_tuple = mst_nw_ip_bkt->tail->prev; // note New tail
                mst_nw_ip_bkt->tail->next = mst_nw_ip_bkt->head;
                mst_nw_ip_bkt->head->prev = mst_nw_ip_bkt->tail;
                mst_nw_ip_bkt->tail->prev = NULL;

                mst_nw_ip_bkt->head = mst_nw_ip_bkt->tail;
                mst_nw_ip_bkt->tail = temp_tuple;
            }
            else {
                // This node is smewhr b/w head and tail. De-link it and make it head
                ip_tuple->prev->next = ip_tuple->next;
                ip_tuple->next->prev = ip_tuple->prev;

                ip_tuple->prev = NULL;
                ip_tuple->next = mst_nw_ip_bkt->head;
                mst_nw_ip_bkt->head->prev = ip_tuple;
                mst_nw_ip_bkt->head = ip_tuple;
            }
            break;
        }
    }

    pthread_mutex_unlock(&mst_nw_ip_bkt->b_lock);
    return l_sid;
}

int mst_insert_ip_tuple (unsigned sip, unsigned dip, mst_ip_dir_t ip_dir, unsigned sid)
{
    unsigned bucket_id = 0;
    mst_nw_ip_flow_t *mst_nw_ip_bkt;
    mst_ip_tuple_t *ip_tuple;
    mst_ip_tuple_t *temp_tuple;


    ip_tuple = (mst_ip_tuple_t *)malloc(sizeof(mst_ip_tuple_t));
    assert(ip_tuple);

    ip_tuple->next = NULL;
    ip_tuple->prev = NULL;
    if (E_NW_IN == ip_dir) {
        ip_tuple->sip = dip;
        ip_tuple->dip = sip;
    }
    else {
        ip_tuple->sip = sip;
        ip_tuple->dip = dip;
    }
    ip_tuple->sid = sid;
    ip_tuple->hits = 1;
    
    bucket_id = jhash_2words(ip_tuple->sip, ip_tuple->dip, 0);
    
    bucket_id %= D_IP_FLOW_TABLE_SIZE;
    mst_nw_ip_bkt = &mst_ip_ct[bucket_id];
    
    fprintf(stderr, "Adding SIP: "D_IPV4_STR_FMT", DIP: "D_IPV4_STR_FMT"\n", M_NIPQUAD(&ip_tuple->sip), M_NIPQUAD(&ip_tuple->dip));

    pthread_mutex_lock(&mst_nw_ip_bkt->b_lock);
    // Check if this bucket has all LRU slots filled
    if (mst_nw_ip_bkt->slots >= D_IP_SLOTS_PER_FLOW) {
        // Add this new node to head and chuck tail off
        ip_tuple->next = mst_nw_ip_bkt->head;
        mst_nw_ip_bkt->head->prev = ip_tuple;
        mst_nw_ip_bkt->head = ip_tuple;

        temp_tuple = mst_nw_ip_bkt->tail->prev; // New tail
        temp_tuple->next = NULL;
        free(mst_nw_ip_bkt->tail); // free old tail
        mst_nw_ip_bkt->tail = temp_tuple; // Set new tail
    }
    else {
        // Just update head and do not disturb tail (NO circular LRU here)
        if (mst_nw_ip_bkt->head) {
            ip_tuple->next = mst_nw_ip_bkt->head;
            mst_nw_ip_bkt->head->prev = ip_tuple;
            mst_nw_ip_bkt->head = ip_tuple;
        }
        else {
            // This is the first node
            mst_nw_ip_bkt->head = ip_tuple;
        }
        mst_nw_ip_bkt->slots++;
    }

    pthread_mutex_unlock(&mst_nw_ip_bkt->b_lock);

    return 0;
}

void mst_dump_ip_flow_table(void)
{
    int index = 0;
    mst_ip_tuple_t *ip_tuple;
    for (index = 0; index < D_IP_FLOW_TABLE_SIZE; index++) {
        ip_tuple = mst_ip_ct[index].head;
        if (ip_tuple) {
            fprintf(stderr, "[%d] slots: %d\n", index, mst_ip_ct[index].slots);

            for(;ip_tuple; ip_tuple = ip_tuple->next) {
                fprintf(stderr, "SIP: "D_IPV4_STR_FMT", DIP: "D_IPV4_STR_FMT", sid: %d, hits: %d\n", M_NIPQUAD(&ip_tuple->sip), M_NIPQUAD(&ip_tuple->dip), ip_tuple->sid, ip_tuple->hits);
            }
        }
    }

    return;
}

int mst_init_ip_flow_table(void) 
{
    int index = 0;
    for (index = 0; index < D_IP_FLOW_TABLE_SIZE; index++) {
        mst_ip_ct[index].head = NULL;
        mst_ip_ct[index].tail = NULL;
        mst_ip_ct[index].slots = 0;
        pthread_mutex_init(&mst_ip_ct[index].b_lock, NULL);
    }

    return 0;
}

