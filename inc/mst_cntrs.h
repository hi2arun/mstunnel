#ifndef __MST_CNTRS_H__
#define __MST_CNTRS_H__

#define D_MST_SHM_SIZE (1024 * 16) // 4 * 4k = 4*53 counters

#define D_MST_SHM_ID "./mst_shm_counters"
#define D_MST_CNTR_LEN 63

typedef struct mst_shm_hdr {
    int hdr_cnt;
    int shm_offset; // or size
} __attribute__((packed)) mst_shm_hdr_t;

typedef struct mst_shm_body {
    char cntr_name[D_MST_CNTR_LEN + 1];
    unsigned value;
    int flag; // 0 - inactive, 1 - active
} __attribute__((packed)) mst_shm_body_t;

#ifndef offsetof
#define offsetof(type,member) ((char *)(&((type *)0)->member) - (char *)((type *)0))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type,member)))
#endif

extern int mst_init_shm_cntrs(void);
extern int mst_register_cntr(char *name, int **cntr);
extern int mst_deregister_cntr(int **cntr);

#endif // !__MST_CNTRS_H__
