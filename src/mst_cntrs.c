#include "mstunnel.h"
#include "mst_cntrs.h"

void *g_mst_shm_ptr;
int g_shm_cntr_fd;

int mst_deregister_cntr(int **cntr)
{
    mst_shm_body_t *cntr_body;
    
    cntr_body = container_of(*cntr, struct mst_shm_body, value);
    fprintf(stderr, "Dereg cntr request for '%s' -> '%u'\n", cntr_body->cntr_name, cntr_body->value);
    cntr_body->flag = 0;

    // TODO: Add this cntr_body to free cntrs queue
    return 0;
}

int mst_register_cntr(char *name, int **cntr)
{
    mst_shm_hdr_t *cntr_hdr;
    mst_shm_body_t *cntr_body;

    cntr_hdr = (mst_shm_hdr_t *)g_mst_shm_ptr;
    if ((D_MST_SHM_SIZE - (cntr_hdr->shm_offset + sizeof(mst_shm_hdr_t))) >= (sizeof(mst_shm_body_t))) {
        cntr_body = (mst_shm_body_t *)((char *)cntr_hdr + sizeof(mst_shm_hdr_t) + cntr_hdr->shm_offset);
        cntr_body->flag = 1;
        cntr_body->value = 0;
        strncpy(cntr_body->cntr_name, name, D_MST_CNTR_LEN);
        *cntr = &cntr_body->value;

        cntr_hdr->shm_offset += sizeof(mst_shm_body_t);
        cntr_hdr->hdr_cnt += 1;

        fprintf(stderr, "Successfully added '%s' to shm space\n", name);

        return 0;
    }

    fprintf(stderr, "Space for counters exceeded\n");
    return -1;
}

int mst_init_shm_cntrs(void)
{
    int rv = 0;

    g_shm_cntr_fd = shm_open(D_MST_SHM_ID, O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);

    if (g_shm_cntr_fd < 0) {
        fprintf(stderr, "shm_open error: %s\n", strerror(errno));
        return -1;
    }

    rv = ftruncate(g_shm_cntr_fd, D_MST_SHM_SIZE);

    if (rv < 0) {
        fprintf(stderr, "shm_cntr ftruncate failed: %s\n", strerror(errno));
        return rv;
    }

    g_mst_shm_ptr = mmap(NULL, D_MST_SHM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, g_shm_cntr_fd, 0);

    if (MAP_FAILED == g_mst_shm_ptr) {
        fprintf(stderr, "ERROR: Failed to mmap shm_fd: %s\n", strerror(errno));
        return -1;
    }

    memset(g_mst_shm_ptr, 0, D_MST_SHM_SIZE);

    fprintf(stderr, "MST_SHM_CNTRS init successful\n");

    return 0;
}

