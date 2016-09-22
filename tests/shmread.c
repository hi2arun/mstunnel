#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../inc/mst_cntrs.h"

int main(int argc, char **argv)
{
    int shm_fd = -1;
    void *shm_ptr = NULL;
    mst_shm_hdr_t *cntr_hdr;
    mst_shm_body_t *cntr_body;
    int count = 0;
    int size = D_MST_SHM_SIZE;
    int cntr_index = 0;
    int mc = 0;
    int fc = 0;

    shm_fd = shm_open(D_MST_SHM_ID, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);

    if (shm_fd < 0) {
        fprintf(stderr, "shm_open error: %s\n", strerror(errno));
        return -1;
    }

    shm_ptr = mmap(NULL, D_MST_SHM_SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);

    if (MAP_FAILED == shm_ptr) {
        fprintf(stderr, "shm_mmap error: %s\n", strerror(errno));
        return -1;
    }

    fprintf(stderr, "MMAP successfull\n");

    cntr_hdr = (mst_shm_hdr_t *)shm_ptr;
    while (1) {
        count = 0;
        while(count < cntr_hdr->hdr_cnt) {
            cntr_body = (mst_shm_body_t *)((char *)cntr_hdr + sizeof(mst_shm_hdr_t) + (count * sizeof(mst_shm_body_t)));
            if (cntr_body->flag) {
                if (!strcmp(cntr_body->cntr_name, "malloc_cnt")) {
                    mc = cntr_body->value;
                }
                if (!strcmp(cntr_body->cntr_name, "free_cnt")) {
                    fc = cntr_body->value;
                }
                fprintf(stderr, "%s \t\t\t: %20u\n", cntr_body->cntr_name, cntr_body->value);
            }
            count++;
        }
        fprintf(stderr, "malloc free delta: %u\n", (mc - fc));

        fprintf(stderr, "============\n");
        sleep(1);
    }

    munmap(shm_ptr, D_MST_SHM_SIZE);

    shm_unlink(D_MST_SHM_ID);

    return 0;
}
