#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "memmgmt.h"
extern void mst_memmgmt_init(void);

int main(void)
{
    char *cptr = NULL;
    mst_memmgmt_init();

    cptr = (char *) mst_malloc(32, 0);

    memset(cptr, 'a', 31);
    fprintf(stderr, "Cptr: %s\n", cptr);
    mst_free(cptr, 0);
    return 0;
}

