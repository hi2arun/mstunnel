#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "libcli.h"
#include "mst_cli.h"
#include "mst_cntrs.h"

int mst_cli_show_counters(struct cli_def *cdef, 
	const char *command,
	char **argv,
	int argc)
{
    static int shm_cntrs_init = 0;
    static int shm_fd = -1;
    static void *shm_ptr = NULL;
    mst_shm_hdr_t *cntr_hdr;
    mst_shm_body_t *cntr_body;
    int count = 0;
    
    if ((argc == 1) && !strcmp(argv[0], "?")) {
	    cli_print(cdef, "Display all counters");
        goto do_exit;
    }

    if (!shm_cntrs_init) {
        shm_fd = shm_open(D_MST_SHM_ID, O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);

        if (shm_fd < 0) {
            cli_error(cdef, "shm_open error: %s\n", strerror(errno));
            return CLI_ERROR;
        }

        shm_ptr = mmap(NULL, D_MST_SHM_SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);

        if (MAP_FAILED == shm_ptr) {
            shm_unlink(D_MST_SHM_ID);
            cli_error(cdef, "shm_mmap error: %s", strerror(errno));
            return CLI_ERROR;
        }

        fprintf(stderr, "SHM_CNTRS: mmap success\n");
        shm_cntrs_init = 1;
    }

    cntr_hdr = (mst_shm_hdr_t *)shm_ptr;
    while(count < cntr_hdr->hdr_cnt) {
        cntr_body = (mst_shm_body_t *)((char *)cntr_hdr + sizeof(mst_shm_hdr_t) + (count * sizeof(mst_shm_body_t)));
        cli_print(cdef, "%s \t\t\t: %20u", cntr_body->cntr_name, cntr_body->value);
        count++;
    }

do_exit:
    return CLI_OK;
}

int mst_cli_show(struct cli_def *cdef, 
	const char *command,
	char **argv,
	int argc)
{
    mst_clictx_t *cctx = cli_get_context(cdef);

    if ((argc < 2) || !strcmp(argv[0], "?")) {
	    cli_print(cdef, "counters \t Display all counters");
        goto do_exit;
    }

do_exit:
    return CLI_OK;
}

int mst_cli_show_init(struct cli_def *cdef)
{
    mst_cli_cmds_t cli_show[] = {
	{
	    6,
	    0,
	    "show",
	    mst_cli_show,
	    PRIVILEGE_PRIVILEGED,
	    MODE_EXEC,
	    "Show commands",
	},
	{
	    7,
	    6, // parent is 'show'
	    "counters",
	    mst_cli_show_counters,
	    PRIVILEGE_PRIVILEGED,
	    MODE_EXEC,
	    "Command to display counters",
	},
	{
	    D_MST_CLI_EOC,
	    D_MST_CLI_EOC,
	    NULL,
	    NULL,
	    D_MST_CLI_EOC,
	    D_MST_CLI_EOC,
	    NULL,
	}
    };

    mst_register_cli_cmds(cdef, cli_show);

    return 0;
}
