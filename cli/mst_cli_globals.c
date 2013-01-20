#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "libcli.h"
#include "mst_cli.h"

// Globals - Banner
#define D_CLI_G_BANNER 0x1 
// Globals - Hostname
#define D_CLI_G_HN 0x2

mst_cli_error_t cli_global_error[] = {
    {D_CLI_G_BANNER, "banner \t\t - set CLI banner"},
    {D_CLI_G_HN, "hostname \t - set hostname"},
    {D_MST_CLI_EOC, NULL},
};

void mst_cli_global_error(struct cli_def *cdef, int cli_global_flags)
{
    int index = 0;
    int val = 0;
    
    for(index = 0; cli_global_error[index].string; index++) {
	if (!(cli_global_flags & cli_global_error[index].flags)) {
	    cli_print(cdef, cli_global_error[index].string);
	    val = 1;
	}
    }

    if (!val) {
	cli_print(cdef, "Invalid command received.");
    }

    return;
}

int mst_cli_global_set(struct cli_def *cdef, 
	const char *command,
	char **argv,
	int argc)
{
// bitmap for CLI global features (currently limited to 32)
    int cli_global_flags = 0;
    mst_clictx_t *cctx = cli_get_context(cdef);
    mst_global_config_t *gc;

    gc = &cctx->global_config;

    //fprintf(stderr, "%s(): argc: %d\n", __func__, argc);

    if ((argc < 2) || !strcmp(argv[0], "?")) {
	mst_cli_global_error(cdef, cli_global_flags);
	goto do_exit;
    }

    if (!strcmp(argv[0], "banner") && (argc > 1)) {
	if (!strcmp(argv[1], "?")) {
	    cli_print(cdef, "<string> \t Banner string to be displayed [max len - 1000]");
	}
	else {
	    strncpy(gc->cli_banner, argv[1], D_MST_CLI_BANNER_LEN);
	    cli_set_banner(cdef, gc->cli_banner);
	    cli_global_flags |= D_CLI_G_BANNER;
	}
	goto do_exit;
    }

    if (!strcmp(argv[0], "hostname") && (argc > 1)) {
	if (!strcmp(argv[1], "?")) {
	    cli_print(cdef, "<string> \t Hostname of the system [max len - 60]");
	}
	else {
	    strncpy(gc->cli_hostname, argv[1], D_MST_CLI_HOSTNAME_LEN);
	    cli_set_hostname(cdef, gc->cli_hostname);
	    cli_global_flags |= D_CLI_G_HN;
	}
	goto do_exit;
    }

    mst_cli_global_error(cdef, cli_global_flags);
    
do_exit:
    return CLI_OK;
}

int mst_cli_global_init(struct cli_def *cdef)
{
    mst_cli_cmds_t cli_global[] = {
	{
	    1,
	    0,
	    "set",
	    mst_cli_global_set,
	    PRIVILEGE_PRIVILEGED,
	    MODE_EXEC,
	    "Command to set global params",
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

    mst_register_cli_cmds(cdef, cli_global);

    return 0;
}
