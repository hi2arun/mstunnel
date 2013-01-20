#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "libcli.h"
#include "mst_cli.h"

int mst_cli_interface_set(struct cli_def *cdef,
	const char *command,
	char **argv,
	int argc)
{
    mst_clictx_t *cctx = cli_get_context(cdef);

    return CLI_OK;
}

int mst_cli_interface_del(struct cli_def *cdef,
	const char *command,
	char **argv,
	int argc)
{
    mst_clictx_t *cctx = cli_get_context(cdef);

    return CLI_OK;
}

int mst_cli_interface(struct cli_def *cdef,
	const char *command,
	char **argv,
	int argc)
{
    mst_clictx_t *cctx = cli_get_context(cdef);

    return CLI_OK;
}

int mst_cli_intf_init(struct cli_def *cdef)
{
    mst_cli_cmds_t cli_intf[] = {
	{
	    3,
	    0, 
	    "interface",
	    mst_cli_interface,
	    PRIVILEGE_PRIVILEGED,
	    MODE_CONFIG,
	    "Configure Network Interface card",
	},
	{
	    4,
	    3, // Falls under 'interface'
	    "set", // set interface params
	    mst_cli_interface_set,
	    PRIVILEGE_PRIVILEGED,
	    MODE_CONFIG,
	    "Set interface parameters",
	},
	{
	    5,
	    3, // Falls under 'interface'
	    "del", // delete interface
	    mst_cli_interface_del,
	    PRIVILEGE_PRIVILEGED,
	    MODE_CONFIG,
	    "Delete network interface",
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

    mst_register_cli_cmds(cdef, cli_intf);

    return 0;
}
