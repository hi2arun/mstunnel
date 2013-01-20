#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "libcli.h"
#include "mst_cli.h"

mst_clictx_t g_clictx;

extern mst_cli_cmds_tree_t *g_cli_tree;

mst_cli_module_t g_cli_mods[] = {
    {"mst_global", mst_cli_global_init},
    {"mst_interface", mst_cli_intf_init},
    {"mst_show", mst_cli_show_init},
    {NULL, NULL},
};

int mst_idle_timeo(struct cli_def *cdef)
{
    cli_print(cdef, "Logging out due to idleness");
    return CLI_QUIT;
}

int mst_regular_callback(struct cli_def *cdef)
{
    return CLI_OK;
}

int mst_register_cli_cmds(struct cli_def *cdef, mst_cli_cmds_t *cli_cmds)
{
    int index = 0;
    struct cli_command *pcom = NULL;
    struct cli_command *ccom = NULL;

    for(index = 0; cli_cmds[index].comm_id > 0; index++) {
        if (cli_cmds[index].parent_id) {
            pcom = mst_cli_lookup_cmd(g_cli_tree, cli_cmds[index].parent_id);
        }
        ccom = cli_register_command(cdef, pcom, cli_cmds[index].command, cli_cmds[index].cli_handler, 
                cli_cmds[index].privilege, cli_cmds[index].mode, cli_cmds[index].cli_help);
        mst_cli_insert_cmd(g_cli_tree, cli_cmds[index].comm_id, (int)ccom, (int)pcom);
        pcom = NULL;
    }

    return 0;
}

int mst_cli_cmds_init(struct cli_def *cdef)
{
    int index = 0;
    int rv = -1;
    struct cli_command *ccom;  // This is needed to setup parent-children CLI hierarchy

    for(index = 0; g_cli_mods[index].mod_name; index++) {
        fprintf(stderr, "Attempting to register CLI module '%s' .... ", g_cli_mods[index].mod_name);
        rv = g_cli_mods[index].cli_mod_init(cdef);
        if (!rv) {
            fprintf(stderr, " succeeded\n");
        }
        else {
            fprintf(stderr, " failed\n");
            return rv;
        }
    }

    return 0;
}

#define D_MST_CLI_PORT 10000

int mst_cli_loop(struct cli_def *mst_cdef)
{
    struct sockaddr_in server;
    struct sockaddr_in client;
    int sfd = -1, cfd = -1;
    int rv = -1;
    int flag = 1;
    int slen = sizeof(struct sockaddr_in);

    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(D_MST_CLI_PORT);

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return rv;
    }

    rv = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    if (rv < 0) {
        fprintf(stderr, "setsockopt SO_REUSEADDR failed: %s\n", strerror(errno));
        return rv;
    }

    rv = bind(sfd, (struct sockaddr *)&server, sizeof(server));
    if (rv < 0) {
        fprintf(stderr, "Failed to bind server: %s\n", strerror(errno));
        return rv;
    }

    rv = listen(sfd, 5);
    if (rv < 0) {
        fprintf(stderr, "Failed to listen: %s\n", strerror(errno));
        return rv;
    }

    while(1) {
        cfd = accept(sfd, (struct sockaddr *)&client, &slen);
        if (cfd > 2) {
            cli_loop(mst_cdef, cfd);
            close(cfd);
        }
    }

    close(sfd);

    return rv;
}

int main(int argc, char **argv)
{
    struct cli_command *mst_ccom;
    struct cli_def *mst_cdef;

    memset(&g_clictx, 0, sizeof(mst_clictx_t));

    // Initialize (get memory) for cli_def
    mst_cdef = cli_init();

    // Set CLI banner to default
    cli_set_banner(mst_cdef, D_MST_CLI_BANNER);

    // Set CLI hostname to default
    cli_set_hostname(mst_cdef, D_MST_CLI_HOSTNAME);

    // Enable Telnet protocol mode
    cli_telnet_protocol(mst_cdef, 1 /* 1 = Enable */);

    // Setup regular callback interval and handler. This callback will do any periodical background work, if any
    cli_regular(mst_cdef, mst_regular_callback);
    cli_regular_interval(mst_cdef, D_MST_CLI_REG_CB_INVL);

    // Set default idle timeout and its callback handler
    cli_set_idle_timeout_callback(mst_cdef, D_MST_CLI_IDLE_TO, mst_idle_timeo);

    // From hereon, set all callbacks
    if (mst_cli_cmds_init(mst_cdef)) {
        exit(EXIT_FAILURE);
    }

    // Set our private context that holds the complete volatile configuration and params
    cli_set_context(mst_cdef, (void *)&g_clictx);

    mst_cli_loop(mst_cdef);

    return 0;
}
