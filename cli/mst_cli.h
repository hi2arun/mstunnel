#ifndef __MSTCLI_H__
#define __MSTCLI_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <linux/if.h>

#define D_MST_CLI_BANNER "MSTUNNEL_nXgLb v0.1 - CLI"
#define D_MST_CLI_HOSTNAME "mst_nXgLb"
// Default regular callback interval in seconds
#define D_MST_CLI_REG_CB_INVL 5
// Default Idle timeout in seconds
#define D_MST_CLI_IDLE_TO 90

#define D_MST_CLI_EOC -1

typedef struct mst_cli_cmds_tree {
    struct mst_cli_cmds_tree *parent;
    struct mst_cli_cmds_tree *left;
    struct mst_cli_cmds_tree *right;
    int comm_id;
    int pcom; // parent command
    int ccom; // cli command
} mst_cli_cmds_tree_t;

typedef struct mst_cli_error {
    int flags;
    char *string;
} mst_cli_error_t;

typedef struct mst_cli_cmds {
    int comm_id;
    int parent_id;
    const char *command;
    int (*cli_handler)(struct cli_def *, const char *, char **, int);
    int privilege;
    int mode;
    const char *cli_help;
} mst_cli_cmds_t;

// List of CLI modules
typedef struct mst_cli_module {
    char *mod_name;
    int (*cli_mod_init)(struct cli_def *);
} mst_cli_module_t;

#define D_MST_CLI_ARGS_CNT 256 // It will be ugly to have a mile length CLI
// List that maintains the running-configuration
typedef struct mst_rc {
    struct mst_rc *next;
    char *cmd_args[256];
} mst_rc_t;

#define D_MST_TOT_INTF 32 // Maximum number of interfaces supported
#define D_MST_CLI_CODE_INTF 0x10000001
// All interface related configuration go here
typedef struct mst_intf_config {
    char intf_name[IFNAMSIZ + 1];
    int mode; // static or dynamic
    unsigned ipv4_address;
    unsigned ipv4_netmask;
    unsigned mtu;
} mst_intf_config_t;

#define D_MST_CLI_BANNER_LEN 1023
#define D_MST_CLI_HOSTNAME_LEN 63
#define D_MST_CLI_CODE_GLOBAL 0x10000002
typedef struct mst_global_config {
    char cli_banner[D_MST_CLI_BANNER_LEN + 1];
    char cli_hostname[D_MST_CLI_HOSTNAME_LEN + 1];
} mst_global_config_t;

typedef struct mst_clictx {
    mst_rc_t *rc;
    mst_rc_t *rc_tail;
    int tot_cmds;

    mst_intf_config_t intf_config[D_MST_TOT_INTF];
    mst_global_config_t global_config;

} mst_clictx_t;

extern int mst_register_cli_cmds(struct cli_def *cdef, mst_cli_cmds_t *cli_cmds);
extern int mst_cli_global_init(struct cli_def *cdef);
extern int mst_cli_show_init(struct cli_def *cdef);
extern int mst_cli_intf_init(struct cli_def *cdef);
extern int mst_cli_insert_cmd(mst_cli_cmds_tree_t *tnode, int comm_id, int ccom, int pcom);
extern struct cli_command *mst_cli_lookup_cmd(mst_cli_cmds_tree_t *tnode, const int comm_id);

#endif // !__MSTCLI_H__
