#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "libcli.h"
#include "mst_cli.h"

mst_cli_cmds_tree_t *g_cli_tree;

struct cli_command *mst_cli_lookup_cmd(mst_cli_cmds_tree_t *tnode, const int comm_id)
{
    if (!tnode) {
	return NULL;
    }
    if (comm_id == tnode->comm_id) {
	return (struct cli_command *)tnode->ccom;
    }
    if (comm_id < tnode->comm_id) {
	return mst_cli_lookup_cmd(tnode->left, comm_id);
    }
    else {
	return mst_cli_lookup_cmd(tnode->right, comm_id);
    }

    return NULL;
}

int mst_cli_insert_cmd(mst_cli_cmds_tree_t *tnode, int comm_id, int ccom, int pcom)
{
    if (!tnode) {
	mst_cli_cmds_tree_t *new = (mst_cli_cmds_tree_t *)malloc(sizeof(mst_cli_cmds_tree_t));
	assert(new);
	new->parent = NULL;
	new->left = NULL;
	new->right = NULL;
	new->comm_id = comm_id;
	new->ccom = ccom;
	new->pcom = pcom;
	g_cli_tree = new;
	return 0;
    }

    if (comm_id == tnode->comm_id) {
	return -1;
    }
    else if (comm_id < tnode->comm_id) {
	if (tnode->left) {
	    mst_cli_insert_cmd(tnode->left, comm_id, ccom, pcom);
	}
	else {
	    tnode->left = (mst_cli_cmds_tree_t *)malloc(sizeof(mst_cli_cmds_tree_t));
	    assert(tnode->left);
	    tnode->left->parent = tnode;
	    tnode->left->left = NULL;
	    tnode->left->right = NULL;
	    tnode->left->comm_id = comm_id;
	    tnode->left->ccom = ccom;
	    tnode->left->pcom = pcom;
	    return 0;
	}
    }
    else {
	if (tnode->right) {
	    mst_cli_insert_cmd(tnode->right, comm_id, ccom, pcom);
	}
	else {
	    tnode->right = (mst_cli_cmds_tree_t *)malloc(sizeof(mst_cli_cmds_tree_t));
	    assert(tnode->right);
	    tnode->right->parent = tnode;
	    tnode->right->left = NULL;
	    tnode->right->right = NULL;
	    tnode->right->comm_id = comm_id;
	    tnode->right->ccom = ccom;
	    tnode->right->pcom = pcom;
	    return 0;
	}
    }

    return 0;
	
}

int mst_cli_track_cmd(int comm_id, int ccom, int pcom)
{
    mst_cli_insert_cmd(g_cli_tree, comm_id, ccom, pcom);
}
