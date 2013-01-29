#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <event2/event.h>
#include <assert.h>
#include <libconfig.h>

#include "mstunnel.h"
#include "memmgmt.h"

config_t g_config;
mst_conf_t g_mst_conf;

#define D_LOOKUP_STR_LEN 1023

void mst_config_dump(mst_conf_t *pconfig)
{
    int index;
    int link_up_cnt;
    int link_down_cnt;
    fprintf(stderr, "Version: %hu\n", pconfig->version);
    fprintf(stderr, "Type: %d\n", pconfig->mst_type);
    fprintf(stderr, "mpool: %d\n", pconfig->mpool_size);
    fprintf(stderr, "mbuf: %d\n", pconfig->mbuf_size);
    fprintf(stderr, "nw_streams: %d\n", pconfig->nw_streams);

    fprintf(stderr, "policy: %s\n", pconfig->policy);
    fprintf(stderr, "lbmode: %d\n", pconfig->lbmode);
    fprintf(stderr, "links_cnt: %d\n", pconfig->links_cnt);
    for(index = 0; index < pconfig->links_cnt; index++) {
        fprintf(stderr, "Link Left[%d] %s:%u\n", index, pconfig->links[index].leftip, pconfig->links[index].leftport);
        if (pconfig->links[index].rightip) {
            fprintf(stderr, "Link right[%d] %s:%u\n", index, pconfig->links[index].rightip, pconfig->links[index].rightport);
        }
    }
    fprintf(stderr, "nw_conf_cnt: %d\n", pconfig->nw_conf_cnt);
    for(index = 0; index < pconfig->nw_conf_cnt; index++) {
        fprintf(stderr, "nw_conf[%d] nw_id: 0x%X\n", index, pconfig->nw_conf[index].nw_id);
        link_up_cnt = pconfig->nw_conf[index].link_up_cnt;
        fprintf(stderr, "nw_conf[%d] link_up_cmds_cnt: %d\n", index, link_up_cnt);
        for(;link_up_cnt;link_up_cnt--) {
            fprintf(stderr, "nw_conf[%d] up cmd: %s\n", index, pconfig->nw_conf[index].link_up[link_up_cnt - 1]);
        }
        link_down_cnt = pconfig->nw_conf[index].link_down_cnt;
        fprintf(stderr, "nw_conf[%d] link_down_cmds_cnt: %d\n", index, link_down_cnt);
        for(;link_down_cnt;link_down_cnt--) {
            fprintf(stderr, "nw_conf[%d] down cmd: %s\n", index, pconfig->nw_conf[index].link_down[link_down_cnt - 1]);
        }
    }

    return;
}

int mst_read_policy_details(config_t *pconfig)
{
    int rv = -1;
    const char *strval;
    int intval;
    int index;
    int index_2;
    int count, count_2;
    config_setting_t *policy;
    config_setting_t *links_setting;
    config_setting_t *nw_conf_setting;
    config_setting_t *link_up_setting;
    config_setting_t *link_down_setting;
    char lookup_string[D_LOOKUP_STR_LEN + 1] = {0};

    rv = config_lookup_string(pconfig, "policy", &strval);
    if (CONFIG_FALSE == rv) {
        fprintf(stderr, "No active policy is chosen.\n");
        return -1;
    }

    g_mst_conf.policy = strdup(strval);

    policy = config_lookup(pconfig, g_mst_conf.policy);
    if (!policy) {
        fprintf(stderr, "Chosen policy is not configured.\n");
        return -1;
    }

    if (0 == g_mst_conf.mst_type) {
        g_mst_conf.lbmode = 0;
        rv = config_setting_lookup_int(policy, "lbmode", &intval);
        if (CONFIG_TRUE == rv) {
            g_mst_conf.lbmode = intval;
        }
    }

    snprintf(lookup_string, D_LOOKUP_STR_LEN, "%s.links", g_mst_conf.policy);
    links_setting = config_lookup(pconfig, lookup_string);

    if (!links_setting) {
        fprintf(stderr, "No links section is present.\n");
        return -1;
    }
    count = config_setting_length(links_setting);
    if (!count) {
        fprintf(stderr, "Empty links section is not accepted.\n");
        return -1;
    }

    g_mst_conf.links_cnt = count;
    g_mst_conf.links = (mst_links_t *) malloc(count * sizeof(mst_links_t));
    assert(g_mst_conf.links);

    for(index = 0; index < count; index++) {
        config_setting_t *links = config_setting_get_elem(links_setting, index);

        rv = config_setting_lookup_string(links, "leftip", &strval);
        if (CONFIG_FALSE == rv) {
            fprintf(stderr, "Leftip is not configured.\n");
            return -1;
        }
        g_mst_conf.links[index].leftip = strdup(strval);
        
        rv = config_setting_lookup_string(links, "rightip", &strval);
        if (CONFIG_TRUE == rv) {
            g_mst_conf.links[index].rightip = strdup(strval);
        }
        else {
            g_mst_conf.links[index].rightip = NULL;
            if (0 == g_mst_conf.mst_type) {
                fprintf(stderr, "rightip is not configured.\n");
                return -1;
            }
        }
        
        rv = config_setting_lookup_int(links, "leftport", &intval);
        if (CONFIG_FALSE == rv) {
            fprintf(stderr, "Leftport is not configured.\n");
            return -1;
        }
        g_mst_conf.links[index].leftport = intval;
        
        rv = config_setting_lookup_int(links, "rightport", &intval);
        if (CONFIG_TRUE == rv) {
            g_mst_conf.links[index].rightport = intval;
        }
        else {
            g_mst_conf.links[index].rightport = 0;
            if (0 == g_mst_conf.mst_type) {
                fprintf(stderr, "rightport is not configured.\n");
                return -1;
            }
        }
    }

    snprintf(lookup_string, D_LOOKUP_STR_LEN, "%s.nw_conf", g_mst_conf.policy);
    nw_conf_setting = config_lookup(pconfig, lookup_string);

    if (!nw_conf_setting) {
        fprintf(stderr, "No nw_conf section is present.\n");
        return -1;
    }
    count = config_setting_length(nw_conf_setting);
    if (!count) {
        fprintf(stderr, "Empty nw_conf section is not allowed\n");
        return -1;
    }

    g_mst_conf.nw_conf_cnt = count;
    g_mst_conf.nw_conf = (mst_nw_ctrl_t *)malloc(count * sizeof(mst_nw_ctrl_t));
    assert(g_mst_conf.nw_conf);

    for(index = 0; index < count; index++) {
        config_setting_t *nw_conf = config_setting_get_elem(nw_conf_setting, index);

        rv = config_setting_lookup_int(nw_conf, "nw_id", &intval);
        if (CONFIG_FALSE == rv) {
            fprintf(stderr, "nw_id is not configured in %s\n", lookup_string);
            return -1;
        }

        g_mst_conf.nw_conf[index].nw_id = intval;

        link_up_setting = config_setting_get_member(nw_conf, "link_up");
        if (link_up_setting) {
            count_2 = config_setting_length(link_up_setting);
            g_mst_conf.nw_conf[index].link_up_cnt = count_2;
            if (count_2) {
                g_mst_conf.nw_conf[index].link_up = (char **)malloc(count_2 * sizeof(char *));
                assert(g_mst_conf.nw_conf[index].link_up);
            }
            for(index_2 = 0; index_2 < count_2; index_2++) {
                config_setting_t *link_up = config_setting_get_elem(link_up_setting, index_2);
                rv = config_setting_lookup_string(link_up, "cmd", &strval);
                if (CONFIG_TRUE == rv) {
                    g_mst_conf.nw_conf[index].link_up[index_2] = strdup(strval);
                }
                else {
                    g_mst_conf.nw_conf[index].link_up[index_2] = NULL;
                }
            }
        }
        link_down_setting = config_setting_get_member(nw_conf, "link_down");
        if (link_down_setting) {
            count_2 = config_setting_length(link_down_setting);
            g_mst_conf.nw_conf[index].link_down_cnt = count_2;
            if (count_2) {
                g_mst_conf.nw_conf[index].link_down = (char **)malloc(count_2 * sizeof(char *));
                assert(g_mst_conf.nw_conf[index].link_down);
            }
            for(index_2 = 0; index_2 < count_2; index_2++) {
                config_setting_t *link_down = config_setting_get_elem(link_down_setting, index_2);
                rv = config_setting_lookup_string(link_down, "cmd", &strval);
                if (CONFIG_TRUE == rv) {
                    g_mst_conf.nw_conf[index].link_down[index_2] = strdup(strval);
                }
                else {
                    g_mst_conf.nw_conf[index].link_down[index_2] = NULL;
                }
            }
        }
    }

    return CONFIG_TRUE;
}

int mst_read_globals(config_t *pconfig)
{
    int rv = -1;
    config_setting_t *globals;
    int intval = 0;

    // Load default globals value
    g_mst_conf.mpool_size = 80; // 80 MB
    g_mst_conf.mbuf_size = 16; // 16 MB
    g_mst_conf.nw_streams = 10; // 10 outstreams

    globals = config_lookup(pconfig, "globals");

    if (!globals) {
        fprintf(stderr, "No globals sections was found. Proceeding with defaults.\n");
        return CONFIG_TRUE;
    }

    rv = config_setting_lookup_int(globals, "mpool", &intval);
    if (CONFIG_TRUE == rv) {
        g_mst_conf.mpool_size = intval; 
    }
    rv = config_setting_lookup_int(globals, "mbuf", &intval);
    if (CONFIG_TRUE == rv) {
        g_mst_conf.mbuf_size = intval; 
    }
    rv = config_setting_lookup_int(globals, "nw_streams", &intval);
    if (CONFIG_TRUE == rv) {
        g_mst_conf.nw_streams = intval; 
    }

    return CONFIG_TRUE;
}

int mst_read_type(config_t *pconfig)
{
    int rv = -1;
    const char *strval = NULL;

    rv = config_lookup_string(pconfig, "type", &strval);
    if (CONFIG_FALSE == rv) {
        fprintf(stderr, "No type info is found\n");
        return rv;
    }

    if (!strcmp(strval, "client")) {
        g_mst_conf.mst_type = 0;
    }
    else if (!strcmp(strval, "server")) {
        g_mst_conf.mst_type = 1;
    }
    else {
        fprintf(stderr, "Invalid type '%s' was found\n", strval);
        return -1;
    }

    return CONFIG_TRUE;
}

int mst_read_version(config_t *pconfig)
{
    int rv = -1;
    int val = 0;

    rv = config_lookup_int(pconfig, "version", &val);
    if (CONFIG_FALSE == rv) {
        fprintf(stderr, "No version info is found: %d\n", rv);
        return rv;
    }

    g_mst_conf.version = val;
    return CONFIG_TRUE;
}

int mst_config_load(const char *conf_path)
{
    int rv = -1;

    config_init(&g_config);

    rv = config_read_file(&g_config, conf_path);

    if (CONFIG_FALSE == rv) {
        fprintf(stderr, "Failed to load config: %s @ %d\n", config_error_text(&g_config), config_error_line(&g_config));
        return -1;
    }

    if (CONFIG_TRUE != (rv = mst_read_version(&g_config))) {
        fprintf(stderr, "Error: %s @ %d\n", config_error_text(&g_config), config_error_line(&g_config));
        return -1;
    }
    if (CONFIG_TRUE != (rv = mst_read_type(&g_config))) {
        fprintf(stderr, "Error: %s @ %d\n", config_error_text(&g_config), config_error_line(&g_config));
        return -1;
    }
    if (CONFIG_TRUE != (rv = mst_read_globals(&g_config))) {
        fprintf(stderr, "Error: %s @ %d\n", config_error_text(&g_config), config_error_line(&g_config));
        return -1;
    }

    if (CONFIG_TRUE != (rv = mst_read_policy_details(&g_config))) {
        fprintf(stderr, "Error: %s @ %d\n", config_error_text(&g_config), config_error_line(&g_config));
        return -1;
    }

    return 0;
}

