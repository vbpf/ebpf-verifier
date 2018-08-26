/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */
#include <openvswitch/compiler.h>
#include "ovs-p4.h"
#include "api.h"
#include "helpers.h"
#include "maps.h"

/* eBPF executes actions by tailcall because eBPF doesn't support for-loop and
 * unroll produces oversized code.
 *
 * Each action handler uses current packet's key to look for the next action.
 * However, the key can be changed by some actions like hash, so a stable
 * key is kept in an eBPF map named percpu_executing_key. In action handler,
 * firstly, the stable key is got from percpu_executing_key, then it is used
 * to look up the actions being executed. skb->cb[OVS_CB_ACT_IDX] points to
 * next action.
 */
static inline void ovs_execute_actions(struct __sk_buff *skb,
                                       struct bpf_action *action)
{
    int type;

    type = action->type;

    printt("action type %d\n", type);
	/* note: this isn't a for loop, tail call won't return. */
    switch (type) {
    case OVS_ACTION_ATTR_UNSPEC:    //0
        printt("end of action processing\n");
        break;

    case OVS_ACTION_ATTR_OUTPUT: {  //1
        printt("output action port = %d\n", action->u.out.port);
        break;
    }
    case OVS_ACTION_ATTR_USERSPACE: {   //2
        printt("userspace action, len = %d, ifindex = %d upcall back\n",
               action->u.userspace.nlattr_len, ovs_cb_get_ifindex(skb));
        break;
    }
    case OVS_ACTION_ATTR_SET: { //3
        printt("set action, remote ipv4 = %x, is_set = %d\n",
               action->u.tunnel.remote_ipv4, action->is_set);
        break;
    }
    case OVS_ACTION_ATTR_PUSH_VLAN: { //4
        printt("vlan push tci %d\n", action->u.push_vlan.vlan_tci);
        break;
    }
    case OVS_ACTION_ATTR_POP_VLAN: { //5
        printt("vlan pop\n");
        break;
    }
    case OVS_ACTION_ATTR_RECIRC: { //7
        printt("recirc\n");
        break;
    }
    case OVS_ACTION_ATTR_HASH: { //8
        printt("hash\n");
        break;
    }
    case OVS_ACTION_ATTR_SET_MASKED: { //11
        printt("set masked\n");
        break;
    }
    case OVS_ACTION_ATTR_CT: { //12
        printt("ct\n");
        break;
    }
    case OVS_ACTION_ATTR_TRUNC: { //13
        printt("truncate\n");
        break;
    }
    default:
        printt("action type %d not support\n", type);
        break;
    }
    bpf_tail_call(skb, &tailcalls, type);
    return;
}

static inline void
stats_account(enum ovs_bpf_dp_stats index)
{
    uint32_t stat = 1;
    uint64_t *value;

    value = map_lookup_elem(&datapath_stats, &index);
    if (value) {
        __sync_fetch_and_add(value, stat);
    }
}
static inline void
flow_stats_account(struct ebpf_headers_t *headers,
                   struct ebpf_metadata_t *mds,
                   size_t bytes)
{
    struct bpf_flow_key flow_key;
    struct bpf_flow_stats *flow_stats;

    flow_key.headers = *headers;
    flow_key.mds = *mds;

    flow_stats = bpf_map_lookup_elem(&dp_flow_stats, &flow_key);
    if (!flow_stats) {
        struct bpf_flow_stats s = {0, 0, 0};
        int err;

        printt("flow not found in flow stats, first install\n");
        s.packet_count = 1;
        s.byte_count = bytes;
        s.used = bpf_ktime_get_ns() / (1000*1000); /* msec */
        err = bpf_map_update_elem(&dp_flow_stats, &flow_key, &s, BPF_ANY);
        if (err) {
            return;
        }
    } else {
        flow_stats->packet_count += 1;
        flow_stats->byte_count += bytes;
        flow_stats->used = bpf_ktime_get_ns() / (1000*1000); /* msec */
        printt("current: packets %d count %d ts %d\n",
            flow_stats->packet_count, flow_stats->byte_count, flow_stats->used);
    }

    return;
}

static inline struct bpf_action_batch *
ovs_lookup_flow(struct ebpf_headers_t *headers,
                struct ebpf_metadata_t *mds)
{
    struct bpf_flow_key flow_key;

    flow_key.headers = *headers;
    flow_key.mds = *mds;

    return bpf_map_lookup_elem(&flow_table, &flow_key);
}

/* first function called after tc ingress */
__section_tail(MATCH_ACTION_CALL)
static int lookup(struct __sk_buff* skb OVS_UNUSED)
{
    struct bpf_action_batch *action_batch;
    struct ebpf_headers_t *headers;
    struct ebpf_metadata_t *mds;

    headers = bpf_get_headers();
    if (!headers) {
        printt("no header\n");
        ERR_EXIT();
    }

    mds = bpf_get_mds();
    if (!mds) {
        printt("no md\n");
        ERR_EXIT();
    }

    /* LOOKUP */
    action_batch = ovs_lookup_flow(headers, mds);
    if (!action_batch) {
        printt("no action found, upcall\n");
        bpf_tail_call(skb, &tailcalls, UPCALL_CALL);
        return TC_ACT_OK;// this is tricky.
    }
    else {
        /* DP Stats Update */
        stats_account(OVS_DP_STATS_HIT);
        /* Flow Stats Update */
        flow_stats_account(headers, mds, skb->len);
        printt("found action\n");
    }

    struct bpf_flow_key flow_key;
    flow_key.headers = *headers;
    flow_key.mds = *mds;
    int index = 0;
    int error = bpf_map_update_elem(&percpu_executing_key, &index,
                                    &flow_key, BPF_ANY);
    if (error) {
        printt("update percpu_executing_key failed: %d\n", error);
        return TC_ACT_OK;
    }

    /* the subsequent actions will be tail called. */
    ovs_execute_actions(skb, &action_batch->actions[0]);

    printt("ERROR: tail call fails\n");
    return TC_ACT_OK;
}
