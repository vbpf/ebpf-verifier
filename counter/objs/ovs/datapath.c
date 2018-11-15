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

#include <errno.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>

#include "api.h"
#include "odp-bpf.h"
#include "datapath.h"

/* Instead of having multiple BPF object files,
 * include all headers and generate one datapath.o
 */
#include "maps.h"
#include "parser.h"
#include "lookup.h"
#include "action.h"
#include "xdp.h"

/* We don't rely on specific versions of the kernel; however libbpf requires
 * this to be both specified and non-zero. */
static const __maybe_unused __section("version") uint32_t version = 0x1;

static inline void __maybe_unused
bpf_debug(struct __sk_buff *skb, enum ovs_dbg_subtype subtype, int error)
{
    uint64_t cpu = get_smp_processor_id();
    uint64_t flags = skb->len;
    struct bpf_upcall md = {
        .type = OVS_UPCALL_DEBUG,
        .subtype = subtype,
        .ifindex = skb->ingress_ifindex,
        .cpu = cpu,
        .skb_len = skb->len,
        .error = error
    };

    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;

    skb_event_output(skb, &upcalls, flags, &md, sizeof(md));
}

__section_tail(UPCALL_CALL)
static inline int process_upcall(struct __sk_buff *skb) //remove ifindex
{
    struct bpf_upcall md = {
        .type = OVS_UPCALL_MISS,
        .skb_len = skb->len,
        //.ifindex = ovs_cb_get_ifindex(skb),
    };
    int stat, err;
    struct ebpf_headers_t *hdrs = bpf_get_headers();
    struct ebpf_metadata_t *mds = bpf_get_mds();

    if (!hdrs || !mds) {
        printt("headers/mds is NULL\n");
        return TC_ACT_OK;
    }

    md.ifindex = mds->md.in_port;

    memcpy(&md.key.headers, hdrs, sizeof(struct ebpf_headers_t));
    memcpy(&md.key.mds, mds, sizeof(struct ebpf_metadata_t));

    if (hdrs->valid & VLAN_VALID) {
        printt("upcall skb->len(%d) with vlan %x %x\n",
               skb->len, hdrs->vlan.etherType, hdrs->vlan.tci);
        skb_vlan_push(skb, hdrs->vlan.etherType,
                      hdrs->vlan.tci & ~VLAN_TAG_PRESENT);
        md.skb_len = skb->len;
    }

    uint64_t flags = skb->len;
    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;

    err = skb_event_output(skb, &upcalls, flags, &md, sizeof(md));
    stat = !err ? OVS_DP_STATS_MISSED
                : err == -ENOSPC ? OVS_DP_STATS_LOST
                                 : OVS_DP_STATS_ERRORS;
    stats_account(stat);
    return TC_ACT_OK;
}

/* ENTRY POINT */
__section("ingress")
static int to_stack(struct __sk_buff *skb)
{
    printt("\n\ningress from %d (%d)\n", skb->ingress_ifindex, skb->ifindex);

    ovs_cb_init(skb, true);
    bpf_tail_call(skb, &tailcalls, PARSER_CALL);

    printt("[ERROR] tail call fail in ingress\n");
    return TC_ACT_SHOT;
}

__section("egress")
static int from_stack(struct __sk_buff *skb)
{
    printt("\n\negress from %d (%d)\n", skb->ingress_ifindex, skb->ifindex);

    ovs_cb_init(skb, false);
    bpf_tail_call(skb, &tailcalls, PARSER_CALL);

    printt("[ERROR] tail call fail in egress\n");
    return TC_ACT_SHOT;
}

__section("downcall")
static int execute(struct __sk_buff *skb)
{
    struct bpf_downcall md;
    u32 ebpf_zero = 0;
    int flags, ofs;

    ofs = skb->len - sizeof(md);
    skb_load_bytes(skb, ofs, &md, sizeof(md));
    flags = md.flags & OVS_BPF_FLAGS_TX_STACK ? BPF_F_INGRESS : 0;

    printt("downcall (%d) from %d flags %d\n", md.type,
           md.ifindex, flags);

    bpf_map_update_elem(&percpu_metadata, &ebpf_zero, &md.md, BPF_ANY);

    skb_change_tail(skb, ofs, 0);

    switch (md.type) {
    case OVS_BPF_DOWNCALL_EXECUTE: {
        struct bpf_action_batch *action_batch;

        action_batch = bpf_map_lookup_elem(&execute_actions, &ebpf_zero);
        if (action_batch) {
            printt("get valid action_batch\n");
            skb->cb[OVS_CB_DOWNCALL_EXE] = 1;
            bpf_tail_call(skb, &tailcalls, action_batch->actions[0].type);
        } else {
            printt("get null action_batch\n");
        }
        break;
    }
    case OVS_BPF_DOWNCALL_OUTPUT: {
        /* Skip writing the BPF metadata in parser */
        skb->cb[OVS_CB_ACT_IDX] = -1;
        /* Redirect to the device this packet came from, so it's as though the
         * packet was freshly received. This should execute PARSER_CALL. */
        return redirect(md.ifindex, flags);
    }
    default:
        printt("Unknown downcall type %d\n", md.type);
        break;
    }
    return 0;
}

BPF_LICENSE("GPL");
