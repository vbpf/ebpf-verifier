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
#include <linux/ip.h>

#include "api.h"
#include "maps.h"
#include "helpers.h"
#define ALIGNED_CAST(TYPE, ATTR) ((TYPE) (void *) (ATTR))
/*
 * Every OVS action need to lookup the action list and
 * with index, find out the action to process
 */
static inline struct bpf_action *pre_tail_action(struct __sk_buff *skb,
    struct bpf_action_batch **__batch)
{
    uint32_t index = ovs_cb_get_action_index(skb);
    struct bpf_action *action = NULL;
    struct bpf_action_batch *batch;
    int zero_index = 0;

    if (index >= BPF_DP_MAX_ACTION)
        return NULL;

    if (skb->cb[OVS_CB_DOWNCALL_EXE]) {
        batch = bpf_map_lookup_elem(&execute_actions, &zero_index);
    } else {
        struct bpf_flow_key *exe_flow_key, flow_key;

        exe_flow_key = bpf_map_lookup_elem(&percpu_executing_key,
                                           &zero_index);
        if (!exe_flow_key) {
            printt("empty percpu_executing_key\n");
            return NULL;
        }

        flow_key = *exe_flow_key;
        batch = bpf_map_lookup_elem(&flow_table, &flow_key);
    }
    if (!batch) {
        printt("no batch action found\n");
        return NULL;
    }

    *__batch = batch;
    action = &((batch)->actions[index]); /* currently processing action */
    return action;
}

/*
 * After processing the action, tail call the next.
 */
static inline int post_tail_action(struct __sk_buff *skb,
    struct bpf_action_batch *batch)
{
    struct bpf_action *next_action;
    uint32_t index;

    if (!batch)
        return TC_ACT_SHOT;

    index = skb->cb[OVS_CB_ACT_IDX] + 1;
    skb->cb[OVS_CB_ACT_IDX] = index;

    if (index >= BPF_DP_MAX_ACTION)
        goto finish;

    next_action = &batch->actions[index];
    if (next_action->type == 0)
        goto finish;

    printt("next action type = %d\n", next_action->type);
    bpf_tail_call(skb, &tailcalls, next_action->type);
    printt("[BUG] tail call missing\n");
    return TC_ACT_SHOT;

finish:
    if (skb->cb[OVS_CB_DOWNCALL_EXE]) {
        int index = 0;
        bpf_map_delete_elem(&execute_actions, &index);
    }
    return TC_ACT_STOLEN;
}

__section_tail(OVS_ACTION_ATTR_UNSPEC)
static int tail_action_unspec(struct __sk_buff *skb)
{
    int index OVS_UNUSED = ovs_cb_get_action_index(skb);

    printt("action index = %d, end of processing\n", index);

    /* Handle actions=drop, we return SHOT so the device's dropped stats
       will be incremented (see sch_handle_ingress). 

       If there are more actions, ex: actions=a1,a2,drop, this is
       handled in post_tail_actions and return STOLEN
    */
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_OUTPUT)
static int tail_action_output(struct __sk_buff *skb)
{
    int ret __attribute__((__unused__));
    struct bpf_action *action;
    struct bpf_action_batch *batch;
    int flags;

    /* Deparser will update the packet content and metadata */
#if 0
    ret = ovs_deparser(skb);
    if (ret != 0)
        return TC_ACT_SHOT;
#endif

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* Internal dev is tap type and hooked only to bpf egress filter.
       When output to an internal device, a packet is clone-redirected to
       this device's ingress so that this packet is processed by kernel stack.
       Why? Since if the packet is sent to its egress, it is delivered to the
       tap device's socket, not kernel.
    */
    flags = action->u.out.flags & OVS_BPF_FLAGS_TX_STACK ? BPF_F_INGRESS : 0;
    printt("output action port = %d ingress? %d\n",
           action->u.out.port, (flags));
    bpf_clone_redirect(skb, action->u.out.port, flags);

    return post_tail_action(skb, batch);
}

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define TTL_OFF (ETH_HLEN + offsetof(struct iphdr, ttl))
#define DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))

static inline void set_ip_tos(struct __sk_buff *skb, __u8 new_tos)
{
    __u8 old_tos = load_byte(skb, TOS_OFF);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_tos, new_tos, 2);
    bpf_skb_store_bytes(skb, TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline void set_ip_ttl(struct __sk_buff *skb, __u8 new_ttl)
{
    __u8 old_ttl = load_byte(skb, TTL_OFF);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ttl, new_ttl, 2);
    bpf_skb_store_bytes(skb, TTL_OFF, &new_ttl, sizeof(new_ttl), 0);
}

static inline void set_ip_dst(struct __sk_buff *skb, __u32 new_dst)
{
    __u32 old_dst = load_word(skb, DST_OFF);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_dst, new_dst, 4);
    bpf_skb_store_bytes(skb, DST_OFF, &new_dst, sizeof(new_dst), 0);
} 

static inline void set_ip_src(struct __sk_buff *skb, __u32 new_src)
{
    __u32 old_src = load_word(skb, SRC_OFF);

    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_src, new_src, 4);
    bpf_skb_store_bytes(skb, SRC_OFF, &new_src, sizeof(new_src), 0);
}

__section_tail(OVS_ACTION_ATTR_SET)
static int tail_action_tunnel_set(struct __sk_buff *skb)
{
    struct bpf_tunnel_key key;
    int ret;
    uint64_t flags;

    struct bpf_action *action;
    struct bpf_action_batch *batch;
    struct ovs_action_set_tunnel *tunnel;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    if (!action->is_set)
        goto tunnel;

    switch (action->u.mset.key_type) {
    case OVS_KEY_ATTR_ETHERNET: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct ethhdr *eth = (struct ethhdr *)data;

        if (data + sizeof(*eth) > data_end) {
            return TC_ACT_SHOT;
        }

        memcpy((void *)eth->h_dest, (void *)&action->u.mset.key.ether.eth_dst, 6);
        memcpy((void *)eth->h_source, (void *)&action->u.mset.key.ether.eth_src, 6);
        break;
    }
    case OVS_KEY_ATTR_IPV4: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct ovs_key_ipv4 *ipv4 = &action->u.mset.key.ipv4;

        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
            return TC_ACT_SHOT;
        }

        set_ip_tos(skb, ipv4->ipv4_tos);
        set_ip_ttl(skb, ipv4->ipv4_ttl);
        //set_ip_src(skb, ipv4->ipv4_src);
        //set_ip_dst(skb, ipv4->ipv4_dst);

        //bpf_l3_csum_replace(skb, IP_CSUM_OFF, nh->saddr, ipv4->ipv4_src, 4);
        //bpf_l3_csum_replace(skb, IP_CSUM_OFF, nh->daddr, ipv4->ipv4_dst, 4);
        //bpf_l3_csum_replace(skb, IP_CSUM_OFF, nh->protocol, ipv4->ipv4_proto, 1);
        //bpf_l3_csum_replace(skb, IP_CSUM_OFF, nh->tos, ipv4->ipv4_tos, 2);
        //bpf_l3_csum_replace(skb, IP_CSUM_OFF, nh->ttl, ipv4->ipv4_ttl, 1);

        //nh->saddr = ipv4->ipv4_src;
        //nh->daddr = ipv4->ipv4_dst;
#if 0
        memcpy(&nh->saddr, &ipv4->ipv4_src, 8); 
        // printt("%x", ipv4->ipv4_dst);
        // nh->daddr = 1; 
        nh->protocol = ipv4->ipv4_proto;
        nh->tos = ipv4->ipv4_tos;
        nh->ttl = ipv4->ipv4_ttl;
        /* XXX ignore frag */
#endif
        break;
    }
    default:
        printt("Unsupported set %d\n", action->type);
        return TC_ACT_SHOT;
    }
    goto out;

tunnel:
    tunnel = &action->u.tunnel;

    /* hard-coded now, should fetch it from action->u */
    __builtin_memset(&key, 0x0, sizeof(key));
    key.tunnel_id = tunnel->tunnel_id;
    key.tunnel_tos = tunnel->tunnel_tos;
    key.tunnel_ttl = tunnel->tunnel_ttl;

    printt("tunnel_id = %x\n", key.tunnel_id);

    /* TODO: handle BPF_F_DONT_FRAGMENT and BPF_F_SEQ_NUMBER */
    flags = BPF_F_ZERO_CSUM_TX;
    if (!tunnel->use_ipv6) {
        key.remote_ipv4 = tunnel->remote_ipv4;
        flags &= ~BPF_F_TUNINFO_IPV6;
    } else {
        memcpy(&key.remote_ipv4, &tunnel->remote_ipv4, 16);
        flags |= BPF_F_TUNINFO_IPV6;
    }

    ret = bpf_skb_set_tunnel_key(skb, &key, sizeof(key), flags);
    if (ret < 0)
        printt("[ERROR] setting tunnel key\n");

    if (tunnel->gnvopt_valid) {
        ret = bpf_skb_set_tunnel_opt(skb, &tunnel->gnvopt,
                                     sizeof tunnel->gnvopt);
        if (ret < 0)
            printt("[ERROR] setting tunnel opt\n");
    }
out:
    return post_tail_action(skb, batch);
}

__section_tail(OVS_ACTION_ATTR_PUSH_VLAN)
static int tail_action_push_vlan(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    // -- Add vlan_tag_t and regenerate P4 --
    //  key->eth.vlan.tci = vlan->vlan_tci;
    //  key->eth.vlan.tpid = vlan->vlan_tpid;
    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("vlan push tci %d\n", action->u.push_vlan.vlan_tci);
    printt("vlan push tpid %d\n", action->u.push_vlan.vlan_tpid);
    bpf_skb_vlan_push(skb, action->u.push_vlan.vlan_tpid,
                           action->u.push_vlan.vlan_tci & ~VLAN_TAG_PRESENT);

    return post_tail_action(skb, batch);
}

__section_tail(OVS_ACTION_ATTR_POP_VLAN)
static int tail_action_pop_vlan(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("vlan pop %d\n");
    bpf_skb_vlan_pop(skb);

    // TODO: invalidate_flow_key()?
    //  key->eth.vlan.tci = 0;
    //  key->eth.vlan.tpid = 0;
    return post_tail_action(skb, batch);
}

__section_tail(OVS_ACTION_ATTR_RECIRC)
static int tail_action_recirc(struct __sk_buff *skb)
{
    u32 recirc_id = 0;
    struct bpf_action *action;
    struct bpf_action_batch *batch ;
    struct ebpf_metadata_t *ebpf_md;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    /* recirc should be the last action.
     * level does not handle */

    /* don't check the is_flow_key_valid(),
     * now always re-parsing the header.
     */
    recirc_id = action->u.recirc_id;
    printt("recirc id = %d\n", recirc_id);

    /* update metadata */
    ebpf_md = bpf_get_mds();
    if (!ebpf_md) {
        printt("lookup metadata failed\n");
        return TC_ACT_SHOT;
    }
    ebpf_md->md.recirc_id = recirc_id;

    skb->cb[OVS_CB_ACT_IDX] = 0;
    skb->cb[OVS_CB_DOWNCALL_EXE] = 0;

    /* FIXME: recirc should not call this. */
    // post_tail_action(skb, batch);
    // start from beginning, call the ebpf_filter()
    // but metadata should keep untouched?
    bpf_tail_call(skb, &tailcalls, MATCH_ACTION_CALL);
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_HASH)
static int tail_action_hash(struct __sk_buff *skb)
{
    u32 hash = 0;
    int index = 0;
    struct ebpf_metadata_t *ebpf_md;
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("skb->hash before = %x\n", skb->hash);
    hash = bpf_get_hash_recalc(skb);
    printt("skb->hash = %x hash \n", skb->hash);
    if (!hash)
        hash = 0x1;

    ebpf_md = bpf_map_lookup_elem(&percpu_metadata, &index);
    if (!ebpf_md) {
        printt("LOOKUP metadata failed\n");
        return TC_ACT_SHOT;
    }
    printt("save hash to ebpf_md->md.dp_hash\n");
    ebpf_md->md.dp_hash = hash; // or create a ovs_flow_hash?

    return post_tail_action(skb, batch);
}

/* write to packet's md, let deparser write to packet.
 * currently csum computation isn't supported.
 * here we only handle skb metadata udpate */
__section_tail(OVS_ACTION_ATTR_SET_MASKED)
static int tail_action_set_masked(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    switch (action->u.mset.key_type) {
    case OVS_KEY_ATTR_ETHERNET: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct ethhdr *eth;
        struct ovs_key_ethernet *ether;
        int i;

        /* packet data */
        eth = (struct ethhdr *)data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        /* value from map */
        ether = &action->u.mset.key.ether;
        for (i = 0; i < 6; i++)
            eth->h_dest[i] = ether->eth_dst.ea[i];
        for (i = 0; i < 6; i++)
            eth->h_source[i] = ether->eth_src.ea[i];
        break;
    }
    case OVS_KEY_ATTR_IPV4: {
        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;
        struct iphdr *nh;
        struct ovs_key_ipv4 *ipv4;

        /* packet data */
        nh = ALIGNED_CAST(struct iphdr *, data + sizeof(struct ethhdr));
        if ((u8 *)nh + sizeof(struct iphdr) + 12 > data_end) {
            return TC_ACT_SHOT;
        }

        /* value from map */
        ipv4 = &action->u.mset.key.ipv4;
        memcpy(&nh->saddr, &ipv4->ipv4_src, 8); 
        nh->protocol = ipv4->ipv4_proto;
        nh->tos = ipv4->ipv4_tos;
        nh->ttl = ipv4->ipv4_ttl;
        /* XXX ignore frag */
        break;
    }
    default:
        printt("ERR Unsupported set %d\n", action->type);
        return TC_ACT_SHOT;
    }

    return post_tail_action(skb, batch);
}

__section_tail(OVS_ACTION_ATTR_TRUNC)
static int tail_action_trunc(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    printt("len before: %d\n", skb->len);
    printt("truncate to %d\n", action->u.trunc.max_len);

    /* The helper will resize the skb to the given new size */
    bpf_skb_change_tail(skb, action->u.trunc.max_len, 0);

    printt("len after: %d\n", skb->len);
    return post_tail_action(skb, batch);
}

#define SKB_DATA_CAST(x) ((void *)(long)x)

__section_tail(OVS_ACTION_ATTR_CT)
static int tail_action_ct(struct __sk_buff *skb __attribute__((__unused__)))
{
#if 0
    struct ipv4_ct_tuple tuple = {};
    struct ct_state ct_state = {};
    void *data = SKB_DATA_CAST(skb->data);
    void *data_end = SKB_DATA_CAST(skb->data_end);

    struct bpf_action_batch *batch;
    struct ebpf_headers_t *headers;
    struct ebpf_metadata_t *md;
    struct bpf_action *action;
    struct iphdr *ipv4;
    int l4_ofs, dir;
    bool commit;
    int res;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    commit = action->u.ct.commit;

    headers = bpf_get_headers();
    if (!headers) {
        printt("no header\n");
        return TC_ACT_SHOT;
    }

    if (headers->ethernet.etherType != 0x0800) {
        printt("ct: dropping non-IPv4 packet\n");
        return TC_ACT_SHOT;
    }

#define ETH_HLEN 14 /* XXX */

    if (data + sizeof(*ipv4) + ETH_HLEN > data_end) {
        printt("ct: IP packet too short\n");
        return TC_ACT_SHOT;
    }

    ipv4 = (struct iphdr *)(data + ETH_HLEN);
    tuple.daddr = ipv4->daddr;
    tuple.saddr = ipv4->saddr;
    tuple.nexthdr = ipv4->protocol;
    l4_ofs = ETH_HLEN + ipv4_hdrlen(ipv4);
    /* tuple l4 ports are filled by ct_lookup */
    dir = skb->cb[OVS_CB_INGRESS] ? CT_INGRESS : CT_EGRESS;

    res = ct_lookup4(&ct_table4, &tuple, skb, l4_ofs, 0, dir, &ct_state);
    if (res < 0) {
        /* XXX: OVS_CS_F_INVALID */
        printt("ct() err=%d\n", res);
        return TC_ACT_SHOT;
    }
    printt("ct() success=%d\n", res);

    md = bpf_get_mds();
    if (!md) {
        printt("lookup metadata failed\n");
        return TC_ACT_SHOT;
    }
    //md->md.ct_state = OVS_CS_F_TRACKED;

    //switch (res) {
    //case CT_NEW:
    //    md->md.ct_state |= OVS_CS_F_NEW;
    //    break;
    //case CT_ESTABLISHED:
    //    md->md.ct_state |= OVS_CS_F_ESTABLISHED;
    //    break;
    //case CT_RELATED:
    //    md->md.ct_state |= OVS_CS_F_RELATED;
    //    break;
    //case CT_REPLY:
    //    md->md.ct_state |= OVS_CS_F_REPLY_DIR;
    //default:
    //    return TC_ACT_SHOT;
    //}

    /* XXX: Commit, mark, label */
    if (commit) {
        int err;

        printt("ct commit\n");
        err = ct_create4(&ct_table4, &tuple, skb, dir, &ct_state, false);
        if (err) {
            printt("ct creation failed\n");
            return TC_ACT_SHOT;
        }
    }

    /* XXX: NAT, etc. */
    /* XXX: OVS_CS_F_SRC_NAT; OVS_CS_F_DST_NAT */

    post_tail_action(skb, batch);
#endif
    return TC_ACT_SHOT;
}

__section_tail(OVS_ACTION_ATTR_USERSPACE)
static int tail_action_userspace(struct __sk_buff *skb)
{
    struct bpf_action *action;
    struct bpf_action_batch *batch;

    action = pre_tail_action(skb, &batch);
    if (!action)
        return TC_ACT_SHOT;

    // XXX If move this declaration to top, the stack will overflow..
    struct bpf_upcall md = {
        .type = OVS_UPCALL_ACTION,
        .skb_len = skb->len,
        .ifindex = skb->ifindex,
    };

    if (action->u.userspace.nlattr_len > sizeof(md.uactions)) {
        printt("userspace action is too large\n");
        return TC_ACT_SHOT;
    }

    memcpy(md.uactions, action->u.userspace.nlattr_data, sizeof(md.uactions));
    md.uactions_len = action->u.userspace.nlattr_len;

    struct ebpf_headers_t *hdrs = bpf_get_headers();
    if (!hdrs) {
        printt("headers is NULL\n");
        return TC_ACT_SHOT;
    }

    memcpy(&md.key.headers, hdrs, sizeof(*hdrs));

    uint64_t flags = skb->len;
    flags <<= 32;
    flags |= BPF_F_CURRENT_CPU;
    int err = skb_event_output(skb, &upcalls, flags, &md, sizeof md);
    if (err) {
        printt("skb_event_output of userspace action: %d", err);
        return TC_ACT_SHOT;
    }

    return post_tail_action(skb, batch);
}
