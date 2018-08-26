/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * This file is offered under your choice of two licenses: Apache 2.0 or GNU
 * GPL 2.0 or later.  The permission statements for each of these licenses is
 * given below.  You may license your modifications to this file under either
 * of these licenses or both.  If you wish to license your modifications under
 * only one of these licenses, delete the permission text for the other
 * license.
 *
 * ----------------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------
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
 * ----------------------------------------------------------------------
 */

#ifndef BPF_OPENVSWITCH_H
#define BPF_OPENVSWITCH_H 1

#include "odp-netlink.h"
#include "generated_headers.h"

enum ovs_upcall_cmd {
    OVS_UPCALL_UNSPEC = OVS_PACKET_CMD_UNSPEC,

    /* Kernel-to-user notifications. */
    OVS_UPCALL_MISS = OVS_PACKET_CMD_MISS,
    OVS_UPCALL_ACTION = OVS_PACKET_CMD_ACTION,

    /* Userspace commands. */
    OVS_UPCALL_EXECUTE = OVS_PACKET_CMD_EXECUTE,

    OVS_UPCALL_DEBUG,
};

enum ovs_dbg_subtype {
    OVS_DBG_ST_UNSPEC,
    OVS_DBG_ST_REDIRECT,
    __OVS_DBG_ST_MAX,
};
#define OVS_DBG_ST_MAX (__OVS_DBG_ST_MAX - 1)

static const char *bpf_upcall_subtypes[] OVS_UNUSED = {
    [OVS_DBG_ST_UNSPEC] = "Unspecified",
    [OVS_DBG_ST_REDIRECT] = "Downcall redirect",
};

/* Used with 'datapath_stats' map. */
enum ovs_bpf_dp_stats {
    OVS_DP_STATS_UNSPEC,
    OVS_DP_STATS_HIT,
    OVS_DP_STATS_MISSED,
    OVS_DP_STATS_LOST,
    OVS_DP_STATS_FLOWS,
    OVS_DP_STATS_MASK_HIT,
    OVS_DP_STATS_MASKS,
    OVS_DP_STATS_ERRORS,
    __OVS_DP_STATS_MAX,
};
#define OVS_DP_STATS_MAX (__OVS_DP_STATS_MAX - 1)

struct bpf_flow {
    uint64_t value;             /* XXX */
};

struct bpf_flow_stats {
    uint64_t packet_count;  /* Number of packets matched. */
    uint64_t byte_count;    /* Number of bytes matched. */
    uint64_t used;     /* Last used time (in jiffies). */
    //spinlock_t lock;        /* Lock for atomic stats update. */
    //__be16 tcp_flags;       /* Union of seen TCP flags. */
};

struct bpf_flow_key {
    struct ebpf_headers_t headers;
    struct ebpf_metadata_t mds;
};

struct bpf_upcall {
    uint8_t type;
    uint8_t subtype;
    uint32_t ifindex;           /* Incoming device */
    uint32_t cpu;
    uint32_t error;
    uint32_t skb_len;
#ifdef BPF_ENABLE_IPV6
    uint8_t uactions[24];      /* Contains 'struct nlattr' */
#else
    uint8_t uactions[64];
#endif
    uint32_t uactions_len;
    struct bpf_flow_key key;
    /* Followed by 'skb_len' of packet data. */
};

#define OVS_BPF_FLAGS_TX_STACK (1 << 0)

#define OVS_BPF_DOWNCALL_UNSPEC     0
#define OVS_BPF_DOWNCALL_OUTPUT     1
#define OVS_BPF_DOWNCALL_EXECUTE    2

struct bpf_downcall {
    uint32_t type;
    uint32_t ifindex;
    uint32_t debug;
    uint32_t flags;
    struct ebpf_metadata_t md;
    /* Followed by packet data. */
};

#define ETH_ALEN 6

#define OVS_ACTION_ATTR_UNSPEC      0
#define OVS_ACTION_ATTR_OUTPUT      1
#define OVS_ACTION_ATTR_USERSPACE   2
#define OVS_ACTION_ATTR_SET         3
#define OVS_ACTION_ATTR_PUSH_VLAN   4
#define OVS_ACTION_ATTR_POP_VLAN    5
#define OVS_ACTION_ATTR_SAMPLE      6
#define OVS_ACTION_ATTR_RECIRC      7
#define OVS_ACTION_ATTR_HASH        8
#define OVS_ACTION_ATTR_PUSH_MPLS   9
#define OVS_ACTION_ATTR_POP_MPLS    10
#define OVS_ACTION_ATTR_SET_MASKED  11
#define OVS_ACTION_ATTR_CT          12
#define OVS_ACTION_ATTR_TRUNC       13
#define OVS_ACTION_ATTR_PUSH_ETH    14
#define OVS_ACTION_ATTR_POP_ETH     15

#define VLAN_CFI_MASK       0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT    VLAN_CFI_MASK

struct flow_key {
    __be32 src;
    __be32 dst;
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
};

struct ovs_action_set_tunnel {
    /* light weight tunnel key */
   __u32 tunnel_id; /* tunnel id is host byte order */
   union {
        __u32 remote_ipv4; /* host byte order */
        __u32 remote_ipv6[4];
   };
   __u8 tunnel_tos;
   __u8 tunnel_ttl;
   __u16 tunnel_ext;
   __u32 tunnel_label;
   struct gnv_opt gnvopt;
   __u8 gnvopt_valid;
   __u8 use_ipv6;
};

struct ovs_action_set_masked {
    int key_type;
    union {
        struct ovs_key_ethernet ether;
        struct ovs_key_mpls mpls;
        struct ovs_key_ipv4 ipv4;
        struct ovs_key_ipv6 ipv6;
        struct ovs_key_tcp tcp;
        struct ovs_key_udp udp;
        struct ovs_key_sctp sctp;
        struct ovs_key_icmp icmp;
        struct ovs_key_icmpv6 icmpv6;
        struct ovs_key_arp arp;
    } key;
#if 0
    /* BPF datapath does not support mask */
    union {
        struct ovs_key_ethernet ether;
        struct ovs_key_mpls mpls;
        struct ovs_key_ipv4 ipv4;
        struct ovs_key_ipv6 ipv6;
        struct ovs_key_tcp tcp;
        struct ovs_key_udp udp;
        struct ovs_key_sctp sctp;
        struct ovs_key_icmp icmp;
        struct ovs_key_icmpv6 icmpv6;
        struct ovs_key_arp arp;
    } mask;
#endif
};

struct ovs_action_output {
    uint32_t port;
    uint32_t flags;
};

struct ovs_action_ct {
    int commit;
    /* XXX: Include everything in enum ovs_ct_attr. */
};

struct ovs_action_userspace {
    __u16 nlattr_len;
    __u8 nlattr_data[64];
};

struct bpf_action {
    uint32_t type;  /* action type */
    uint32_t is_set;
    union {
        struct ovs_action_output out;   /* OVS_ACTION_ATTR_OUTPUT: 8B */
        struct ovs_action_trunc trunc;  /* OVS_ACTION_ATTR_TRUNC: 4B */
        struct ovs_action_hash hash;    /* OVS_ACTION_ATTR_HASH: 8B */
        struct ovs_action_push_mpls mpls;   /* OVS_ACTION_ATTR_PUSH_MPLS: 6B */
        ovs_be16 ethertype;                   /* OVS_ACTION_ATTR_POP_MPLS: 2B */
        struct ovs_action_push_vlan push_vlan;  /* OVS_ACTION_ATTR_PUSH_VLAN: 4B */
                                                /* OVS_ACTION_ATTR_POP_VLAN: 0B */
        uint32_t recirc_id;                 /* OVS_ACTION_ATTR_RECIRC: 4B */
        struct ovs_action_set_tunnel tunnel;
        struct ovs_action_set_masked mset;  /* OVS_ACTION_ATTR_SET_MASK: */
        struct ovs_action_ct ct;        /* OVS_ACTION_ATTR_CT:  */
        struct ovs_action_userspace userspace;  /* OVS_ACTION_ATTR_USERSPACE: */

        uint64_t aligned[16]; // make it 128 byte
    } u;
};

#define BPF_DP_MAX_ACTION 32
struct bpf_action_batch {
    struct bpf_action actions[BPF_DP_MAX_ACTION];
};

#endif /* BPF_OPENVSWITCH_H */
