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

/* Protocol parser generated from P4 1.0
 *
 * TODO:
 * - move to P4 2016
 * - use union for protocol header to save space
 */
#include "ovs-p4.h"
#include "api.h"
#include "helpers.h"
#include "maps.h"
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>


/* First function called after tc ingress.
 *
 * This function takes skb->ifindex as packet's in_port. Watch out that
 * for packets from downcall, their skb->ifindex may not be accurate.
 */
__section_tail(PARSER_CALL)
static int ovs_parser(struct __sk_buff* skb) {
    struct ebpf_headers_t ebpf_headers = {};
    struct ebpf_metadata_t ebpf_metadata = {};
    unsigned skbOffsetInBits = 0;
    enum ErrorCode ebpf_error = p4_pe_no_error;
    u32 ebpf_zero = 0;
    int offset = 0;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if ((char *)data + sizeof(*eth) > (char *)(long)skb->data_end) {
        return 0;
    }

    ebpf_headers.valid = 0;
    printt("proto = %x len = %d vlan_tci = %x\n",
           eth->h_proto, skb->len, (int)skb->vlan_tci);
    printt("skb->ingress_ifindex %d skb->ifindex %d\n",
           skb->ingress_ifindex, skb->ifindex);

    //if (eth->h_proto == 0 || eth->h_proto == 0xdd86) {
    //    return 0;
    //}

    if (skb->cb[OVS_CB_ACT_IDX] != 0) {
        printt("this is a downcall packet\n");
    }

    if (skb_load_bytes(skb, offset, &ebpf_headers.ethernet, 14) < 0) {
        ebpf_error = p4_pe_header_too_short;
        goto end;
    }
    ebpf_headers.valid |= ETHER_VALID;
    offset += 14;
    skbOffsetInBits = offset * 8;

    /* vlan_tci is in host byte order. */
    if (skb->vlan_tci) {
        ebpf_headers.vlan.tci = skb->vlan_tci | VLAN_TAG_PRESENT;
        ebpf_headers.vlan.etherType = skb->vlan_proto;
        ebpf_headers.valid |= VLAN_VALID;
        printt("vlan proto %x tci %x\n", skb->vlan_proto, skb->vlan_tci);
    }

    u32 tmp_3 = eth->h_proto;
    if (tmp_3 == 0x0081 || tmp_3 == 0xA888) {
        if (ebpf_headers.valid & VLAN_VALID) {
            goto parse_cvlan;
        }

        printt("XXX nested vlan? not supported!\n");
        if (1) return 0;
        if (skb->vlan_tci) {
            goto parse_cvlan;
        } else {
            goto parse_vlan;
        }
    } if (tmp_3 == 0x0608) {
        goto parse_arp;
    } if (tmp_3 == 0x0008) {
        goto parse_ipv4;
    } if (tmp_3 == 0xDD86) {
        goto parse_ipv6;
    } else {
        goto ovs_tbl_4;
    }

    parse_vlan: {
        struct vlan_tag_t *vlan = &ebpf_headers.vlan;
        if (skb_load_bytes(skb, offset, &vlan, 4) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        printt("parsing vlan\n");
        offset += 4;
        skbOffsetInBits = offset * 8;

        {
            u32 tmp_5 = ebpf_headers.vlan.etherType;
            if (tmp_5 == 0x0608)
                goto parse_arp;
            if (tmp_5 == 0x0008)
                goto parse_ipv4;
            if (tmp_5 == 0xDD86)
                goto parse_ipv6;
            if (tmp_5 == 0x0081 || tmp_5 == 0xA888) {
                printt("not support 3-layer of vlan");
                goto parse_cvlan;
            } else
                goto ovs_tbl_4;
        }
    }
    parse_cvlan: {
        if (skb_load_bytes(skb, offset, &ebpf_headers.cvlan, 4) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        printt("parsing vlanc\n");
        offset += 4;
        skbOffsetInBits = offset * 8;
        ebpf_headers.valid |= CVLAN_VALID;
        u32 tmp_5 = ebpf_headers.cvlan.etherType;
        if (tmp_5 == 0x0608)
            goto parse_arp;
        if (tmp_5 == 0x0008)
            goto parse_ipv4;
        if (tmp_5 == 0xDD86)
            goto parse_ipv6;
        if (tmp_5 == 0x0081) {
            ebpf_error = p4_pe_too_many_encap;
            goto end;
        }
        else
            goto ovs_tbl_4;
    }
    parse_arp: {
        struct arp_rarp_t *arp = &ebpf_headers.arp;
        if (skb_load_bytes(skb, offset, arp, sizeof ebpf_headers.arp) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        if (arp->ar_hrd == 0x0100 &&
            arp->ar_pro == 0x0008 &&
            arp->ar_hln == 6 &&
            arp->ar_pln == 4) {

            printt("valid arp\n");
        } else {
            printt("Invalid arp\n");
        }
        offset += sizeof ebpf_headers.arp;
        skbOffsetInBits = offset * 8;
        ebpf_headers.valid |= ARP_VALID;
        goto ovs_tbl_4;
    }
    parse_ipv4: {
        struct iphdr nh;
        if (skb_load_bytes(skb, offset, &nh, 20) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        offset += nh.ihl * 4;
        ebpf_headers.ipv4.ttl = nh.ttl;
        ebpf_headers.ipv4.protocol = nh.protocol;
        ebpf_headers.ipv4.srcAddr = nh.saddr;
        ebpf_headers.ipv4.dstAddr = nh.daddr;
        skbOffsetInBits = offset * 8;
        ebpf_headers.valid |= IPV4_VALID;
        u32 tmp_6 = ebpf_headers.ipv4.protocol;
        if (tmp_6 == 6)
            goto parse_tcp;
        if (tmp_6 == 17)
            goto parse_udp;
        if (tmp_6 == 1)
            goto parse_icmp;
        else
            goto ovs_tbl_4;
    }
    parse_ipv6: {
#ifdef BPF_ENABLE_IPV6
        if (skb->len < BYTES(skbOffsetInBits + 4)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.version = ((load_byte(skb, (skbOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u8, 4);
        skbOffsetInBits += 4;
        if (skb->len < BYTES(skbOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv6.trafficClass = ((load_half(skb, (skbOffsetInBits + 0) / 8)) >> (4)) & EBPF_MASK(u16, 8);
        ebpf_headers.ipv6.trafficClass = 0;
        skbOffsetInBits += 8;
        if (skb->len < BYTES(skbOffsetInBits + 20)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.flowLabel = ((load_word(skb, (skbOffsetInBits + 0) / 8)) >> (8)) & EBPF_MASK(u32, 20);
        skbOffsetInBits += 20;
        if (skb->len < BYTES(skbOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv6.payloadLen = ((load_half(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv6.payloadLen = 0;
        skbOffsetInBits += 16;
        if (skb->len < BYTES(skbOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.ipv6.nextHdr = ((load_byte(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        skbOffsetInBits += 8;
        if (skb->len < BYTES(skbOffsetInBits + 8)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.ipv6.hopLimit = ((load_byte(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.ipv6.hopLimit = 0;
        skbOffsetInBits += 8;
        if (skb->len < BYTES(skbOffsetInBits + 8*16*2)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        if (skb_load_bytes(skb, skbOffsetInBits/8, &ebpf_headers.ipv6.srcAddr, 32) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        skbOffsetInBits += 8*16*2;;
        ebpf_headers.valid |= IPV6_VALID;
        u32 tmp_7 = ebpf_headers.ipv6.nextHdr;
        printt("ipv6 proto %d\n", tmp_7);
        if (tmp_7 == 6)
            goto parse_tcp;
        if (tmp_7 == 17)
            goto parse_udp;
        if (tmp_7 == 58)
            goto parse_icmpv6;
        if (tmp_7 == 41 || tmp_7 == 43 || tmp_7 == 44 || tmp_7 == 51) { /* IPPROTO_FRAGMENT */
            printt("icmpv6 extension header not support");
            return TC_ACT_SHOT;
        }
        else {
            printt("ipv6 proto %x not parsed\n");
            goto ovs_tbl_4;
        }
#else
        ebpf_error = p4_pe_ipv6_disabled;
        goto end;
#endif
    }
    parse_tcp: {
        if (skb_load_bytes(skb, offset, &ebpf_headers.tcp, 4) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        offset += sizeof ebpf_headers.tcp - 1;

        skbOffsetInBits = offset * 8;
        ebpf_headers.valid |= TCP_VALID;
        goto ovs_tbl_4;
    }
    parse_udp: {
        if (skb->len < BYTES(skbOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.udp.srcPort = ((load_half(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        skbOffsetInBits += 16;
        if (skb->len < BYTES(skbOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        ebpf_headers.udp.dstPort = ((load_half(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        skbOffsetInBits += 16;
        if (skb->len < BYTES(skbOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        //ebpf_headers.udp.length_ = ((load_half(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.udp.length_ = 0;
        skbOffsetInBits += 16;
        if (skb->len < BYTES(skbOffsetInBits + 16)) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        // Remove from key
        // ebpf_headers.udp.checksum = ((load_half(skb, (skbOffsetInBits + 0) / 8)) >> (0));
        ebpf_headers.udp.checksum = 0;
        skbOffsetInBits += 16;
        ebpf_headers.valid |= UDP_VALID;
        goto ovs_tbl_4;
    }
    parse_icmp: {
        if (skb_load_bytes(skb, offset, &ebpf_headers.icmp, 2) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        printt("icmp type = %x code = %x\n", ebpf_headers.icmp.type,
               ebpf_headers.icmp.code);

        // XXX frag
        if (ebpf_headers.icmp.code > 15) {
            ebpf_headers.icmp.type = 0;
            ebpf_headers.icmp.code = 0;
        }
        offset += 8;
        skbOffsetInBits = offset * 8;
        ebpf_headers.valid |= ICMP_VALID;
        goto ovs_tbl_4;
    }
#ifdef BPF_ENABLE_IPV6
    parse_icmpv6: {
        if (skb_load_bytes(skb, offset, &ebpf_headers.icmpv6,
                           sizeof(struct icmpv6_t)) < 0) {
            ebpf_error = p4_pe_header_too_short;
            goto end;
        }
        printt("icmpv6 type = %x code = %x\n", ebpf_headers.icmpv6.type,
               ebpf_headers.icmpv6.code);

        offset += 16;
        skbOffsetInBits = offset * 8;
        ebpf_headers.valid |= ICMPV6_VALID;
        goto ovs_tbl_4;
    }
#endif

    /* Most of the code are generated by P4C-EBPF
       Manual code starts here */
    ovs_tbl_4:
    {
        int ret;
        struct bpf_tunnel_key key;

        ebpf_metadata.md.skb_priority = skb->priority;

        /* Don't use ovs_cb_get_ifindex(), that gets optimized into something
         * that can't be verified. >:( */
        if (skb->cb[OVS_CB_INGRESS]) {
            ebpf_metadata.md.in_port = skb->ingress_ifindex;
        }
        if (!skb->cb[OVS_CB_INGRESS]) {
            ebpf_metadata.md.in_port = skb->ifindex;
        }
        ebpf_metadata.md.pkt_mark = skb->mark;
        ebpf_metadata.md.packet_length = skb->len;

        ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key), 0);
        if (!ret) {
            printt("bpf_skb_get_tunnel_key id = %d ipv4\n", key.tunnel_id);
            ebpf_metadata.tnl_md.tun_id = key.tunnel_id;
            ebpf_metadata.tnl_md.ip4.ip_src = key.remote_ipv4;
            ebpf_metadata.tnl_md.ip_tos = key.tunnel_tos;
            ebpf_metadata.tnl_md.ip_ttl = key.tunnel_ttl;
            ebpf_metadata.tnl_md.use_ipv6 = 0;
            ebpf_metadata.tnl_md.flags = 0; //0x10;
#ifdef BPF_ENABLE_IPV6
        } else if (ret == -EPROTO) {
            ret = bpf_skb_get_tunnel_key(skb, &key, sizeof(key),
                                         BPF_F_TUNINFO_IPV6);
            if (!ret) {
                printt("bpf_skb_get_tunnel_key id = %d ipv6\n", key.tunnel_id);
                ebpf_metadata.tnl_md.tun_id = key.tunnel_id;
                memcpy(&ebpf_metadata.tnl_md.ip6.ipv6_src, &key.remote_ipv4, 16);
                ebpf_metadata.tnl_md.ip_tos = key.tunnel_tos;
                ebpf_metadata.tnl_md.ip_ttl = key.tunnel_ttl;
                ebpf_metadata.tnl_md.use_ipv6 = 1;
                ebpf_metadata.tnl_md.flags = 0; //0x10;
            }
#endif
        }

        if (!ret) {
            ret = bpf_skb_get_tunnel_opt(skb, &ebpf_metadata.tnl_md.gnvopt,
                                         sizeof ebpf_metadata.tnl_md.gnvopt);
            if (ret > 0)
                ebpf_metadata.tnl_md.gnvopt_valid = 1;
            printt("bpf_skb_get_tunnel_opt ret = %d\n", ret);
        }
    }

end:
    if (ebpf_error != p4_pe_no_error) {
        printt("parse error, drop\n";);
        return TC_ACT_SHOT;
    }

    /* write flow key and md to key map */
    printt("Parser: updating flow key\n");
    bpf_map_update_elem(&percpu_headers,
                        &ebpf_zero, &ebpf_headers, BPF_ANY);

    if (ovs_cb_is_initial_parse(skb)) {
        bpf_map_update_elem(&percpu_metadata,
                            &ebpf_zero, &ebpf_metadata, BPF_ANY);
    }
    skb->cb[OVS_CB_ACT_IDX] = 0;

    /* tail call next stage */
    printt("tail call match+lookup stage\n");
    bpf_tail_call(skb, &tailcalls, MATCH_ACTION_CALL);

    printt("[ERROR] missing tail call\n");
    return TC_ACT_OK;
}
