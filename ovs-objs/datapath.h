/*
 * Copyright (c) 2017 Nicira, Inc.
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

#include "odp-bpf.h"

#define SKB_CB_U32S 5   /* According to linux/bpf.h. */

enum ovs_cb_idx {
    OVS_CB_ACT_IDX,         /* Next action to process in action batch. */
    OVS_CB_INGRESS,         /* 0 = egress; nonzero = ingress. */
    OVS_CB_DOWNCALL_EXE,    /* 0 = match/execute, 1 = downcall/execute. */
};

static void
ovs_cb_init(struct __sk_buff *skb, bool ingress)
{
    for (int i = 0; i < SKB_CB_U32S; i++)
        skb->cb[i] = 0;
    skb->cb[OVS_CB_INGRESS] = ingress;
}

static bool
ovs_cb_is_initial_parse(struct __sk_buff *skb) {
    int index = skb->cb[OVS_CB_ACT_IDX];

    if (index != 0) {
        printt("recirc, don't update metadata, index %d\n", index);
    }
    return index == 0;
}

static uint32_t
ovs_cb_get_action_index(struct __sk_buff *skb)
{
    return skb->cb[OVS_CB_ACT_IDX];
}

static uint32_t OVS_UNUSED
ovs_cb_get_ifindex(struct __sk_buff *skb)
{
    uint32_t ifindex;

    if (!skb)
        return 0;

    if (skb->cb[OVS_CB_INGRESS]) {
        __asm__ __volatile__("": : :"memory");
        return skb->ingress_ifindex;
    }
    ifindex = skb->ifindex;
    __asm__ __volatile__("": : :"memory");


    return ifindex;
}
