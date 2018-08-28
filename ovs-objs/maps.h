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

#ifndef BPFMAP_OPENVSWITCH_H
#define BPFMAP_OPENVSWITCH_H 1

#include "api.h"
#include "openvswitch.h"
#include "ovs-p4.h"

/* ovs-vswitchd as a writer will update these maps.
 * bpf datapath as reader lookup and processes */

/* FIXME: copy from iproute2 */
enum {
    BPF_MAP_ID_PROTO,
    BPF_MAP_ID_QUEUE,
    BPF_MAP_ID_DROPS,
    BPF_MAP_ID_ACTION,
    BPF_MAP_ID_INGRESS,
    __BPF_MAP_ID_MAX,
#define BPF_MAP_ID_MAX  __BPF_MAP_ID_MAX
};

/* ---------------------*/
/*    BPF Program Map   */
/* ---------------------*/
BPF_PERCPU_ARRAY(percpu_headers,
        0,
        sizeof(struct ebpf_headers_t),
        0,
        1
);
BPF_PERCPU_ARRAY(percpu_metadata,
        0,
        sizeof(struct ebpf_metadata_t),
        0,
        1 // need to clear? umount
);

BPF_HASH(flow_table,
        0,
        sizeof(struct bpf_flow_key),
        sizeof(struct bpf_action_batch),
        0, // pin?
        256
);

/* XXX: CT for IPv6? */
BPF_PERF_OUTPUT(upcalls, 0);

BPF_HASH(dp_flow_stats,
        0,
        sizeof(struct bpf_flow_key),
        sizeof(struct bpf_flow_stats),
        0, // pin?
        256
);

/* XXX: Percpu */
BPF_ARRAY(datapath_stats,
        0,
        sizeof(uint64_t),
        0,
        __OVS_DP_STATS_MAX
);

/* Global tail call map:
 * Use index  0-31 for actions
 *     index 32-63 for others
 */
BPF_PROG_ARRAY(tailcalls,
        0,
        0,
        64
);

BPF_ARRAY(execute_actions,
        0,
        sizeof(struct bpf_action_batch),
        0,
        1
);

BPF_PERCPU_ARRAY(percpu_executing_key,
        0,
        sizeof(struct bpf_flow_key),
        0,
        1
);

struct ebpf_headers_t;
struct ebpf_metadata_t;

static inline struct ebpf_headers_t *bpf_get_headers()
{
    int ebpf_zero = 0;
    return bpf_map_lookup_elem(&percpu_headers, &ebpf_zero);
}

static inline struct ebpf_metadata_t *bpf_get_mds()
{
    int ebpf_zero = 0;
    return bpf_map_lookup_elem(&percpu_metadata, &ebpf_zero);
}

/* ------------------------*/
/*    BPF Flow Table: EMC  */
/* ------------------------*/
/*
struct bpf_elf_map __section_maps emc_map = {
    .type       = BPF_MAP_TYPE_HASH,
    //.size_key   = sizeof(u32),
    .size_key   = sizeof(struct ebpf_headers_t),
    .size_value = sizeof(struct bpf_action_batch),
    .max_elem   = 256,
    .pinning    = 0,
};
*/
/*
struct bpf_elf_map __section_maps tailcalls = {
    .type       = BPF_MAP_TYPE_PROG_ARRAY,
    .id         = BPF_MAP_ID_ACTION,
    .size_key   = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning    = 0,
    .max_elem   = 64,
};
*/
/* Program array map for OVS_ATTR_ACTION_* */
/*
struct bpf_elf_map __section_maps action_calls = {
    .type       = BPF_MAP_TYPE_PROG_ARRAY,
    .id         = BPF_MAP_ID_ACTION,
    .size_key   = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning    = 0,
    .max_elem   = 16,
};
*/
/* Program array map for the entire pipeline */
/*
struct bpf_elf_map __section_maps ingress_calls = {
    .type       = BPF_MAP_TYPE_PROG_ARRAY,
    .id         = BPF_MAP_ID_INGRESS,
    .size_key   = sizeof(uint32_t),
    .size_value = sizeof(u32),//struct ovs_flow_stats),
    .pinning    = 0,
    .max_elem   = 64,
};
*/
/* ---------------------*/
/*    BPF Flow Key      */
/* ---------------------*/
/* per cpu flow key at index 0 */
/*
struct bpf_elf_map __section_maps percpu_headers = {
    .type       = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key   = sizeof(u32),
    .size_value = sizeof(struct ebpf_headers_t),
    .pinning    = 0,
    .max_elem   = 1,
};
*/
/* per cpu packet metadata */
/*
struct bpf_elf_map __section_maps percpu_metadata = {
    .type       = BPF_MAP_TYPE_PERCPU_ARRAY,
    .size_key   = sizeof(u32),
    .size_value = sizeof(struct ebpf_metadata_t),
    .pinning    = 0,
    .max_elem   = 1,
};
*/
/* remove */
/*
struct bpf_elf_map __section_maps percpu_map = {
    .type       = BPF_MAP_TYPE_ARRAY,
    .size_key   = sizeof(u32),
    .size_value = sizeof(struct globals),
    .pinning    = 0,
    .max_elem   = __NR_CPUS__,
};
*/

/* ---------------------*/
/*    BPF Upcall Map    */
/* ---------------------*/
/*
struct bpf_elf_map __section_maps perf_events = {
    .type       = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .size_key   = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning    = 0,
    .max_elem   = __NR_CPUS__,
};
*/

#endif /* BPFMAP_OPENVSWITCH_H */
