#include <stdbool.h>
#include "prototypes.hpp"

static const struct bpf_func_proto bpf_unspec_proto = {
};
const struct bpf_func_proto bpf_tail_call_proto = {
	//.func		= NULL,
	//.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_override_return_proto = {
	//.func		= bpf_override_return,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_probe_read_proto = {
	//.func		= bpf_probe_read,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_probe_write_user_proto = {
	//.func		= bpf_probe_write_user,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_trace_printk_proto = {
	//.func		= bpf_trace_printk,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_perf_event_read_proto = {
	//.func		= bpf_perf_event_read,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_perf_event_read_value_proto = {
	//.func		= bpf_perf_event_read_value,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_perf_event_output_proto = {
	//.func		= bpf_perf_event_output,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};
static const struct bpf_func_proto bpf_get_current_task_proto = {
	//.func		= bpf_get_current_task,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_current_task_under_cgroup_proto = {
	//.func       = bpf_current_task_under_cgroup,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_CONST_MAP_PTR,
	.arg2_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_probe_read_str_proto = {
	//.func		= bpf_probe_read_str,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_perf_event_output_proto_tp = {
	//.func		= bpf_perf_event_output_tp,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};
static const struct bpf_func_proto bpf_get_stackid_proto_tp = {
	//.func		= bpf_get_stackid_tp,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_get_stack_proto_tp = {
	//.func		= bpf_get_stack_tp,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_perf_prog_read_value_proto = {
	//.func       = bpf_perf_prog_read_value,
	//.gpl_only   = true,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
	.arg2_type  = ARG_PTR_TO_UNINIT_MEM,
	.arg3_type  = ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_perf_event_output_proto_raw_tp = {
	//.func		= bpf_perf_event_output_raw_tp,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};
static const struct bpf_func_proto bpf_get_stackid_proto_raw_tp = {
	//.func		= bpf_get_stackid_raw_tp,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_get_stack_proto_raw_tp = {
	//.func		= bpf_get_stack_raw_tp,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};
/*
static const struct bpf_func_proto bpf_map_lookup_elem_proto __weak;
static const struct bpf_func_proto bpf_map_update_elem_proto __weak;
static const struct bpf_func_proto bpf_map_delete_elem_proto __weak;

static const struct bpf_func_proto bpf_get_prandom_u32_proto __weak;
static const struct bpf_func_proto bpf_get_smp_processor_id_proto __weak;
static const struct bpf_func_proto bpf_get_numa_node_id_proto __weak;
static const struct bpf_func_proto bpf_ktime_get_ns_proto __weak;

static const struct bpf_func_proto bpf_get_current_pid_tgid_proto __weak;
static const struct bpf_func_proto bpf_get_current_uid_gid_proto __weak;
static const struct bpf_func_proto bpf_get_current_comm_proto __weak;
static const struct bpf_func_proto bpf_sock_map_update_proto __weak;
static const struct bpf_func_proto bpf_sock_hash_update_proto __weak;
static const struct bpf_func_proto bpf_get_current_cgroup_id_proto __weak;
*/

/* Always built-in helper functions. */

static const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	//.func		= bpf_map_lookup_elem,
	//.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};
static const struct bpf_func_proto bpf_map_update_elem_proto = {
	//.func		= bpf_map_update_elem,
	//.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_map_delete_elem_proto = {
	//.func		= bpf_map_delete_elem,
	//.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};
static const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	//.func		= bpf_user_rnd_u32,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	//.func		= bpf_get_smp_processor_id,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_get_numa_node_id_proto = {
	//.func		= bpf_get_numa_node_id,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	//.func		= bpf_ktime_get_ns,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	//.func		= bpf_get_current_pid_tgid,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	//.func		= bpf_get_current_uid_gid,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_get_current_comm_proto = {
	//.func		= bpf_get_current_comm,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_get_current_cgroup_id_proto = {
	//.func		= bpf_get_current_cgroup_id,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_sock_map_update_proto = {
	//.func		= bpf_sock_map_update,
	//.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_sock_hash_update_proto = {
	//.func		= bpf_sock_hash_update,
	//.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_get_stackid_proto = {
	//.func		= bpf_get_stackid,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_get_stack_proto = {
	//.func		= bpf_get_stack,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_get_raw_smp_processor_id_proto = {
	//.func		= bpf_get_raw_cpu_id,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};
static const struct bpf_func_proto bpf_skb_store_bytes_proto = {
	//.func		= bpf_skb_store_bytes,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_load_bytes_proto = {
	//.func		= bpf_skb_load_bytes,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_skb_load_bytes_relative_proto = {
	//.func		= bpf_skb_load_bytes_relative,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_pull_data_proto = {
	//.func		= bpf_skb_pull_data,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto sk_skb_pull_data_proto = {
	//.func		= sk_skb_pull_data,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_l3_csum_replace_proto = {
	//.func		= bpf_l3_csum_replace,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_l4_csum_replace_proto = {
	//.func		= bpf_l4_csum_replace,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_csum_diff_proto = {
	//.func		= bpf_csum_diff,
	//.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_csum_update_proto = {
	//.func		= bpf_csum_update,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_clone_redirect_proto = {
	//.func       = bpf_clone_redirect,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
	.arg2_type  = ARG_ANYTHING,
	.arg3_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_redirect_proto = {
	//.func       = bpf_redirect,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_ANYTHING,
	.arg2_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_sk_redirect_hash_proto = {
	//.func       = bpf_sk_redirect_hash,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type  = ARG_CONST_MAP_PTR,
	.arg3_type  = ARG_PTR_TO_MAP_KEY,
	.arg4_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_sk_redirect_map_proto = {
	//.func       = bpf_sk_redirect_map,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type  = ARG_CONST_MAP_PTR,
	.arg3_type  = ARG_ANYTHING,
	.arg4_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_msg_redirect_hash_proto = {
	//.func       = bpf_msg_redirect_hash,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type  = ARG_CONST_MAP_PTR,
	.arg3_type  = ARG_PTR_TO_MAP_KEY,
	.arg4_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_msg_redirect_map_proto = {
	//.func       = bpf_msg_redirect_map,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type  = ARG_CONST_MAP_PTR,
	.arg3_type  = ARG_ANYTHING,
	.arg4_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_msg_apply_bytes_proto = {
	//.func       = bpf_msg_apply_bytes,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_msg_cork_bytes_proto = {
	//.func       = bpf_msg_cork_bytes,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_msg_pull_data_proto = {
	//.func		= bpf_msg_pull_data,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
	//.func       = bpf_get_cgroup_classid,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_get_route_realm_proto = {
	//.func       = bpf_get_route_realm,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_get_hash_recalc_proto = {
	//.func		= bpf_get_hash_recalc,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_set_hash_invalid_proto = {
	//.func		= bpf_set_hash_invalid,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_set_hash_proto = {
	//.func		= bpf_set_hash,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_vlan_push_proto = {
	//.func       = bpf_skb_vlan_push,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
	.arg2_type  = ARG_ANYTHING,
	.arg3_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_vlan_pop_proto = {
	//.func       = bpf_skb_vlan_pop,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_skb_change_proto_proto = {
	//.func		= bpf_skb_change_proto,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_change_type_proto = {
	//.func		= bpf_skb_change_type,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_adjust_room_proto = {
	//.func		= bpf_skb_adjust_room,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_change_tail_proto = {
	//.func		= bpf_skb_change_tail,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto sk_skb_change_tail_proto = {
	//.func		= sk_skb_change_tail,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_change_head_proto = {
	//.func		= bpf_skb_change_head,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto sk_skb_change_head_proto = {
	//.func		= sk_skb_change_head,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_xdp_adjust_head_proto = {
	//.func		= bpf_xdp_adjust_head,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_xdp_adjust_tail_proto = {
	//.func		= bpf_xdp_adjust_tail,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_xdp_adjust_meta_proto = {
	//.func		= bpf_xdp_adjust_meta,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_xdp_redirect_proto = {
	//.func       = bpf_xdp_redirect,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_ANYTHING,
	.arg2_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_xdp_redirect_map_proto = {
	//.func       = bpf_xdp_redirect_map,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_CONST_MAP_PTR,
	.arg2_type  = ARG_ANYTHING,
	.arg3_type  = ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_event_output_proto = {
	//.func		= bpf_skb_event_output,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};
static const struct bpf_func_proto bpf_skb_get_tunnel_key_proto = {
	//.func		= bpf_skb_get_tunnel_key,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_get_tunnel_opt_proto = {
	//.func		= bpf_skb_get_tunnel_opt,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_skb_set_tunnel_key_proto = {
	//.func		= bpf_skb_set_tunnel_key,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_set_tunnel_opt_proto = {
	//.func		= bpf_skb_set_tunnel_opt,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_skb_under_cgroup_proto = {
	//.func		= bpf_skb_under_cgroup,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_cgroup_id_proto = {
	//.func       = bpf_skb_cgroup_id,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_xdp_event_output_proto = {
	//.func		= bpf_xdp_event_output,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};
static const struct bpf_func_proto bpf_get_socket_cookie_proto = {
	//.func       = bpf_get_socket_cookie,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_get_socket_uid_proto = {
	//.func       = bpf_get_socket_uid,
	//.gpl_only   = false,
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_setsockopt_proto = {
	//.func		= bpf_setsockopt,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_getsockopt_proto = {
	//.func		= bpf_getsockopt,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg5_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_sock_ops_cb_flags_set_proto = {
	//.func		= bpf_sock_ops_cb_flags_set,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_bind_proto = {
	//.func		= bpf_bind,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};
static const struct bpf_func_proto bpf_skb_get_xfrm_state_proto = {
	//.func		= bpf_skb_get_xfrm_state,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_xdp_fib_lookup_proto = {
	//.func		= bpf_xdp_fib_lookup,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
	.arg2_type  = ARG_PTR_TO_MEM,
	.arg3_type  = ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_skb_fib_lookup_proto = {
	//.func		= bpf_skb_fib_lookup,
	//.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
	.arg2_type  = ARG_PTR_TO_MEM,
	.arg3_type  = ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_lwt_push_encap_proto = {
	//.func		= bpf_lwt_push_encap,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE
};
static const struct bpf_func_proto bpf_lwt_seg6_store_bytes_proto = {
	//.func		= bpf_lwt_seg6_store_bytes,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE
};
static const struct bpf_func_proto bpf_lwt_seg6_action_proto = {
	//.func		= bpf_lwt_seg6_action,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE
};
static const struct bpf_func_proto bpf_lwt_seg6_adjust_srh_proto = {
	//.func		= bpf_lwt_seg6_adjust_srh,
	//.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto bpf_rc_repeat_proto = { //without bpf_ originally
	//.func	   = bpf_rc_repeat,
	//.gpl_only  = true, /* rc_repeat is EXPORT_SYMBOL_GPL */
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
};
static const struct bpf_func_proto bpf_rc_keydown_proto = { //without bpf_ originally
	//.func	   = bpf_rc_keydown,
	//.gpl_only  = true, /* rc_keydown is EXPORT_SYMBOL_GPL */
	.ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_CTX,
	.arg2_type  = ARG_ANYTHING,
	.arg3_type  = ARG_ANYTHING,
	.arg4_type  = ARG_ANYTHING,
};

#define FN(x) bpf_ ## x ## _proto

const struct bpf_func_proto prototypes[81] = {
	FN(unspec),
	FN(map_lookup_elem),
	FN(map_update_elem),
	FN(map_delete_elem),
	FN(probe_read),
	FN(ktime_get_ns),
	FN(trace_printk),
	FN(get_prandom_u32),
	FN(get_smp_processor_id),
	FN(skb_store_bytes),
	FN(l3_csum_replace),
	FN(l4_csum_replace),
	FN(tail_call),
	FN(clone_redirect),
	FN(get_current_pid_tgid),
	FN(get_current_uid_gid),
	FN(get_current_comm),
	FN(get_cgroup_classid),
	FN(skb_vlan_push),
	FN(skb_vlan_pop),
	FN(skb_get_tunnel_key),
	FN(skb_set_tunnel_key),
	FN(perf_event_read),
	FN(redirect),
	FN(get_route_realm),
	FN(perf_event_output),
	FN(skb_load_bytes),
	FN(get_stackid),
	FN(csum_diff),
	FN(skb_get_tunnel_opt),
	FN(skb_set_tunnel_opt),
	FN(skb_change_proto),
	FN(skb_change_type),
	FN(skb_under_cgroup),
	FN(get_hash_recalc),
	FN(get_current_task),
	FN(probe_write_user),
	FN(current_task_under_cgroup),
	FN(skb_change_tail),
	FN(skb_pull_data),
	FN(csum_update),
	FN(set_hash_invalid),
	FN(get_numa_node_id),
	FN(skb_change_head),
	FN(xdp_adjust_head),
	FN(probe_read_str),
	FN(get_socket_cookie),
	FN(get_socket_uid),
	FN(set_hash),
	FN(setsockopt),
	FN(skb_adjust_room),
	FN(redirect),// redirect_map originally
	FN(sk_redirect_map),
	FN(sock_map_update),
	FN(xdp_adjust_meta),
	FN(perf_event_read_value),
	FN(perf_prog_read_value),
	FN(getsockopt),
	FN(override_return),
	FN(sock_ops_cb_flags_set),
	FN(msg_redirect_map),
	FN(msg_apply_bytes),
	FN(msg_cork_bytes),
	FN(msg_pull_data),
	FN(bind),
	FN(xdp_adjust_tail),
	FN(skb_get_xfrm_state),
	FN(get_stack), // 67
	FN(skb_load_bytes_relative),
	FN(xdp_fib_lookup), // without xdp_ originally
	FN(sock_hash_update),
	FN(msg_redirect_hash),
	FN(sk_redirect_hash),
	FN(lwt_push_encap),
	FN(lwt_seg6_store_bytes),
	FN(lwt_seg6_adjust_srh),
	FN(lwt_seg6_action),
	FN(rc_repeat),
	FN(rc_keydown),
	FN(skb_cgroup_id),
	FN(get_current_cgroup_id),
};

bpf_func_proto get_prototype(unsigned int n)
{
	if (n >= sizeof(prototypes)/sizeof(prototypes[0]))
		return bpf_unspec_proto;
	return prototypes[n];
}

bool is_valid_prototype(unsigned int n)
{
	return n < sizeof(prototypes)/sizeof(prototypes[0]) && n > 0;
}
