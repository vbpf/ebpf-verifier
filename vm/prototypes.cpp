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

/* BPF helper function descriptions:
 *
 * void *bpf_map_lookup_elem(&map, &key)
 *     Return: Map value or NULL
 *
 * int bpf_map_update_elem(&map, &key, &value, flags)
 *     Return: 0 on success or negative error
 *
 * int bpf_map_delete_elem(&map, &key)
 *     Return: 0 on success or negative error
 *
 * int bpf_probe_read(void *dst, int size, void *src)
 *     Return: 0 on success or negative error
 *
 * u64 bpf_ktime_get_ns(void)
 *     Return: current ktime
 *
 * int bpf_trace_printk(const char *fmt, int fmt_size, ...)
 *     Return: length of buffer written or negative error
 *
 * u32 bpf_prandom_u32(void)
 *     Return: random value
 *
 * u32 bpf_raw_smp_processor_id(void)
 *     Return: SMP processor ID
 *
 * int bpf_skb_store_bytes(skb, offset, from, len, flags)
 *     store bytes into packet
 *     @skb: pointer to skb
 *     @offset: offset within packet from skb->mac_header
 *     @from: pointer where to copy bytes from
 *     @len: number of bytes to store into packet
 *     @flags: bit 0 - if true, recompute skb->csum
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l3_csum_replace(skb, offset, from, to, flags)
 *     recompute IP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where IP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l4_csum_replace(skb, offset, from, to, flags)
 *     recompute TCP/UDP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where TCP/UDP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             bit 4 - is pseudo header
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_tail_call(ctx, prog_array_map, index)
 *     jump into another BPF program
 *     @ctx: context pointer passed to next program
 *     @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
 *     @index: 32-bit index inside array that selects specific program to run
 *     Return: 0 on success or negative error
 *
 * int bpf_clone_redirect(skb, ifindex, flags)
 *     redirect to another netdev
 *     @skb: pointer to skb
 *     @ifindex: ifindex of the net device
 *     @flags: bit 0 - if set, redirect to ingress instead of egress
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * u64 bpf_get_current_pid_tgid(void)
 *     Return: current->tgid << 32 | current->pid
 *
 * u64 bpf_get_current_uid_gid(void)
 *     Return: current_gid << 32 | current_uid
 *
 * int bpf_get_current_comm(char *buf, int size_of_buf)
 *     stores current->comm into buf
 *     Return: 0 on success or negative error
 *
 * u32 bpf_get_cgroup_classid(skb)
 *     retrieve a proc's classid
 *     @skb: pointer to skb
 *     Return: classid if != 0
 *
 * int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_vlan_pop(skb)
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_get_tunnel_key(skb, key, size, flags)
 * int bpf_skb_set_tunnel_key(skb, key, size, flags)
 *     retrieve or populate tunnel metadata
 *     @skb: pointer to skb
 *     @key: pointer to 'struct bpf_tunnel_key'
 *     @size: size of 'struct bpf_tunnel_key'
 *     @flags: room for future extensions
 *     Return: 0 on success or negative error
 *
 * u64 bpf_perf_event_read(map, flags)
 *     read perf event counter value
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     Return: value of perf event counter read or error code
 *
 * int bpf_redirect(ifindex, flags)
 *     redirect to another netdev
 *     @ifindex: ifindex of the net device
 *     @flags:
 *	  cls_bpf:
 *          bit 0 - if set, redirect to ingress instead of egress
 *          other bits - reserved
 *	  xdp_bpf:
 *	    all bits - reserved
 *     Return: cls_bpf: TC_ACT_REDIRECT on success or TC_ACT_SHOT on error
 *	       xdp_bfp: XDP_REDIRECT on success or XDP_ABORT on error
 * int bpf_redirect_map(map, key, flags)
 *     redirect to endpoint in map
 *     @map: pointer to dev map
 *     @key: index in map to lookup
 *     @flags: --
 *     Return: XDP_REDIRECT on success or XDP_ABORT on error
 *
 * u32 bpf_get_route_realm(skb)
 *     retrieve a dst's tclassid
 *     @skb: pointer to skb
 *     Return: realm if != 0
 *
 * int bpf_perf_event_output(ctx, map, flags, data, size)
 *     output perf raw sample
 *     @ctx: struct pt_regs*
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @data: data on stack to be output as raw data
 *     @size: size of data
 *     Return: 0 on success or negative error
 *
 * int bpf_get_stackid(ctx, map, flags)
 *     walk user or kernel stack and return id
 *     @ctx: struct pt_regs*
 *     @map: pointer to stack_trace map
 *     @flags: bits 0-7 - numer of stack frames to skip
 *             bit 8 - collect user stack instead of kernel
 *             bit 9 - compare stacks by hash only
 *             bit 10 - if two different stacks hash into the same stackid
 *                      discard old
 *             other bits - reserved
 *     Return: >= 0 stackid on success or negative error
 *
 * s64 bpf_csum_diff(from, from_size, to, to_size, seed)
 *     calculate csum diff
 *     @from: raw from buffer
 *     @from_size: length of from buffer
 *     @to: raw to buffer
 *     @to_size: length of to buffer
 *     @seed: optional seed
 *     Return: csum result or negative error code
 *
 * int bpf_skb_get_tunnel_opt(skb, opt, size)
 *     retrieve tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: option size
 *
 * int bpf_skb_set_tunnel_opt(skb, opt, size)
 *     populate tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_change_proto(skb, proto, flags)
 *     Change protocol of the skb. Currently supported is v4 -> v6,
 *     v6 -> v4 transitions. The helper will also resize the skb. eBPF
 *     program is expected to fill the new headers via skb_store_bytes
 *     and lX_csum_replace.
 *     @skb: pointer to skb
 *     @proto: new skb->protocol type
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_change_type(skb, type)
 *     Change packet type of skb.
 *     @skb: pointer to skb
 *     @type: new skb->pkt_type type
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_under_cgroup(skb, map, index)
 *     Check cgroup2 membership of skb
 *     @skb: pointer to skb
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 skb failed the cgroup2 descendant test
 *       == 1 skb succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * u32 bpf_get_hash_recalc(skb)
 *     Retrieve and possibly recalculate skb->hash.
 *     @skb: pointer to skb
 *     Return: hash
 *
 * u64 bpf_get_current_task(void)
 *     Returns current task_struct
 *     Return: current
 *
 * int bpf_probe_write_user(void *dst, void *src, int len)
 *     safely attempt to write to a location
 *     @dst: destination address in userspace
 *     @src: source address on stack
 *     @len: number of bytes to copy
 *     Return: 0 on success or negative error
 *
 * int bpf_current_task_under_cgroup(map, index)
 *     Check cgroup2 membership of current task
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 current failed the cgroup2 descendant test
 *       == 1 current succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * int bpf_skb_change_tail(skb, len, flags)
 *     The helper will resize the skb to the given new size, to be used f.e.
 *     with control messages.
 *     @skb: pointer to skb
 *     @len: new skb length
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_pull_data(skb, len)
 *     The helper will pull in non-linear data in case the skb is non-linear
 *     and not all of len are part of the linear section. Only needed for
 *     read/write with direct packet access.
 *     @skb: pointer to skb
 *     @len: len to make read/writeable
 *     Return: 0 on success or negative error
 *
 * s64 bpf_csum_update(skb, csum)
 *     Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
 *     @skb: pointer to skb
 *     @csum: csum to add
 *     Return: csum on success or negative error
 *
 * void bpf_set_hash_invalid(skb)
 *     Invalidate current skb->hash.
 *     @skb: pointer to skb
 *
 * int bpf_get_numa_node_id()
 *     Return: Id of current NUMA node.
 *
 * int bpf_skb_change_head()
 *     Grows headroom of skb and adjusts MAC header offset accordingly.
 *     Will extends/reallocae as required automatically.
 *     May change skb data pointer and will thus invalidate any check
 *     performed for direct packet access.
 *     @skb: pointer to skb
 *     @len: length of header to be pushed in front
 *     @flags: Flags (unused for now)
 *     Return: 0 on success or negative error
 *
 * int bpf_xdp_adjust_head(xdp_md, delta)
 *     Adjust the xdp_md.data by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data
 *     Return: 0 on success or negative on error
 *
 * int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
 *     Copy a NUL terminated string from unsafe address. In case the string
 *     length is smaller than size, the target is not padded with further NUL
 *     bytes. In case the string length is larger than size, just count-1
 *     bytes are copied and the last byte is set to NUL.
 *     @dst: destination address
 *     @size: maximum number of bytes to copy, including the trailing NUL
 *     @unsafe_ptr: unsafe address
 *     Return:
 *       > 0 length of the string including the trailing NUL on success
 *       < 0 error
 *
 * u64 bpf_get_socket_cookie(skb)
 *     Get the cookie for the socket stored inside sk_buff.
 *     @skb: pointer to skb
 *     Return: 8 Bytes non-decreasing number on success or 0 if the socket
 *     field is missing inside sk_buff
 *
 * u32 bpf_get_socket_uid(skb)
 *     Get the owner uid of the socket stored inside sk_buff.
 *     @skb: pointer to skb
 *     Return: uid of the socket owner on success or overflowuid if failed.
 *
 * u32 bpf_set_hash(skb, hash)
 *     Set full skb->hash.
 *     @skb: pointer to skb
 *     @hash: hash to set
 *
 * int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls setsockopt. Not all opts are available, only those with
 *     integer optvals plus TCP_CONGESTION.
 *     Supported levels: SOL_SOCKET and IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: SOL_SOCKET or IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_getsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls getsockopt. Not all opts are available.
 *     Supported levels: IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_sock_ops_cb_flags_set(bpf_sock_ops, flags)
 *     Set callback flags for sock_ops
 *     @bpf_sock_ops: pointer to bpf_sock_ops_kern struct
 *     @flags: flags value
 *     Return: 0 for no error
 *             -EINVAL if there is no full tcp socket
 *             bits in flags that are not supported by current kernel
 *
 * int bpf_skb_adjust_room(skb, len_diff, mode, flags)
 *     Grow or shrink room in sk_buff.
 *     @skb: pointer to skb
 *     @len_diff: (signed) amount of room to grow/shrink
 *     @mode: operation mode (enum bpf_adj_room_mode)
 *     @flags: reserved for future use
 *     Return: 0 on success or negative error code
 *
 * int bpf_sk_redirect_map(map, key, flags)
 *     Redirect skb to a sock in map using key as a lookup key for the
 *     sock in map.
 *     @map: pointer to sockmap
 *     @key: key to lookup sock in map
 *     @flags: reserved for future use
 *     Return: SK_PASS
 *
 * int bpf_sock_map_update(skops, map, key, flags)
 *	@skops: pointer to bpf_sock_ops
 *	@map: pointer to sockmap to update
 *	@key: key to insert/update sock in map
 *	@flags: same flags as map update elem
 *
 * int bpf_xdp_adjust_meta(xdp_md, delta)
 *     Adjust the xdp_md.data_meta by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data_meta
 *     Return: 0 on success or negative on error
 *
 * int bpf_perf_event_read_value(map, flags, buf, buf_size)
 *     read perf event counter value and perf event enabled/running time
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return: 0 on success or negative error code
 *
 * int bpf_perf_prog_read_value(ctx, buf, buf_size)
 *     read perf prog attached perf event counter and enabled/running time
 *     @ctx: pointer to ctx
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return : 0 on success or negative error code
 *
 * int bpf_override_return(pt_regs, rc)
 *	@pt_regs: pointer to struct pt_regs
 *	@rc: the return value to set
 */

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
