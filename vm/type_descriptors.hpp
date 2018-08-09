#pragma once

enum ebpf_prog_type {
    EBPF_PROG_TYPE_UNSPEC,
	EBPF_PROG_TYPE_SOCKET_FILTER,
	EBPF_PROG_TYPE_KPROBE,
	EBPF_PROG_TYPE_SCHED_CLS,
	EBPF_PROG_TYPE_SCHED_ACT,
	EBPF_PROG_TYPE_TRACEPOINT,
	EBPF_PROG_TYPE_XDP,
	EBPF_PROG_TYPE_PERF_EVENT,
	EBPF_PROG_TYPE_CGROUP_SKB,
	EBPF_PROG_TYPE_CGROUP_SOCK,
	EBPF_PROG_TYPE_LWT_IN,
	EBPF_PROG_TYPE_LWT_OUT,
	EBPF_PROG_TYPE_LWT_XMIT,
	EBPF_PROG_TYPE_SOCK_OPS,
	EBPF_PROG_TYPE_SK_SKB,
	EBPF_PROG_TYPE_CGROUP_DEVICE,
	EBPF_PROG_TYPE_SK_MSG,
	EBPF_PROG_TYPE_RAW_TRACEPOINT,
	EBPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	EBPF_PROG_TYPE_LWT_SEG6LOCAL,
	EBPF_PROG_TYPE_LIRC_MODE2,
    
    EBPF_PROG_TYPE_MAX
};

// rough estimates:
constexpr int perf_max_trace_size = 2048;
constexpr int ptregs_size = (3 + 63 + 8 + 2) * 8;
constexpr int cgroup_dev_regions = 3 * 4;
constexpr int kprobe_regions = ptregs_size;
constexpr int tracepoint_regions = perf_max_trace_size;
constexpr int perf_event_regions = 3 * 8 + ptregs_size;
constexpr int socket_filter_regions = 24 * 4;
constexpr int sched_regions = 24 * 4;
constexpr int xdp_regions = 5 * 4;
constexpr int lwt_regions = 24 * 4;
constexpr int cgroup_sock_regions = 12 * 4;
constexpr int sock_ops_regions =  42 * 4 + 2 * 8;
constexpr int sk_skb_regions = 36 * 4;

struct ptype_descr {
    int size;
    int data = -1;
    int end = -1;
    int meta = -1; // data to meta is like end to data. i.e. meta <= data <= end
};

constexpr ptype_descr sk_buff = { sk_skb_regions, 19*4, 20*4, 35*4};
constexpr ptype_descr xdp_md = { xdp_regions, 0, 1*4, 2*4};
constexpr ptype_descr sk_msg_md = { 11*4, 0, 1*4, -1};
constexpr ptype_descr unspec_descr = { 0 };
constexpr ptype_descr cgroup_dev_descr = {cgroup_dev_regions};
constexpr ptype_descr kprobe_descr = {kprobe_regions};
constexpr ptype_descr tracepoint_descr = {tracepoint_regions};
constexpr ptype_descr perf_event_descr = {perf_event_regions};
constexpr ptype_descr socket_filter_descr = sk_buff;
constexpr ptype_descr sched_descr = sk_buff;
constexpr ptype_descr xdp_descr = xdp_md;
constexpr ptype_descr lwt_xmit_descr = sk_buff;
constexpr ptype_descr lwt_inout_descr = sk_buff;
constexpr ptype_descr cgroup_sock_descr = {cgroup_sock_regions};
constexpr ptype_descr sock_ops_descr = {sock_ops_regions};
constexpr ptype_descr sk_skb_descr = sk_buff;

inline ptype_descr get_descriptor(ebpf_prog_type t)
{
    switch (t) {
	case EBPF_PROG_TYPE_UNSPEC: return unspec_descr;
	case EBPF_PROG_TYPE_CGROUP_DEVICE: return cgroup_dev_descr;
	case EBPF_PROG_TYPE_KPROBE: return kprobe_descr;
	case EBPF_PROG_TYPE_TRACEPOINT: return tracepoint_descr;
    case EBPF_PROG_TYPE_RAW_TRACEPOINT: return tracepoint_descr;
	case EBPF_PROG_TYPE_PERF_EVENT: return perf_event_descr;
	case EBPF_PROG_TYPE_SOCKET_FILTER: return socket_filter_descr;
	case EBPF_PROG_TYPE_CGROUP_SKB: return socket_filter_descr;
	case EBPF_PROG_TYPE_SCHED_ACT: return sched_descr;
	case EBPF_PROG_TYPE_SCHED_CLS: return sched_descr;
	case EBPF_PROG_TYPE_XDP: return xdp_descr;
	case EBPF_PROG_TYPE_LWT_XMIT: return lwt_xmit_descr;
	case EBPF_PROG_TYPE_LWT_IN: return  lwt_inout_descr;
	case EBPF_PROG_TYPE_LWT_OUT: return lwt_inout_descr;
	case EBPF_PROG_TYPE_CGROUP_SOCK: return cgroup_sock_descr;
	case EBPF_PROG_TYPE_SOCK_OPS: return sock_ops_descr;
	case EBPF_PROG_TYPE_SK_SKB: return sk_skb_descr;
    case EBPF_PROG_TYPE_SK_MSG: return sk_msg_md;
    default: throw "";
    }
}