#pragma once
#include <unordered_map>
#include <string>
#include <vector>

#include "linux_ebpf.hpp"

enum class BpfProgType : int {
    UNSPEC,
    SOCKET_FILTER,
    KPROBE,
    SCHED_CLS,
    SCHED_ACT,
    TRACEPOINT,
    XDP,
    PERF_EVENT,
    CGROUP_SKB,
    CGROUP_SOCK,
    LWT_IN,
    LWT_OUT,
    LWT_XMIT,
    SOCK_OPS,
    SK_SKB,
    CGROUP_DEVICE,
    SK_MSG,
    RAW_TRACEPOINT,
    CGROUP_SOCK_ADDR,
    LWT_SEG6LOCAL,
    LIRC_MODE2,

    MAX
};

constexpr int STACK_SIZE=512;

struct program_info {
    BpfProgType program_type;
    std::vector<unsigned int> map_sizes;
};

struct raw_program {
    std::string filename;
    std::string section;
    std::vector<ebpf_inst> prog;
    program_info info;
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
constexpr ptype_descr sk_msg_md = { 17*4, 0, 1*8, -1}; // TODO: verify
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

inline ptype_descr get_descriptor(BpfProgType t)
{
    switch (t) {
	case BpfProgType::UNSPEC: return unspec_descr;
	case BpfProgType::CGROUP_DEVICE: return cgroup_dev_descr;
	case BpfProgType::KPROBE: return kprobe_descr;
	case BpfProgType::TRACEPOINT: return tracepoint_descr;
    case BpfProgType::RAW_TRACEPOINT: return tracepoint_descr;
	case BpfProgType::PERF_EVENT: return perf_event_descr;
	case BpfProgType::SOCKET_FILTER: return socket_filter_descr;
	case BpfProgType::CGROUP_SKB: return socket_filter_descr;
	case BpfProgType::SCHED_ACT: return sched_descr;
	case BpfProgType::SCHED_CLS: return sched_descr;
	case BpfProgType::XDP: return xdp_descr;
	case BpfProgType::LWT_XMIT: return lwt_xmit_descr;
	case BpfProgType::LWT_IN: return  lwt_inout_descr;
	case BpfProgType::LWT_OUT: return lwt_inout_descr;
	case BpfProgType::CGROUP_SOCK: return cgroup_sock_descr;
	case BpfProgType::SOCK_OPS: return sock_ops_descr;
	case BpfProgType::SK_SKB: return sk_skb_descr;
    case BpfProgType::SK_MSG: return sk_msg_md;
    default: throw "";
    }
}

inline BpfProgType section_to_progtype(std::string section) {
	static const std::unordered_map<std::string, BpfProgType> prefixes{
        { "socket", BpfProgType::SOCKET_FILTER },
        { "kprobe/", BpfProgType::KPROBE },
        { "kretprobe/", BpfProgType::KPROBE },
        { "tracepoint/", BpfProgType::TRACEPOINT },
        { "raw_tracepoint/", BpfProgType::RAW_TRACEPOINT },
        { "xdp", BpfProgType::XDP },
        { "perf_section", BpfProgType::PERF_EVENT },
        { "cgroup/skb", BpfProgType::CGROUP_SKB },
        { "cgroup/sock", BpfProgType::CGROUP_SOCK },
        { "sockops", BpfProgType::SOCK_OPS },
        { "sk_skb", BpfProgType::SK_SKB },
        { "sk_msg", BpfProgType::SK_MSG },
    };
	for (const auto [prefix, t] : prefixes) {
		if (section.find(prefix) == 0)
			return t;
	}
	return BpfProgType::SK_SKB;
}
