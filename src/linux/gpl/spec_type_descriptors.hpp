#pragma once
#include <cassert>
#include <string>
#include <unordered_map>
#include <vector>

#include "ebpf_vm_isa.hpp"

constexpr int NMAPS = 64;
constexpr int NONMAPS = 5;
constexpr int ALL_TYPES = NMAPS + NONMAPS;

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
constexpr int sock_ops_regions = 42 * 4 + 2 * 8;
constexpr int sk_skb_regions = 36 * 4;

constexpr EbpfContextDescriptor sk_buff = {sk_skb_regions, 19 * 4, 20 * 4, 35 * 4};
constexpr EbpfContextDescriptor xdp_md = {xdp_regions, 0, 1 * 4, 2 * 4};
constexpr EbpfContextDescriptor sk_msg_md = {17 * 4, 0, 1 * 8, -1}; // TODO: verify
constexpr EbpfContextDescriptor unspec_descr = {0};
constexpr EbpfContextDescriptor cgroup_dev_descr = {cgroup_dev_regions};
constexpr EbpfContextDescriptor kprobe_descr = {kprobe_regions};
constexpr EbpfContextDescriptor tracepoint_descr = {tracepoint_regions};
constexpr EbpfContextDescriptor perf_event_descr = {perf_event_regions};
constexpr EbpfContextDescriptor cgroup_sock_descr = {cgroup_sock_regions};
constexpr EbpfContextDescriptor sock_ops_descr = {sock_ops_regions};

extern const EbpfContextDescriptor g_sk_buff;
extern const EbpfContextDescriptor g_xdp_md;
extern const EbpfContextDescriptor g_sk_msg_md;
extern const EbpfContextDescriptor g_unspec_descr;
extern const EbpfContextDescriptor g_cgroup_dev_descr;
extern const EbpfContextDescriptor g_kprobe_descr;
extern const EbpfContextDescriptor g_tracepoint_descr;
extern const EbpfContextDescriptor g_perf_event_descr;
extern const EbpfContextDescriptor g_cgroup_sock_descr;
extern const EbpfContextDescriptor g_sock_ops_descr;

// The following all used the sk_buff descriptor and so the ctx is apparently interchangeable.
#define g_socket_filter_descr g_sk_buff
#define g_sched_descr g_sk_buff
#define g_lwt_xmit_descr g_sk_buff
#define g_lwt_inout_descr g_sk_buff
#define g_sk_skb_descr g_sk_buff

// And these were also interchangeable.
#define g_xdp_descr g_xdp_md
