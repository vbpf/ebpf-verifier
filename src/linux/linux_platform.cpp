// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#if __linux__
#include <linux/bpf.h>
#endif
#include "spec_type_descriptors.hpp"
#include "helpers.hpp"
#include "platform.hpp"
#include "linux_platform.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

#ifdef BPF_PROG_TYPE_UNSPEC
#define PTYPE(name, descr, native_type, prefixes) \
               {name, descr, native_type, prefixes}

#define PTYPE(name, descr, native_type, prefixes, is_privileged) \
                       {name, descr, native_type, prefixes, is_privileged}

#else

#define PTYPE(name, descr, native_type, prefixes) \
                       {name, descr, 0, prefixes}

#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
                       {name, descr, 0, prefixes, true}
#endif

// Allow for comma as a separator between multiple prefixes, to make
// the preprocessor treat a prefix list as one macro argument.
#define COMMA ,

const EbpfProgramType linux_socket_filter_program_type =
    PTYPE("socket_filter", socket_filter_descr, BPF_PROG_TYPE_SOCKET_FILTER, {"socket"});

const EbpfProgramType linux_xdp_program_type =
    PTYPE("xdp", xdp_descr, BPF_PROG_TYPE_XDP, {"xdp"});

const EbpfProgramType cilium_lxc_program_type =
    PTYPE("lxc", sched_descr, BPF_PROG_TYPE_SOCKET_FILTER, {});

const std::vector<EbpfProgramType> linux_program_types = {
    PTYPE("unspec", unspec_descr, BPF_PROG_TYPE_UNSPEC, {}),
    linux_socket_filter_program_type,
    linux_xdp_program_type,
    PTYPE("cgroup_device", cgroup_dev_descr, BPF_PROG_TYPE_CGROUP_DEVICE, {"cgroup/dev"}),
    PTYPE("cgroup_skb", socket_filter_descr, BPF_PROG_TYPE_CGROUP_SKB, {"cgroup/skb"}),
    PTYPE("cgroup_sock", cgroup_sock_descr, BPF_PROG_TYPE_CGROUP_SOCK, {"cgroup/sock"}),
    PTYPE_PRIVILEGED("kprobe", kprobe_descr, BPF_PROG_TYPE_KPROBE, {"kprobe/" COMMA "kretprobe/"}),
    PTYPE("lwt_in", lwt_inout_descr, BPF_PROG_TYPE_LWT_IN, {"lwt_in"}),
    PTYPE("lwt_out", lwt_inout_descr, BPF_PROG_TYPE_LWT_OUT, {"lwt_out"}),
    PTYPE("lwt_xmit", lwt_xmit_descr, BPF_PROG_TYPE_LWT_XMIT, {"lwt_xmit"}),
    PTYPE("perf_event", perf_event_descr, BPF_PROG_TYPE_PERF_EVENT, {"perf_section" COMMA "perf_event"}),
    PTYPE("sched_act", sched_descr, BPF_PROG_TYPE_SCHED_ACT, {"action"}),
    PTYPE("sched_cls", sched_descr, BPF_PROG_TYPE_SCHED_CLS, {"classifier"}),
    PTYPE("sk_skb", sk_skb_descr, BPF_PROG_TYPE_SK_SKB, {"sk_skb"}),
    PTYPE("sock_ops", sock_ops_descr, BPF_PROG_TYPE_SOCK_OPS, {"sockops"}),
    PTYPE("tracepoint", tracepoint_descr, BPF_PROG_TYPE_TRACEPOINT, {"tracepoint/"}),

    // The following types are currently mapped to the socket filter program
    // type but should be mapped to the relevant native linux program type
    // value.
    PTYPE("sk_msg", sk_msg_md, BPF_PROG_TYPE_SOCKET_FILTER, {"sk_msg"}),
    PTYPE("raw_tracepoint", tracepoint_descr, BPF_PROG_TYPE_SOCKET_FILTER, {"raw_tracepoint/"}),
    PTYPE("cgroup_sock_addr", cgroup_sock_descr, BPF_PROG_TYPE_SOCKET_FILTER, {}),
    PTYPE("lwt_seg6local", lwt_xmit_descr, BPF_PROG_TYPE_SOCKET_FILTER, {"lwt_seg6local"}),
    PTYPE("lirc_mode2", sk_msg_md, BPF_PROG_TYPE_SOCKET_FILTER, {"lirc_mode2"}),
};

static EbpfProgramType get_program_type_linux(const std::string& section, const std::string& path) {
    EbpfProgramType type{};

    // linux only deduces from section, but cilium and cilium_test have this information
    // in the filename:
    // * cilium/bpf_xdp.o:from-netdev is XDP
    // * bpf_cilium_test/bpf_lb-DLB_L3.o:from-netdev is SK_SKB
    if (path.find("cilium") != std::string::npos) {
        if (path.find("xdp") != std::string::npos) {
            return linux_xdp_program_type;
        }
        if (path.find("lxc") != std::string::npos) {
            return cilium_lxc_program_type;
        }
    }

    for (const EbpfProgramType t : linux_program_types) {
        for (const std::string prefix : t.section_prefixes) {
            if (section.find(prefix) == 0)
                return t;
        }
    }

    return linux_socket_filter_program_type;
}

const ebpf_platform_t g_ebpf_platform_linux = {
    get_program_type_linux,
    get_helper_prototype_linux,
    is_helper_usable_linux,
};
