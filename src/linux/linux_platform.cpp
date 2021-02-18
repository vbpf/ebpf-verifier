// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <stdexcept>
#if __linux__
#include <linux/bpf.h>
#define PTYPE(name, descr, native_type, prefixes) \
             {name, descr, native_type, prefixes}
#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
                        {name, descr, native_type, prefixes, true}
#else
#define PTYPE(name, descr, native_type, prefixes) \
             {name, descr, 0, prefixes}
#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
                        {name, descr, 0, prefixes, true}
#endif
#include "crab_verifier.hpp"
#include "helpers.hpp"
#include "platform.hpp"
#include "linux_platform.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"

// Map definitions as they appear in an ELF file, so field width matters.
struct bpf_load_map_def {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};

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

void parse_maps_section_linux(std::vector<EbpfMapDescriptor>& map_descriptors, const char* data, size_t size, ebpf_create_map_fn create_map, ebpf_verifier_options_t options)
{
    if (size % sizeof(bpf_load_map_def) != 0) {
        throw std::runtime_error(std::string("bad maps section size"));
    }

    auto mapdefs = std::vector<bpf_load_map_def>((bpf_load_map_def*)data, (bpf_load_map_def*)(data + size));
    for (auto s : mapdefs) {
        map_descriptors.emplace_back(EbpfMapDescriptor{
            .original_fd = create_map(s.type, s.key_size, s.value_size, s.max_entries, options),
            .type = s.type,
            .key_size = s.key_size,
            .value_size = s.value_size,
        });
    }
    for (size_t i = 0; i < mapdefs.size(); i++) {
        unsigned int inner = mapdefs[i].inner_map_idx;
        if (inner >= map_descriptors.size())
            throw std::runtime_error(std::string("bad inner map index ") + std::to_string(inner)
                                     + " for map " + std::to_string(i));
        map_descriptors[i].inner_map_fd = map_descriptors.at(inner).original_fd;
    }
}

#if __linux__
static int do_bpf(bpf_cmd cmd, union bpf_attr& attr) { return syscall(321, cmd, &attr, sizeof(attr)); }
#endif

/** Try to allocate a Linux map.
 *
 *  This function requires admin privileges.
 */
int create_map_linux(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                     ebpf_verifier_options_t options)
{
    if (options.mock_map_fds) {
        return create_map_crab(map_type, key_size, value_size, max_entries, options);
    }

#if __linux__
    union bpf_attr attr {};
    memset(&attr, '\0', sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = 20;
    attr.map_flags = map_type == BPF_MAP_TYPE_HASH ? BPF_F_NO_PREALLOC : 0;
    int map_fd = do_bpf(BPF_MAP_CREATE, attr);
    if (map_fd < 0) {
        if (options.print_failures) {
            std::cerr << "Failed to create map, " << strerror(errno) << "\n";
            std::cerr << "Map: \n"
                      << " map_type = " << attr.map_type << "\n"
                      << " key_size = " << attr.key_size << "\n"
                      << " value_size = " << attr.value_size << "\n"
                      << " max_entries = " << attr.max_entries << "\n"
                      << " map_flags = " << attr.map_flags << "\n";
        }
        exit(2);
    }
    return map_fd;
#else
    throw std::runtime_error(std::string("cannot create a Linux map"));
#endif
}

EbpfMapDescriptor& get_map_descriptor_linux(int map_fd)
{
    // First check if we already have the map descriptor cached.
    EbpfMapDescriptor* map = find_map_descriptor(map_fd);
    if (map != nullptr) {
        return *map;
    }

    // This fd was not created from the maps section of an ELF file,
    // but it may be an fd created by an app before calling the verifier.
    // In this case, we would like to query the map descriptor info
    // (key size, value size) from the execution context, but this is
    // not yet supported on Linux.

    throw std::runtime_error(std::string("map_fd not found"));
}

const ebpf_platform_t g_ebpf_platform_linux = {
    get_program_type_linux,
    get_helper_prototype_linux,
    is_helper_usable_linux,
    sizeof(bpf_load_map_def),
    parse_maps_section_linux,
    create_map_linux,
    get_map_descriptor_linux,
};
