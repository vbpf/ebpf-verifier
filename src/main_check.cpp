#include <iostream>
#include <vector>

#include <crab/common/debug.hpp>

#include <boost/container_hash/hash.hpp>

#include "CLI11.hpp"

#include "memsize.hpp"
#include "config.hpp"
#include "crab_verifier.hpp"
#include "asm.hpp"
#include "spec_assertions.hpp"
#include "ai.hpp"

#include <linux/bpf.h>

bpf_prog_type to_linuxtype(BpfProgType t)
{
    switch (t) {
    case BpfProgType::UNSPEC: return BPF_PROG_TYPE_UNSPEC; 
    case BpfProgType::SOCKET_FILTER: return BPF_PROG_TYPE_SOCKET_FILTER; 
    case BpfProgType::KPROBE: return BPF_PROG_TYPE_KPROBE; 
    case BpfProgType::SCHED_CLS: return BPF_PROG_TYPE_SCHED_CLS; 
    case BpfProgType::SCHED_ACT: return BPF_PROG_TYPE_SCHED_ACT; 
    case BpfProgType::TRACEPOINT: return BPF_PROG_TYPE_TRACEPOINT; 
    case BpfProgType::XDP: return BPF_PROG_TYPE_XDP; 
    case BpfProgType::PERF_EVENT: return BPF_PROG_TYPE_PERF_EVENT; 
    case BpfProgType::CGROUP_SKB: return BPF_PROG_TYPE_CGROUP_SKB; 
    case BpfProgType::CGROUP_SOCK: return BPF_PROG_TYPE_CGROUP_SOCK; 
    case BpfProgType::LWT_IN: return BPF_PROG_TYPE_LWT_IN; 
    case BpfProgType::LWT_OUT: return BPF_PROG_TYPE_LWT_OUT; 
    case BpfProgType::LWT_XMIT: return BPF_PROG_TYPE_LWT_XMIT; 
    case BpfProgType::SOCK_OPS: return BPF_PROG_TYPE_SOCK_OPS; 
    case BpfProgType::SK_SKB: return BPF_PROG_TYPE_SK_SKB; 
    case BpfProgType::CGROUP_DEVICE: return BPF_PROG_TYPE_CGROUP_DEVICE; 
    //case BpfProgType::SK_MSG: return BPF_PROG_TYPE_SK_MSG; 
    //case BpfProgType::RAW_TRACEPOINT: return BPF_PROG_TYPE_RAW_TRACEPOINT; 
    //case BpfProgType::CGROUP_SOCK_ADDR: return BPF_PROG_TYPE_CGROUP_SOCK_ADDR; 
    //case BpfProgType::LWT_SEG6LOCAL: return BPF_PROG_TYPE_LWT_SEG6LOCAL; 
    //case BpfProgType::LIRC_MODE2: return BPF_PROG_TYPE_LIRC_MODE2; 
    }
    return BPF_PROG_TYPE_UNSPEC;
};

static int create_map(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries)
{
	union bpf_attr attr;
	memset(&attr, '\0', sizeof(attr));
	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = map_type == BPF_MAP_TYPE_HASH ? BPF_F_NO_PREALLOC : 0;
	int fd = syscall(321, BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0) {
		cout << "Failed to create map, " << strerror(errno) << "\n";
        exit(2);
    }
	return fd;
}

static void load_maps(struct bpf_map_data *maps, int nr_maps,
                     fixup_map_cb fixup_map)
{
    for (int i = 0; i < nr_maps; i++) {
        if (fixup_map) {
            fixup_map(&maps[i], i);
            /* Allow userspace to assign map FD prior to creation */
            if (maps[i].fd != -1) {
                map_fd[i] = maps[i].fd;
                continue;
            }
        }

        if (maps[i].def.type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
            maps[i].def.type == BPF_MAP_TYPE_HASH_OF_MAPS) {
            map_fd[i] = bpf_create_map_in_map_node(maps[i].def.type,
                                            maps[i].name,
                                            maps[i].def.key_size,
                                            map_fd[maps[i].def.inner_map_idx],
                                            maps[i].def.max_entries,
                                            maps[i].def.map_flags,
                                            -1);
        } else {
            map_fd[i] = bpf_create_map_node(maps[i].def.type,
                                            maps[i].name,
                                            maps[i].def.key_size,
                                            maps[i].def.value_size,
                                            maps[i].def.max_entries,
                                            maps[i].def.map_flags,
                                            -1);
        }
        assert(map_fd[i] >= 0);
        maps[i].fd = map_fd[i];
        if (maps[i].def.type == BPF_MAP_TYPE_PROG_ARRAY)
            prog_array_fd = map_fd[i];
    }
}

int bpf_verify_program(bpf_prog_type type, std::vector<ebpf_inst>& raw_prog)
{
    int log_level = 0;
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.prog_type = (__u32)type;
	attr.insn_cnt = (__u32)raw_prog.size();
	attr.insns = (__u64)raw_prog.data();
	attr.license = (__u64)"GPL";
	attr.log_buf = (__u64)malloc(1024);
	attr.log_size = 1024;
	attr.log_level = 3;
	((char*)attr.log_buf)[0] = 0;
	attr.kern_version = 0x041800;
	attr.prog_flags = 0;

	int res = syscall(321, BPF_PROG_LOAD, &attr, sizeof(attr));
    std::cout << (char*)attr.log_buf << "\n";
    return res;
}


using std::string;
using std::vector;



static size_t hash(const raw_program& raw_prog) {
    char* start = (char*)raw_prog.prog.data();
    char* end = start + (raw_prog.prog.size() * sizeof(ebpf_inst));
    return boost::hash_range(start, end);
}

int main(int argc, char **argv)
{
    crab::CrabEnableWarningMsg(false);

    CLI::App app{"A new eBPF verifier"};

    std::string filename;
    app.add_option("path", filename, "Elf file to analyze")->required()->type_name("FILE");

    std::string desired_section;

    app.add_option("section", desired_section, "Section to analyze")->type_name("SECTION");
    bool list=false;
    app.add_flag("-l", list, "List sections");

    std::string domain="zoneCrab";
    std::set<string> doms{"stats", "linux"};
    for (auto const [name, desc] : domain_descriptions())
        doms.insert(name);
    app.add_set("-d,--dom,--domain", domain, doms, "Abstract domain")->type_name("DOMAIN");

    app.add_flag("-v", global_options.print_invariants, "Print invariants");
    
    std::string asmfile;
    app.add_option("--asm", asmfile, "Print disassembly to FILE")->type_name("FILE");
    std::string dotfile;
    app.add_option("--dot", dotfile, "Export cfg to dot FILE")->type_name("FILE");

    CLI11_PARSE(app, argc, argv);
    if (filename == "@headers") {
        if (domain == "stats") {
            std::cout << "hash";
            for (string h : Cfg::stats_headers()) {
                std::cout << "," << h;
            }
        } else {
            std::cout << domain << "?,";
            std::cout << domain << "_sec,";
            std::cout << domain << "_kb";
        } 
        return 0;
    } 
    global_options.print_failures = global_options.print_invariants;

    auto raw_progs = read_elf(filename, desired_section);
    if (list || raw_progs.size() != 1) {
        if (!list) {
            std::cout << "please specify a section\n";
            std::cout << "available sections:\n";
        }
        for (raw_program raw_prog : raw_progs) {
            std::cout << raw_prog.section << " ";
        }
        std::cout << "\n";
        return 64;
    }
    raw_program raw_prog = raw_progs.back();
    if (domain == "linux") {
        int res = bpf_verify_program(to_linuxtype(raw_prog.info.program_type), raw_prog.prog);
        std::cout << (res != -1) << "," << 0 << "," << 0 << "\n";
        return 0;
    } 

    auto prog_or_error = unmarshal(raw_prog);
    if (std::holds_alternative<string>(prog_or_error)) {
        std::cout << "trivial verification failure: " << std::get<string>(prog_or_error) << "\n";
        return 1;
    }

    auto& prog = std::get<InstructionSeq>(prog_or_error);
    if (!asmfile.empty()) print(prog, asmfile);

    Cfg cfg = Cfg::make(prog);
    cfg = cfg.to_nondet(true);
    cfg.simplify();
    if (!dotfile.empty()) print_dot(cfg, dotfile);

    if (domain == "stats") {
        std::cout << std::hex << hash(raw_prog) << std::dec;
        auto stats = cfg.collect_stats();
        for (string h : Cfg::stats_headers()) {
            std::cout  << "," << stats.at(h);
        }
        std::cout << "\n";
    } else {
        const auto [res, seconds] = abs_validate(cfg, domain, raw_prog.info);
        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
    }
    return 0;
}
