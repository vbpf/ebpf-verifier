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

#if __linux__
 
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
    default: return BPF_PROG_TYPE_SOCKET_FILTER;
    }
    return BPF_PROG_TYPE_UNSPEC;
};

int do_bpf(bpf_cmd cmd, union bpf_attr& attr) {
    return syscall(321, cmd, &attr, sizeof(attr));
}


static int create_map(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries)
{
    static int i = -1;
    i++;
    union bpf_attr attr;
    memset(&attr, '\0', sizeof(attr));
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = 20;
    attr.map_flags = map_type == BPF_MAP_TYPE_HASH ? BPF_F_NO_PREALLOC : 0;
    int fd = do_bpf(BPF_MAP_CREATE, attr);
    if (fd < 0) {
        if (global_options.print_failures) {
            std::cerr << "Failed to create map, " << strerror(errno) << "\n";
            std::cerr << "Map: \n"
                      << " map_type = "   << attr.map_type << "\n"
                      << " key_size = "   << attr.key_size << "\n"
                      << " value_size = " << attr.value_size << "\n"
                      << " max_entries = "<< attr.max_entries << "\n"
                      << " map_flags = "  << attr.map_flags << "\n";
        }
        exit(2);
    }
    return fd;
}

int bpf_verify_program(bpf_prog_type type, const std::vector<ebpf_inst>& raw_prog)
{
    std::vector<char> buf(100000);
    buf[0] = 0;
    memset(buf.data(), '\0', buf.size());

    union bpf_attr attr;
    memset(&attr, '\0', sizeof(attr));
    attr.prog_type = (__u32)type;
    attr.insn_cnt = (__u32)raw_prog.size();
    attr.insns = (__u64)raw_prog.data();
    attr.license = (__u64)"GPL";
    attr.log_buf = (__u64)buf.data();
    attr.log_size = buf.size();
    attr.log_level = 3;
    attr.kern_version = 0x041800;
    attr.prog_flags = 0;

    int res = do_bpf(BPF_PROG_LOAD, attr);
    if (res < 0) {
        if (global_options.print_failures) {
            std::cerr << "Failed to verify program: " << strerror(errno) << " (" << errno << ")\n";
            std::cerr << "LOG: " << (char*)attr.log_buf;
        }
        return 0;
    }
    return 1;
}
#endif

static int allocate_fds(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries)
{
    static int i = -1;
    i++;
    return i;
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
    std::set<string> doms{"stats", "linux", "rcp"};
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

#if __linux__
    if (filename == "blowup") {
        std::vector<LabeledInstruction> blowup;
        blowup.emplace_back("0", Bin{Bin::Op::MOV, true, Reg{0}, (Value)Imm{1}, false});
        blowup.emplace_back("1", Bin{Bin::Op::MOV, true, Reg{1}, (Value)Imm{2}, false});
        blowup.emplace_back("2", Jmp{Condition{Condition::Op::GT, Reg{0}, (Value)Reg{1}}, "5"});
        blowup.emplace_back("3", Bin{Bin::Op::ADD, true, Reg{1}, (Value)Reg{0}, false});
        blowup.emplace_back("4", Jmp{{}, "6"});
        blowup.emplace_back("5", Bin{Bin::Op::ADD, true, Reg{0}, (Value)Reg{1}, false});
        blowup.emplace_back("6", Exit{});
        print(blowup);
        auto raw_blowup = marshal(blowup);
        int res = bpf_verify_program(BPF_PROG_TYPE_SOCKET_FILTER, raw_blowup);
        std::cout << res << "," << 0 << "," << 0 << "\n";
        return res;
    }
    auto raw_progs = read_elf(filename, desired_section, domain == "linux" ? create_map : allocate_fds);
#else
    auto raw_progs = read_elf(filename, desired_section, allocate_fds);
#endif

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
    int res;
    raw_program raw_prog = raw_progs.back();
#if __linux__
    if (domain == "linux") {
        res = bpf_verify_program(to_linuxtype(raw_prog.info.program_type), raw_prog.prog);
        std::cout << res << "," << 0 << "," << 0 << "\n";
    } 
#endif

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

    if (domain == "linux") {
        return res;
    }

    if (domain == "stats") {
        std::cout << std::hex << hash(raw_prog) << std::dec;
        auto stats = cfg.collect_stats();
        for (string h : Cfg::stats_headers()) {
            std::cout  << "," << stats.at(h);
        }
        std::cout << "\n";
    } else if (domain == "rcp") {
        analyze_rcp(cfg, raw_prog.info);
    } else {
        const auto [res, seconds] = abs_validate(cfg, domain, raw_prog.info);
        std::cout << res << "," << seconds << "," << resident_set_size_kb() << "\n";
    }
    return 0;
}

