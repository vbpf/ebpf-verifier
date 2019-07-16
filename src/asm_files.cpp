#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "asm_files.hpp"
#include "spec_type_descriptors.hpp"

#include "asm_marshal.hpp"
#include "asm_ostream.hpp"
#include "asm_unmarshal.hpp"
#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

#define MAX_MAPS 32
#define MAX_PROGS 32

struct bpf_load_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int inner_map_idx;
    unsigned int numa_node;
};

struct bpf_map_data {
    int fd;
    char* name;
    size_t elf_offset;
    struct bpf_load_map_def def;
};

template <typename T>
static vector<T> vector_of(ELFIO::section* sec) {
    if (!sec)
        return {};
    auto data = sec->get_data();
    auto size = sec->get_size();
    assert(size % sizeof(T) == 0);
    return {(T*)data, (T*)(data + size)};
}

int create_map_rcp(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries) {
    static int i = -1;
    i++;
    return i;
}

int create_map_crab(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries) {
    if (map_type == 12 || map_type == 13) {
        return -1;
    }
    return (value_size << 14) + (key_size << 6); // + i;
}

static BpfProgType section_to_progtype(std::string section, std::string path) {
    // linux only deduces from section, but cilium and cilium_test have this information
    // in the filename:
    // * cilium/bpf_xdp.o:from-netdev is XDP
    // * bpf_cilium_test/bpf_lb-DLB_L3.o:from-netdev is SK_SKB
    if (path.find("cilium") != std::string::npos) {
        if (path.find("xdp") != std::string::npos)
            return BpfProgType::XDP;
        if (path.find("lxc") != std::string::npos)
            return BpfProgType::SCHED_CLS;
    }
    static const std::unordered_map<std::string, BpfProgType> prefixes{
        {"socket", BpfProgType::SOCKET_FILTER},
        {"kprobe/", BpfProgType::KPROBE},
        {"kretprobe/", BpfProgType::KPROBE},
        {"tracepoint/", BpfProgType::TRACEPOINT},
        {"raw_tracepoint/", BpfProgType::RAW_TRACEPOINT},
        {"xdp", BpfProgType::XDP},
        {"perf_section", BpfProgType::PERF_EVENT},
        {"perf_event", BpfProgType::PERF_EVENT},
        {"classifier", BpfProgType::SCHED_CLS},
        {"action", BpfProgType::SCHED_ACT},
        {"cgroup/skb", BpfProgType::CGROUP_SKB},
        {"cgroup/sock", BpfProgType::CGROUP_SOCK},
        {"cgroup/dev", BpfProgType::CGROUP_DEVICE},
        {"lwt_in", BpfProgType::LWT_IN},
        {"lwt_out", BpfProgType::LWT_OUT},
        {"lwt_xmit", BpfProgType::LWT_XMIT},
        {"lwt_seg6local", BpfProgType::LWT_SEG6LOCAL},
        {"lirc_mode2", BpfProgType::LIRC_MODE2},
        {"sockops", BpfProgType::SOCK_OPS},
        {"sk_skb", BpfProgType::SK_SKB},
        {"sk_msg", BpfProgType::SK_MSG},
    };
    for (const auto [prefix, t] : prefixes) {
        if (section.find(prefix) == 0)
            return t;
    }
    return BpfProgType::SOCKET_FILTER;
}

vector<raw_program> read_elf(std::string path, std::string desired_section, MapFd* fd_alloc) {
    assert(fd_alloc != nullptr);
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        std::cerr << "Can't find or process ELF file " << path << "\n";
        exit(2);
    }

    program_info info;
    auto mapdefs = vector_of<bpf_load_map_def>(reader.sections["maps"]);
    for (auto s : mapdefs) {
        info.map_defs.emplace_back(map_def{
            .original_fd = fd_alloc(s.type, s.key_size, s.value_size, s.max_entries),
            .type = MapType{s.type},
            .key_size = s.key_size,
            .value_size = s.value_size,
        });
    }
    for (size_t i = 0; i < mapdefs.size(); i++) {
        int inner = mapdefs[i].inner_map_idx;
        info.map_defs[i].inner_map_fd = info.map_defs[inner].original_fd;
    }

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    auto read_reloc_value = [&symbols](int symbol) -> int {
        string symbol_name;
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half section_index;
        unsigned char other;
        symbols.get_symbol(symbol, symbol_name, value, size, bind, type, section_index, other);
        return value / sizeof(bpf_load_map_def);
    };

    vector<raw_program> res;

    for (const auto section : reader.sections) {
        const string name = section->get_name();
        if (!desired_section.empty() && name != desired_section)
            continue;
        if (name == "license" || name == "version" || name == "maps")
            continue;
        if (name.find(".") == 0) {
            continue;
        }
        info.program_type = section_to_progtype(name, path);
        info.descriptor = get_descriptor(info.program_type);
        if (section->get_size() == 0)
            continue;
        raw_program prog{path, name, vector_of<ebpf_inst>(section), info};
        auto prelocs = reader.sections[string(".rel") + name];
        if (!prelocs)
            prelocs = reader.sections[string(".rela") + name];

        // // std::vector<int> updated_fds = sort_maps_by_size(info.map_defs);
        // for (auto n : updated_fds) {
        //     std::cout << "old=" << info.map_defs[n].original_fd << ", "
        //               << "new=" << n << ", "
        //               << "size=" << info.map_defs[n].value_size << "\n";
        // }
        if (prelocs) {
            ELFIO::const_relocation_section_accessor reloc{reader, prelocs};
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol{};
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;
            for (unsigned int i = 0; i < reloc.get_entries_num(); i++) {
                if (reloc.get_entry(i, offset, symbol, type, addend)) {
                    auto& inst = prog.prog[offset / sizeof(ebpf_inst)];
                    inst.src = 1; // magic number for LoadFd
                                  // if (fd_alloc == allocate_fds) {
                                  //     std::cout << read_reloc_value(symbol) << "=" <<
                    //     info.map_defs[updated_fds.at(read_reloc_value(symbol))].value_size << "\n"; inst.imm =
                    //     updated_fds.at(read_reloc_value(symbol));
                    // } else {
                    inst.imm = info.map_defs[read_reloc_value(symbol)].original_fd;
                    // }
                }
            }
        }
        res.push_back(prog);
    }
    if (res.empty()) {
        std::cerr << "Could not find relevant section!\n";
    }
    return res;
}
