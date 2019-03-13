#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sys/stat.h>

#include "asm_files.hpp"
#include "spec_type_descriptors.hpp"

#include "asm_unmarshal.hpp"
#include "asm_marshal.hpp"
#include "asm_ostream.hpp"
#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

static vector<ebpf_inst> stream_to_prog(std::istream& is, size_t nbytes)
{
    vector<ebpf_inst> ebpf_insts(nbytes / sizeof(ebpf_inst));
    is.read((char*)ebpf_insts.data(), nbytes);
    return ebpf_insts;
} 

std::vector<raw_program> read_raw(std::string path, program_info info)
{
    using std::ifstream;
    ifstream is(path, ifstream::ate | ifstream::binary);
    if (is.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    size_t nbytes = is.tellg();
    is.seekg(0);
    return { raw_program{path, "",  stream_to_prog(is, nbytes), info} };
}

void write_binary_file(std::string path, const char* data, size_t size) {
    using std::ofstream;
    ofstream os(path, ofstream::binary);
    if (os.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    os.write(data, size);
}

std::ifstream open_asm_file(std::string path)
{
    struct stat path_stat;
    stat(path.c_str(), &path_stat);
    if (!S_ISREG(path_stat.st_mode)) {
        std::cerr << "Cannot read from a directory: " << path << "\n";
        exit(65);
    }
    std::ifstream is(path);
    if (is.fail()) {
        std::cerr << "file " << path << " does not exist\n";
        exit(65);
    }
    return is;
}

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
	char *name;
	size_t elf_offset;
	struct bpf_load_map_def def;
};

template<typename T>
static vector<T> vector_of(ELFIO::section* sec) {
    if (!sec) return {};
    auto data = sec->get_data();
    auto size = sec->get_size();
    assert(size % sizeof(T) == 0);
    return {(T*)data, (T*)(data + size)};
}

std::vector<int> sort_maps_by_size(std::vector<map_def>& map_defs) {
    // after sorting, the map that was previously at index i will be at index res[i]
    std::sort(map_defs.begin(), map_defs.end(), [](auto a, auto b) { return a.value_size < b.value_size; });
    std::vector<int> res(map_defs.size());
    for (size_t i=0; i<map_defs.size(); i++) {
        res[map_defs[i].original_fd] = i;
    }
    return res;
}

static int allocate_fds(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries) {
    static int i = -1;
    i++;
    return i;
}

vector<raw_program> create_blowup()
{
    std::vector<LabeledInstruction> blowup;
    //blowup.emplace_back("0", Bin{Bin::Op::MOV, true, Reg{0}, (Value)Imm{1}, false});
    blowup.emplace_back("0", Call{5, "get_ns"});
    blowup.emplace_back("1", Bin{Bin::Op::MOV, true, Reg{1}, (Value)Imm{2}, false});
    using std::to_string;
    int i = 2;
    while (i < 142) {
        blowup.emplace_back(to_string(i), Jmp{Condition{Condition::Op::GT, Reg{0}, (Value)Reg{1}}, to_string(i+3)});
        i++;
        blowup.emplace_back(to_string(i), Bin{Bin::Op::SUB, true, Reg{1}, (Value)Reg{0}, false});
        i++;
        blowup.emplace_back(to_string(i), Jmp{{}, to_string(i+2)});
        i++;
        blowup.emplace_back(to_string(i), Bin{Bin::Op::SUB, true, Reg{0}, (Value)Reg{1}, false});
        i++;
    }
    blowup.emplace_back(to_string(i), Exit{});
    raw_program res;
    res.prog = marshal(blowup);
    res.info.program_type = BpfProgType::SOCKET_FILTER;
    return {res};
}

vector<raw_program> read_elf(std::string path, std::string desired_section, MapFd* fd_alloc)
{
    if (fd_alloc == nullptr) {
        fd_alloc = allocate_fds;
    }
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        std::cerr << "Can't find or process ELF file " << path << "\n";
        exit(2);
    }
    
    program_info info;
    auto mapdefs = vector_of<bpf_load_map_def>(reader.sections["maps"]);
    for (auto s : mapdefs) {
        info.map_defs.emplace_back(map_def{
            .original_fd=fd_alloc(s.type, s.key_size, s.value_size, s.max_entries),
            .type=MapType{s.type},
            .key_size=s.key_size,
            .value_size=s.value_size,
        });
    }
    for (size_t i=0; i < mapdefs.size(); i++) {
        int inner = mapdefs[i].inner_map_idx;
        info.map_defs[i].inner_map_fd = info.map_defs[inner].original_fd;
    }
    //std::vector<int> updated_fds = sort_maps_by_size(info.map_defs);

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    auto read_reloc_value = [&symbols](int symbol) -> int {
        string symbol_name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half section_index;
        unsigned char other;
        symbols.get_symbol(symbol, symbol_name, value, size, bind, type, section_index, other);
        return value / sizeof(bpf_load_map_def);
    };

    vector<raw_program> res;
    
    for (const auto section : reader.sections)
    {
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
        if (!prelocs) prelocs = reader.sections[string(".rela") + name];
        if (prelocs) {
            ELFIO::const_relocation_section_accessor reloc{reader, prelocs};
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol;
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;
            for (unsigned int i=0; i < reloc.get_entries_num(); i++) {
                if (reloc.get_entry(i, offset, symbol, type, addend)) {
                    auto& inst = prog.prog[offset / sizeof(ebpf_inst)];
                    inst.src = 1; // magic number for LoadFd
                    inst.imm = info.map_defs[read_reloc_value(symbol)].original_fd;
                    //inst.imm = updated_fds.at(read_reloc_value(symbol));
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
