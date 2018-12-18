#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sys/stat.h>

#include "asm_files.hpp"
#include "spec_type_descriptors.hpp"

#include "asm_unmarshal.hpp"
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
    auto data = sec->get_data();
    auto size = sec->get_size();
    assert(size % sizeof(T) == 0);
    return {(T*)data, (T*)(data + size)};
}

vector<raw_program> read_elf(std::string path)
{
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        std::cerr << "Can't find or process ELF file " << path << "\n";
        exit(2);
    }
    
    // TODO: relocation
    program_info info;
    for (auto s : vector_of<bpf_load_map_def>(reader.sections["maps"]))
        info.map_sizes.push_back(s.value_size);

    vector<raw_program> res;
    for (const auto section : reader.sections)
    {
        const string name = section->get_name();
        if (name == "license" || name == "version" || name == "maps" || name.find(".") == 0)
            continue;
        info.program_type = section_to_progtype(name);
        raw_program prog{path, name, vector_of<ebpf_inst>(section), info};
        if (!prog.prog.empty())
            res.push_back(prog);
    }
    return res;
}
