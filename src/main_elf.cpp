#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_set>
#include <string>

#include "asm_unmarshal.hpp"
#include "asm_ostream.hpp"
#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

using namespace ELFIO;


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

static const std::unordered_set<string> predefined{
    ".strtab",
    ".text",
    ".rodata",
    "license",
    "version",
    ".eh_frame",
    ".rel",
    ".symtab",
};

int main(int argc, char **argv)
{
    vector<string> args{argv + 1, argv + argc};
    elfio reader;
    if (!reader.load(args.at(0))) {
        cout << "Can't find or process ELF file " << args.at(0) << "\n";
        return 2;
    }
    
    Elf_Half sec_num = reader.sections.size();

    // TODO:
    // 1. relocation
    cout << args.at(0) << ": ";
    for (int i = 0; i < sec_num; ++i)
    {
        const section& sec = *reader.sections[i];
        const string name = sec.get_name();
        const auto size = sec.get_size();
        const char* p = sec.get_data();
        if (name == "maps") {
            vector<bpf_load_map_def> vec((bpf_load_map_def*)p, (bpf_load_map_def*)(p + size));
            int j = 0;
            for (auto s : vec) {
                if (j++) cout << ", ";
                cout << s.value_size;
            }
            continue;
        }
        if (size == 0 || predefined.count(name) || name.find(".") == 0)
            continue;
        //cout << " [" << i << "] " << name << "\t" << size << "\n";
        
        auto s = unmarshal(p, size);
        if (std::holds_alternative<string>(s)) {
            cout << std::get<string>(s) << "\n";
            continue;
        }
        std::get<InstructionSeq>(s);
        if (sec.get_type() == SHT_SYMTAB)
        {
            /*
            const symbol_section_accessor symbols(reader, psec);
            for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j)
            {
                std::string name;
                Elf64_Addr value;
                Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                Elf_Half section_index;
                unsigned char other;
                symbols.get_symbol(j, name, value, size, bind,
                                   type, section_index, other);
                cout << j << " " << name << "\n";
            }
            */
        }
    }
    cout << "\n";
}
