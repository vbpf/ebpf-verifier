// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sys/stat.h>

#include "asm_files.hpp"
#include "platform.hpp"

#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

template <typename T>
static vector<T> vector_of(const ELFIO::section& sec) {
    auto data = sec.get_data();
    auto size = sec.get_size();
    assert(size % sizeof(T) == 0);
    return {(T*)data, (T*)(data + size)};
}

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options) {
    EquivalenceKey equiv{map_type.value_type, key_size, value_size, map_type.is_array ? max_entries : 0};
    if (!global_program_info.cache.count(equiv)) {
        // +1 so 0 is the null FD
        global_program_info.cache[equiv] = (int)global_program_info.cache.size() + 1;
    }
    return global_program_info.cache.at(equiv);
}

EbpfMapDescriptor* find_map_descriptor(int map_fd) {
    for (EbpfMapDescriptor& map : global_program_info.map_descriptors) {
        if (map.original_fd == map_fd) {
            return &map;
        }
    }
    return nullptr;
}

// Maps sections are identified as any section called "maps", or matching "maps/<map-name>".
static bool is_map_section(const std::string& name) {
    std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

// parse_maps_sections processes all maps sections in the provided ELF file by calling the platform-specific maps
// parser. The section index of each maps section is inserted into section_indices.
static std::vector<EbpfMapDescriptor> parse_map_sections(const ebpf_verifier_options_t* options, const ebpf_platform_t* platform, const ELFIO::elfio& reader) {
    std::vector<EbpfMapDescriptor> map_descriptors;
    for (const auto s : reader.sections) {
        if (is_map_section(s->get_name())) {
            platform->parse_maps_section(map_descriptors, s->get_data(), s->get_size(), platform, *options);
        }
    }
    return map_descriptors;
}

enum reloc_type_t { // (see https://www.kernel.org/doc/html/latest/bpf/llvm_reloc.html)
                         // Description      BitSize  Offset        Calculation
    R_BPF_NONE=0,        // None
    R_BPF_64_64=1,       // ld_imm64 insn    32       r_offset + 4  S + A
    R_BPF_64_ABS64=2,    // normal data      64       r_offset      S + A
    R_BPF_64_ABS32=3,    // normal data      32       r_offset      S + A
    R_BPF_64_NODYLD32=4, // .BTF[.ext] data  32       r_offset      S + A
    R_BPF_64_32=10       // call insn        32       r_offset + 4  (S + A) / 8 - 1
};

static vector<std::tuple<ELFIO::Elf64_Addr, size_t>> collect_fd_relocs(ELFIO::elfio& reader, const string& name, const ebpf_platform_t* platform) {
    auto prelocs = reader.sections[string(".rel") + name];
    if (!prelocs)
        prelocs = reader.sections[string(".rela") + name];
    if (!prelocs)
        return {};

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};

    vector<std::tuple<ELFIO::Elf64_Addr, size_t>> map_fd_relocs;
    ELFIO::const_relocation_section_accessor reloc{reader, prelocs};
    ELFIO::Elf64_Addr offset{};
    ELFIO::Elf_Word symbol{};
    unsigned char type{};
    ELFIO::Elf_Sxword addend{};

    // Fetch and store relocation count locally to permit static
    // analysis tools to correctly reason about the code below.
    const ELFIO::Elf_Xword relocation_count = reloc.get_entries_num();

    for (ELFIO::Elf_Xword i = 0; i < relocation_count; i++) {
        const bool valid_entry = reloc.get_entry(i, offset, symbol, type, addend);
        std::cout << "type of reloc " << i << "(" << symbol << ", " << offset / sizeof(ebpf_inst) << ") : " << (int)type << "\n";
        if (valid_entry && (type == R_BPF_64_64 || type == R_BPF_NONE)) {

            string symbol_name;
            ELFIO::Elf64_Addr symbol_value{};
            unsigned char symbol_bind{};
            unsigned char symbol_type{};
            ELFIO::Elf_Half symbol_section_index{};
            unsigned char symbol_other{};
            ELFIO::Elf_Xword symbol_size{};

            symbols.get_symbol(symbol, symbol_name, symbol_value, symbol_size, symbol_bind, symbol_type,
                               symbol_section_index, symbol_other);

            map_fd_relocs.emplace_back(offset / sizeof(ebpf_inst), symbol_value / platform->map_record_size);
        }
    }
    return map_fd_relocs;
}

static ELFIO::elfio open_file(const std::string& path) {
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        struct stat st;
        if (stat(path.c_str(), &st)) {
            throw std::runtime_error(string(strerror(errno)) + " opening " + path);
        }
        throw std::runtime_error(string("Can't process ELF file ") + path);
    }
    return reader;
}

void apply_reloc(raw_program& prog, unsigned long instruction_index, int32_t reloc_value) {
    ebpf_inst& inst = prog.prog[instruction_index];

    // Only permit loading the address of the map.
    if ((inst.opcode & INST_CLS_MASK) != INST_CLS_LD) {
        throw std::runtime_error(string("Illegal operation at location " + std::to_string(instruction_index)));
    }
    inst.src = 1; // magic number for LoadFd
    inst.imm = reloc_value;
}

vector<raw_program> read_elf(const std::string& path, const std::string& desired_section, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;

    program_info info{platform};

    ELFIO::elfio reader = open_file(path);
    info.map_descriptors = parse_map_sections(options, platform, reader);

    vector<raw_program> res;

    vector<ELFIO::section*> maps_sections;
    vector<ELFIO::section*> program_sections;
    for (const ELFIO::section* section : reader.sections) {
        const string name = section->get_name();
        //  switch {
        //  case sec.Name == ".maps":
        //  	sections[idx] = newElfSection(sec, btfMapSection)
        //  case sec.Name == ".bss" || sec.Name == ".data" || strings.HasPrefix(sec.Name, ".rodata"):
        //  	sections[idx] = newElfSection(sec, dataSection)
        //  case sec.Type == elf.SHT_REL:
        //  	// Store relocations under the section index of the target
        //  	relSections[elf.SectionIndex(sec.Info)] = sec
        //  case sec.Type == elf.SHT_PROGBITS && (sec.Flags&elf.SHF_EXECINSTR) != 0 && sec.Size > 0:
        //  	sections[idx] = newElfSection(sec, programSection)
        //  }
        if (!desired_section.empty() && name != desired_section)
            continue;
        if (name == "license" || name == "version" || name == "maps")
            continue;
        if (name != ".text" && name.find('.') == 0) {
            continue;
        }
        info.type = platform->get_program_type(name, path);
        if (section->get_size() == 0)
            continue;
        raw_program prog{path, name, vector_of<ebpf_inst>(*section), info};

        for (const auto& [instruction_index, reloc_value]: collect_fd_relocs(reader, name, platform)) {
            if (reloc_value >= info.map_descriptors.size()) {
                throw std::runtime_error(string("Bad reloc value (") + std::to_string(reloc_value) + "). "
                                         + "Make sure to compile with -O2.");
            }
            apply_reloc(prog, instruction_index, info.map_descriptors.at(reloc_value).original_fd);
        }
        res.push_back(prog);
    }
    if (res.empty()) {
        if (desired_section.empty()) {
            throw std::runtime_error(string("Can't find any non-empty TEXT sections in file ") + path);
        }
        throw std::runtime_error(string("Can't find section ") + desired_section + " in file " + path);
    }
    return res;
}
