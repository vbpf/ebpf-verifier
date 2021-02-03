// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "asm_files.hpp"
#include "platform.hpp"

#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

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

struct bpf_map_data {
    int map_fd;
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

int create_map_crab(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options) {
    if (map_type == 12 || map_type == 13) {
        return -1;
    }
    return (value_size << 14) + (key_size << 6); // + i;
}

vector<raw_program> read_elf(const std::string& path, const std::string& desired_section, MapFd* fd_alloc, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    assert(fd_alloc != nullptr);
    if (options == nullptr)
        options = &ebpf_verifier_default_options;
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        throw std::runtime_error(string("Can't find or process ELF file ") + path);
    }

    program_info info{platform};
    auto mapdefs = vector_of<bpf_load_map_def>(reader.sections["maps"]);
    for (auto s : mapdefs) {
        info.map_descriptors.emplace_back(EbpfMapDescriptor{
            .original_fd = fd_alloc(s.type, s.key_size, s.value_size, s.max_entries, *options),
            .type = s.type,
            .key_size = s.key_size,
            .value_size = s.value_size,
        });
    }
    for (size_t i = 0; i < mapdefs.size(); i++) {
        unsigned int inner = mapdefs[i].inner_map_idx;
        if (inner >= info.map_descriptors.size())
            throw std::runtime_error(string("bad inner map index ") + std::to_string(inner)
                                     + " for map " + std::to_string(i));
        info.map_descriptors[i].inner_map_fd = info.map_descriptors.at(inner).original_fd;
    }

    ELFIO::const_symbol_section_accessor symbols{reader, reader.sections[".symtab"]};
    auto read_reloc_value = [&symbols](int symbol) -> size_t {
        string symbol_name;
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size{};
        unsigned char bind{};
        unsigned char type{};
        ELFIO::Elf_Half section_index{};
        unsigned char other{};
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
        if (name != ".text" && name.find('.') == 0) {
            continue;
        }
        info.type = platform->get_program_type(name, path);
        if (section->get_size() == 0)
            continue;
        raw_program prog{path, name, vector_of<ebpf_inst>(section), info};
        auto prelocs = reader.sections[string(".rel") + name];
        if (!prelocs)
            prelocs = reader.sections[string(".rela") + name];

        // // std::vector<int> updated_fds = sort_maps_by_size(info.map_descriptors);
        // for (auto n : updated_fds) {
        //     std::cout << "old=" << info.map_descriptors[n].original_fd << ", "
        //               << "new=" << n << ", "
        //               << "size=" << info.map_descriptors[n].value_size << "\n";
        // }
        if (prelocs) {
            ELFIO::const_relocation_section_accessor reloc{reader, prelocs};
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol{};
            ELFIO::Elf_Word type;
            ELFIO::Elf_Sxword addend;
            for (ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); i++) {
                if (reloc.get_entry(i, offset, symbol, type, addend)) {
                    ebpf_inst& inst = prog.prog[offset / sizeof(ebpf_inst)];
                    inst.src = 1; // magic number for LoadFd

                    // if (fd_alloc == allocate_fds) {
                    //     std::cout << read_reloc_value(symbol) << "=" <<
                    //     info.map_descriptors[updated_fds.at(read_reloc_value(symbol))].value_size << "\n";
                    //     inst.imm = updated_fds.at(read_reloc_value(symbol));
                    // } else {
                    size_t reloc_value = read_reloc_value(symbol);
                    if (reloc_value >= info.map_descriptors.size()) {
                        throw std::runtime_error(string("Bad reloc value (") + std::to_string(reloc_value) + "). "
                                                 + "Make sure to compile with -O2.");
                    }
                    inst.imm = info.map_descriptors.at(reloc_value).original_fd;
                    // }
                }
            }
        }
        res.push_back(prog);
    }
    if (res.empty()) {
        throw std::runtime_error(string("Can't find section ") + desired_section + " in file " + path);
    }
    return res;
}
