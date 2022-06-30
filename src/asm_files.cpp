// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <sys/stat.h>

#include "asm_files.hpp"
#include "btf_parser.h"
#include "platform.hpp"

#include "elfio/elfio.hpp"

using std::cout;
using std::string;
using std::vector;

template <typename T>
static vector<T> vector_of(const ELFIO::section& sec) {
    auto data = sec.get_data();
    auto size = sec.get_size();
    if ((size % sizeof(T) != 0) || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
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
bool is_map_section(const std::string& name) {
    std::string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

// parse_maps_sections processes all maps sections in the provided ELF file by calling the platform-specific maps
// parser. The section index of each maps section is inserted into section_indices.
static size_t parse_map_sections(const ebpf_verifier_options_t* options, const ebpf_platform_t* platform, const ELFIO::elfio& reader, std::vector<EbpfMapDescriptor>& map_descriptors, std::set<ELFIO::Elf_Half>& section_indices, ELFIO::const_symbol_section_accessor& symbols) {
    size_t map_record_size = platform->map_record_size;
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        auto s = reader.sections[i];
        if (!is_map_section(s->get_name()))
            continue;

        // Count the number of symbols that point into this maps section.
        int map_count = 0;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
            string symbol_name;
            ELFIO::Elf64_Addr value{};
            ELFIO::Elf_Xword size{};
            unsigned char bind{};
            unsigned char type{};
            ELFIO::Elf_Half section_index{};
            unsigned char other{};
            symbols.get_symbol(index, symbol_name, value, size, bind, type, section_index, other);
            if ((section_index == i) && !symbol_name.empty())
                map_count++;
        }

        if (map_count > 0) {
            map_record_size = s->get_size() / map_count;
            if ((s->get_data() == nullptr) || (map_record_size == 0)) {
                throw std::runtime_error(std::string("bad maps section"));
            }
            if (s->get_size() % map_record_size != 0) {
                throw std::runtime_error(std::string("bad maps section size"));
            }
            platform->parse_maps_section(map_descriptors, s->get_data(), map_record_size, map_count, platform,
                                         *options);
        }
        section_indices.insert(s->get_index());
    }
    return map_record_size;
}

vector<raw_program> read_elf(const std::string& path, const std::string& desired_section, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        return read_elf(stream, path, desired_section, options, platform);
    }
    struct stat st;
    if (stat(path.c_str(), &st)) {
        throw std::runtime_error(string(strerror(errno)) + " opening " + path);
    }
    throw std::runtime_error(string("Can't process ELF file ") + path);
}

vector<raw_program> read_elf(std::istream& input_stream, const std::string& path, const std::string& desired_section, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw std::runtime_error(string("Can't process ELF file ") + path);
    }

    program_info info{platform};
    std::set<ELFIO::Elf_Half> map_section_indices;

    auto symbol_section = reader.sections[".symtab"];
    if (!symbol_section) {
        throw std::runtime_error(string("No symbol section found in ELF file ") + path);
    }

    // Make sure the ELFIO library will be able to parse the symbol section correctly.
    auto expected_entry_size =
        (reader.get_class() == ELFIO::ELFCLASS32) ? sizeof(ELFIO::Elf32_Sym) : sizeof(ELFIO::Elf64_Sym);
    if (symbol_section->get_entry_size() != expected_entry_size) {
        throw std::runtime_error(string("Invalid symbol section found in ELF file ") + path);
    }

    ELFIO::const_symbol_section_accessor symbols{reader, symbol_section};
    size_t map_record_size = parse_map_sections(options, platform, reader, info.map_descriptors, map_section_indices, symbols);

    auto read_reloc_value = [&symbols,platform,map_record_size](ELFIO::Elf_Word symbol) -> size_t {
        string symbol_name;
        ELFIO::Elf64_Addr value{};
        ELFIO::Elf_Xword size{};
        unsigned char bind{};
        unsigned char type{};
        ELFIO::Elf_Half section_index{};
        unsigned char other{};
        symbols.get_symbol(symbol, symbol_name, value, size, bind, type, section_index, other);

        return value / map_record_size;
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
        if ((section->get_size() == 0) || (section->get_data() == nullptr))
            continue;
        info.type = platform->get_program_type(name, path);
        raw_program prog{path, name, vector_of<ebpf_inst>(*section), info};
        auto prelocs = reader.sections[string(".rel") + name];
        if (!prelocs)
            prelocs = reader.sections[string(".rela") + name];

        if (prelocs) {
            if (!prelocs->get_data()) {
                throw std::runtime_error("Malformed relocation data");
            }
            ELFIO::const_relocation_section_accessor reloc{reader, prelocs};
            ELFIO::Elf64_Addr offset;
            ELFIO::Elf_Word symbol{};
            unsigned type;
            ELFIO::Elf_Sxword addend;
            // Fetch and store relocation count locally to permit static
            // analysis tools to correctly reason about the code below.
            ELFIO::Elf_Xword relocation_count = reloc.get_entries_num();

            // Below, only relocations of symbols located in the map sections are allowed,
            // so if there are relocations there needs to be a maps section.
            if (relocation_count && !map_section_indices.size()) {
                throw std::runtime_error(string("Can't find any maps sections in file ") + path);
            }

            for (ELFIO::Elf_Xword i = 0; i < relocation_count; i++) {
                if (reloc.get_entry(i, offset, symbol, type, addend)) {
                    if ((offset / sizeof(ebpf_inst)) >= prog.prog.size()) {
                        throw std::runtime_error("Invalid relocation data");
                    }
                    ebpf_inst& inst = prog.prog[offset / sizeof(ebpf_inst)];

                    string symbol_name;
                    ELFIO::Elf64_Addr symbol_value{};
                    unsigned char symbol_bind{};
                    unsigned char symbol_type{};
                    ELFIO::Elf_Half symbol_section_index{};
                    unsigned char symbol_other{};
                    ELFIO::Elf_Xword symbol_size{};

                    symbols.get_symbol(symbol, symbol_name, symbol_value, symbol_size, symbol_bind, symbol_type,
                                       symbol_section_index, symbol_other);

                    // Only perform relocation for symbols located in the maps section.
                    if (map_section_indices.find(symbol_section_index) == map_section_indices.end()) {
                        throw std::runtime_error(string("Unresolved external symbol " + symbol_name +
                                                        " at location " + std::to_string(offset / sizeof(ebpf_inst))));
                    }

                    // Only permit loading the address of the map.
                    if ((inst.opcode & INST_CLS_MASK) != INST_CLS_LD)
                    {
                        throw std::runtime_error(string("Illegal operation on symbol " + symbol_name +
                                                        " at location " + std::to_string(offset / sizeof(ebpf_inst))));
                    }
                    inst.src = 1; // magic number for LoadFd

                    size_t reloc_value = read_reloc_value(symbol);
                    if (reloc_value >= info.map_descriptors.size()) {
                        throw std::runtime_error(string("Bad reloc value (") + std::to_string(reloc_value) + "). "
                                                 + "Make sure to compile with -O2.");
                    }
                    inst.imm = info.map_descriptors.at(reloc_value).original_fd;
                }
            }
        }
        prog.line_info.resize(prog.prog.size());
        res.push_back(prog);
    }

    auto btf = reader.sections[string(".BTF")];
    auto btf_ext = reader.sections[string(".BTF.ext")];
    if (btf != nullptr && btf_ext != nullptr) {
        std::map<std::string, raw_program&> segment_to_program;
        for (auto& program : res) {
            segment_to_program.insert({program.section, program});
        }

        auto visitor = [&](const std::string& section, uint32_t instruction_offset, const std::string& file_name,
                        const std::string& source, uint32_t line_number, uint32_t column_number) {
            auto program_iter = segment_to_program.find(section);
            if (program_iter == segment_to_program.end()) {
                return;
            }
            auto& program = program_iter->second;
            if ((instruction_offset / sizeof(ebpf_inst)) >= program.line_info.size()) {
                throw std::runtime_error("Invalid BTF data");
            }
            program.line_info[instruction_offset / sizeof(ebpf_inst)] = {file_name, source, line_number, column_number};
        };

        btf_parse_line_information(vector_of<uint8_t>(*btf), vector_of<uint8_t>(*btf_ext), visitor);

        // BTF doesn't include line info for every instruction, only on the first instruction per source line.
        for (auto& [name, program] : segment_to_program) {
            for (size_t i = 1; i < program.line_info.size(); i++) {
                // If the previous PC has line info, copy it.
                if ((program.line_info[i].line_number == 0) && (program.line_info[i - 1].line_number != 0)) {
                    program.line_info[i] = program.line_info[i - 1];
                }
            }
        }
    }

    if (res.empty()) {
        if (desired_section.empty()) {
            throw std::runtime_error(string("Can't find any non-empty TEXT sections in file ") + path);
        }
        throw std::runtime_error(string("Can't find section ") + desired_section + " in file " + path);
    }
    return res;
}
