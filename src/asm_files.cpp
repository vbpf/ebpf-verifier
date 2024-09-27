// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "elfio/elfio.hpp"
#include "libbtf/btf.h"
#include "libbtf/btf_json.h"
#include "libbtf/btf_map.h"
#include "libbtf/btf_parse.h"

#include "asm_files.hpp"
#include "platform.hpp"

using std::cout;
using std::string;
using std::vector;

template <typename T>
static vector<T> vector_of(const char* data, ELFIO::Elf_Xword size) {
    if ((size % sizeof(T) != 0) || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {(T*)data, (T*)(data + size)};
}

template <typename T>
static vector<T> vector_of(const ELFIO::section& sec) {
    auto data = sec.get_data();
    auto size = sec.get_size();
    return vector_of<T>(data, size);
}

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options) {
    EquivalenceKey equiv{map_type.value_type, key_size, value_size, map_type.is_array ? max_entries : 0};
    if (!global_program_info->cache.count(equiv)) {
        // +1 so 0 is the null FD
        global_program_info->cache[equiv] = (int)global_program_info->cache.size() + 1;
    }
    return global_program_info->cache.at(equiv);
}

EbpfMapDescriptor* find_map_descriptor(int map_fd) {
    for (EbpfMapDescriptor& map : global_program_info->map_descriptors) {
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

std::tuple<string, ELFIO::Elf_Half> get_symbol_name_and_section_index(const ELFIO::const_symbol_section_accessor& symbols,
                                                                      ELFIO::Elf_Xword index) {
    string symbol_name;
    ELFIO::Elf64_Addr value{};
    ELFIO::Elf_Xword size{};
    unsigned char bind{};
    unsigned char type{};
    ELFIO::Elf_Half section_index{};
    unsigned char other{};
    symbols.get_symbol(index, symbol_name, value, size, bind, type, section_index, other);
    return {symbol_name, section_index};
}

std::tuple<ELFIO::Elf64_Addr, unsigned char> get_value(const ELFIO::const_symbol_section_accessor& symbols,
                                                       ELFIO::Elf_Xword index) {
    string symbol_name;
    ELFIO::Elf64_Addr value{};
    ELFIO::Elf_Xword size{};
    unsigned char bind{};
    unsigned char type{};
    ELFIO::Elf_Half section_index{};
    unsigned char other{};
    symbols.get_symbol(index, symbol_name, value, size, bind, type, section_index, other);
    return {value, type};
}

// parse_maps_sections processes all maps sections in the provided ELF file by calling the platform-specific maps
// parser. The section index of each maps section is inserted into section_indices.
static size_t parse_map_sections(const ebpf_verifier_options_t* options, const ebpf_platform_t* platform,
                                 const ELFIO::elfio& reader, std::vector<EbpfMapDescriptor>& map_descriptors,
                                 std::set<ELFIO::Elf_Half>& section_indices,
                                 ELFIO::const_symbol_section_accessor& symbols) {
    size_t map_record_size = platform->map_record_size;
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        auto s = reader.sections[i];
        if (!is_map_section(s->get_name())) {
            continue;
        }

        // Count the number of symbols that point into this maps section.
        int map_count = 0;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
            auto [symbol_name, section_index] = get_symbol_name_and_section_index(symbols, index);
            if ((section_index == i) && !symbol_name.empty()) {
                map_count++;
            }
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
    platform->resolve_inner_map_references(map_descriptors);
    return map_record_size;
}

vector<raw_program> read_elf(const std::string& path, const std::string& desired_section,
                             const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        return read_elf(stream, path, desired_section, options, platform);
    }
    struct stat st;
    if (stat(path.c_str(), &st)) {
        throw std::runtime_error(string(strerror(errno)) + " opening " + path);
    }
    throw std::runtime_error(string("Can't process ELF file ") + path);
}

std::tuple<string, ELFIO::Elf_Xword> get_program_name_and_size(ELFIO::section& sec, ELFIO::Elf_Xword start,
                                                               ELFIO::const_symbol_section_accessor& symbols) {
    ELFIO::Elf_Xword symbol_count = symbols.get_symbols_num();
    ELFIO::Elf_Half section_index = sec.get_index();
    string program_name = sec.get_name();
    ELFIO::Elf_Xword size = sec.get_size() - start;
    for (ELFIO::Elf_Xword index = 0; index < symbol_count; index++) {
        auto [symbol_name, symbol_section_index] = get_symbol_name_and_section_index(symbols, index);
        if (symbol_section_index == section_index && !symbol_name.empty()) {
            auto [relocation_offset, relocation_type] = get_value(symbols, index);
            if (relocation_type != ELFIO::STT_FUNC) {
                continue;
            }
            if (relocation_offset == start) {
                // We found the program name for this program.
                program_name = symbol_name;
            } else if (relocation_offset > start && relocation_offset < start + size) {
                // We found another program that follows, so truncate the size of this program.
                size = relocation_offset - start;
            }
        }
    }
    return {program_name, size};
}

void relocate_map(ebpf_inst& inst, const std::string& symbol_name,
                  const std::variant<size_t, std::map<std::string, size_t>>& map_record_size_or_map_offsets,
                  const program_info& info, ELFIO::Elf64_Addr offset, ELFIO::Elf_Word index,
                  const ELFIO::const_symbol_section_accessor& symbols) {
    // Only permit loading the address of the map.
    if ((inst.opcode & INST_CLS_MASK) != INST_CLS_LD) {
        throw std::runtime_error("Illegal operation on symbol " + symbol_name + " at location " +
                                 std::to_string(offset / sizeof(ebpf_inst)));
    }
    inst.src = 1; // magic number for LoadFd

    // Relocation value is an offset into the "maps" or ".maps" section.
    auto [relocation_offset, relocation_type] = get_value(symbols, index);
    if (map_record_size_or_map_offsets.index() == 0) {
        // The older maps section format uses a single map_record_size value, so we can
        // calculate the map descriptor index directly.
        size_t reloc_value = relocation_offset / std::get<0>(map_record_size_or_map_offsets);
        if (reloc_value >= info.map_descriptors.size()) {
            throw std::runtime_error("Bad reloc value (" + std::to_string(reloc_value) + "). " +
                                     "Make sure to compile with -O2.");
        }

        inst.imm = info.map_descriptors.at(reloc_value).original_fd;
    } else {
        // The newer .maps section format uses a variable-length map descriptor array,
        // so we need to look up the map descriptor index in a map.
        auto& map_descriptors_offsets = std::get<1>(map_record_size_or_map_offsets);
        auto it = map_descriptors_offsets.find(symbol_name);

        if (it == map_descriptors_offsets.end()) {
            throw std::runtime_error("Bad reloc value (" + std::to_string(index) + "). " +
                                     "Make sure to compile with -O2.");
        }
        inst.imm = info.map_descriptors.at(it->second).original_fd;
    }
}

// Structure used to keep track of subprogram relocation data until any subprograms
// are loaded and can be appended to the calling program.
struct function_relocation {
    size_t prog_index{};              // Index of source program in vector of raw programs.
    ELFIO::Elf_Xword source_offset{}; // Instruction offset in source section of source instruction.
    ELFIO::Elf_Xword relocation_entry_index{};
    std::string target_function_name;
};

static void append_subprogram(raw_program& prog, ELFIO::section* subprogram_section,
                              ELFIO::const_symbol_section_accessor& symbols, std::string symbol_name) {
    // Find subprogram by name.
    for (ELFIO::Elf_Xword subprogram_offset = 0; subprogram_offset < subprogram_section->get_size();) {
        auto [subprogram_name, subprogram_size] =
            get_program_name_and_size(*subprogram_section, subprogram_offset, symbols);
        if (subprogram_size == 0) {
            throw std::runtime_error("Zero-size subprogram '" + subprogram_name + "' in section '" +
                                     subprogram_section->get_name() + "'");
        }
        if (subprogram_name == symbol_name) {
            // Append subprogram instructions to the main program.
            auto subprogram = vector_of<ebpf_inst>(subprogram_section->get_data() + subprogram_offset, subprogram_size);
            prog.prog.insert(prog.prog.end(), subprogram.begin(), subprogram.end());
            return;
        }
        subprogram_offset += subprogram_size;
    }
    throw std::runtime_error("Subprogram '" + symbol_name + "' not found in section '" +
                             subprogram_section->get_name() + "'");
}

static void append_subprograms(raw_program& prog, vector<raw_program>& res, vector<function_relocation>& function_relocations, ELFIO::elfio& reader,
                               ELFIO::const_symbol_section_accessor& symbols) {
    // Perform function relocations and fill in the inst.imm values of CallLocal instructions.
    std::map<std::string, ELFIO::Elf_Xword> subprogram_offsets;
    for (auto& reloc : function_relocations) {
        if (res[reloc.prog_index].function_name != prog.function_name) {
            continue;
        }

        // Check whether we already appended the target program, and append it if not.
        if (subprogram_offsets.find(reloc.target_function_name) == subprogram_offsets.end()) {
            subprogram_offsets[reloc.target_function_name] = prog.prog.size();

            auto [symbol_name, section_index] = get_symbol_name_and_section_index(symbols, reloc.relocation_entry_index);
            ELFIO::section* subprogram_section = reader.sections[section_index];
            append_subprogram(prog, subprogram_section, symbols, symbol_name);
        }

        // Fill in the PC offset into the imm field of the CallLocal instruction.
        ELFIO::Elf_Xword target_offset = subprogram_offsets[reloc.target_function_name];
        int64_t offset_diff = (int64_t)(target_offset - reloc.source_offset - 1);
        if (offset_diff < INT32_MIN || offset_diff > INT32_MAX) {
            throw std::runtime_error("Offset difference out of int32_t range for instruction at source offset " +
                                     std::to_string(reloc.source_offset));
        }
        prog.prog[reloc.source_offset].imm = (int32_t)offset_diff;
    }
}

vector<raw_program> read_elf(std::istream& input_stream, const std::string& path, const std::string& desired_section,
                             const ebpf_verifier_options_t* options, const ebpf_platform_t* platform) {
    if (options == nullptr) {
        options = &ebpf_verifier_default_options;
    }
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw std::runtime_error(string("Can't process ELF file ") + path);
    }

    program_info info{platform};
    std::set<ELFIO::Elf_Half> map_section_indices;

    auto btf = reader.sections[string(".BTF")];
    auto btf_ext = reader.sections[string(".BTF.ext")];
    std::optional<libbtf::btf_type_data> btf_data;

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

    if (btf) {
        // Parse the BTF type data.
        btf_data = vector_of<std::byte>(*btf);
        if (options->dump_btf_types_json) {
            std::stringstream output;
            std::cout << "Dumping BTF data for" << path << std::endl;
            // Dump the BTF data to cout for debugging purposes.
            btf_data->to_json(output);
            std::cout << libbtf::pretty_print_json(output.str()) << std::endl;
            std::cout << std::endl;
        }
    }

    std::variant<size_t, std::map<std::string, size_t>> map_record_size_or_map_offsets = size_t(0);
    if (reader.sections[string(".maps")]) {
        if (!btf_data.has_value()) {
            throw std::runtime_error(string("No BTF section found in ELF file ") + path);
        }
        auto map_data = libbtf::parse_btf_map_section(btf_data.value());
        std::map<std::string, size_t> map_offsets;
        for (auto& map : map_data) {
            map_offsets.insert({map.name, info.map_descriptors.size()});
            info.map_descriptors.push_back({
                .original_fd = static_cast<int>(map.type_id),
                .type = map.map_type,
                .key_size = map.key_size,
                .value_size = map.value_size,
                .max_entries = map.max_entries,
                .inner_map_fd = map.inner_map_type_id != 0 ? map.inner_map_type_id : DEFAULT_MAP_FD,
            });
        }
        map_record_size_or_map_offsets = map_offsets;
        // Prevail requires:
        // Map fds are sequential starting from 1.
        // Map fds are assigned in the order of the maps in the ELF file.

        // Build a map from the original type id to the pseudo-fd.
        std::map<int, int> type_id_to_fd_map;
        int pseudo_fd = 1;
        // Gather the typeids for each map and assign a pseudo-fd to each map.
        for (auto& map_descriptor : info.map_descriptors) {
            if (type_id_to_fd_map.find(map_descriptor.original_fd) == type_id_to_fd_map.end()) {
                type_id_to_fd_map[map_descriptor.original_fd] = pseudo_fd++;
            }
        }
        // Replace the typeids with the pseudo-fds.
        for (auto& map_descriptor : info.map_descriptors) {
            map_descriptor.original_fd = type_id_to_fd_map[map_descriptor.original_fd];
            if (map_descriptor.inner_map_fd != DEFAULT_MAP_FD) {
                map_descriptor.inner_map_fd = type_id_to_fd_map[map_descriptor.inner_map_fd];
            }
        }
        map_section_indices.insert(reader.sections[string(".maps")]->get_index());
    } else {
        map_record_size_or_map_offsets =
            parse_map_sections(options, platform, reader, info.map_descriptors, map_section_indices, symbols);
    }

    vector<raw_program> res;
    vector<string> unresolved_symbols;

    vector<function_relocation> function_relocations;
    for (const auto& section : reader.sections) {
        const string name = section->get_name();
        if (!desired_section.empty() && name != desired_section) {
            continue;
        }
        if (name == "license" || name == "version" || is_map_section(name)) {
            continue;
        }
        if (name != ".text" && name.find('.') == 0) {
            continue;
        }
        if ((section->get_size() == 0) || (section->get_data() == nullptr)) {
            continue;
        }
        info.type = platform->get_program_type(name, path);

        for (ELFIO::Elf_Xword program_offset = 0; program_offset < section->get_size();) {
            auto [program_name, program_size] = get_program_name_and_size(*section, program_offset, symbols);
            raw_program prog{path,
                             name,
                             program_offset,
                             program_name,
                             vector_of<ebpf_inst>(section->get_data() + program_offset, program_size),
                             info};

            // We will need to recursively append any subprograms called, but only once
            // for each subprogram no matter how many times called. So initialize a set
            // to hold the list of subprogram names included.
            std::set<string> subprograms{};
            subprograms.insert(program_name);

            auto prelocs = reader.sections[string(".rel") + name];
            if (!prelocs) {
                prelocs = reader.sections[string(".rela") + name];
            }

            if (prelocs) {
                if (!prelocs->get_data()) {
                    throw std::runtime_error("Malformed relocation data");
                }
                ELFIO::const_relocation_section_accessor reloc{reader, prelocs};

                // Fetch and store relocation count locally to permit static
                // analysis tools to correctly reason about the code below.
                ELFIO::Elf_Xword relocation_count = reloc.get_entries_num();

                for (ELFIO::Elf_Xword i = 0; i < relocation_count; i++) {
                    ELFIO::Elf64_Addr offset{};
                    ELFIO::Elf_Word index{};
                    unsigned type{};
                    ELFIO::Elf_Sxword addend{};
                    if (!reloc.get_entry(i, offset, index, type, addend)) {
                        continue;
                    }
                    if (offset < program_offset || offset >= program_offset + program_size) {
                        // Relocation is not for this program.
                        continue;
                    }
                    offset -= program_offset;
                    if ((offset / sizeof(ebpf_inst)) >= prog.prog.size()) {
                        throw std::runtime_error("Invalid relocation data");
                    }
                    ebpf_inst& inst = prog.prog[offset / sizeof(ebpf_inst)];

                    auto [symbol_name, symbol_section_index] = get_symbol_name_and_section_index(symbols, index);

                    // Queue up relocation for function symbols.
                    if ((inst.opcode == INST_OP_CALL) && (inst.src == INST_CALL_LOCAL) &&
                        (reader.sections[symbol_section_index] == section.get())) {
                        function_relocation fr{.prog_index = res.size(),
                                               .source_offset = offset / sizeof(ebpf_inst),
                                               .relocation_entry_index = index,
                                               .target_function_name = symbol_name};
                        function_relocations.push_back(fr);
                        continue;
                    }

                    // Perform relocation for symbols located in the maps section.
                    if (map_section_indices.contains(symbol_section_index)) {
                        relocate_map(inst, symbol_name, map_record_size_or_map_offsets, info, offset, index, symbols);
                        continue;
                    }

                    std::string unresolved_symbol = "Unresolved external symbol " + symbol_name + " in section " +
                                                    name + " at location " + std::to_string(offset / sizeof(ebpf_inst));
                    unresolved_symbols.push_back(unresolved_symbol);
                }
            }
            prog.line_info.resize(prog.prog.size());
            res.push_back(prog);
            program_offset += program_size;
        }
    }

    // Now that we have all programs in the list, we can recursively append any subprograms
    // to the calling programs.  We have to keep them as programs themselves in case the caller
    // wants to verify them separately, but we also have to append them if used as subprograms to
    // allow the caller to be fully verified since inst.imm can only point into the same program.
    for (auto& prog : res) {
        append_subprograms(prog, res, function_relocations, reader, symbols);
    }

    // Below, only relocations of symbols located in the map sections are allowed,
    // so if there are relocations there needs to be a maps section.
    if (!unresolved_symbols.empty()) {
        for (const auto& unresolved_symbol : unresolved_symbols) {
            std::cerr << unresolved_symbol << std::endl;
        }
        throw std::runtime_error("There are relocations in section but no maps sections in file " + path +
                                 "\nMake sure to inline all function calls.");
    }

    if (btf != nullptr && btf_ext != nullptr) {
        auto visitor = [&](const std::string& section, uint32_t instruction_offset, const std::string& file_name,
                           const std::string& source, uint32_t line_number, uint32_t column_number) {
            for (auto& program : res) {
                if ((program.section_name == section) && (instruction_offset >= program.insn_off) &&
                    (instruction_offset < program.insn_off + program.prog.size() * sizeof(ebpf_inst))) {
                    size_t inst_index = (instruction_offset - program.insn_off) / sizeof(ebpf_inst);
                    if (inst_index >= program.line_info.size()) {
                        throw std::runtime_error("Invalid BTF data");
                    }
                    program.line_info[inst_index] = {file_name, source, line_number, column_number};
                    return;
                }
            }
        };

        libbtf::btf_parse_line_information(vector_of<std::byte>(*btf), vector_of<std::byte>(*btf_ext), visitor);

        // BTF doesn't include line info for every instruction, only on the first instruction per source line.
        for (auto& program : res) {
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
