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
#include "crab_utils/num_safety.hpp"
#include "platform.hpp"

using std::string;
using std::vector;

template <typename T>
    requires std::is_trivially_copyable_v<T>
static vector<T> vector_of(const char* data, const ELFIO::Elf_Xword size) {
    if (size % sizeof(T) != 0 || size > std::numeric_limits<uint32_t>::max() || !data) {
        throw UnmarshalError("Invalid argument to vector_of");
    }
    return {reinterpret_cast<const T*>(data), reinterpret_cast<const T*>(data + size)};
}

template <typename T>
    requires std::is_trivially_copyable_v<T>
static vector<T> vector_of(const ELFIO::section& sec) {
    return vector_of<T>(sec.get_data(), sec.get_size());
}

int create_map_crab(const EbpfMapType& map_type, const uint32_t key_size, const uint32_t value_size,
                    const uint32_t max_entries, ebpf_verifier_options_t) {
    const EquivalenceKey equiv{map_type.value_type, key_size, value_size, map_type.is_array ? max_entries : 0};
    if (!thread_local_program_info->cache.contains(equiv)) {
        // +1 so 0 is the null FD
        thread_local_program_info->cache[equiv] = gsl::narrow<int>(thread_local_program_info->cache.size()) + 1;
    }
    return thread_local_program_info->cache.at(equiv);
}

EbpfMapDescriptor* find_map_descriptor(const int map_fd) {
    for (EbpfMapDescriptor& map : thread_local_program_info->map_descriptors) {
        if (map.original_fd == map_fd) {
            return &map;
        }
    }
    return nullptr;
}

// Maps sections are identified as any section called "maps", or matching "maps/<map-name>".
static bool is_map_section(const string& name) {
    const string maps_prefix = "maps/";
    return name == "maps" || (name.length() > 5 && name.compare(0, maps_prefix.length(), maps_prefix) == 0);
}

static std::tuple<string, ELFIO::Elf_Half>
get_symbol_name_and_section_index(const ELFIO::const_symbol_section_accessor& symbols, const ELFIO::Elf_Xword index) {
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

static std::tuple<ELFIO::Elf64_Addr, unsigned char> get_value(const ELFIO::const_symbol_section_accessor& symbols,
                                                              const ELFIO::Elf_Xword index) {
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

// parse_maps_sections processes all maps sections in the provided ELF file by calling the platform-specific maps'
// parser. The section index of each maps section is inserted into section_indices.
static size_t parse_map_sections(const ebpf_verifier_options_t& options, const ebpf_platform_t* platform,
                                 const ELFIO::elfio& reader, vector<EbpfMapDescriptor>& map_descriptors,
                                 std::set<ELFIO::Elf_Half>& section_indices,
                                 const ELFIO::const_symbol_section_accessor& symbols) {
    size_t map_record_size = platform->map_record_size;
    for (ELFIO::Elf_Half i = 0; i < reader.sections.size(); ++i) {
        const auto s = reader.sections[i];
        if (!is_map_section(s->get_name())) {
            continue;
        }

        // Count the number of symbols that point into this maps section.
        int map_count = 0;
        for (ELFIO::Elf_Xword index = 0; index < symbols.get_symbols_num(); index++) {
            auto [symbol_name, section_index] = get_symbol_name_and_section_index(symbols, index);
            if (section_index == i && !symbol_name.empty()) {
                map_count++;
            }
        }

        if (map_count > 0) {
            map_record_size = s->get_size() / map_count;
            if (s->get_data() == nullptr || map_record_size == 0) {
                throw UnmarshalError("bad maps section");
            }
            if (s->get_size() % map_record_size != 0) {
                throw UnmarshalError("bad maps section size");
            }
            platform->parse_maps_section(map_descriptors, s->get_data(), map_record_size, map_count, platform, options);
        }
        section_indices.insert(s->get_index());
    }
    platform->resolve_inner_map_references(map_descriptors);
    return map_record_size;
}

vector<raw_program> read_elf(const string& path, const string& desired_section, const ebpf_verifier_options_t& options,
                             const ebpf_platform_t* platform) {
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        return read_elf(stream, path, desired_section, options, platform);
    }
    struct stat st;
    if (stat(path.c_str(), &st)) {
        throw UnmarshalError(string(strerror(errno)) + " opening " + path);
    }
    throw UnmarshalError("Can't process ELF file " + path);
}

static std::tuple<string, ELFIO::Elf_Xword>
get_program_name_and_size(const ELFIO::section& sec, const ELFIO::Elf_Xword start,
                          const ELFIO::const_symbol_section_accessor& symbols) {
    const ELFIO::Elf_Xword symbol_count = symbols.get_symbols_num();
    const ELFIO::Elf_Half section_index = sec.get_index();
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

void verify_load_instruction(const ebpf_inst& instruction, const std::string& symbol_name, ELFIO::Elf64_Addr offset) {
    if ((instruction.opcode & INST_CLS_MASK) != INST_CLS_LD) {
        throw UnmarshalError("Illegal operation on symbol " + symbol_name + " at location " +
                             std::to_string(offset / sizeof(ebpf_inst)));
    }
}

void relocate_map(ebpf_inst& reloc_inst, const std::string& symbol_name,
                  const std::variant<size_t, std::map<std::string, size_t>>& map_record_size_or_map_offsets,
                  const program_info& info, const ELFIO::Elf64_Addr offset, const ELFIO::Elf_Word index,
                  const ELFIO::const_symbol_section_accessor& symbols) {
    // Only permit loading the address of the map.
    verify_load_instruction(reloc_inst, symbol_name, offset);
    reloc_inst.src = INST_LD_MODE_MAP_FD;

    // Relocation value is an offset into the "maps" or ".maps" section.
    size_t reloc_value = std::numeric_limits<size_t>::max();
    if (map_record_size_or_map_offsets.index() == 0) {
        // The older maps section format uses a single map_record_size value, so we can
        // calculate the map descriptor index directly.
        auto [relocation_offset, relocation_type] = get_value(symbols, index);
        reloc_value = relocation_offset / std::get<0>(map_record_size_or_map_offsets);
    } else {
        // The newer .maps section format uses a variable-length map descriptor array,
        // so we need to look up the map descriptor index in a map.
        auto& map_descriptors_offsets = std::get<1>(map_record_size_or_map_offsets);
        const auto it = map_descriptors_offsets.find(symbol_name);
        if (it != map_descriptors_offsets.end()) {
            reloc_value = it->second;
        } else {
            throw UnmarshalError("Map descriptor not found for symbol " + symbol_name);
        }
    }
    if (reloc_value >= info.map_descriptors.size()) {
        throw UnmarshalError("Bad reloc value (" + std::to_string(reloc_value) + "). " +
                             "Make sure to compile with -O2.");
    }
    reloc_inst.imm = info.map_descriptors.at(reloc_value).original_fd;
}

void relocate_global_variable(ebpf_inst& reloc_inst, ebpf_inst& next_reloc_inst, const std::string& symbol_name,
                              const program_info& info,
                              const std::variant<size_t, std::map<std::string, size_t>>& map_record_size_or_map_offsets,
                              const ELFIO::Elf64_Addr offset) {
    // Only permit loading the address of the global variable.
    verify_load_instruction(reloc_inst, symbol_name, offset);

    // Copy the immediate value to the next instruction.
    next_reloc_inst.imm = reloc_inst.imm;
    reloc_inst.src = INST_LD_MODE_MAP_VALUE;

    size_t reloc_value = std::numeric_limits<size_t>::max();
    auto& map_descriptors_offsets = std::get<1>(map_record_size_or_map_offsets);
    const auto it = map_descriptors_offsets.find(symbol_name);
    if (it != map_descriptors_offsets.end()) {
        reloc_value = it->second;
    } else {
        throw UnmarshalError("Map descriptor not found for symbol " + symbol_name);
    }

    if (reloc_value >= info.map_descriptors.size()) {
        throw UnmarshalError("Bad reloc value (" + std::to_string(reloc_value) + "). " +
                             "Make sure to compile with -O2.");
    }
    reloc_inst.imm = info.map_descriptors.at(reloc_value).original_fd;
}

// Structure used to keep track of subprogram relocation data until any subprograms
// are loaded and can be appended to the calling program.
struct function_relocation {
    size_t prog_index{};              // Index of source program in vector of raw programs.
    ELFIO::Elf_Xword source_offset{}; // Instruction offset in source section of source instruction.
    ELFIO::Elf_Xword relocation_entry_index{};
    string target_function_name;
};

static raw_program* find_subprogram(vector<raw_program>& programs, const ELFIO::section& subprogram_section,
                                    const std::string& symbol_name) {
    // Find subprogram by name.
    for (auto& subprog : programs) {
        if ((subprog.section_name == subprogram_section.get_name()) && (subprog.function_name == symbol_name)) {
            return &subprog;
        }
    }
    return nullptr;
}

// Returns an error message, or empty string on success.
static std::string append_subprograms(raw_program& prog, vector<raw_program>& programs,
                                      const vector<function_relocation>& function_relocations,
                                      const ELFIO::elfio& reader, const ELFIO::const_symbol_section_accessor& symbols) {
    if (prog.resolved_subprograms) {
        // We've already appended any relevant subprograms.
        return {};
    }
    prog.resolved_subprograms = true;

    // Perform function relocations and fill in the inst.imm values of CallLocal instructions.
    std::map<string, ELFIO::Elf_Xword> subprogram_offsets;
    for (const auto& reloc : function_relocations) {
        if (reloc.prog_index >= programs.size()) {
            continue;
        }
        if (programs[reloc.prog_index].function_name != prog.function_name) {
            continue;
        }

        // Check whether we already appended the target program, and append it if not.
        if (!subprogram_offsets.contains(reloc.target_function_name)) {
            subprogram_offsets[reloc.target_function_name] = prog.prog.size();

            auto [symbol_name, section_index] =
                get_symbol_name_and_section_index(symbols, reloc.relocation_entry_index);
            if (section_index >= reader.sections.size()) {
                throw UnmarshalError("Invalid section index " + std::to_string(section_index) + " at source offset " +
                                     std::to_string(reloc.source_offset));
            }
            ELFIO::section& subprogram_section = *reader.sections[section_index];

            if (auto subprogram = find_subprogram(programs, subprogram_section, symbol_name)) {
                // Make sure subprogram has already had any subprograms of its own appended.
                std::string error = append_subprograms(*subprogram, programs, function_relocations, reader, symbols);
                if (!error.empty()) {
                    return error;
                }

                // Append subprogram to program.
                prog.prog.insert(prog.prog.end(), subprogram->prog.begin(), subprogram->prog.end());
                for (int i = 0; i < subprogram->info.line_info.size(); i++) {
                    prog.info.line_info[prog.info.line_info.size()] = subprogram->info.line_info[i];
                }
            } else {
                // The program will be invalid, but continue rather than throwing an exception
                // since we might be verifying a different program in the file.
                return std::string("Subprogram '" + symbol_name + "' not found in section '" +
                                   subprogram_section.get_name() + "'");
            }
        }

        // Fill in the PC offset into the imm field of the CallLocal instruction.
        const int64_t target_offset = gsl::narrow_cast<int64_t>(subprogram_offsets[reloc.target_function_name]);
        const auto offset_diff = target_offset - gsl::narrow<int64_t>(reloc.source_offset) - 1;
        if (offset_diff < std::numeric_limits<int32_t>::min() || offset_diff > std::numeric_limits<int32_t>::max()) {
            throw UnmarshalError("Offset difference out of int32_t range for instruction at source offset " +
                                 std::to_string(reloc.source_offset));
        }
        prog.prog[reloc.source_offset].imm = gsl::narrow_cast<int32_t>(offset_diff);
    }
    return {};
}

std::map<std::string, size_t> parse_map_section(const libbtf::btf_type_data& btf_data,
                                                std::vector<EbpfMapDescriptor>& map_descriptors) {
    std::map<std::string, size_t> map_offsets;
    for (const auto& map : parse_btf_map_section(btf_data)) {
        map_offsets.emplace(map.name, map_descriptors.size());
        map_descriptors.push_back({
            .original_fd = gsl::narrow_cast<int>(map.type_id),
            .type = map.map_type,
            .key_size = map.key_size,
            .value_size = map.value_size,
            .max_entries = map.max_entries,
            .inner_map_fd = map.inner_map_type_id != 0 ? map.inner_map_type_id : DEFAULT_MAP_FD,
        });
    }
    return map_offsets;
}

vector<raw_program> read_elf(std::istream& input_stream, const std::string& path, const std::string& desired_section,
                             const ebpf_verifier_options_t& options, const ebpf_platform_t* platform) {
    ELFIO::elfio reader;
    if (!reader.load(input_stream)) {
        throw UnmarshalError("Can't process ELF file " + path);
    }

    auto symbol_section = reader.sections[".symtab"];
    if (!symbol_section) {
        throw UnmarshalError("No symbol section found in ELF file " + path);
    }

    // Make sure the ELFIO library will be able to parse the symbol section correctly.
    auto expected_entry_size =
        reader.get_class() == ELFIO::ELFCLASS32 ? sizeof(ELFIO::Elf32_Sym) : sizeof(ELFIO::Elf64_Sym);

    if (symbol_section->get_entry_size() != expected_entry_size) {
        throw UnmarshalError("Invalid symbol section found in ELF file " + path);
    }

    program_info info{platform};
    std::set<ELFIO::Elf_Half> map_section_indices;
    std::set<ELFIO::Elf_Half> global_variable_section_indices;

    auto btf = reader.sections[".BTF"];
    std::optional<libbtf::btf_type_data> btf_data;

    if (btf) {
        // Parse the BTF type data.
        btf_data = vector_of<std::byte>(*btf);
        if (options.verbosity_opts.dump_btf_types_json) {
            std::stringstream output;
            std::cout << "Dumping BTF data for" << path << std::endl;
            // Dump the BTF data to cout for debugging purposes.
            btf_data->to_json(output);
            std::cout << libbtf::pretty_print_json(output.str()) << std::endl;
            std::cout << std::endl;
        }
    }

    std::variant<size_t, std::map<std::string, size_t>> map_record_size_or_map_offsets = size_t{0};
    ELFIO::const_symbol_section_accessor symbols{reader, symbol_section};

    if (std::ranges::any_of(reader.sections, [](const auto& section) { return is_map_section(section->get_name()); })) {
        map_record_size_or_map_offsets =
            parse_map_sections(options, platform, reader, info.map_descriptors, map_section_indices, symbols);
    } else if (btf_data.has_value()) {
        map_record_size_or_map_offsets = parse_map_section(*btf_data, info.map_descriptors);
        // Prevail requires:
        // Map fds are sequential starting from 1.
        // Map fds are assigned in the order of the maps in the ELF file.

        // Build a map from the original type id to the pseudo-fd.
        std::map<int, int> type_id_to_fd_map;
        int pseudo_fd = 1;
        // Gather the typeids for each map and assign a pseudo-fd to each map.
        for (const auto& map_descriptor : info.map_descriptors) {
            if (!type_id_to_fd_map.contains(map_descriptor.original_fd)) {
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
        if (reader.sections[".maps"]) {
            map_section_indices.insert(reader.sections[".maps"]->get_index());
        }

        for (auto section_name : {".rodata", ".data", ".bss"}) {
            if (const auto section = reader.sections[section_name]) {
                if (section->get_size() != 0) {
                    global_variable_section_indices.insert(section->get_index());
                }
            }
        }
    }

    vector<raw_program> res;
    vector<string> unresolved_symbols_errors;
    vector<function_relocation> function_relocations;
    for (const auto& section : reader.sections) {
        if (!(section->get_flags() & ELFIO::SHF_EXECINSTR)) {
            // Section does not contain executable instructions.
            continue;
        }
        const auto section_size = section->get_size();
        if (section_size == 0) {
            continue;
        }
        const auto section_data = section->get_data();
        if (section_data == nullptr) {
            continue;
        }
        const string name = section->get_name();
        info.type = platform->get_program_type(name, path);

        for (ELFIO::Elf_Xword program_offset = 0; program_offset < section_size;) {
            auto [program_name, program_size] = get_program_name_and_size(*section, program_offset, symbols);
            raw_program prog{path,
                             name,
                             gsl::narrow_cast<uint32_t>(program_offset),
                             program_name,
                             vector_of<ebpf_inst>(section_data + program_offset, program_size),
                             info};

            auto prelocs = reader.sections[".rel" + name];
            if (!prelocs) {
                prelocs = reader.sections[".rela" + name];
            }

            if (prelocs) {
                if (!prelocs->get_data()) {
                    throw UnmarshalError("Malformed relocation data");
                }
                ELFIO::const_relocation_section_accessor reloc{reader, prelocs};

                // Fetch and store relocation count locally to permit static
                // analysis tools to correctly reason about the code below.
                for (ELFIO::Elf_Xword i = 0; i < reloc.get_entries_num(); i++) {
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
                    if (offset / sizeof(ebpf_inst) >= prog.prog.size()) {
                        throw UnmarshalError("Invalid relocation data");
                    }

                    ebpf_inst& reloc_inst = prog.prog[offset / sizeof(ebpf_inst)];

                    auto [symbol_name, symbol_section_index] = get_symbol_name_and_section_index(symbols, index);

                    // Queue up relocation for function symbols.
                    if (reloc_inst.opcode == INST_OP_CALL && reloc_inst.src == INST_CALL_LOCAL) {
                        function_relocation fr{.prog_index = res.size(),
                                               .source_offset = offset / sizeof(ebpf_inst),
                                               .relocation_entry_index = index,
                                               .target_function_name = symbol_name};
                        function_relocations.push_back(fr);
                        continue;
                    }

                    // Verify that this is a map or global variable relocation.
                    verify_load_instruction(reloc_inst, symbol_name, offset);

                    // Load instructions are two instructions long, so we need to check the next instruction.
                    if (prog.prog.size() <= offset / sizeof(ebpf_inst) + 1) {
                        throw UnmarshalError("Invalid relocation data");
                    }
                    ebpf_inst& next_reloc_inst = prog.prog[offset / sizeof(ebpf_inst) + 1];

                    // Perform relocation for symbols located in the maps section.
                    if (map_section_indices.contains(symbol_section_index)) {
                        relocate_map(reloc_inst, symbol_name, map_record_size_or_map_offsets, info, offset, index,
                                     symbols);
                        continue;
                    }

                    if (global_variable_section_indices.contains(symbol_section_index)) {
                        relocate_global_variable(reloc_inst, next_reloc_inst,
                                                 reader.sections[symbol_section_index]->get_name(), info,
                                                 map_record_size_or_map_offsets, offset);
                        continue;
                    }

                    string unresolved_symbol = "Unresolved external symbol " + symbol_name + " in section " + name +
                                               " at location " + std::to_string(offset / sizeof(ebpf_inst));
                    unresolved_symbols_errors.push_back(unresolved_symbol);
                }
            }
            res.push_back(prog);
            program_offset += program_size;
        }
    }

    // Below, only relocations of symbols located in the map sections are allowed,
    // so if there are relocations there needs to be a maps section.
    if (!unresolved_symbols_errors.empty()) {
        for (const auto& unresolved_symbol : unresolved_symbols_errors) {
            std::cerr << unresolved_symbol << std::endl;
        }
        throw UnmarshalError("There are relocations in section but no maps sections in file " + path +
                             "\nMake sure to inline all function calls.");
    }

    auto btf_ext = reader.sections[".BTF.ext"];
    if (btf && btf_ext) {
        auto visitor = [&](const string& section, const uint32_t instruction_offset, const string& file_name,
                           const string& source, const uint32_t line_number, const uint32_t column_number) {
            for (auto& program : res) {
                if (program.section_name == section && instruction_offset >= program.insn_off &&
                    instruction_offset < program.insn_off + program.prog.size() * sizeof(ebpf_inst)) {
                    const size_t inst_index = (instruction_offset - program.insn_off) / sizeof(ebpf_inst);
                    if (inst_index >= program.prog.size()) {
                        throw UnmarshalError("Invalid BTF data");
                    }
                    program.info.line_info.insert_or_assign(
                        inst_index, btf_line_info_t{file_name, source, line_number, column_number});
                }
            }
        };

        libbtf::btf_parse_line_information(vector_of<std::byte>(*btf), vector_of<std::byte>(*btf_ext), visitor);

        // BTF doesn't include line info for every instruction, only on the first instruction per source line.
        for (auto& program : res) {
            for (size_t i = 1; i < program.prog.size(); i++) {
                // If the previous PC has line info, copy it.
                if (program.info.line_info[i].line_number == 0 && program.info.line_info[i - 1].line_number != 0) {
                    program.info.line_info[i] = program.info.line_info[i - 1];
                }
            }
        }
    }

    // Now that we have all programs in the list, we can recursively append any subprograms
    // to the calling programs.  We have to keep them as programs themselves in case the caller
    // wants to verify them separately, but we also have to append them if used as subprograms to
    // allow the caller to be fully verified since inst.imm can only point into the same program.
    for (auto& prog : res) {
        std::string error = append_subprograms(prog, res, function_relocations, reader, symbols);
        if (!error.empty()) {
            if (prog.section_name == desired_section) {
                throw UnmarshalError(error);
            }
        }
    }

    // Now that we've incorporated any subprograms from other sections, we can narrow the list
    // to return to just those programs in the desired section, if any.
    if (!desired_section.empty() && !res.empty()) {
        for (int index = res.size() - 1; index >= 0; index--) {
            if (res[index].section_name != desired_section) {
                res.erase(res.begin() + index);
            }
        }
    }

    if (res.empty()) {
        if (desired_section.empty()) {
            throw UnmarshalError("Can't find any non-empty TEXT sections in file " + path);
        }
        throw UnmarshalError("Can't find section " + desired_section + " in file " + path);
    }
    return res;
}
