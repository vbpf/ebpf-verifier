// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <vector>
#include <iostream>
#include <string>
#include <cassert>
#include <variant>

#include <sys/stat.h>

#include "elfio/elfio.hpp"

#include "ebpf_vm_isa.hpp"
#include "dump_elf.hpp"

#include "CLI11.hpp"

using std::vector;
using std::string;

template <typename T>
static T read_single(const ELFIO::section* sec) {
    auto data = sec->get_data();
    assert(sec->get_size() >= sizeof(T));
    return *(T*)data;
}

template <typename T>
static vector<T> read_vector_of(const ELFIO::section* sec) {
    auto data = sec->get_data();
    auto size = sec->get_size();
    assert(size % sizeof(T) == 0);
    return {(T*)data, (T*)(data + size)};
}

bool has_prefix(const string& prefix, const string& target) {
    return target.length() >= prefix.length() && target.compare(0, prefix.length(), prefix) == 0;
}


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

// BTF handling
// reference: https://www.kernel.org/doc/html/latest/bpf/btf.html
// https://github.com/cilium/ebpf/blob/e4c6eabc2fd7a1fe5556ed38a01c18caa6dc020e/internal/btf/btf_types.go

struct section_data_t {
    /* All offsets are in bytes relative to the end of this header */
    uint32_t offset;
    uint32_t length;
};
static_assert(sizeof(section_data_t)==8);

struct btf_pre_header_t {
    uint16_t   magic; // 0xeB9F
    uint8_t    version;
    uint8_t    flags;
    uint32_t   size;
};

struct btf_header_t {
    btf_pre_header_t header;
    section_data_t type_section;
    section_data_t string_section;
};
static_assert(sizeof(btf_header_t)==24);


struct btf_ext_header_t {
    btf_pre_header_t header;
    section_data_t   func_info;
    section_data_t   line_info;
};
static_assert(sizeof(btf_ext_header_t)==24);

enum class Linkage: int {
    STATIC = 0,
    GLOBAL = 1,
    EXTERN = 2
};

struct btf_type_t {
    uint32_t name_offset;
    struct {
        unsigned vlen:16; // e.g. number of struct's members
        unsigned reserved:8;
        unsigned kind:5; // btf_kind_t
        unsigned unused:2;
        unsigned kind_flag:1;
    } info;
    union {
        /// Size of the type it is describing. Used by INT, ENUM, STRUCT and UNION.
        uint32_t size;

        /// A type_id referring to another type,
        /// used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC and FUNC_PROTO.
        uint32_t type_id;
    };
};
static_assert(sizeof(btf_type_t) == 12);

struct btf_kind_void_t {
    btf_type_t type_info; };

struct btf_kind_int_t {
    btf_type_t type_info;
    uint32_t bits;
};

struct btf_kind_ptr_t {
    btf_type_t type_info; };

struct btf_kind_array_t {
    btf_type_t type_info;
    uint32_t type;
    uint32_t index_type;
    uint32_t number_of_elements;
};
static_assert(sizeof(btf_kind_array_t) == sizeof(btf_type_t) + 12);

struct btf_kind_member_aux_t {
    uint32_t name_offset; ///< offset to a valid C identifier
    uint32_t type; ///< the member type
    uint32_t offset;
};
static_assert(sizeof(btf_kind_member_aux_t)==12);

struct btf_kind_struct_t {
    btf_type_t type_info;
    using item_t = btf_kind_member_aux_t;
    vector<btf_kind_member_aux_t> items;
};

struct btf_kind_union_t {
    btf_type_t type_info;
    using item_t = btf_kind_member_aux_t;
    vector<item_t> items;
};

struct btf_kind_enum_t {
    btf_type_t type_info;
    struct item_t {
        uint32_t name_offset; ///< offset to a valid C identifier
        int32_t val;
    };
    vector<item_t> items;
};
static_assert(sizeof(btf_kind_enum_t::item_t)==8);

struct btf_kind_fwd_t {
    btf_type_t type_info;
};

struct btf_kind_typedef_t {
    btf_type_t type_info;
};

struct btf_kind_volatile_t {
    btf_type_t type_info;
};

struct btf_kind_const_t {
    btf_type_t type_info;
};

struct btf_kind_restrict_t {
    btf_type_t type_info;
};

struct btf_kind_func_t {
    btf_type_t type_info;
};

struct btf_kind_func_proto_t {
    btf_type_t type_info;
    struct item_t {
        uint32_t name_offset;
        uint32_t type;
    };
    vector<item_t> items;
};
static_assert(sizeof(btf_kind_func_proto_t::item_t)==8);

struct btf_kind_var_t {
    btf_type_t type_info;
    uint32_t linkage;
};
static_assert(sizeof(btf_kind_var_t::linkage)==4);

struct btf_kind_data_section_info_t {
    btf_type_t type_info;
    struct item_t {
        uint32_t type;   ///< the type of the BTF_KIND_VAR variable
        uint32_t offset; ///< the in-section offset of the variable
        uint32_t size;   ///< the size of the variable in bytes
    };
    vector<item_t> items;
};
static_assert(sizeof(btf_kind_data_section_info_t::item_t)==12);

struct btf_kind_float_t {
    btf_type_t type_info;
};

using btf_kind_variant_t = std::variant<
     btf_kind_void_t,
     btf_kind_int_t,
     btf_kind_ptr_t,
     btf_kind_array_t,
     btf_kind_struct_t,
     btf_kind_union_t,
     btf_kind_enum_t,
     btf_kind_fwd_t,
     btf_kind_typedef_t,
     btf_kind_volatile_t,
     btf_kind_const_t,
     btf_kind_restrict_t,
     btf_kind_func_t,
     btf_kind_func_proto_t,
     btf_kind_var_t,
     btf_kind_data_section_info_t,
     btf_kind_float_t
>;

enum class BtfKind: unsigned {
    VOID         = 0,
    INT          = 1,
    PTR          = 2,
    ARRAY        = 3,
    STRUCT       = 4,
    UNION        = 5,
    ENUM         = 6,
    FORWARD      = 7,
    TYPEDEF      = 8,
    VOLATILE     = 9,
    CONST        = 10,
    RESTRICT     = 11,
    FUNC         = 12,
    FUNC_PROTO   = 13,
    VAR          = 14,
    DATA_SECTION = 15,
    FLOAT        = 16,
};

enum reloc_type_t { // (see https://www.kernel.org/doc/html/latest/bpf/llvm_reloc.html)
                         // Description      BitSize  Offset        Calculation
    R_BPF_NONE=0,        // None
    R_BPF_64_64=1,       // ld_imm64 insn    32       r_offset + 4  S + A
    R_BPF_64_ABS64=2,    // normal data      64       r_offset      S + A
    R_BPF_64_ABS32=3,    // normal data      32       r_offset      S + A
    R_BPF_64_NODYLD32=4, // .BTF[.ext] data  32       r_offset      S + A
    R_BPF_64_32=10       // call insn        32       r_offset + 4  (S + A) / 8 - 1
};


static vector<std::tuple<ELFIO::Elf64_Addr, size_t>> collect_fd_relocs(ELFIO::elfio& reader, const string& name) {
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
    unsigned int type{};
    ELFIO::Elf_Sxword addend{};

    // Fetch and store relocation count locally to permit static
    // analysis tools to correctly reason about the code below.
    const ELFIO::Elf_Xword relocation_count = reloc.get_entries_num();

    for (ELFIO::Elf_Xword i = 0; i < relocation_count; i++) {
        const bool valid_entry = reloc.get_entry(i, offset, symbol, type, addend);
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

            auto map_record_size = sizeof(bpf_load_map_def);
            map_fd_relocs.emplace_back(offset / sizeof(ebpf_inst), symbol_value / map_record_size);
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

enum class SectionKind {
    OTHER,
    LICENSE,
    VERSION,
    BTF,
    DATA,
    MAPS,
    BTF_MAPS,
    CODE,
};

static SectionKind get_section_kind(const ELFIO::section* section) {
    const std::string& name = section->get_name();

    if (name == "license")
        return SectionKind::LICENSE;

    if (name == "version")
        return SectionKind::VERSION;

    if (name == "maps" || has_prefix("maps/", name)) {
        return SectionKind::MAPS;
    }
    if (name == ".maps") {
        return SectionKind::BTF_MAPS;
    }
    if (name == ".bss" || name == ".data" || has_prefix(".rodata", name)) {
        return SectionKind::DATA;
    }
    if (name == ".BTF") {
        return SectionKind::BTF;
    }
    if (section->get_type() == SHT_PROGBITS && (section->get_flags() & SHF_EXECINSTR) != 0 && section->get_size() > 0) {
        return SectionKind::CODE;
    }
    return SectionKind::OTHER;
}

struct raw_elf_data {
    vector<vector<ebpf_inst>> code_list{};
    btf_header_t btf_header{};
    vector<vector<bpf_load_map_def>> map_def_list{};
    vector<btf_kind_variant_t> btf_types{};
};

template <typename T>
T read_single_and_incremet(const char*& base) {
    auto current = base;
    base += sizeof(T);
    return *(T*)(current);
}

template <typename T>
T read_items_and_incremet(const char*& base) {
    using item_t = typename T::item_t;
    btf_type_t tmp = *(btf_type_t*)(base);
    const auto vlen = tmp.info.vlen;
    const char* current = base;
    base += sizeof(T) + vlen * sizeof(item_t);
    return T{
        .type_info = tmp,
        .items = vector<item_t>((item_t*)current, ((item_t*)current)+vlen),
    };
}

vector<btf_kind_variant_t> read_btf_types(const ELFIO::section* section, const btf_header_t header) {
    // Parsing the type information is somewhat involved.
    // https://github.com/cilium/ebpf/blob/e4c6eabc2fd7a1fe5556ed38a01c18caa6dc020e/internal/btf/btf_types.go
    vector<btf_kind_variant_t> res;
    const char* base = section->get_data() + header.header.size + header.type_section.offset;
    const char* last = base + header.type_section.length;
    while (base < last) {
        btf_type_t current = *(btf_type_t*)(base);
        btf_kind_variant_t actual;
        switch ((BtfKind)current.info.kind) {
        case BtfKind::VOID:         actual = read_single_and_incremet<btf_kind_void_t>(base); break;
        case BtfKind::INT:          actual = read_single_and_incremet<btf_kind_int_t>(base); break;
        case BtfKind::PTR:          actual = read_single_and_incremet<btf_kind_ptr_t>(base); break;
        case BtfKind::ARRAY:        actual = read_single_and_incremet<btf_kind_array_t>(base); break;
        case BtfKind::STRUCT:       actual = read_items_and_incremet<btf_kind_struct_t>(base); break;
        case BtfKind::UNION:        actual = read_items_and_incremet<btf_kind_union_t>(base); break;
        case BtfKind::ENUM:         actual = read_items_and_incremet<btf_kind_enum_t>(base); break;
        case BtfKind::FORWARD:      actual = read_single_and_incremet<btf_kind_fwd_t>(base);break;
        case BtfKind::TYPEDEF:      actual = read_single_and_incremet<btf_kind_typedef_t>(base); break;
        case BtfKind::VOLATILE:     actual = read_single_and_incremet<btf_kind_volatile_t>(base); break;
        case BtfKind::CONST:        actual = read_single_and_incremet<btf_kind_const_t>(base); break;
        case BtfKind::RESTRICT:     actual = read_single_and_incremet<btf_kind_restrict_t>(base); break;
        case BtfKind::FUNC:         actual = read_single_and_incremet<btf_kind_func_t>(base); break;
        case BtfKind::FUNC_PROTO:   actual = read_items_and_incremet<btf_kind_func_proto_t>(base); break;
        case BtfKind::VAR:          actual = read_single_and_incremet<btf_kind_var_t>(base); break;
        case BtfKind::DATA_SECTION: actual = read_items_and_incremet<btf_kind_data_section_info_t>(base); break;
        case BtfKind::FLOAT:        actual = read_single_and_incremet<btf_kind_float_t>(base); break;
        }
        res.emplace_back(std::move(actual));
    }
    return res;
}

raw_elf_data read_elf(const std::string& path) {
    ELFIO::elfio reader = open_file(path);

    raw_elf_data res;
    for (const ELFIO::section* section : reader.sections) {
        const string name = section->get_name();
        //  switch {
        //  case sec.Type == elf.SHT_REL:
        //  	// Store relocations under the section index of the target
        //  	relSections[elf.SectionIndex(sec.Info)] = sec
        //  }
        switch (get_section_kind(section)) {
        case SectionKind::LICENSE: {
            break;
        }
        case SectionKind::VERSION: {
            break;
        }
        case SectionKind::MAPS: {
            res.map_def_list.emplace_back(read_vector_of<bpf_load_map_def>(section));
            break;
        }
        case SectionKind::DATA: {
            break;
        }
        case SectionKind::BTF: {
            res.btf_header = read_single<btf_header_t>(section);
            res.btf_types = read_btf_types(section, res.btf_header);
            break;
        }
        case SectionKind::BTF_MAPS: {
            break;
        }
        case SectionKind::CODE: {
            res.code_list.emplace_back(read_vector_of<ebpf_inst>(section));
            break;
        }
        case SectionKind::OTHER: {
            break;
        }
        }
    }
    return res;
}

struct Printer {

    template <typename T>
    struct Hex{ const T& v;};

    std::ostream& os;
    int indentation = 0;
    static constexpr int STEP = 4;

    void indent(const string& type_name) {
        os << type_name << " {\n";
        indentation += STEP;
    }

    void dedent() {
        indentation -= STEP;
        print_indent();
        os << "}\n";
    }

    void print_indent() {
        for (int n=0; n < indentation; n++) {
            os << " ";
        }
    }

#define PRINT_FIELD_HEX(obj, field) do { \
        print_indent(); \
        (os) << "." << #field << " = ";        \
        print(Hex<typeof(obj.field)>{obj . field});       \
        (os) << "\n";\
    } while (false)

#define PRINT_FIELD_ROW(obj, field) do { \
        (os) << "." << #field << " = ";        \
        print(obj . field);       \
        (os) << " ";\
    } while (false)

#define PRINT_FIELD(obj, field) do { \
        print_indent(); \
        PRINT_FIELD_ROW(obj, field); \
        (os) << "\n";\
    } while (false)

#define PRINT_NA(obj, field) do { \
        print_indent();           \
        (os) << "." << #field << " = N/A\n";\
    } while (false)

    void print(uint32_t n) { os << n; }
    void print(const string& s) { os << s; }

    void print(const bpf_load_map_def& obj) {
        indent("bpf_load_map_def");
        PRINT_FIELD(obj, type);
        PRINT_FIELD(obj, key_size);
        PRINT_FIELD(obj, value_size);
        PRINT_FIELD(obj, map_flags);
        PRINT_FIELD(obj, inner_map_idx);
        PRINT_FIELD(obj, numa_node);
        dedent();
    }

    void print(const section_data_t& obj) {
        indent("section_data_t");
        PRINT_FIELD(obj, offset);
        PRINT_FIELD(obj, length);
        dedent();
    }

    void print(const btf_pre_header_t& obj) {
        indent("btf_pre_header_t");
        PRINT_FIELD_HEX(obj, magic);
        PRINT_FIELD(obj, version);
        PRINT_FIELD(obj, flags);
        PRINT_FIELD(obj, size);
        dedent();
    }

    void print(const btf_header_t& obj) {
        indent("btf_header_t");
        PRINT_FIELD(obj, header);
        PRINT_FIELD(obj, type_section);
        PRINT_FIELD(obj, string_section);
        dedent();
    }
    void print(const ebpf_inst& obj) {
        os << "ebpf_inst {";
        PRINT_FIELD_ROW(obj, opcode);
        PRINT_FIELD_ROW(obj, dst);
        PRINT_FIELD_ROW(obj, src);
        PRINT_FIELD_ROW(obj, offset);
        PRINT_FIELD_ROW(obj, imm);
        os << "}\n";
    }

    template<typename T>
    void print(const Hex<T>& h) {
        os << std::hex << "0x" << h.v << std::oct;
    }

    template<typename T>
    void print(const vector<T>& ts) {
        indent("vector");
        for (const auto& t: ts) {
            print_indent();
            print(t);
        }
        dedent();
    }

    void print(const btf_type_t& obj) {
        indent("btf_type_t");
        PRINT_FIELD(obj, name_offset);
        PRINT_FIELD(obj, info.vlen);
        PRINT_FIELD(obj, info.kind);
        PRINT_FIELD(obj, info.unused);
        PRINT_FIELD(obj, info.kind_flag);
        PRINT_FIELD(obj, size);
        PRINT_FIELD(obj, type_id);
        dedent();
    }

    void print(const raw_elf_data& obj) {
        indent("raw_elf_data");
        PRINT_FIELD(obj, code_list);
        if (obj.btf_header.header.magic == 0)
            PRINT_NA(obj, btf_header);
        else
            PRINT_FIELD(obj, btf_header);
        PRINT_FIELD(obj, map_def_list);
        PRINT_FIELD(obj, btf_types);
        dedent();
    }

     void print(const btf_kind_variant_t& obj) {
         std::visit([&](auto x) { print(x); }, obj);
     }

     void print(const btf_kind_void_t& obj) { os << "void"; }
     void print(const btf_kind_int_t& obj) { os << "int"; }
     void print(const btf_kind_ptr_t& obj) { os << "ptr";  }
     void print(const btf_kind_array_t& obj) { os << "array"; }
     void print(const btf_kind_struct_t& obj) { os << "struct"; }
     void print(const btf_kind_union_t& obj) { os << "union"; }
     void print(const btf_kind_enum_t& obj) { os << "enum"; }
     void print(const btf_kind_fwd_t& obj) { os << "fwd"; }
     void print(const btf_kind_typedef_t& obj) { os << "typedef"; }
     void print(const btf_kind_volatile_t& obj) { os << "volatile"; }
     void print(const btf_kind_const_t& obj) { os << "const"; }
     void print(const btf_kind_restrict_t& obj) { os << "restrict"; }
     void print(const btf_kind_func_t& obj) { os << "func"; }
     void print(const btf_kind_func_proto_t& obj) { os << "func_proto"; }
     void print(const btf_kind_var_t& obj) { os << "var"; }
     void print(const btf_kind_data_section_info_t& obj) { os << "data_section_info"; }
     void print(const btf_kind_float_t& obj) { os << "float"; }
};

int main(int argc, char** argv) {
    CLI::App app{"Dump elf data"};

    std::string path;
    app.add_option("path", path, "YAML file.")->required()->type_name("FILE");

    CLI11_PARSE(app, argc, argv);
    Printer{std::cout}.print(read_elf(path));
}
