// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <map>
#include <set>
#include <stdexcept>
#include <string.h>

#include "btf.h"
#include "btf_parser.h"

/**
 * @brief Read a type from the .BTF section and advance the offset. Throws if
 * the reading goes out of bounds.
 *
 * @tparam T Type to read
 * @param[in] btf The .BTF section
 * @param[in,out] offset Offset to read from. Will be advanced by the size of T.
 * @param[in] minimum_offset Minimum offset allowed to read from.
 * @param[in] maximum_offset Maximum offset allowed to read from.
 * @return Value of type T read from the .BTF section
 */
template <typename T>
static T _read_btf(const std::vector<std::byte>& btf, size_t& offset, size_t minimum_offset = 0,
                   size_t maximum_offset = 0) {
    size_t length = 0;
    if (maximum_offset == 0) {
        maximum_offset = btf.size();
    }
    if (offset < minimum_offset || offset > maximum_offset) {
        throw std::runtime_error("Invalid .BTF section - invalid offset");
    }

    if constexpr (std::is_same<T, std::string>::value) {
        length = strnlen(reinterpret_cast<const char*>(btf.data()) + offset, maximum_offset - offset);
        offset += length + 1;
        if (offset > maximum_offset) {
            throw std::runtime_error("Invalid .BTF section - invalid string length");
        }
        return std::string(reinterpret_cast<const char*>(btf.data()) + offset - length - 1, length);
    } else {
        length = sizeof(T);
        offset += length;
        if (offset > maximum_offset) {
            throw std::runtime_error("Invalid .BTF section - invalid type length");
        }
        return *reinterpret_cast<const T*>(btf.data() + offset - length);
    }
}

static void _validate_offset(std::vector<std::byte> const& btf, size_t offset) {
    if (offset < 0) {
        throw std::runtime_error("Invalid .BTF section - invalid offset");
    }

    if (offset > btf.size()) {
        throw std::runtime_error("Invalid .BTF section - invalid offset");
    }
}

static void _validate_range(std::vector<std::byte> const& btf, size_t start, size_t end) {
    _validate_offset(btf, start);
    _validate_offset(btf, end);

    if (start > end) {
        throw std::runtime_error("Invalid .BTF section - invalid range");
    }
}

static std::map<size_t, std::string> _btf_parse_string_table(const std::vector<std::byte>& btf) {
    std::map<size_t, std::string> string_table;

    size_t offset = 0;
    auto btf_header = _read_btf<btf_header_t>(btf, offset);
    if (btf_header.magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .BTF section - wrong magic");
    }
    if (btf_header.version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .BTF section - wrong version");
    }
    if (btf_header.hdr_len < sizeof(btf_header_t)) {
        throw std::runtime_error("Invalid .BTF section - wrong size");
    }
    if (btf_header.hdr_len > btf.size()) {
        throw std::runtime_error("Invalid .BTF section - invalid header length");
    }

    size_t string_table_start = static_cast<size_t>(btf_header.hdr_len) + static_cast<size_t>(btf_header.str_off);
    size_t string_table_end = string_table_start + static_cast<size_t>(btf_header.str_len);

    _validate_range(btf, string_table_start, string_table_end);

    for (size_t offset = string_table_start; offset < string_table_end;) {
        size_t string_offset = offset - string_table_start;
        std::string value = _read_btf<std::string>(btf, offset, string_table_start, string_table_end);
        if (offset > string_table_end) {
            throw std::runtime_error("Invalid .BTF section - invalid string length");
        }
        string_table.insert({string_offset, value});
    }
    return string_table;
}

static std::string _btf_find_string(const std::map<size_t, std::string>& string_table, size_t string_offset) {
    auto it = string_table.find(string_offset);
    if (it == string_table.end()) {
        throw std::runtime_error(std::string("Invalid .BTF section - invalid string offset"));
    }
    return it->second;
}

void btf_parse_line_information(const std::vector<std::byte>& btf, const std::vector<std::byte>& btf_ext,
                                btf_line_info_visitor visitor) {
    std::map<size_t, std::string> string_table = _btf_parse_string_table(btf);

    size_t btf_ext_offset = 0;
    auto bpf_ext_header = _read_btf<btf_ext_header_t>(btf_ext, btf_ext_offset);
    if (bpf_ext_header.hdr_len < sizeof(btf_ext_header_t)) {
        throw std::runtime_error("Invalid .BTF.ext section - wrong size");
    }
    if (bpf_ext_header.magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .BTF.ext section - wrong magic");
    }
    if (bpf_ext_header.version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .BTF.ext section - wrong version");
    }
    if (bpf_ext_header.hdr_len > btf_ext.size()) {
        throw std::runtime_error("Invalid .BTF.ext section - invalid header length");
    }

    size_t line_info_start =
        static_cast<size_t>(bpf_ext_header.hdr_len) + static_cast<size_t>(bpf_ext_header.line_info_off);
    size_t line_info_end = line_info_start + static_cast<size_t>(bpf_ext_header.line_info_len);

    _validate_range(btf_ext, line_info_start, line_info_end);

    btf_ext_offset = line_info_start;
    uint32_t line_info_record_size = _read_btf<uint32_t>(btf_ext, btf_ext_offset, line_info_start, line_info_end);
    if (line_info_record_size < sizeof(bpf_line_info_t)) {
        throw std::runtime_error(std::string("Invalid .BTF.ext section - invalid line info record size"));
    }

    for (; btf_ext_offset < line_info_end;) {
        auto section_info = _read_btf<btf_ext_info_sec_t>(btf_ext, btf_ext_offset, line_info_start, line_info_end);
        auto section_name = _btf_find_string(string_table, section_info.sec_name_off);
        for (size_t index = 0; index < section_info.num_info; index++) {
            auto btf_line_info = _read_btf<bpf_line_info_t>(btf_ext, btf_ext_offset, line_info_start, line_info_end);
            auto file_name = _btf_find_string(string_table, btf_line_info.file_name_off);
            auto source = _btf_find_string(string_table, btf_line_info.line_off);
            visitor(section_name, btf_line_info.insn_off, file_name, source,
                    BPF_LINE_INFO_LINE_NUM(btf_line_info.line_col), BPF_LINE_INFO_LINE_COL(btf_line_info.line_col));
        }
    }
}

void btf_parse_types(const std::vector<std::byte>& btf, btf_type_visitor visitor) {
    std::map<size_t, std::string> string_table = _btf_parse_string_table(btf);
    btf_type_id id = 0;
    size_t offset = 0;

    auto btf_header = _read_btf<btf_header_t>(btf, offset);

    if (btf_header.magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .BTF section - wrong magic");
    }

    if (btf_header.version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .BTF section - wrong version");
    }

    if (btf_header.hdr_len < sizeof(btf_header_t)) {
        throw std::runtime_error("Invalid .BTF section - wrong size");
    }

    size_t type_start = static_cast<size_t>(btf_header.hdr_len) + static_cast<size_t>(btf_header.type_off);
    size_t type_end = type_start + static_cast<size_t>(btf_header.type_len);

    _validate_range(btf, type_start, type_end);

    btf_kind_null kind_null;
    visitor(0, "void", {kind_null});

    size_t type_offset = type_start;
    for (offset = type_start; offset < type_end;) {
        std::optional<std::string> name;
        auto btf_type = _read_btf<btf_type_t>(btf, offset, type_start, type_end);
        if (btf_type.name_off) {
            name = _btf_find_string(string_table, btf_type.name_off);
        } else {
            // Throw for types that should have a name.
            switch (BPF_TYPE_INFO_KIND(btf_type.info)) {
            case BTF_KIND_INT:
            case BTF_KIND_FWD:
            case BTF_KIND_TYPEDEF:
            case BTF_KIND_FUNC:
            case BTF_KIND_VAR:
            case BTF_KIND_DATASEC:
            case BTF_KIND_FLOAT:
            case BTF_KIND_DECL_TAG:
            case BTF_KIND_TYPE_TAG: throw std::runtime_error("Invalid .BTF section - missing name");
            default: name = std::nullopt; break;
            }
        }
        btf_kind kind;
        switch (BPF_TYPE_INFO_KIND(btf_type.info)) {
        case BTF_KIND_INT: {
            btf_kind_int kind_int;
            uint32_t int_data = _read_btf<uint32_t>(btf, offset, type_start, type_end);
            uint32_t encoding = BTF_INT_ENCODING(int_data);
            kind_int.offset_from_start_in_bits = BTF_INT_OFFSET(int_data);
            kind_int.field_width_in_bits = BTF_INT_BITS(int_data);
            kind_int.is_signed = BTF_INT_SIGNED & encoding;
            kind_int.is_bool = BTF_INT_BOOL & encoding;
            kind_int.is_char = BTF_INT_CHAR & encoding;
            kind_int.size_in_bytes = btf_type.size;
            kind_int.name = name.value();
            kind = kind_int;
            break;
        }
        case BTF_KIND_PTR: {
            btf_kind_ptr kind_ptr;
            kind_ptr.type = btf_type.type;
            kind = kind_ptr;
            break;
        }
        case BTF_KIND_ARRAY: {
            auto btf_array = _read_btf<btf_array_t>(btf, offset, type_start, type_end);
            btf_kind_array kind_array;
            kind_array.element_type = btf_array.type;
            kind_array.index_type = btf_array.index_type;
            kind_array.count_of_elements = btf_array.nelems;
            kind = kind_array;
            break;
        }
        case BTF_KIND_STRUCT: {
            uint32_t member_count = BPF_TYPE_INFO_VLEN(btf_type.info);
            btf_kind_struct kind_struct;
            for (uint32_t index = 0; index < member_count; index++) {
                btf_kind_struct_member member;
                auto btf_member = _read_btf<btf_member_t>(btf, offset, type_start, type_end);
                if (btf_member.name_off) {
                    member.name = _btf_find_string(string_table, btf_member.name_off);
                }
                member.type = btf_member.type;
                member.offset_from_start_in_bits = btf_member.offset;
                kind_struct.members.push_back(member);
            }
            kind_struct.size_in_bytes = btf_type.size;
            kind_struct.name = name;
            kind = kind_struct;
            break;
        }
        case BTF_KIND_UNION: {
            uint32_t member_count = BPF_TYPE_INFO_VLEN(btf_type.info);
            btf_kind_union kind_union;
            for (uint32_t index = 0; index < member_count; index++) {
                btf_kind_struct_member member;
                auto btf_member = _read_btf<btf_member_t>(btf, offset, type_start, type_end);
                if (btf_member.name_off) {
                    member.name = _btf_find_string(string_table, btf_member.name_off);
                }
                member.type = btf_member.type;
                member.offset_from_start_in_bits = btf_member.offset;
                kind_union.members.push_back(member);
            }
            kind_union.name = name;
            kind_union.size_in_bytes = btf_type.size;
            kind = kind_union;
            break;
        }
        case BTF_KIND_ENUM: {
            uint32_t enum_count = BPF_TYPE_INFO_VLEN(btf_type.info);
            btf_kind_enum kind_enum;
            for (uint32_t index = 0; index < enum_count; index++) {
                auto btf_enum = _read_btf<btf_enum_t>(btf, offset, type_start, type_end);
                btf_kind_enum_member member;
                if (!btf_enum.name_off) {
                    throw std::runtime_error("Invalid .BTF section - invalid BTF_KIND_ENUM member name");
                }
                member.name = _btf_find_string(string_table, btf_enum.name_off);
                member.value = btf_enum.val;
                kind_enum.members.push_back(member);
            }
            kind_enum.is_signed = BPF_TYPE_INFO_KIND_FLAG(btf_type.info);
            kind_enum.name = name;
            kind_enum.size_in_bytes = btf_type.size;
            kind = kind_enum;
            break;
        }
        case BTF_KIND_FWD: {
            btf_kind_fwd kind_fwd;
            kind_fwd.name = name.value();
            kind_fwd.is_struct = BPF_TYPE_INFO_KIND_FLAG(btf_type.info);
            kind = kind_fwd;
            break;
        }
        case BTF_KIND_TYPEDEF: {
            btf_kind_typedef kind_typedef;
            kind_typedef.name = name.value();
            kind_typedef.type = btf_type.type;
            kind = kind_typedef;
            break;
        }
        case BTF_KIND_VOLATILE: {
            btf_kind_volatile kind_volatile;
            kind_volatile.type = btf_type.type;
            kind = kind_volatile;
            break;
        }
        case BTF_KIND_CONST: {
            btf_kind_const kind_const;
            kind_const.type = btf_type.type;
            kind = kind_const;
            break;
        }
        case BTF_KIND_RESTRICT: {
            btf_kind_restrict kind_restrict;
            kind_restrict.type = btf_type.type;
            kind = kind_restrict;
            break;
        }
        case BTF_KIND_FUNC: {
            btf_kind_function kind_function;
            kind_function.name = name.value();
            kind_function.type = btf_type.type;
            kind_function.linkage = static_cast<decltype(kind_function.linkage)>(BPF_TYPE_INFO_VLEN(btf_type.info));
            // kind_func.linkage = BPF_TYPE_INFO_VLEN(btf_type.info);
            kind = kind_function;
            break;
        }
        case BTF_KIND_FUNC_PROTO: {
            btf_kind_function_prototype kind_function;
            uint32_t param_count = BPF_TYPE_INFO_VLEN(btf_type.info);
            for (uint32_t index = 0; index < param_count; index++) {
                auto btf_param = _read_btf<btf_param_t>(btf, offset, type_start, type_end);
                btf_kind_function_parameter param;
                // Name is optional.
                if (btf_param.name_off) {
                    param.name = _btf_find_string(string_table, btf_param.name_off);
                }
                param.type = btf_param.type;
                kind_function.parameters.push_back(param);
            }
            kind_function.return_type = btf_type.type;
            kind = kind_function;
            break;
        }
        case BTF_KIND_VAR: {
            btf_kind_var kind_var;
            auto btf_var = _read_btf<btf_var_t>(btf, offset, type_start, type_end);
            kind_var.name = name.value();
            kind_var.type = btf_type.type;
            kind_var.linkage = static_cast<decltype(btf_kind_var::linkage)>(btf_var.linkage);
            kind = kind_var;
            break;
        }
        case BTF_KIND_DATASEC: {
            btf_kind_data_section kind_data_section;
            uint32_t section_count = BPF_TYPE_INFO_VLEN(btf_type.info);
            for (uint32_t index = 0; index < section_count; index++) {
                auto btf_section_info = _read_btf<btf_var_secinfo_t>(btf, offset, type_start, type_end);
                btf_kind_data_member member;
                member.type = btf_section_info.type;
                member.offset = btf_section_info.offset;
                member.size = btf_section_info.size;
                kind_data_section.members.push_back(member);
            }
            kind_data_section.name = name.value();
            kind_data_section.size = btf_type.size;
            kind = kind_data_section;
            break;
        }
        case BTF_KIND_FLOAT: {
            btf_kind_float kind_float;
            kind_float.name = name.value();
            kind_float.size_in_bytes = btf_type.size;
            kind = kind_float;
            break;
        }
        case BTF_KIND_DECL_TAG: {
            btf_kind_decl_tag kind_decl_tag;
            auto btf_decl_tag = _read_btf<btf_decl_tag_t>(btf, offset, type_start, type_end);
            kind_decl_tag.name = name.value();
            kind_decl_tag.type = btf_type.type;
            kind_decl_tag.component_index = btf_decl_tag.component_idx;
            kind = kind_decl_tag;
            break;
        }
        case BTF_KIND_TYPE_TAG: {
            btf_kind_type_tag kind_type_tag;
            kind_type_tag.name = name.value();
            kind_type_tag.type = btf_type.type;
            kind = kind_type_tag;
            break;
        }
        case BTF_KIND_ENUM64: {
            uint32_t enum_count = BPF_TYPE_INFO_VLEN(btf_type.info);
            btf_kind_enum64 kind_enum;
            for (uint32_t index = 0; index < enum_count; index++) {
                auto btf_enum64 = _read_btf<btf_enum64_t>(btf, offset, type_start, type_end);
                btf_kind_enum64_member member;
                member.name = _btf_find_string(string_table, btf_enum64.name_off);
                member.value = (static_cast<uint64_t>(btf_enum64.val_hi32) << 32) | btf_enum64.val_lo32;
                kind_enum.members.push_back(member);
            }
            kind_enum.is_signed = BPF_TYPE_INFO_KIND_FLAG(btf_type.info);
            kind_enum.name = name;
            kind_enum.size_in_bytes = btf_type.size;
            kind = kind_enum;
            break;
        }
        default: throw std::runtime_error("Invalid .BTF section - invalid BTF_KIND");
        }
        visitor(++id, name, kind);
    }
}

std::string pretty_print_json(const std::string& input) {
    // Walk over the input string, inserting newlines and indentation.
    std::string output;
    int indent = 0;
    bool in_string = false;
    for (size_t i = 0; i < input.size(); i++) {
        char c = input[i];
        if (c == '"') {
            in_string = !in_string;
        }
        if (in_string) {
            output += c;
            continue;
        }
        switch (c) {
        case '{':
        case '[':
            output += c;
            if (i + 1 < input.size() && input[i + 1] != '}' && input[i + 1] != ']') {
                output += '\n';
                indent += 2;
                output += std::string(indent, ' ');
            } else {
                output += input[++i];
            }
            break;
        case '}':
        case ']':
            output += '\n';
            indent -= 2;
            output += std::string(indent, ' ');
            output += c;
            break;
        case ',':
            output += c;
            output += '\n';
            output += std::string(indent, ' ');
            break;
        case ':':
            output += c;
            output += ' ';
            break;
        default: output += c; break;
        }
    }
    return output;
}

template <typename T>
void print_json_value(bool& first, const std::string& name, T value, std::ostream& out) {
    // If T is a string type, print it as a string, then quote the value.
    if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, const char*> || std::is_same_v<T, char*>) {
        out << (first ? "" : ",") << "\"" << name << "\":\"" << value << "\"";
        first = false;
    }
    // If T is a bool, print it as a string, then quote the value.
    else if constexpr (std::is_same_v<T, bool>) {
        out << (first ? "" : ",") << "\"" << name << "\":" << (value ? "true" : "false");
        first = false;
    }
    // If T is a std::optional<std::string>, then only print if it's present
    else if constexpr (std::is_same_v<T, std::optional<std::string>>) {
        if (value.has_value()) {
            out << (first ? "" : ",") << "\"" << name << "\":\"" << value.value() << "\"";
            first = false;
        }
    } else {
        out << (first ? "" : ",") << "\"" << name << "\":" << std::to_string(value);
        first = false;
    }
}

void print_array_start(const std::string& name, std::ostream& out) { out << "\"" << name << "\":["; }

void print_array_end(std::ostream& out) { out << "]"; }

#define PRINT_JSON_FIXED(name, value) print_json_value(first, name, value, out);

#define PRINT_JSON_VALUE(object, value) print_json_value(first, #value, object.value, out)

#define PRINT_JSON_TYPE(object, value) \
    if (!first) {                      \
        out << ",";                    \
    } else {                           \
        first = false;                 \
    };                                 \
    out << "\"" << #value << "\":";    \
    print_btf_kind(object.value, id_to_kind.at(object.value));

#define PRINT_JSON_ARRAY_START(object, value) \
    if (!first) {                             \
        out << ",";                           \
    } else {                                  \
        first = false;                        \
    }                                         \
    print_array_start(#value, out);           \
    {                                         \
        bool first = true;

#define PRINT_JSON_ARRAY_END() \
    print_array_end(out);      \
    }

#define PRINT_JSON_OBJECT_START() \
    if (!first) {                 \
        out << ",";               \
    } else {                      \
        first = false;            \
    };                            \
    {                             \
        bool first = true;        \
        out << "{";

#define PRINT_JSON_OBJECT_END() \
    out << "}";                 \
    }

void btf_type_to_json(const std::map<btf_type_id, btf_kind>& id_to_kind, std::ostream& out) {
    std::function<void(btf_type_id, const btf_kind&)> print_btf_kind = [&](btf_type_id id, const btf_kind& kind) {
        bool first = true;
        PRINT_JSON_OBJECT_START();
        PRINT_JSON_FIXED("id", id);
        switch (kind.index()) {
        case 0: PRINT_JSON_FIXED("kind_type", "BTF_KIND_VOID"); break;
        case BTF_KIND_INT: {
            auto& kind_int = std::get<BTF_KIND_INT>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_INT");
            PRINT_JSON_VALUE(kind_int, name);
            PRINT_JSON_VALUE(kind_int, size_in_bytes);
            PRINT_JSON_VALUE(kind_int, offset_from_start_in_bits);
            PRINT_JSON_VALUE(kind_int, field_width_in_bits);
            PRINT_JSON_VALUE(kind_int, is_signed);
            PRINT_JSON_VALUE(kind_int, is_char);
            PRINT_JSON_VALUE(kind_int, is_bool);
            break;
        }
        case BTF_KIND_PTR: {
            auto& kind_ptr = std::get<BTF_KIND_PTR>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_PTR");
            PRINT_JSON_TYPE(kind_ptr, type);
            break;
        }
        case BTF_KIND_ARRAY: {
            auto& kind_array = std::get<BTF_KIND_ARRAY>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_ARRAY");
            PRINT_JSON_VALUE(kind_array, count_of_elements);
            PRINT_JSON_TYPE(kind_array, element_type);
            PRINT_JSON_TYPE(kind_array, index_type);
            break;
        }
        case BTF_KIND_STRUCT: {
            auto& kind_struct = std::get<BTF_KIND_STRUCT>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_STRUCT");
            PRINT_JSON_VALUE(kind_struct, name);
            PRINT_JSON_VALUE(kind_struct, size_in_bytes);
            PRINT_JSON_ARRAY_START(kind_struct, members);
            for (auto& member : kind_struct.members) {
                PRINT_JSON_OBJECT_START();
                PRINT_JSON_VALUE(member, name);
                PRINT_JSON_VALUE(member, offset_from_start_in_bits);
                PRINT_JSON_TYPE(member, type);
                PRINT_JSON_OBJECT_END();
            }
            PRINT_JSON_ARRAY_END();
            break;
        }
        case BTF_KIND_UNION: {
            auto kind_union = std::get<BTF_KIND_UNION>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_UNION");
            PRINT_JSON_VALUE(kind_union, name);
            PRINT_JSON_VALUE(kind_union, size_in_bytes);
            PRINT_JSON_ARRAY_START(kind_union, members);
            for (auto& member : kind_union.members) {
                PRINT_JSON_OBJECT_START();
                PRINT_JSON_VALUE(member, name);
                PRINT_JSON_VALUE(member, offset_from_start_in_bits);
                PRINT_JSON_TYPE(member, type);
                PRINT_JSON_OBJECT_END();
            }
            PRINT_JSON_ARRAY_END();
            break;
        }
        case BTF_KIND_ENUM: {
            auto& kind_enum = std::get<BTF_KIND_ENUM>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_ENUM");
            PRINT_JSON_VALUE(kind_enum, name);
            PRINT_JSON_VALUE(kind_enum, size_in_bytes);
            PRINT_JSON_ARRAY_START(kind_union, members);
            for (auto& member : kind_enum.members) {
                PRINT_JSON_OBJECT_START();
                PRINT_JSON_VALUE(member, name);
                PRINT_JSON_VALUE(member, value);
                PRINT_JSON_OBJECT_END();
            }
            PRINT_JSON_ARRAY_END();
            break;
        }
        case BTF_KIND_FWD: {
            auto kind_fwd = std::get<BTF_KIND_FWD>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_FWD");
            PRINT_JSON_VALUE(kind_fwd, name);
            PRINT_JSON_VALUE(kind_fwd, is_struct);
            break;
        }
        case BTF_KIND_TYPEDEF: {
            auto& kind_typedef = std::get<BTF_KIND_TYPEDEF>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_TYPEDEF");
            PRINT_JSON_VALUE(kind_typedef, name);
            PRINT_JSON_TYPE(kind_typedef, type);
            break;
        }
        case BTF_KIND_VOLATILE: {
            auto& kind_volatile = std::get<BTF_KIND_VOLATILE>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_VOLATILE");
            PRINT_JSON_TYPE(kind_volatile, type);
            break;
        }
        case BTF_KIND_CONST: {
            auto& kind_const = std::get<BTF_KIND_CONST>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_CONST");
            PRINT_JSON_TYPE(kind_const, type);
            break;
        }
        case BTF_KIND_RESTRICT: {
            auto& kind_restrict = std::get<BTF_KIND_RESTRICT>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_RESTRICT");
            PRINT_JSON_TYPE(kind_restrict, type);
            break;
        }
        case BTF_KIND_FUNC: {
            auto kind_func = std::get<BTF_KIND_FUNC>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_FUNC");
            PRINT_JSON_VALUE(kind_func, name);
            switch (kind_func.linkage) {
            case 0: PRINT_JSON_FIXED("linkage", "BTF_FUNC_STATIC"); break;
            case 1: PRINT_JSON_FIXED("linkage", "BTF_FUNC_GLOBAL"); break;
            case 2: PRINT_JSON_FIXED("linkage", "BTF_FUNC_EXTERN"); break;
            default: PRINT_JSON_FIXED("linkage", "UNKNOWN"); break;
            }
            PRINT_JSON_TYPE(kind_func, type);
            break;
        }
        case BTF_KIND_FUNC_PROTO: {
            auto& kind_func_proto = std::get<BTF_KIND_FUNC_PROTO>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_FUNC_PROTO");
            PRINT_JSON_ARRAY_START(kind_func_proto, parameters);
            for (auto& parameter : kind_func_proto.parameters) {
                PRINT_JSON_OBJECT_START();
                PRINT_JSON_VALUE(parameter, name);
                PRINT_JSON_TYPE(parameter, type);
                PRINT_JSON_OBJECT_END();
            }
            PRINT_JSON_ARRAY_END();
            PRINT_JSON_TYPE(kind_func_proto, return_type);
            break;
        }
        case BTF_KIND_VAR: {
            auto& kind_var = std::get<BTF_KIND_VAR>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_VAR");
            PRINT_JSON_VALUE(kind_var, name);
            switch (kind_var.linkage) {
            case 0: PRINT_JSON_FIXED("linkage", "BTF_LINKAGE_GLOBAL"); break;
            case 1: PRINT_JSON_FIXED("linkage", "BTF_LINKAGE_STATIC"); break;
            default: PRINT_JSON_FIXED("linkage", "UNKNOWN"); break;
            }
            PRINT_JSON_TYPE(kind_var, type);
            break;
        }
        case BTF_KIND_DATASEC: {
            auto& kind_datasec = std::get<BTF_KIND_DATASEC>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_DATASEC");
            PRINT_JSON_VALUE(kind_datasec, name);
            PRINT_JSON_VALUE(kind_datasec, size);
            PRINT_JSON_ARRAY_START(kind_datasec, members);
            for (auto& data : kind_datasec.members) {
                PRINT_JSON_OBJECT_START();
                PRINT_JSON_VALUE(data, offset);
                PRINT_JSON_VALUE(data, size);
                PRINT_JSON_TYPE(data, type);
                PRINT_JSON_OBJECT_END();
            }
            PRINT_JSON_ARRAY_END();
            break;
        }
        case BTF_KIND_FLOAT: {
            auto kind_float = std::get<BTF_KIND_FLOAT>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_FLOAT");
            PRINT_JSON_VALUE(kind_float, name);
            PRINT_JSON_VALUE(kind_float, size_in_bytes);
            break;
        }
        case BTF_KIND_DECL_TAG: {
            auto& kind_decl_tag = std::get<BTF_KIND_DECL_TAG>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_DECL_TAG");
            PRINT_JSON_VALUE(kind_decl_tag, name);
            PRINT_JSON_TYPE(kind_decl_tag, type);
            break;
        }
        case BTF_KIND_TYPE_TAG: {
            auto& kind_type_tag = std::get<BTF_KIND_TYPE_TAG>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_TYPE_TAG");
            PRINT_JSON_VALUE(kind_type_tag, name);
            PRINT_JSON_TYPE(kind_type_tag, type);
            break;
        }
        case BTF_KIND_ENUM64: {
            auto& kind_enum = std::get<BTF_KIND_ENUM64>(kind);
            PRINT_JSON_FIXED("kind_type", "BTF_KIND_ENUM64");
            PRINT_JSON_VALUE(kind_enum, name);
            PRINT_JSON_VALUE(kind_enum, size_in_bytes);
            PRINT_JSON_ARRAY_START(kind_enum, members);
            for (auto& member : kind_enum.members) {
                PRINT_JSON_OBJECT_START();
                PRINT_JSON_VALUE(member, name);
                PRINT_JSON_VALUE(member, value);
                PRINT_JSON_OBJECT_END();
            }
            PRINT_JSON_ARRAY_END();
            break;
        }
        default: PRINT_JSON_FIXED("kind_type", "UNKNOWN");
        }
        PRINT_JSON_OBJECT_END();
    };

    // Determine the list of types that are not referenced by other types. These are the root types.
    std::set<btf_type_id> root_types;

    // Add all types as root types.
    for (auto& [id, kind] : id_to_kind) {
        root_types.insert(id);
    }

    // Erase the VOID type.
    root_types.erase(0);

    // Remove all types that are referenced by other types.
    for (auto& [id, kind] : id_to_kind) {
        switch (kind.index()) {
        case BTF_KIND_PTR: root_types.erase(std::get<BTF_KIND_PTR>(kind).type); break;
        case BTF_KIND_ARRAY:
            root_types.erase(std::get<BTF_KIND_ARRAY>(kind).element_type);
            root_types.erase(std::get<BTF_KIND_ARRAY>(kind).index_type);
            break;
        case BTF_KIND_STRUCT:
            for (auto& member : std::get<BTF_KIND_STRUCT>(kind).members) {
                root_types.erase(member.type);
            }
            break;
        case BTF_KIND_UNION:
            for (auto& member : std::get<BTF_KIND_UNION>(kind).members) {
                root_types.erase(member.type);
            }
            break;
        case BTF_KIND_TYPEDEF: root_types.erase(std::get<BTF_KIND_TYPEDEF>(kind).type); break;
        case BTF_KIND_VOLATILE: root_types.erase(std::get<BTF_KIND_VOLATILE>(kind).type); break;
        case BTF_KIND_CONST: root_types.erase(std::get<BTF_KIND_CONST>(kind).type); break;
        case BTF_KIND_RESTRICT: root_types.erase(std::get<BTF_KIND_RESTRICT>(kind).type); break;
        case BTF_KIND_FUNC_PROTO:
            for (auto& param : std::get<BTF_KIND_FUNC_PROTO>(kind).parameters) {
                root_types.erase(param.type);
            }
            root_types.erase(std::get<BTF_KIND_FUNC_PROTO>(kind).return_type);
            break;
        case BTF_KIND_FUNC: root_types.erase(std::get<BTF_KIND_FUNC>(kind).type); break;
        case BTF_KIND_VAR: root_types.erase(std::get<BTF_KIND_VAR>(kind).type); break;
        case BTF_KIND_DATASEC:
            for (auto& variable : std::get<BTF_KIND_DATASEC>(kind).members) {
                root_types.erase(variable.type);
            }
            break;
        case BTF_KIND_DECL_TAG: root_types.erase(std::get<BTF_KIND_DECL_TAG>(kind).type); break;
        case BTF_KIND_TYPE_TAG: root_types.erase(std::get<BTF_KIND_TYPE_TAG>(kind).type); break;
        }
    }
    bool first = true;
    PRINT_JSON_OBJECT_START();
    PRINT_JSON_ARRAY_START("", btf_kinds);
    for (const auto& [id, kind] : id_to_kind) {
        // Skip non-root types.
        if (root_types.find(id) == root_types.end()) {
            continue;
        }

        out << (first ? "" : ",");
        first = false;
        print_btf_kind(id, kind);
    }
    PRINT_JSON_ARRAY_END();
    PRINT_JSON_OBJECT_END();
}

btf_type_data::btf_type_data(const std::vector<std::byte>& btf_data) {
    auto visitor = [&, this](btf_type_id id, const std::optional<std::string>& name, const btf_kind& kind) {
        this->id_to_kind.insert({id, kind});
        if (name.has_value()) {
            this->name_to_id.insert({name.value(), id});
        }
    };
    btf_parse_types(btf_data, visitor);
    // Validate that the type graph is valid.
    for (const auto& [id, kind] : id_to_kind) {
        std::set<btf_type_id> visited;
        validate_type_graph(id, visited);
    }
}

btf_type_id btf_type_data::get_id(const std::string& name) const {
    auto it = name_to_id.find(name);
    if (it == name_to_id.end()) {
        return 0;
    }
    return it->second;
}

btf_kind btf_type_data::get_kind(btf_type_id id) const {
    auto it = id_to_kind.find(id);
    if (it == id_to_kind.end()) {
        throw std::runtime_error("BTF type id not found: " + std::to_string(id));
    }
    return it->second;
}

btf_type_id btf_type_data::dereference_pointer(btf_type_id id) const {
    auto kind = get_kind(id);
    if (kind.index() != BTF_KIND_PTR) {
        throw std::runtime_error("BTF type is not a pointer: " + std::to_string(id));
    }
    return std::get<BTF_KIND_PTR>(kind).type;
}

size_t btf_type_data::get_size(btf_type_id id) const {
    // Compute the effective size of a BTF type.

    auto kind = id_to_kind.at(id);

    switch (kind.index()) {
    case BTF_KIND_INT: return std::get<BTF_KIND_INT>(kind).size_in_bytes;
    case BTF_KIND_PTR: return sizeof(void*);
    case BTF_KIND_ARRAY:
        return std::get<BTF_KIND_ARRAY>(kind).count_of_elements * get_size(std::get<BTF_KIND_ARRAY>(kind).element_type);
    case BTF_KIND_STRUCT: return std::get<BTF_KIND_STRUCT>(kind).size_in_bytes;
    case BTF_KIND_UNION: return std::get<BTF_KIND_UNION>(kind).size_in_bytes;
    case BTF_KIND_ENUM: return std::get<BTF_KIND_ENUM>(kind).size_in_bytes;
    case BTF_KIND_FWD: return 0;
    case BTF_KIND_TYPEDEF: return get_size(std::get<BTF_KIND_TYPEDEF>(kind).type);
    case BTF_KIND_VOLATILE: return get_size(std::get<BTF_KIND_VOLATILE>(kind).type);
    case BTF_KIND_CONST: return get_size(std::get<BTF_KIND_CONST>(kind).type);
    case BTF_KIND_RESTRICT: return get_size(std::get<BTF_KIND_RESTRICT>(kind).type);
    case BTF_KIND_FUNC_PROTO: return 0;
    case BTF_KIND_FUNC: return 0;
    case BTF_KIND_VAR: return get_size(std::get<BTF_KIND_VAR>(kind).type);
    case BTF_KIND_DATASEC: return 0;
    case BTF_KIND_FLOAT: return std::get<BTF_KIND_FLOAT>(kind).size_in_bytes;
    case BTF_KIND_DECL_TAG: return get_size(std::get<BTF_KIND_DECL_TAG>(kind).type);
    case BTF_KIND_TYPE_TAG: return get_size(std::get<BTF_KIND_TYPE_TAG>(kind).type);
    case BTF_KIND_ENUM64: return std::get<BTF_KIND_ENUM64>(kind).size_in_bytes;
    default: throw std::runtime_error("unknown BTF type kind");
    }
}

void btf_type_data::to_json(std::ostream& out) const { btf_type_to_json(id_to_kind, out); }

void btf_type_data::validate_type_graph(btf_type_id id, std::set<btf_type_id>& visited) const {
    // BTF types must be an acyclic graph. This function validates that the type graph is acyclic.
    if (visited.find(id) != visited.end()) {
        throw std::runtime_error("BTF type cycle detected: " + std::to_string(id));
    } else {
        visited.insert(id);
    }

    auto kind = get_kind(id);
    switch (kind.index()) {
    case 0: break;
    case BTF_KIND_INT: break;
    case BTF_KIND_PTR: validate_type_graph(std::get<BTF_KIND_PTR>(kind).type, visited); break;
    case BTF_KIND_ARRAY:
        validate_type_graph(std::get<BTF_KIND_ARRAY>(kind).element_type, visited);
        validate_type_graph(std::get<BTF_KIND_ARRAY>(kind).index_type, visited);
        break;
    case BTF_KIND_STRUCT: {
        auto& struct_ = std::get<BTF_KIND_STRUCT>(kind);
        for (auto& member : struct_.members) {
            validate_type_graph(member.type, visited);
        }
        break;
    }
    case BTF_KIND_UNION: {
        auto& union_ = std::get<BTF_KIND_UNION>(kind);
        for (auto& member : union_.members) {
            validate_type_graph(member.type, visited);
        }
        break;
    }
    case BTF_KIND_ENUM: break;
    case BTF_KIND_FWD: break;
    case BTF_KIND_TYPEDEF: validate_type_graph(std::get<BTF_KIND_TYPEDEF>(kind).type, visited); break;
    case BTF_KIND_VOLATILE: validate_type_graph(std::get<BTF_KIND_VOLATILE>(kind).type, visited); break;
    case BTF_KIND_CONST: validate_type_graph(std::get<BTF_KIND_CONST>(kind).type, visited); break;
    case BTF_KIND_RESTRICT: validate_type_graph(std::get<BTF_KIND_RESTRICT>(kind).type, visited); break;
    case BTF_KIND_FUNC: validate_type_graph(std::get<BTF_KIND_FUNC>(kind).type, visited); break;
    case BTF_KIND_FUNC_PROTO: {
        auto& prototype = std::get<BTF_KIND_FUNC_PROTO>(kind);
        for (auto& parameter : prototype.parameters) {
            validate_type_graph(parameter.type, visited);
        }
        validate_type_graph(prototype.return_type, visited);
        break;
    }
    case BTF_KIND_VAR: validate_type_graph(std::get<BTF_KIND_VAR>(kind).type, visited); break;
    case BTF_KIND_DATASEC: {
        auto& datasec = std::get<BTF_KIND_DATASEC>(kind);
        for (auto& variable : datasec.members) {
            validate_type_graph(variable.type, visited);
        }
        break;
    }
    case BTF_KIND_FLOAT: break;
    case BTF_KIND_DECL_TAG: validate_type_graph(std::get<BTF_KIND_DECL_TAG>(kind).type, visited); break;
    case BTF_KIND_TYPE_TAG: validate_type_graph(std::get<BTF_KIND_TYPE_TAG>(kind).type, visited); break;
    case BTF_KIND_ENUM64: break;
    default: throw std::runtime_error("unknown BTF type kind " + std::to_string(kind.index()));
    }

    visited.erase(id);
}

/**
 * @brief Given the BTF type ID of a value declared via the __uint macro, return the value.
 *
 * @param[in] type_id The BTF type ID of the value.
 * @param[in] id_to_kind The map from BTF type ID to BTF type kind.
 * @return The value.
 */
static uint32_t value_from_BTF__uint(const btf_type_data& btf_types, btf_type_id type_id) {
    // The __uint macro is defined as follows:
    // #define __uint(name, val) int (*name)[val]
    // So, we need to get the value of val from the BTF type.

    // Top level should be a pointer. Dereference it.
    type_id = btf_types.dereference_pointer(type_id);

    // Next level should be an array.
    auto array = btf_types.get_kind(type_id);
    if (array.index() != BTF_KIND_ARRAY) {
        throw std::runtime_error("expected array type");
    }
    auto array_type = std::get<BTF_KIND_ARRAY>(array);

    // Value is encoded in the count of elements.
    return array_type.count_of_elements;
}

/**
 * @brief Get the map descriptor from a BTF map type.
 *
 * @param[in] map_type_id The BTF type ID of the map type.
 * @param[in] id_to_kind The map from BTF type ID to BTF type kind.
 * @return The map descriptor.
 */
static EbpfMapDescriptor get_map_descriptor_from_btf(const btf_type_data& btf_types, btf_type_id map_type_id) {
    btf_type_id type = 0;
    btf_type_id max_entries = 0;
    btf_type_id key = 0;
    btf_type_id key_size = 0;
    btf_type_id value = 0;
    btf_type_id value_size = 0;
    btf_type_id values = 0;

    auto map_var = btf_types.get_kind(map_type_id);
    if (map_var.index() != BTF_KIND_VAR) {
        throw std::runtime_error("expected BTF_KIND_VAR type");
    }

    auto map_struct = btf_types.get_kind(std::get<BTF_KIND_VAR>(map_var).type);
    if (map_struct.index() != BTF_KIND_STRUCT) {
        throw std::runtime_error("expected BTF_KIND_STRUCT type");
    }

    for (const auto& member : std::get<BTF_KIND_STRUCT>(map_struct).members) {
        if (member.name == "type") {
            type = member.type;
        } else if (member.name == "max_entries") {
            max_entries = member.type;
        } else if (member.name == "key") {
            key = btf_types.dereference_pointer(member.type);
        } else if (member.name == "value") {
            value = btf_types.dereference_pointer(member.type);
        } else if (member.name == "key_size") {
            key_size = member.type;
        } else if (member.name == "value_size") {
            value_size = member.type;
        } else if (member.name == "values") {
            values = member.type;
        }
    }

    if (type == 0) {
        throw std::runtime_error("invalid map type");
    }

    EbpfMapDescriptor map_descriptor = {0};

    // Required fields.
    map_descriptor.original_fd = static_cast<int>(std::get<BTF_KIND_VAR>(map_var).type);
    map_descriptor.type = value_from_BTF__uint(btf_types, type);
    map_descriptor.max_entries = value_from_BTF__uint(btf_types, max_entries);

    // Optional fields.
    if (key) {
        size_t key_size = btf_types.get_size(key);
        if (key_size > UINT32_MAX) {
            throw std::runtime_error("key size too large");
        }
        map_descriptor.key_size = static_cast<uint32_t>(key_size);
    } else if (key_size) {
        map_descriptor.key_size = value_from_BTF__uint(btf_types, key_size);
    }

    if (value) {
        size_t value_size = btf_types.get_size(value);
        if (value_size > UINT32_MAX) {
            throw std::runtime_error("value size too large");
        }
        map_descriptor.value_size = static_cast<uint32_t>(value_size);
    } else if (value_size) {
        map_descriptor.value_size = value_from_BTF__uint(btf_types, value_size);
    }

    if (values) {
        // Values is an array of pointers to BTF map definitions.
        auto values_array = btf_types.get_kind(values);
        if (values_array.index() != BTF_KIND_ARRAY) {
            throw std::runtime_error("expected array type");
        }
        auto ptr = btf_types.get_kind(std::get<BTF_KIND_ARRAY>(values_array).element_type);
        if (ptr.index() != BTF_KIND_PTR) {
            throw std::runtime_error("expected pointer type");
        }
        // Verify this is a pointer to a BTF map definition.
        auto map_def = btf_types.get_kind(std::get<BTF_KIND_PTR>(ptr).type);
        map_descriptor.inner_map_fd = static_cast<int>(std::get<BTF_KIND_PTR>(ptr).type);
    } else {
        map_descriptor.inner_map_fd = -1;
    }

    return map_descriptor;
}

std::map<std::string, size_t> parse_btf_map_sections(const btf_type_data& btf_data,
                                                     std::vector<EbpfMapDescriptor>& map_descriptors) {
    std::map<std::string, size_t> map_offset_to_descriptor_index;
    auto maps_section_kind = btf_data.get_kind(btf_data.get_id(".maps"));

    // Check that the .maps section is a BTF_KIND_DATASEC.
    if (maps_section_kind.index() != BTF_KIND_DATASEC) {
        throw std::runtime_error("expected .maps section to be a BTF_KIND_DATASEC");
    }

    // For each BTF_KIND_VAR in the maps section, compose the map descriptor from the BTF type.
    auto maps_section = std::get<BTF_KIND_DATASEC>(maps_section_kind);
    size_t index = 0;
    for (const auto& var : maps_section.members) {
        auto map_descriptor = get_map_descriptor_from_btf(btf_data, var.type);
        auto var_kind = btf_data.get_kind(var.type);
        map_descriptors.push_back(map_descriptor);
        map_offset_to_descriptor_index.insert({std::get<BTF_KIND_VAR>(var_kind).name, map_descriptors.size() - 1});
    }
    return map_offset_to_descriptor_index;
}

/**
 * @brief Write a type into a vector and grow it.
 *
 * @tparam T Type to write
 * @param[in] btf The .BTF section
 * @param[in] value The value to write
 */
template <typename T>
void _write_btf(std::vector<std::byte>& btf, const T& value) {
    size_t length = 0;
    size_t offset = btf.size();
    if constexpr (std::is_same<T, std::string>::value) {
        length = value.length();
        btf.resize(offset + length + 1);
        memcpy(btf.data() + offset, value.c_str(), length + 1);
    } else if constexpr (std::is_same<T, std::vector<std::byte>>::value) {
        length = value.size();
        btf.resize(offset + length);
        memcpy(btf.data() + offset, value.data(), length);
    } else {
        length = sizeof(T);
        btf.resize(offset + length);
        memcpy(btf.data() + offset, &value, length);
    }
}

std::vector<std::byte> btf_serialize_types(const std::vector<btf_kind>& btf_kind) {
    std::vector<std::byte> btf;
    std::vector<std::byte> string_table_bytes;
    std::map<std::string, uint32_t> string_table_map;
    std::vector<std::byte> type_table_bytes;

    auto string_to_offset = [&](const std::optional<std::string>& str) -> uint32_t {
        if (!str) {
            return 0;
        }
        auto it = string_table_map.find(*str);
        if (it != string_table_map.end()) {
            return it->second;
        }
        size_t offset = string_table_bytes.size();
        _write_btf(string_table_bytes, *str);
        string_table_map[*str] = static_cast<uint32_t>(offset);
        return static_cast<uint32_t>(offset);
    };

    string_to_offset("");

    auto pack_btf_int_data = [](bool is_signed, bool is_char, bool is_bool, size_t offset, size_t bits) {
        uint32_t value = 0;
        value |= is_signed ? BTF_INT_SIGNED : 0;
        value |= is_char ? BTF_INT_CHAR : 0;
        value |= is_bool ? BTF_INT_BOOL : 0;
        value = value << 24;
        value |= offset & UINT8_MAX << 16;
        value |= bits & UINT8_MAX;
        return value;
    };

    for (const auto& kind : btf_kind) {
        auto pack_btf_info = [&](size_t vlen = 0, bool flag = false) {
            union {
                struct {
                    int vlen : 16;
                    int unused : 8;
                    int kind : 5;
                    int unused2 : 2;
                    int flag : 1;
                };
                uint32_t value;
            } info;
            info.vlen = vlen;
            info.kind = kind.index();
            info.flag = flag;
            return info.value;
        };
        switch (kind.index()) {
        case BTF_KIND_INT: {
            const auto& int_type = std::get<BTF_KIND_INT>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(int_type.name),
                                             .info = pack_btf_info(),
                                             .size = int_type.size_in_bytes,
                                         });
            _write_btf(type_table_bytes,
                       pack_btf_int_data(int_type.is_signed, int_type.is_char, int_type.is_bool,
                                         int_type.offset_from_start_in_bits, int_type.field_width_in_bits));
            break;
        }
        case BTF_KIND_PTR: {
            const auto& ptr_type = std::get<BTF_KIND_PTR>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(),
                                             .type = ptr_type.type,
                                         });
            break;
        }
        case BTF_KIND_ARRAY: {
            const auto& array_type = std::get<BTF_KIND_ARRAY>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(),
                                         });
            _write_btf(type_table_bytes, btf_array_t{
                                             .type = array_type.element_type,
                                             .index_type = array_type.index_type,
                                             .nelems = array_type.count_of_elements,
                                         });
            break;
        }
        case BTF_KIND_STRUCT: {
            const auto& struct_type = std::get<BTF_KIND_STRUCT>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(struct_type.name),
                                             .info = pack_btf_info(struct_type.members.size()),
                                             .size = struct_type.size_in_bytes,
                                         });
            for (const auto& member : struct_type.members) {
                _write_btf(type_table_bytes, btf_member_t{
                                                 .name_off = string_to_offset(member.name),
                                                 .type = member.type,
                                                 .offset = member.offset_from_start_in_bits,
                                             });
            }
            break;
        }
        case BTF_KIND_UNION: {
            const auto& union_type = std::get<BTF_KIND_UNION>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(union_type.name),
                                             .info = pack_btf_info(union_type.members.size()),
                                             .size = union_type.size_in_bytes,
                                         });
            for (const auto& member : union_type.members) {
                _write_btf(type_table_bytes, btf_member_t{
                                                 .name_off = string_to_offset(member.name),
                                                 .type = member.type,
                                                 .offset = member.offset_from_start_in_bits,
                                             });
            }
            break;
        }
        case BTF_KIND_ENUM: {
            const auto& enum_type = std::get<BTF_KIND_ENUM>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(enum_type.name),
                                             .info = pack_btf_info(enum_type.members.size()),
                                             .size = enum_type.size_in_bytes,
                                         });
            for (const auto& member : enum_type.members) {
                _write_btf(type_table_bytes, btf_member_t{
                                                 .name_off = string_to_offset(member.name),
                                                 .offset = member.value,
                                             });
            }
            break;
        }
        case BTF_KIND_FWD: {
            const auto& fwd_type = std::get<BTF_KIND_FWD>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(fwd_type.name),
                                             .info = pack_btf_info(),
                                         });
            break;
        }
        case BTF_KIND_TYPEDEF: {
            const auto& typedef_type = std::get<BTF_KIND_TYPEDEF>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(typedef_type.name),
                                             .info = pack_btf_info(),
                                             .type = typedef_type.type,
                                         });
            break;
        }
        case BTF_KIND_VOLATILE: {
            const auto& volatile_type = std::get<BTF_KIND_VOLATILE>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(),
                                             .type = volatile_type.type,
                                         });
            break;
        }
        case BTF_KIND_CONST: {
            const auto& const_type = std::get<BTF_KIND_CONST>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(),
                                             .type = const_type.type,
                                         });
            break;
        }
        case BTF_KIND_RESTRICT: {
            const auto& restrict_type = std::get<BTF_KIND_RESTRICT>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(),
                                             .type = restrict_type.type,
                                         });
            break;
        }
        case BTF_KIND_FUNC: {
            const auto& func_type = std::get<BTF_KIND_FUNC>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(func_type.name),
                                             .info = pack_btf_info(func_type.linkage),
                                             .type = func_type.type,
                                         });
            break;
        }
        case BTF_KIND_FUNC_PROTO: {
            const auto& func_proto_type = std::get<BTF_KIND_FUNC_PROTO>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(func_proto_type.parameters.size()),
                                             .type = func_proto_type.return_type,
                                         });
            for (const auto& parameter : func_proto_type.parameters) {
                _write_btf(type_table_bytes, btf_param_t{
                                                 .name_off = string_to_offset(parameter.name),
                                                 .type = parameter.type,
                                             });
            }
            break;
        }
        case BTF_KIND_VAR: {
            const auto& var_type = std::get<BTF_KIND_VAR>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(var_type.name),
                                             .info = pack_btf_info(),
                                             .type = var_type.type,
                                         });
            _write_btf(type_table_bytes, static_cast<uint32_t>(var_type.linkage));
            break;
        }
        case BTF_KIND_DATASEC: {
            const auto& datasec_type = std::get<BTF_KIND_DATASEC>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(datasec_type.name),
                                             .info = pack_btf_info(datasec_type.members.size()),
                                         });
            for (const auto& member : datasec_type.members) {
                _write_btf(type_table_bytes, btf_var_secinfo_t{
                                                 .type = member.type,
                                                 .offset = member.offset,
                                                 .size = member.size,
                                             });
            }

            break;
        }
        case BTF_KIND_FLOAT: {
            const auto& float_type = std::get<BTF_KIND_FLOAT>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .info = pack_btf_info(),
                                             .size = float_type.size_in_bytes,
                                         });
            break;
        }
        case BTF_KIND_DECL_TAG: {
            const auto& decl_tag_type = std::get<BTF_KIND_DECL_TAG>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(decl_tag_type.name),
                                             .info = pack_btf_info(),
                                             .type = decl_tag_type.type,
                                         });
            break;
        }
        case BTF_KIND_TYPE_TAG: {
            const auto& type_tag_type = std::get<BTF_KIND_TYPE_TAG>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(type_tag_type.name),
                                             .info = pack_btf_info(),
                                             .type = type_tag_type.type,
                                         });
            break;
        }
        case BTF_KIND_ENUM64: {
            const auto& enum64_type = std::get<BTF_KIND_ENUM64>(kind);
            _write_btf(type_table_bytes, btf_type_t{
                                             .name_off = string_to_offset(enum64_type.name),
                                             .info = pack_btf_info(enum64_type.members.size()),
                                             .size = enum64_type.size_in_bytes,
                                         });
            for (const auto& member : enum64_type.members) {
                btf_enum64_t enum_member = {0};
                enum_member.name_off = string_to_offset(member.name);
                enum_member.val_lo32 = member.value & 0xFFFFFFFF;
                enum_member.val_hi32 = member.value >> 32;
                _write_btf(type_table_bytes, enum_member);
            }
            break;
        }
        }
    }

    // Write the BTF header.
    _write_btf(btf, btf_header_t{
                        .magic = BTF_HEADER_MAGIC,
                        .version = BTF_HEADER_VERSION,
                        .flags = 0,
                        .hdr_len = sizeof(btf_header_t),
                        .type_off = 0,
                        .type_len = static_cast<unsigned int>(type_table_bytes.size()),
                        .str_off = static_cast<unsigned int>(type_table_bytes.size()),
                        .str_len = static_cast<unsigned int>(string_table_bytes.size()),
                    });

    // Write the type table.
    _write_btf(btf, type_table_bytes);

    // Write the string table.
    _write_btf(btf, string_table_bytes);

    return btf;
}

std::vector<std::byte> btf_type_data::to_bytes() const
{
    std::vector<btf_kind> kinds;
    for (const auto& [id, kind] : id_to_kind) {
        kinds.push_back(kind);
    }
    return btf_serialize_types(kinds);
}

void btf_type_data::append(const btf_kind& kind)
{
    btf_type_id next_id = id_to_kind.size();
    id_to_kind.insert({next_id, kind});
    switch (kind.index()) {
    case BTF_KIND_INT:
        name_to_id.insert({std::get<BTF_KIND_INT>(kind).name, next_id});
        break;
    case BTF_KIND_PTR:
        break;
    case BTF_KIND_ARRAY:
        break;
    case BTF_KIND_STRUCT:
        if (std::get<BTF_KIND_STRUCT>(kind).name.has_value()) {
            name_to_id.insert({std::get<BTF_KIND_STRUCT>(kind).name.value(), next_id});
        }
        break;
    case BTF_KIND_UNION:
        if (std::get<BTF_KIND_UNION>(kind).name.has_value()) {
            name_to_id.insert({std::get<BTF_KIND_UNION>(kind).name.value(), next_id});
        }
        break;
    case BTF_KIND_ENUM:
        if (std::get<BTF_KIND_ENUM>(kind).name.has_value()) {
            name_to_id.insert({std::get<BTF_KIND_ENUM>(kind).name.value(), next_id});
        }
        break;
    case BTF_KIND_FWD:
        name_to_id.insert({std::get<BTF_KIND_FWD>(kind).name, next_id});
        break;
    case BTF_KIND_TYPEDEF:
        name_to_id.insert({std::get<BTF_KIND_TYPEDEF>(kind).name, next_id});
        break;
    case BTF_KIND_VOLATILE:
        break;
    case BTF_KIND_CONST:
        break;
    case BTF_KIND_RESTRICT:
        break;
    case BTF_KIND_FUNC:
        name_to_id.insert({std::get<BTF_KIND_FUNC>(kind).name, next_id});
        break;
    case BTF_KIND_FUNC_PROTO:
        break;
    case BTF_KIND_VAR:
        name_to_id.insert({std::get<BTF_KIND_VAR>(kind).name, next_id});
        break;
    case BTF_KIND_DATASEC:
        name_to_id.insert({std::get<BTF_KIND_DATASEC>(kind).name, next_id});
        break;
    case BTF_KIND_FLOAT:
        name_to_id.insert({std::get<BTF_KIND_FLOAT>(kind).name, next_id});
        break;
    case BTF_KIND_DECL_TAG:
        name_to_id.insert({std::get<BTF_KIND_DECL_TAG>(kind).name, next_id});
        break;
    case BTF_KIND_TYPE_TAG:
        name_to_id.insert({std::get<BTF_KIND_TYPE_TAG>(kind).name, next_id});
        break;
    case BTF_KIND_ENUM64:
        if (std::get<BTF_KIND_ENUM64>(kind).name.has_value()) {
            name_to_id.insert({std::get<BTF_KIND_ENUM64>(kind).name.value(), next_id});
        }
        break;
    default:
        throw std::runtime_error("unknown BTF_KIND");
    }
}
