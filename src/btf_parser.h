// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include "spec_type_descriptors.hpp"

#include <functional>
#include <iostream>
#include <optional>
#include <stdint.h>
#include <string>
#include <variant>
#include <vector>

using btf_line_info_visitor =
    std::function<void(const std::string& section, uint32_t instruction_offset, const std::string& file_name,
                       const std::string& source, uint32_t line_number, uint32_t column_number)>;

typedef uint32_t btf_type_id;

struct btf_kind_int {
    std::string name;
    uint32_t
        size_in_bytes; // The size of the integer in bytes. This value multiplied by 8 must be >= field_width_in_bits
    uint16_t offset_from_start_in_bits; // The start of the integer relative to the start of the member.
    uint8_t field_width_in_bits;        // The size of the integer in bits.
    bool is_signed;
    bool is_char;
    bool is_bool;
};

struct btf_kind_ptr {
    btf_type_id type;
};

struct btf_kind_array {
    btf_type_id element_type;
    btf_type_id index_type;
    uint32_t count_of_elements;
};

struct btf_kind_struct_member {
    std::optional<std::string> name;
    btf_type_id type;
    uint32_t offset_from_start_in_bits;
};

using btf_kind_union_member = btf_kind_struct_member;

struct btf_kind_struct {
    std::optional<std::string> name;
    std::vector<btf_kind_struct_member> members;
    uint32_t size_in_bytes;
};

struct btf_kind_union {
    std::optional<std::string> name;
    std::vector<btf_kind_union_member> members;
    uint32_t size_in_bytes;
};

struct btf_kind_enum_member {
    std::string name;
    uint32_t value;
};

struct btf_kind_enum {
    std::optional<std::string> name;
    bool is_signed;
    std::vector<btf_kind_enum_member> members;
    uint32_t size_in_bytes;
};

struct btf_kind_fwd {
    std::string name;
    bool is_struct;
};

struct btf_kind_typedef {
    std::string name;
    btf_type_id type;
};

struct btf_kind_volatile {
    btf_type_id type;
};

struct btf_kind_const {
    btf_type_id type;
};

struct btf_kind_restrict {
    btf_type_id type;
};

struct btf_kind_function {
    std::string name;
    enum {
        BTF_LINKAGE_GLOBAL,
        BTF_LINKAGE_STATIC,
        BTF_LINKAGE_EXTERN,
    } linkage;
    btf_type_id type;
};

struct btf_kind_function_parameter {
    std::string name;
    btf_type_id type;
};

struct btf_kind_function_prototype {
    std::vector<btf_kind_function_parameter> parameters;
    btf_type_id return_type;
};

struct btf_kind_var {
    std::string name;
    btf_type_id type;
    enum {
        BTF_LINKAGE_GLOBAL,
        BTF_LINKAGE_STATIC,
    } linkage;
};

struct btf_kind_data_member {
    btf_type_id type;
    uint32_t offset;
    uint32_t size;
};

struct btf_kind_data_section {
    std::string name;
    std::vector<btf_kind_data_member> members;
    uint32_t size;
};

struct btf_kind_float {
    std::string name;
    uint32_t size_in_bytes;
};

struct btf_kind_decl_tag {
    std::string name;
    btf_type_id type;
    uint32_t component_index;
};

struct btf_kind_type_tag {
    std::string name;
    btf_type_id type;
};

struct btf_kind_enum64_member {
    std::string name;
    uint64_t value;
};

struct btf_kind_enum64 {
    std::optional<std::string> name;
    bool is_signed;
    std::vector<btf_kind_enum64_member> members;
    uint32_t size_in_bytes;
};

struct btf_kind_null {};

// Note: The order of the variant types must match the #define in btf.h.
using btf_kind =
    std::variant<btf_kind_null, btf_kind_int, btf_kind_ptr, btf_kind_array, btf_kind_struct, btf_kind_union,
                 btf_kind_enum, btf_kind_fwd, btf_kind_typedef, btf_kind_volatile, btf_kind_const, btf_kind_restrict,
                 btf_kind_function, btf_kind_function_prototype, btf_kind_var, btf_kind_data_section, btf_kind_float,
                 btf_kind_decl_tag, btf_kind_type_tag, btf_kind_enum64>;

using btf_type_visitor = std::function<void(btf_type_id, const std::optional<std::string>&, const btf_kind&)>;

/**
 * @brief Parse a .BTF and .BTF.ext section from an ELF file invoke vistor for
 * each btf_line_info record.
 *
 * @param[in] btf The .BTF section (containing type info and strings).
 * @param[in] btf_ext The .BTF.ext section (containing function info and
 * line info).
 * @param[in] visitor Function to invoke on each btf_line_info record.
 */
void btf_parse_line_information(const std::vector<uint8_t>& btf, const std::vector<uint8_t>& btf_ext,
                                btf_line_info_visitor visitor);

/**
 * @brief Parse a .BTF section from an ELF file and invoke visitor for each
 * btf_type record.
 *
 * @param[in] btf The .BTF section (containing type info and strings).
 * @param[in] visitor Function to invoke on each btf_type record.
 */
void btf_parse_types(const std::vector<uint8_t>& btf, btf_type_visitor visitor);

/**
 * @brief Given a map of btf_type_id to btf_kind, print the types as JSON to
 * the given output stream. The JSON is not pretty printed. This is useful for
 * debugging and testing.
 *
 * @param[in] id_to_kind A map of btf_type_id to btf_kind.
 * @param[in,out] out The output stream to write the JSON to.
 */
void btf_type_to_json(const std::map<btf_type_id, btf_kind>& id_to_kind, std::ostream& out);

/**
 * @brief Helper function to insert line breaks and indentation into a JSON
 * string to make it more human readable.
 *
 * @param[in] input JSON string to pretty print.
 * @return The pretty printed JSON string.
 */
std::string pretty_print_json(const std::string& input);

class btf_type_data {
  public:
    btf_type_data(const std::vector<uint8_t>& btf_data);
    ~btf_type_data() = default;
    btf_type_id get_id(const std::string& name) const;
    btf_kind get_kind(btf_type_id id) const;
    btf_type_id dereference_pointer(btf_type_id id) const;
    size_t get_size(btf_type_id id) const;
    void to_json(std::ostream& out) const;

  private:
    void validate_type_graph(btf_type_id id, std::set<btf_type_id>& visited) const;
    std::map<btf_type_id, btf_kind> id_to_kind;
    std::map<std::string, btf_type_id> name_to_id;
};

/**
 * @brief Parse the .BTF section of the ELF file and return a map from map offset to map descriptor.
 *
 * @param[in] options The verifier options.
 * @param[in] platform The platform abstraction layer.
 * @param[in] reader ELFIO reader.
 * @return Map from map name to map descriptor index.
 */
std::map<std::string, size_t> parse_btf_map_sections(const btf_type_data& btf_data,
                                                     std::vector<EbpfMapDescriptor>& map_descriptors);
