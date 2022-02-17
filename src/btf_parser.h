// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <functional>
#include <stdint.h>
#include <string>
#include <vector>

typedef std::function<void(const std::string& section, uint32_t instruction_offset, const std::string& file_name,
                           const std::string& source, uint32_t line_number, uint32_t column_number)>
    btf_line_info_visitor;
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
