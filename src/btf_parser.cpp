// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <map>
#include <stdexcept>
#include <string.h>

#include "btf.h"
#include "btf_parser.h"

void btf_parse_line_information(const std::vector<uint8_t>& btf, const std::vector<uint8_t>& btf_ext,
                                btf_line_info_visitor visitor) {
    std::map<size_t, std::string> string_table;

    auto btf_header = reinterpret_cast<const btf_header_t*>(btf.data());
    if (btf_header->magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .BTF section - wrong magic");
    }
    if (btf_header->version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .BTF section - wrong version");
    }
    if (btf_header->hdr_len < sizeof(btf_header_t)) {
        throw std::runtime_error("Invalid .BTF section - wrong size");
    }
    if (btf_header->hdr_len > btf.size()) {
        throw std::runtime_error("Invalid .BTF section - invalid header length");
    }
    if (btf_header->str_off > btf.size()) {
        throw std::runtime_error("Invalid .BTF section - invalid string offest");
    }
    if ((static_cast<size_t>(btf_header->str_off) + static_cast<size_t>(btf_header->str_len) +
         static_cast<size_t>(btf_header->hdr_len)) > btf.size()) {
        throw std::runtime_error("Invalid .BTF section - invalid string length");
    }

    for (size_t offset = btf_header->str_off + static_cast<size_t>(btf_header->hdr_len);
         offset < static_cast<size_t>(btf_header->str_off) + static_cast<size_t>(btf_header->str_len);) {
        std::string value(reinterpret_cast<const char*>(btf.data()) + offset);
        size_t string_offset =
            offset - static_cast<size_t>(btf_header->str_off) - static_cast<size_t>(btf_header->hdr_len);
        offset += value.size() + 1;
        string_table.insert(std::make_pair(string_offset, value));
    }
    auto bpf_ext_header = reinterpret_cast<const btf_ext_header_t*>(btf_ext.data());
    if (bpf_ext_header->magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .BTF.ext section - wrong magic");
    }
    if (bpf_ext_header->version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .BTF.ext section - wrong version");
    }
    if (bpf_ext_header->hdr_len < sizeof(btf_ext_header_t)) {
        throw std::runtime_error("Invalid .BTF.ext section - wrong size");
    }
    if (bpf_ext_header->line_info_off > btf_ext.size()) {
        throw std::runtime_error("Invalid .BTF.ext section - invalid line info offset");
    }
    if ((static_cast<size_t>(bpf_ext_header->line_info_off) + static_cast<size_t>(bpf_ext_header->line_info_len) +
         static_cast<size_t>(bpf_ext_header->hdr_len)) > btf_ext.size()) {
        throw std::runtime_error("Invalid .BTF section - invalid string length");
    }

    uint32_t line_info_record_size =
        *reinterpret_cast<const uint32_t*>(btf_ext.data() + static_cast<size_t>(bpf_ext_header->hdr_len) +
                                           static_cast<size_t>(bpf_ext_header->line_info_off));

    for (size_t offset = static_cast<size_t>(bpf_ext_header->hdr_len) +
                         static_cast<size_t>(bpf_ext_header->line_info_off) + sizeof(uint32_t);
         offset < static_cast<size_t>(bpf_ext_header->hdr_len) + static_cast<size_t>(bpf_ext_header->line_info_off) +
                      static_cast<size_t>(bpf_ext_header->line_info_len);) {
        auto section_info = reinterpret_cast<const btf_ext_info_sec_t*>(btf_ext.data() + offset);
        auto section_name = string_table.find(section_info->sec_name_off);
        if (section_name == string_table.end()) {
            throw std::runtime_error(std::string("Invalid .BTF section - invalid string offset ") +
                                     std::to_string(section_info->sec_name_off));
        }
        for (size_t index = 0; index < section_info->num_info; index++) {
            auto btf_line_info =
                reinterpret_cast<const bpf_line_info_t*>(section_info->data + index * line_info_record_size);
            auto file_name = string_table.find(btf_line_info->file_name_off);
            auto source = string_table.find(btf_line_info->line_off);
            std::string file_name_string;
            std::string source_line_string;
            if (file_name != string_table.end()) {
                file_name_string = file_name->second;
            }
            if (source != string_table.end()) {
                source_line_string = source->second;
            }
            visitor(section_name->second, btf_line_info->insn_off, file_name_string, source_line_string,
                    BPF_LINE_INFO_LINE_NUM(btf_line_info->line_col), BPF_LINE_INFO_LINE_COL(btf_line_info->line_col));
        }
        offset += offsetof(btf_ext_info_sec_t, data) +
                  static_cast<size_t>(line_info_record_size) * static_cast<size_t>(section_info->num_info);
    }
}
