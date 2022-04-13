// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <fstream>
#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "platform.hpp"

std::vector<raw_program> read_raw(std::string path, program_info info);
std::vector<raw_program> read_elf(const std::string& path, const std::string& section, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform);
std::vector<raw_program> read_elf(std::istream& input_stream, const std::string& path, const std::string& section, const ebpf_verifier_options_t* options, const ebpf_platform_t* platform);

void write_binary_file(std::string path, const char* data, size_t size);

std::ifstream open_asm_file(std::string path);
