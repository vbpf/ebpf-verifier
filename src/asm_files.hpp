#pragma once

#include <fstream>
#include <tuple>
#include <string>

#include "asm_syntax.hpp"
#include "spec_type_descriptors.hpp"

std::vector<raw_program> read_raw(std::string path, program_info info);
std::vector<raw_program> read_elf(std::string path);

void write_binary_file(std::string path, const char* data, size_t size);

std::ifstream open_asm_file(std::string path);
