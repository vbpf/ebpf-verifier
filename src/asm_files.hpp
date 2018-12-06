#pragma once

#include <fstream>
#include <tuple>
#include <string>

std::tuple<std::ifstream, size_t> open_binary_file(std::string path);

void write_binary_file(std::string path, const char* data, size_t size);

std::ifstream open_asm_file(std::string path);
