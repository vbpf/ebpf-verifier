// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <concepts>
#include <fstream>
#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "platform.hpp"

template <typename T>
std::vector<T> vector_of(const std::byte* data, std::integral auto size) {
    if (size % sizeof(T) != 0 || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {reinterpret_cast<const T*>(data), reinterpret_cast<const T*>(data + size)};
}

template <typename T>
std::vector<T> vector_of(const char* data, std::integral auto size) {
    if (size % sizeof(T) != 0 || size > UINT32_MAX || !data) {
        throw std::runtime_error("Invalid argument to vector_of");
    }
    return {reinterpret_cast<const T*>(data), reinterpret_cast<const T*>(data + size)};
}

template <typename T>
std::vector<T> vector_of(const std::vector<std::byte>& sec) {
    const auto data = sec.data();
    const auto size = sec.size();
    return vector_of<T>(data, size);
}

template <typename T>
std::vector<T> vector_of(const auto& sec) {
    const auto data = sec.get_data();
    const auto size = sec.get_size();
    return vector_of<T>(data, size);
}

std::vector<raw_program> read_raw(std::string path, program_info info);
std::vector<raw_program> read_elf(const std::string& path, const std::string& section,
                                  const ebpf_verifier_options_t* options, const ebpf_platform_t* platform);
std::vector<raw_program> read_elf(std::istream& input_stream, const std::string& path, const std::string& section,
                                  const ebpf_verifier_options_t* options, const ebpf_platform_t* platform);

void write_binary_file(std::string path, const char* data, size_t size);

std::ifstream open_asm_file(std::string path);
