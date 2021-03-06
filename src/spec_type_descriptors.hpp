// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>
#include "ebpf_base.h"
#include "ebpf_vm_isa.hpp"

constexpr int EBPF_STACK_SIZE = 512;

struct EbpfMapType {
    uint32_t platform_specific_type; // EbpfMapDescriptor.type value.
    std::string name; // For ease of display, not used by the verifier.
    bool is_array; // True if key is integer in range [0,max_entries-1].
    bool is_value_map_fd; // True if value is map_fd.
};

struct EbpfMapDescriptor {
    int original_fd;
    uint32_t type; // Platform-specific type value in ELF file.
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int inner_map_fd;
};

struct EbpfProgramType {
    std::string name; // For ease of display, not used by the verifier.
    const ebpf_context_descriptor_t* context_descriptor;
    uint64_t platform_specific_data; // E.g., integer program type.
    std::vector<std::string> section_prefixes;
    bool is_privileged;
};

struct program_info {
    const struct ebpf_platform_t* platform;
    std::vector<EbpfMapDescriptor> map_descriptors;
    EbpfProgramType type;
};

struct raw_program {
    std::string filename;
    std::string section;
    std::vector<ebpf_inst> prog;
    program_info info;
};

extern thread_local program_info global_program_info;
