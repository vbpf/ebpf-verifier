// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <iostream>
#include "platform.hpp"

#if __linux__

#include <tuple>
#include <vector>

#include "asm_syntax.hpp"
#include "spec_type_descriptors.hpp"
#include "linux/gpl/spec_type_descriptors.hpp"
#include "ebpf_vm_isa.hpp"

int create_map_linux(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);
std::tuple<bool, double> bpf_verify_program(const EbpfProgramType& type, const std::vector<ebpf_inst>& raw_prog, ebpf_verifier_options_t* options);

#else

#define create_map_linux (nullptr)

inline std::tuple<bool, double> bpf_verify_program(EbpfProgramType type, const std::vector<ebpf_inst>& raw_prog, ebpf_verifier_options_t* options) {
    std::cerr << "linux domain is unsupported on this machine\n";
    exit(64);
    return {{}, {}};
}
#endif
