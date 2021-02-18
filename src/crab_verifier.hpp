// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"

bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, program_info info, const ebpf_verifier_options_t* options);

bool ebpf_verify_program(std::ostream& s, const InstructionSeq& prog, program_info info, const ebpf_verifier_options_t* options);

int create_map_crab(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);
