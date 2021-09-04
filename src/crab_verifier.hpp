// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"

bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, const program_info& info, const ebpf_verifier_options_t* options,
    ebpf_verifier_stats_t* stats);

bool ebpf_verify_program(std::ostream& s, const InstructionSeq& prog, const program_info& info, const ebpf_verifier_options_t* options,
    ebpf_verifier_stats_t* stats);

using string_invariants = std::map<crab::label_t, std::optional<std::set<std::string>>>;

std::tuple<ebpf_verifier_stats_t, string_invariants, string_invariants>
ebpf_analyze_program_for_test(const InstructionSeq& prog, const program_info& info,
                              bool no_simplify, bool check_termination);

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);
