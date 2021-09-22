// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

// Toy database to store invariants.
struct checks_db final {
    std::map<label_t, std::vector<std::string>> m_db;
    int total_warnings{};
    int total_unreachable{};
    int max_instruction_count{};
    std::set<label_t> maybe_nonterminating;

    void add(const label_t& label, const std::string& msg) {
        m_db[label].emplace_back(msg);
    }

    void add_warning(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_warnings++;
    }

    void add_unreachable(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_unreachable++;
    }

    void add_nontermination(const label_t& label) {
        maybe_nonterminating.insert(label);
        total_warnings++;
    }

    checks_db() = default;
};

bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, const program_info& info, const ebpf_verifier_options_t* options,
    ebpf_verifier_stats_t* stats);

bool ebpf_verify_program(std::ostream& s, const InstructionSeq& prog, const program_info& info, const ebpf_verifier_options_t* options,
    ebpf_verifier_stats_t* stats);

using string_invariant_map = std::map<crab::label_t, string_invariant>;

std::tuple<checks_db, string_invariant_map, string_invariant_map>
ebpf_analyze_program_for_test(const InstructionSeq& prog, const string_invariant& entry_invariant,
                              const program_info& info,
                              bool no_simplify, bool check_termination);

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);
