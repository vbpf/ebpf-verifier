// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

using string_invariant_map = std::map<label_t, string_invariant>;

struct analyze_params_t {
    std::ostream* os{&std::cout};
    const InstructionSeq* prog{};
    // if exists, it will be moved from
    std::unique_ptr<cfg_t> cfg{};
    // invariants will be added to labels that appear as keys in out_invariants
    const string_invariant* entry_invariant{};
    string_invariant_map* out_invariants{};
    const program_info* info{};
    ebpf_verifier_options_t* options{};
};

ebpf_verifier_stats_t analyze_and_report(const analyze_params_t& params = {});

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();
