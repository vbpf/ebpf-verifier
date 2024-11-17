// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab/fwd_analyzer.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

class Report final {
    std::map<label_t, std::vector<std::string>> warnings;
    std::map<label_t, std::vector<std::string>> reachability;
    friend class Invariants;

  public:
    void print_reachability(std::ostream& os) const;
    void print_warnings(std::ostream& os) const;
    void print_all_messages(std::ostream& os) const;
    std::set<std::string> all_messages() const;
    std::set<std::string> reachability_set() const;
    std::set<std::string> warning_set() const;
    bool verified() const;
};

class Invariants final {
    crab::invariant_table_t invariants;

  public:
    explicit Invariants(crab::invariant_table_t&& invariants) : invariants(std::move(invariants)) {}
    explicit Invariants(Invariants&& invariants) = default;
    explicit Invariants(const Invariants& invariants) = default;

    bool is_valid_after(const label_t& label, const string_invariant& state) const;
    void print_invariants(std::ostream& os, const cfg_t& cfg) const;

    string_invariant invariant_at(const label_t& label) const;

    crab::interval_t exit_value() const;

    int max_loop_count() const;
    bool verified(const cfg_t& cfg) const;
    Report check_assertions(const cfg_t& cfg) const;
};

Invariants analyze(const cfg_t& cfg);
Invariants analyze(const cfg_t& cfg, const string_invariant& entry_invariant);
inline bool verify(const cfg_t& cfg) { return analyze(cfg).verified(cfg); }

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();
