// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "config.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"
#include "string_constraints.hpp"

class Invariants_Abs;
class Report_Abs;

std::unique_ptr<Invariants_Abs> analyze(const cfg_t& cfg);
std::unique_ptr<Invariants_Abs> analyze(const cfg_t& cfg, const string_invariant& entry_invariant);

class Invariants_Abs {
  public:
    virtual string_invariant invariant_at(const label_t& label) const = 0;
    virtual bool is_valid_after(const label_t& label, const string_invariant& entry_invariant) const = 0;
    virtual void print_invariants(std::ostream& os, const cfg_t& cfg) const = 0;
    virtual crab::interval_t exit_value() const = 0;
    virtual int max_loop_count() const = 0;

    virtual bool verified(const cfg_t& cfg) const = 0;
    virtual std::unique_ptr<Report_Abs> check_assertions(const cfg_t& cfg) const = 0;

    virtual ~Invariants_Abs() noexcept {}
};

class Report_Abs {
  public:
    virtual void print_reachability(std::ostream& os) const = 0;
    virtual void print_warnings(std::ostream& os) const = 0;
    virtual void print_all_messages(std::ostream& os) const = 0;

    virtual std::set<std::string> all_messages() const = 0;
    virtual std::set<std::string> reachability_set() const = 0;
    virtual std::set<std::string> warning_set() const = 0;

    virtual bool verified() const = 0;

    virtual ~Report_Abs() noexcept {}
};

int create_map_crab(const EbpfMapType& map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries,
                    ebpf_verifier_options_t options);

EbpfMapDescriptor* find_map_descriptor(int map_fd);

void ebpf_verifier_clear_thread_local_state();
