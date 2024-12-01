// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/

#include <map>
#include <ranges>
#include <string>

#include "asm_files.hpp"
#include "asm_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_verifier.hpp"
#include "string_constraints.hpp"

using crab::cfg_t;
using crab::ebpf_domain_t;
using std::string;

thread_local crab::lazy_allocator<program_info> thread_local_program_info;
thread_local ebpf_verifier_options_t thread_local_options;
void ebpf_verifier_clear_before_analysis();

bool Invariants::is_valid_after(const label_t& label, const string_invariant& state) const {
    const ebpf_domain_t abstract_state =
        ebpf_domain_t::from_constraints(state.value(), thread_local_options.setup_constraints);
    return abstract_state <= invariants.at(label).post;
}

string_invariant Invariants::invariant_at(const label_t& label) const { return invariants.at(label).post.to_set(); }

crab::interval_t Invariants::exit_value() const { return invariants.at(label_t::exit).post.get_r0(); }

int Invariants::max_loop_count() const {
    crab::extended_number max_loop_count{0};
    // Gather the upper bound of loop counts from post-invariants.
    for (const auto& inv_pair : std::views::values(invariants)) {
        max_loop_count = std::max(max_loop_count, inv_pair.post.get_loop_count_upper_bound());
    }
    const auto m = max_loop_count.number();
    if (m && m->fits<int32_t>()) {
        return m->cast_to<int32_t>();
    }
    return std::numeric_limits<int>::max();
}

Invariants analyze(const cfg_t& cfg, ebpf_domain_t&& entry_invariant) {
    return Invariants{run_forward_analyzer(cfg, std::move(entry_invariant))};
}

Invariants analyze(const cfg_t& cfg) {
    ebpf_verifier_clear_before_analysis();
    return analyze(cfg, ebpf_domain_t::setup_entry(thread_local_options.setup_constraints));
}

Invariants analyze(const cfg_t& cfg, const string_invariant& entry_invariant) {
    ebpf_verifier_clear_before_analysis();
    return analyze(cfg,
                   ebpf_domain_t::from_constraints(entry_invariant.value(), thread_local_options.setup_constraints));
}

bool Invariants::verified(const cfg_t& cfg) const {
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        for (const Assertion& assertion : cfg.assertions_at(label)) {
            if (!ebpf_domain_check(inv_pair.pre, assertion).empty()) {
                return false;
            }
        }
    }
    return true;
}

Report Invariants::check_assertions(const cfg_t& cfg) const {
    Report report;
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        for (const Assertion& assertion : cfg.assertions_at(label)) {
            const auto warnings = ebpf_domain_check(inv_pair.pre, assertion);
            for (const auto& msg : warnings) {
                report.warnings[label].emplace_back(msg);
            }
        }
        if (const auto passume = std::get_if<Assume>(&cfg.instruction_at(label))) {
            if (inv_pair.post.is_bottom()) {
                const auto s = to_string(*passume);
                report.reachability[label].emplace_back("Code becomes unreachable (" + s + ")");
            }
        }
    }
    return report;
}

void ebpf_verifier_clear_before_analysis() {
    crab::domains::clear_thread_local_state();
    crab::variable_t::clear_thread_local_state();
}

void ebpf_verifier_clear_thread_local_state() {
    crab::CrabStats::clear_thread_local_state();
    thread_local_program_info.clear();
    crab::domains::clear_thread_local_state();
    crab::domains::SplitDBM::clear_thread_local_state();
}
