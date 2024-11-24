// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/

#include <iostream>
#include <map>
#include <ranges>
#include <string>
#include <vector>

#include "asm_files.hpp"
#include "asm_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_verifier.hpp"
#include "string_constraints.hpp"

using crab::ebpf_domain_t;
using std::string;

thread_local crab::lazy_allocator<program_info> thread_local_program_info;
thread_local ebpf_verifier_options_t thread_local_options;
void ebpf_verifier_clear_before_analysis();

struct LineInfoPrinter {
    std::ostream& os;
    std::string previous_source_line;

    void print_line_info(const label_t& label) {
        if (thread_local_options.verbosity_opts.print_line_info) {
            const auto& line_info_map = thread_local_program_info.get().line_info;
            const auto& line_info = line_info_map.find(label.from);
            // Print line info only once.
            if (line_info != line_info_map.end() && line_info->second.source_line != previous_source_line) {
                os << "\n" << line_info->second << "\n";
                previous_source_line = line_info->second.source_line;
            }
        }
    }
};

bool Invariants::is_valid_after(const label_t& label, const string_invariant& state) const {
    const ebpf_domain_t abstract_state =
        ebpf_domain_t::from_constraints(state.value(), thread_local_options.setup_constraints);
    return abstract_state <= invariants.at(label).post;
}

void Invariants::print_invariants(std::ostream& os, const cfg_t& cfg, const bool simplify) const {
    LineInfoPrinter printer{os};
    for (const auto& bb : basic_block_t::collect_basic_blocks(cfg, simplify)) {
        os << "\nPre-invariant : " << invariants.at(bb.first_label()).pre << "\n";
        const crab::value_t& first_node = cfg.get_node(bb.first_label());
        print_from(os, first_node);
        print_label(os, first_node);
        for (const label_t& label : bb) {
            printer.print_line_info(label);
            const crab::value_t& node = cfg.get_node(label);
            print_assertions(os, node);
            print_instruction(os, node);
        }
        print_goto(os, cfg.get_node(bb.last_label()));
        os << "\nPost-invariant: " << invariants.at(bb.last_label()).post << "\n";
    }
    os << "\n";
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

void Report::print_reachability(std::ostream& os) const {
    for (const auto& [label, notes] : reachability) {
        for (const auto& msg : notes) {
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
}

void Report::print_warnings(std::ostream& os) const {
    LineInfoPrinter printer{os};
    for (const auto& [label, warnings] : warnings) {
        for (const auto& msg : warnings) {
            printer.print_line_info(label);
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
}

void Report::print_all_messages(std::ostream& os) const {
    print_reachability(os);
    print_warnings(os);
}

std::set<std::string> Report::all_messages() const {
    std::set<std::string> result = warning_set();
    for (const auto& note : reachability_set()) {
        result.insert(note);
    }
    return result;
}

std::set<std::string> Report::reachability_set() const {
    std::set<std::string> result;
    for (const auto& [label, warnings] : reachability) {
        for (const auto& msg : warnings) {
            result.insert(to_string(label) + ": " + msg);
        }
    }
    return result;
}

std::set<std::string> Report::warning_set() const {
    std::set<std::string> result;
    for (const auto& [label, warnings] : warnings) {
        for (const auto& msg : warnings) {
            result.insert(to_string(label) + ": " + msg);
        }
    }
    return result;
}

bool Report::verified() const { return warnings.empty(); }

bool Invariants::verified(const cfg_t& cfg) const {
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        for (const Assertion& assertion : cfg.at(label).preconditions) {
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
        const auto ins = cfg.at(label);
        for (const Assertion& assertion : ins.preconditions) {
            const auto warnings = ebpf_domain_check(inv_pair.pre, assertion);
            for (const auto& msg : warnings) {
                report.warnings[label].emplace_back(msg);
            }
        }
        if (std::holds_alternative<Assume>(ins.cmd)) {
            if (inv_pair.post.is_bottom()) {
                const auto s = to_string(std::get<Assume>(ins.cmd));
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
