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

struct Invariants final : Invariants_Abs {
    const crab::invariant_table_t invariants;

    explicit Invariants(crab::invariant_table_t&& invariants) : invariants(std::move(invariants)) {}

    Invariants(Invariants&&) = default;

    bool is_valid_after(const label_t& label, const string_invariant& state) const override {
        const ebpf_domain_t abstract_state =
            ebpf_domain_t::from_constraints(state.value(), thread_local_options.setup_constraints);
        return abstract_state <= invariants.at(label).post;
    }

    void print_invariants(std::ostream& os, const cfg_t& cfg) const override {
        LineInfoPrinter printer{os};
        for (const label_t& label : cfg.sorted_labels()) {
            printer.print_line_info(label);
            const auto& inv_pair = invariants.at(label);
            os << "\nPre-invariant : " << inv_pair.pre << "\n";
            os << cfg.get_node(label);
            os << "\nPost-invariant: " << inv_pair.post << "\n";
        }
        os << "\n";
    }

    string_invariant invariant_at(const label_t& label) const override { return invariants.at(label).post.to_set(); }

    crab::interval_t exit_value() const override { return invariants.at(label_t::exit).post.get_r0(); }

    int max_loop_count() const override {
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

    bool verified(const cfg_t& cfg) const override;
    std::unique_ptr<Report_Abs> check_assertions(const cfg_t& cfg) const override;

    ~Invariants() noexcept override = default;
};

std::unique_ptr<Invariants_Abs> analyze(const cfg_t& cfg, ebpf_domain_t&& entry_invariant) {
    return std::make_unique<Invariants>(run_forward_analyzer(cfg, std::move(entry_invariant)));
}

std::unique_ptr<Invariants_Abs> analyze(const cfg_t& cfg) {
    ebpf_verifier_clear_before_analysis();
    return analyze(cfg, ebpf_domain_t::setup_entry(thread_local_options.setup_constraints));
}

std::unique_ptr<Invariants_Abs> analyze(const cfg_t& cfg, const string_invariant& entry_invariant) {
    ebpf_verifier_clear_before_analysis();
    return analyze(cfg,
                   ebpf_domain_t::from_constraints(entry_invariant.value(), thread_local_options.setup_constraints));
}

struct Report final : Report_Abs {
    std::map<label_t, std::vector<std::string>> warnings;
    std::map<label_t, std::vector<std::string>> reachability;

    explicit Report() = default;

    Report(Report&&) = default;

    void print_reachability(std::ostream& os) const override {
        for (const auto& [label, notes] : reachability) {
            for (const auto& msg : notes) {
                os << label << ": " << msg << "\n";
            }
        }
        os << "\n";
    }

    void print_warnings(std::ostream& os) const override {
        LineInfoPrinter printer{os};
        for (const auto& [label, warnings] : warnings) {
            for (const auto& msg : warnings) {
                printer.print_line_info(label);
                os << label << ": " << msg << "\n";
            }
        }
        os << "\n";
    }

    void print_all_messages(std::ostream& os) const override {
        print_reachability(os);
        print_warnings(os);
    }

    std::set<std::string> all_messages() const override {
        std::set<std::string> result = warning_set();
        for (const auto& note : reachability_set()) {
            result.insert(note);
        }
        return result;
    }

    std::set<std::string> reachability_set() const override {
        std::set<std::string> result;
        for (const auto& [label, warnings] : reachability) {
            for (const auto& msg : warnings) {
                result.insert(to_string(label) + ": " + msg);
            }
        }
        return result;
    }

    std::set<std::string> warning_set() const override {
        std::set<std::string> result;
        for (const auto& [label, warnings] : warnings) {
            for (const auto& msg : warnings) {
                result.insert(to_string(label) + ": " + msg);
            }
        }
        return result;
    }

    bool verified() const override { return warnings.empty(); }

    ~Report() noexcept override = default;
};

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

std::unique_ptr<Report_Abs> Invariants::check_assertions(const cfg_t& cfg) const {
    auto report = std::make_unique<Report>();
    for (const auto& [label, inv_pair] : invariants) {
        if (inv_pair.pre.is_bottom()) {
            continue;
        }
        const auto ins = cfg.at(label);
        for (const Assertion& assertion : ins.preconditions) {
            const auto warnings = ebpf_domain_check(inv_pair.pre, assertion);
            for (const auto& msg : warnings) {
                report->warnings[label].emplace_back(msg);
            }
        }
        if (std::holds_alternative<Assume>(ins.cmd)) {
            if (inv_pair.post.is_bottom()) {
                const auto s = to_string(std::get<Assume>(ins.cmd));
                report->reachability[label].emplace_back("Code becomes unreachable (" + s + ")");
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
