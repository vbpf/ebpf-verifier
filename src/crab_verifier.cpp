// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/
#include <cinttypes>

#include <ctime>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"

#include "asm_syntax.hpp"
#include "crab_verifier.hpp"
#include "string_constraints.hpp"

using std::string;

thread_local program_info global_program_info;
thread_local ebpf_verifier_options_t thread_local_options;

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

static checks_db generate_report(cfg_t& cfg,
                                 crab::invariant_table_t& pre_invariants,
                                 crab::invariant_table_t& post_invariants) {
    checks_db m_db;
    for (const label_t& label : cfg.sorted_labels()) {
        basic_block_t& bb = cfg.get_node(label);
        ebpf_domain_t from_inv(pre_invariants.at(label));
        from_inv.set_require_check([&m_db, label](auto& inv, const linear_constraint_t& cst, const std::string& s) {
            if (inv.is_bottom())
                return true;
            if (cst.is_contradiction()) {
                m_db.add_warning(label, s);
                return false;
            }

            if (inv.entail(cst)) {
                // add_redundant(s);
                return true;
            } else if (inv.intersect(cst)) {
                // TODO: add_error() if imply negation
                m_db.add_warning(label, s);
                return false;
            } else {
                m_db.add_warning(label, s);
                return false;
            }
        });

        if (thread_local_options.check_termination) {
            // Pinpoint the places where divergence might occur.
            int min_instruction_count_upper_bound = INT_MAX;
            for (const label_t& prev_label : bb.prev_blocks_set()) {
                int instruction_count = pre_invariants.at(prev_label).get_instruction_count_upper_bound();
                min_instruction_count_upper_bound = std::min(min_instruction_count_upper_bound, instruction_count);
            }

            constexpr int max_instructions = 100000;
            int instruction_count_upper_bound = from_inv.get_instruction_count_upper_bound();
            if ((min_instruction_count_upper_bound < max_instructions) &&
                (instruction_count_upper_bound >= max_instructions))
                m_db.add_nontermination(label);

            m_db.max_instruction_count = std::max(m_db.max_instruction_count, instruction_count_upper_bound);
        }

        bool pre_bot = from_inv.is_bottom();

        from_inv(bb, thread_local_options.check_termination);

        if (!pre_bot && from_inv.is_bottom()) {
            m_db.add_unreachable(label, std::string("Code is unreachable after ") + to_string(bb.label()));
        }
    }
    return m_db;
}

auto get_line_info(const InstructionSeq& insts) {
    std::map<int, std::optional<btf_line_info_t>> label_to_line_info;
    for (auto& [label, inst, line_info] : insts) {
        if (line_info.has_value())
            label_to_line_info.insert({label.from, line_info});
    }
    return label_to_line_info;
}

static void print_report(std::ostream& os, const checks_db& db, const InstructionSeq& prog, bool print_line_info) {
    auto label_to_line_info = get_line_info(prog);
    os << "\n";
    for (auto [label, messages] : db.m_db) {
        for (const auto& msg : messages) {
            if (print_line_info) {
                auto line_info = label_to_line_info.find(label.from);
                if (line_info != label_to_line_info.end() && line_info->second.has_value())
                    os << line_info->second.value();
            }
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
    if (!db.maybe_nonterminating.empty()) {
        os << "Could not prove termination on join into: ";
        for (const label_t& label : db.maybe_nonterminating) {
            os << label << ", ";
        }
        os << "\n";
    }
}

checks_db get_ebpf_report(std::ostream& s, cfg_t& cfg, program_info info, const ebpf_verifier_options_t* options) {
    global_program_info = std::move(info);
    crab::domains::clear_global_state();
    variable_t::clear_thread_local_state();
    thread_local_options = *options;

    try {
        // Get dictionaries of pre-invariants and post-invariants for each basic block.
        ebpf_domain_t entry_dom = ebpf_domain_t::setup_entry(options->check_termination);
        auto [pre_invariants, post_invariants] =
            crab::run_forward_analyzer(cfg, std::move(entry_dom), options->check_termination);

        // Analyze the control-flow graph.
        checks_db db = generate_report(cfg, pre_invariants, post_invariants);
        if (thread_local_options.print_invariants) {
            for (const label_t& label : cfg.sorted_labels()) {
                s << "\nPre-invariant : " << pre_invariants.at(label) << "\n";
                s << cfg.get_node(label);
                s << "\nPost-invariant: " << post_invariants.at(label) << "\n";
            }
        }
        return db;
    } catch (std::runtime_error& e) {
        // Convert verifier runtime_error exceptions to failure.
        checks_db db;
        db.add_warning(label_t::exit, e.what());
        return db;
    }
}

/// Returned value is true if the program passes verification.
bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, const program_info& info, const ebpf_verifier_options_t* options,
                       ebpf_verifier_stats_t* stats) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;
    checks_db report = get_ebpf_report(s, cfg, info, options);
    if (stats) {
        stats->total_unreachable = report.total_unreachable;
        stats->total_warnings = report.total_warnings;
        stats->max_instruction_count = report.max_instruction_count;
    }
    return (report.total_warnings == 0);
}

static string_invariant_map to_string_invariant_map(crab::invariant_table_t& inv_table) {
    string_invariant_map res;
    for (auto& [label, inv]: inv_table) {
        res.insert_or_assign(label, inv.to_set());
    }
    return res;
}

std::tuple<string_invariant_map, string_invariant_map>
ebpf_analyze_program_for_test(std::ostream& os, const InstructionSeq& prog, const string_invariant& entry_invariant,
                              const program_info& info,
                              bool no_simplify, bool check_termination) {
    ebpf_domain_t entry_inv = entry_invariant.is_bottom()
        ? ebpf_domain_t::bottom()
        : ebpf_domain_t::from_constraints(entry_invariant.value());
    assert(!entry_inv.is_bottom());
    global_program_info = info;
    cfg_t cfg = prepare_cfg(prog, info, !no_simplify, false);
    auto [pre_invariants, post_invariants] = crab::run_forward_analyzer(cfg, entry_inv, check_termination);
    checks_db report = generate_report(cfg, pre_invariants, post_invariants);
    print_report(os, report, prog, false);

    return {
        to_string_invariant_map(pre_invariants),
        to_string_invariant_map(post_invariants)
    };
}

/// Returned value is true if the program passes verification.
bool ebpf_verify_program(std::ostream& os, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t* options, ebpf_verifier_stats_t* stats) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;

    // Convert the instruction sequence to a control-flow graph
    // in a "passive", non-deterministic form.
    cfg_t cfg = prepare_cfg(prog, info, !options->no_simplify);

    checks_db report = get_ebpf_report(os, cfg, info, options);
    if (options->print_failures) {
        print_report(os, report, prog, options->print_line_info);
    }
    if (stats) {
        stats->total_unreachable = report.total_unreachable;
        stats->total_warnings = report.total_warnings;
        stats->max_instruction_count = report.max_instruction_count;
    }
    return (report.total_warnings == 0);
}
