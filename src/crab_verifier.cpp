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

#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"

#include "asm_syntax.hpp"
#include "crab_verifier.hpp"

using std::string;

thread_local program_info global_program_info;
thread_local ebpf_verifier_options_t thread_local_options;

// Numerical domains over integers
//using sdbm_domain_t = crab::domains::SplitDBM;
using crab::domains::ebpf_domain_t;

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

static checks_db generate_report(std::ostream& s,
                                 cfg_t& cfg,
                                 crab::invariant_table_t& preconditions,
                                 crab::invariant_table_t& postconditions) {
    checks_db m_db;
    for (const label_t& label : cfg.sorted_labels()) {
        basic_block_t& bb = cfg.get_node(label);

        if (thread_local_options.print_invariants) {
            s << "\nPreconditions : " << preconditions.at(label) << "\n";
            s << bb;
            s << "\nPostconditions: " << postconditions.at(label) << "\n";
        }

        ebpf_domain_t from_inv(preconditions.at(label));
        from_inv.set_require_check([&m_db, label](auto& inv, const linear_constraint_t& cst, const std::string& s) {
            if (inv.is_bottom())
                return;
            if (cst.is_contradiction()) {
                m_db.add_warning(label, std::string("Contradiction: ") + s);
                return;
            }

            if (inv.entail(cst)) {
                // add_redundant(s);
            } else if (inv.intersect(cst)) {
                // TODO: add_error() if imply negation
                m_db.add_warning(label, s);
            } else {
                m_db.add_warning(label, std::string("assertion failed: ") + s);
            }
        });

        if (thread_local_options.check_termination) {
            // Pinpoint the places where divergence might occur.
            int min_instruction_count_upper_bound = INT_MAX;
            for (const label_t& prev_label : bb.prev_blocks_set()) {
                int instruction_count = preconditions.at(prev_label).get_instruction_count_upper_bound();
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

static void print_report(std::ostream& s, const checks_db& db, const InstructionSeq& prog) {
    s << "\n";
    for (auto [label, messages] : db.m_db) {
        // See if there is an instruction with this label.
        auto it = std::find_if(prog.begin(), prog.end(), [label](const LabeledInstruction& val) {
            return (std::get<0>(val) == label);
        });
        if (it != std::end(prog)) {
            print(prog, s, label);
        } else {
            s << label << ":\n";
        }

        for (const auto& msg : messages)
            s << "  " << msg << "\n";
    }
    s << "\n";
    if (!db.maybe_nonterminating.empty()) {
        s << "Could not prove termination on join into: ";
        for (const label_t& label : db.maybe_nonterminating) {
            s << label << ", ";
        }
        s << "\n";
    }
    s << db.total_warnings << " errors\n";
}

static checks_db get_ebpf_report(std::ostream& s, cfg_t& cfg, program_info info, const ebpf_verifier_options_t* options) {
    global_program_info = std::move(info);
    crab::domains::clear_global_state();
    variable_t::clear_thread_local_state();
    thread_local_options = *options;

    try {
        // Get dictionaries of preconditions and postconditions for each
        // basic block.
        auto [preconditions, postconditions] = crab::run_forward_analyzer(cfg, options->check_termination);

        // Analyze the control-flow graph.
        return generate_report(s, cfg, preconditions, postconditions);
    } catch (std::runtime_error& e) {
        // Convert verifier runtime_error exceptions to failure.
        checks_db db;
        db.add_warning(label_t::exit, e.what());
        return db;
    }
}

/// Returned value is true if the program passes verification.
bool run_ebpf_analysis(std::ostream& s, cfg_t& cfg, program_info info, const ebpf_verifier_options_t* options,
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

/// Returned value is true if the program passes verification.
bool ebpf_verify_program(std::ostream& s, const InstructionSeq& prog, program_info info,
                         const ebpf_verifier_options_t* options, ebpf_verifier_stats_t* stats) {
    if (options == nullptr)
        options = &ebpf_verifier_default_options;

    // Convert the instruction sequence to a control-flow graph
    // in a "passive", non-deterministic form.
    cfg_t cfg = prepare_cfg(prog, info, !options->no_simplify);

    checks_db report = get_ebpf_report(s, cfg, info, options);
    if (options->print_failures) {
        print_report(s, report, prog);
    }
    if (stats) {
        stats->total_unreachable = report.total_unreachable;
        stats->total_warnings = report.total_warnings;
        stats->max_instruction_count = report.max_instruction_count;
    }
    return (report.total_warnings == 0);
}
