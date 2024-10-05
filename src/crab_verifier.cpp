// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab_utils/lazy_allocator.hpp"

#include "asm_syntax.hpp"
#include "crab_verifier.hpp"
#include "string_constraints.hpp"

using crab::ebpf_domain_t;
using std::string;

thread_local crab::lazy_allocator<program_info> global_program_info;
thread_local ebpf_verifier_options_t thread_local_options;

// Toy database to store invariants.
struct checks_db final {
    std::map<label_t, std::vector<std::string>> m_db{};
    int total_warnings{};
    int total_unreachable{};
    crab::extended_number max_loop_count{crab::number_t{0}};

    void add(const label_t& label, const std::string& msg) { m_db[label].emplace_back(msg); }

    void add_warning(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_warnings++;
    }

    void add_unreachable(const label_t& label, const std::string& msg) {
        add(label, msg);
        total_unreachable++;
    }

    [[nodiscard]]
    int get_max_loop_count() const {
        const auto m = this->max_loop_count.number();
        if (m && m->fits<int32_t>()) {
            return m->cast_to<int32_t>();
        }
        return std::numeric_limits<int>::max();
    }
    checks_db() = default;
};

static checks_db generate_report(cfg_t& cfg, const crab::invariant_table_t& pre_invariants,
                                 const crab::invariant_table_t& post_invariants) {
    checks_db m_db;
    for (const label_t& label : cfg.sorted_labels()) {
        basic_block_t& bb = cfg.get_node(label);
        ebpf_domain_t from_inv(pre_invariants.at(label));
        from_inv.set_require_check(
            [&m_db, label](auto& inv, const crab::linear_constraint_t& cst, const std::string& s) {
                if (inv.is_bottom()) {
                    return true;
                }
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

        const bool pre_bot = from_inv.is_bottom();

        from_inv(bb);

        if (!pre_bot && from_inv.is_bottom()) {
            m_db.add_unreachable(label, std::string("Code is unreachable after ") + to_string(bb.label()));
        }
    }

    if (thread_local_options.check_termination) {
        const auto last_inv = post_invariants.at(cfg.exit_label());
        m_db.max_loop_count = last_inv.get_loop_count_upper_bound();
    }
    return m_db;
}

static auto get_line_info(const InstructionSeq& insts) {
    std::map<int, btf_line_info_t> label_to_line_info;
    for (auto& [label, inst, line_info] : insts) {
        if (line_info.has_value()) {
            label_to_line_info.emplace(label.from, line_info.value());
        }
    }
    return label_to_line_info;
}

static void print_report(std::ostream& os, const checks_db& db, const InstructionSeq& prog,
                         const bool print_line_info) {
    auto label_to_line_info = get_line_info(prog);
    os << "\n";
    for (auto [label, messages] : db.m_db) {
        for (const auto& msg : messages) {
            if (print_line_info) {
                auto line_info = label_to_line_info.find(label.from);
                if (line_info != label_to_line_info.end()) {
                    os << line_info->second;
                }
            }
            os << label << ": " << msg << "\n";
        }
    }
    os << "\n";
    const crab::number_t max_loop_count{100000};
    if (db.max_loop_count > max_loop_count) {
        os << "Could not prove termination.\n";
    }
}

static checks_db get_analysis_report(std::ostream& s, cfg_t& cfg, const crab::invariant_table_t& pre_invariants,
                                     const crab::invariant_table_t& post_invariants,
                                     const std::optional<InstructionSeq>& prog = std::nullopt) {
    // Analyze the control-flow graph.
    checks_db db = generate_report(cfg, pre_invariants, post_invariants);
    if (thread_local_options.print_invariants) {
        std::optional<std::map<int, btf_line_info_t>> line_info_map = std::nullopt;
        if (prog.has_value()) {
            line_info_map = get_line_info(*prog);
        }
        std::string previous_source_line = "";
        for (const label_t& label : cfg.sorted_labels()) {
            if (line_info_map.has_value()) {
                auto line_info = line_info_map->find(label.from);
                // Print line info only once.
                if (line_info != line_info_map->end() && line_info->second.source_line != previous_source_line) {
                    s << "\n" << line_info->second << "\n";
                    previous_source_line = line_info->second.source_line;
                }
            }
            s << "\nPre-invariant : " << pre_invariants.at(label) << "\n";
            s << cfg.get_node(label);
            s << "\nPost-invariant: " << post_invariants.at(label) << "\n";
        }
    }
    return db;
}

static checks_db get_ebpf_report(std::ostream& s, cfg_t& cfg, program_info info, const ebpf_verifier_options_t* options,
                                 const std::optional<InstructionSeq>& prog = std::nullopt) {
    global_program_info = std::move(info);
    crab::domains::clear_global_state();
    crab::variable_t::clear_thread_local_state();
    thread_local_options = *options;

    try {
        // Get dictionaries of pre-invariants and post-invariants for each basic block.
        ebpf_domain_t entry_dom = ebpf_domain_t::setup_entry(true);
        auto [pre_invariants, post_invariants] = run_forward_analyzer(cfg, std::move(entry_dom));
        return get_analysis_report(s, cfg, pre_invariants, post_invariants, prog);
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
    if (options == nullptr) {
        options = &ebpf_verifier_default_options;
    }
    const checks_db report = get_ebpf_report(s, cfg, info, options);
    if (stats) {
        stats->total_unreachable = report.total_unreachable;
        stats->total_warnings = report.total_warnings;
        stats->max_loop_count = report.get_max_loop_count();
    }
    return report.total_warnings == 0;
}

static string_invariant_map to_string_invariant_map(crab::invariant_table_t& inv_table) {
    string_invariant_map res;
    for (auto& [label, inv] : inv_table) {
        res.insert_or_assign(label, inv.to_set());
    }
    return res;
}

std::tuple<string_invariant, bool> ebpf_analyze_program_for_test(std::ostream& os, const InstructionSeq& prog,
                                                                 const string_invariant& entry_invariant,
                                                                 const program_info& info,
                                                                 const ebpf_verifier_options_t& options) {
    crab::domains::clear_global_state();
    crab::variable_t::clear_thread_local_state();

    thread_local_options = options;
    global_program_info = info;
    assert(!entry_invariant.is_bottom());
    ebpf_domain_t entry_inv = ebpf_domain_t::from_constraints(entry_invariant.value(), options.setup_constraints);
    if (entry_inv.is_bottom()) {
        throw std::runtime_error("Entry invariant is inconsistent");
    }
    try {
        cfg_t cfg = prepare_cfg(prog, info, options.simplify, false);
        auto [pre_invariants, post_invariants] = run_forward_analyzer(cfg, std::move(entry_inv));
        const checks_db report = get_analysis_report(std::cerr, cfg, pre_invariants, post_invariants);
        print_report(os, report, prog, false);

        auto pre_invariant_map = to_string_invariant_map(pre_invariants);

        return {pre_invariant_map.at(label_t::exit), (report.total_warnings == 0)};
    } catch (std::runtime_error& e) {
        os << e.what();
        return {string_invariant::top(), false};
    }
}

/// Returned value is true if the program passes verification.
bool ebpf_verify_program(std::ostream& os, const InstructionSeq& prog, const program_info& info,
                         const ebpf_verifier_options_t* options, ebpf_verifier_stats_t* stats) {
    if (options == nullptr) {
        options = &ebpf_verifier_default_options;
    }

    // Convert the instruction sequence to a control-flow graph
    // in a "passive", non-deterministic form.
    cfg_t cfg = prepare_cfg(prog, info, options->simplify);

    std::optional<InstructionSeq> prog_opt = std::nullopt;
    if (options->print_failures) {
        prog_opt = prog;
    }

    const checks_db report = get_ebpf_report(os, cfg, info, options, prog_opt);
    if (options->print_failures) {
        print_report(os, report, prog, options->print_line_info);
    }
    if (stats) {
        stats->total_unreachable = report.total_unreachable;
        stats->total_warnings = report.total_warnings;
        stats->max_loop_count = report.get_max_loop_count();
    }
    return report.total_warnings == 0;
}

void ebpf_verifier_clear_thread_local_state() {
    crab::variable_t::clear_thread_local_state();
    crab::CrabStats::clear_thread_local_state();
    global_program_info.clear();
    crab::domains::clear_thread_local_state();
    crab::domains::SplitDBM::clear_thread_local_state();
}
