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

#include "asm_parse.hpp"
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

static checks_db generate_report(const cfg_t& cfg, const crab::invariant_table_t& pre_invariants,
                                 const crab::invariant_table_t& post_invariants) {
    checks_db m_db;
    for (const label_t& label : cfg.sorted_labels()) {
        const basic_block_t& bb = cfg.get_node(label);
        ebpf_domain_t from_inv{pre_invariants.at(label)};
        const bool pre_bot = from_inv.is_bottom();

        for (const GuardedInstruction& ins : bb) {
            for (const Assertion& assertion : ins.preconditions) {
                for (const auto& warning : ebpf_domain_check(from_inv, label, assertion)) {
                    m_db.add_warning(label, warning);
                }
            }
            ebpf_domain_transform(from_inv, ins.cmd);
        }

        if (!pre_bot && from_inv.is_bottom()) {
            m_db.add_unreachable(label, std::string("Code is unreachable after ") + to_string(bb.label()));
        }
    }

    if (thread_local_options.cfg_opts.check_for_termination) {
        // Gather the upper bound of loop counts from post-invariants.
        for (const auto& [label, inv] : post_invariants) {
            if (inv.is_bottom()) {
                continue;
            }
            m_db.max_loop_count = std::max(m_db.max_loop_count, inv.get_loop_count_upper_bound());
        }
    }
    return m_db;
}

static auto get_line_info(const InstructionSeq& insts) {
    std::map<int, btf_line_info_t> label_to_line_info;
    for (const auto& [label, inst, line_info] : insts) {
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
    for (const auto& [label, messages] : db.m_db) {
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
}

static checks_db get_analysis_report(std::ostream& s, const cfg_t& cfg, const crab::invariant_table_t& pre_invariants,
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

static thread_local std::optional<crab::invariant_table_t> saved_pre_invariants = std::nullopt;

static void save_invariants_if_needed(const crab::invariant_table_t& pre_invariants) {
    if (thread_local_options.store_pre_invariants) {
        saved_pre_invariants = pre_invariants;
    }
}

static checks_db get_ebpf_report(std::ostream& s, const cfg_t& cfg, program_info info,
                                 const ebpf_verifier_options_t& options,
                                 const std::optional<InstructionSeq>& prog = std::nullopt) {
    global_program_info = std::move(info);
    crab::domains::clear_global_state();
    crab::variable_t::clear_thread_local_state();
    thread_local_options = options;

    try {
        // Get dictionaries of pre-invariants and post-invariants for each basic block.
        ebpf_domain_t entry_dom = ebpf_domain_t::setup_entry(true);
        auto [pre_invariants, post_invariants] = run_forward_analyzer(cfg, std::move(entry_dom));
        save_invariants_if_needed(pre_invariants);
        return get_analysis_report(s, cfg, pre_invariants, post_invariants, prog);
    } catch (std::runtime_error& e) {
        // Convert verifier runtime_error exceptions to failure.
        checks_db db;
        db.add_warning(label_t::exit, e.what());
        return db;
    }
}

/// Returned value is true if the program passes verification.
bool run_ebpf_analysis(std::ostream& s, const cfg_t& cfg, const program_info& info,
                       const ebpf_verifier_options_t& options, ebpf_verifier_stats_t* stats) {
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
    for (const auto& [label, inv] : inv_table) {
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
        const cfg_t cfg = prepare_cfg(prog, info, options.cfg_opts);
        auto [pre_invariants, post_invariants] = run_forward_analyzer(cfg, std::move(entry_inv));
        save_invariants_if_needed(pre_invariants);
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
                         const ebpf_verifier_options_t& options, ebpf_verifier_stats_t* stats) {
    // Convert the instruction sequence to a control-flow graph
    // in a "passive", non-deterministic form.
    const cfg_t cfg = prepare_cfg(prog, info, options.cfg_opts);

    std::optional<InstructionSeq> prog_opt = std::nullopt;
    if (options.print_failures) {
        prog_opt = prog;
    }

    const checks_db report = get_ebpf_report(os, cfg, info, options, prog_opt);
    if (options.print_failures) {
        print_report(os, report, prog, options.print_line_info);
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
    saved_pre_invariants = std::nullopt;
}

bool ebpf_check_constraints_at_label(std::ostream& os, const std::string& label_string,
                                     const std::set<std::string>& constraints) {
    try {
        label_t label = label_t(label_string);
        if (!saved_pre_invariants.has_value()) {
            os << "No pre-invariants available\n";
            return false;
        }
        if (saved_pre_invariants.value().find(label) == saved_pre_invariants.value().end()) {
            os << "No pre-invariants available for label " << label << "\n";
            return false;
        }
        ebpf_domain_t from_inv(saved_pre_invariants.value().at(label));
        auto concrete_domain = ebpf_domain_t::from_constraints(constraints, false);

        if (concrete_domain.is_bottom()) {
            os << "The provided constraints are unsatisfiable and self-contradictory (concrete domain is bottom)\n";
            os << concrete_domain << "\n";
            return false;
        }
        if (from_inv.is_bottom()) {
            os << "The abstract state is unreachable\n";
            os << from_inv << "\n";
            return false;
        }

        if ((from_inv & concrete_domain).is_bottom()) {
            os << "Concrete state does not match invariant\n";

            // Print the concrete state
            os << "--- Concrete state ---\n";
            os << concrete_domain << "\n";

            os << "--- Abstract state ---\n";
            os << from_inv << "\n";

            return false;
        }

        return true;
    } catch (std::exception& e) {
        os << "Error occurred while checking constraints: " << e.what() << "\n";
        return false;
    }
}

std::set<std::string> ebpf_get_invariants_at_label(const std::string& label) {
    // If the label is malformed, throw an exception so the caller can handle it.
    label_t l = label_t(label);

    if (!saved_pre_invariants.has_value()) {
        return {};
    }
    if (saved_pre_invariants.value().find(l) == saved_pre_invariants.value().end()) {
        return {};
    }
    return saved_pre_invariants.value().at(l).to_set().value();
}
