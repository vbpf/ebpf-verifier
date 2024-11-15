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

#include "asm_syntax.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab_utils/lazy_allocator.hpp"
#include "crab_verifier.hpp"
#include "string_constraints.hpp"

#include <asm_files.hpp>
#include <ranges>

using crab::ebpf_domain_t;
using std::string;

thread_local crab::lazy_allocator<program_info> global_program_info;
thread_local ebpf_verifier_options_t thread_local_options;
void ebpf_verifier_clear_before_analysis();

struct Messages {
    std::map<label_t, std::vector<std::string>> warnings;
    std::map<label_t, std::vector<std::string>> info;
};

static int maximum_loop_count(const crab::invariant_table_t& post_invariants) {
    crab::extended_number max_loop_count{0};
    if (thread_local_options.cfg_opts.check_for_termination) {
        // Gather the upper bound of loop counts from post-invariants.
        for (const auto& inv : std::views::values(post_invariants)) {
            max_loop_count = std::max(max_loop_count, inv.get_loop_count_upper_bound());
        }
    }
    const auto m = max_loop_count.number();
    if (m && m->fits<int32_t>()) {
        return m->cast_to<int32_t>();
    }
    return std::numeric_limits<int>::max();
}

static Messages check_assertions_and_reachability(const cfg_t& cfg, const crab::invariant_map_pair& invariants) {
    Messages messages;
    for (const auto& [label, pre_inv] : invariants.pre) {
        if (pre_inv.is_bottom()) {
            continue;
        }
        const auto ins = cfg.at(label);
        for (const Assertion& assertion : ins.preconditions) {
            const auto warnings = ebpf_domain_check(pre_inv, assertion);
            for (const auto& msg : warnings) {
                messages.warnings[label].emplace_back(msg);
            }
        }
        if (std::holds_alternative<Assume>(ins.cmd)) {
            if (invariants.post.at(label).is_bottom()) {
                const auto s = to_string(std::get<Assume>(ins.cmd));
                messages.info[label].emplace_back("Code becomes unreachable (" + s + ")");
            }
        }
    }
    return messages;
}

static int count_warnings(const Messages& messages) {
    int count = 0;
    for (const auto& msgs : std::views::values(messages.warnings)) {
        count += msgs.size();
    }
    return count;
}

struct LineInfoPrinter {
    std::ostream& os;
    std::string previous_source_line;

    void print_line_info(const label_t& label) {
        if (thread_local_options.print_line_info) {
            const auto& line_info_map = global_program_info.get().line_info;
            const auto& line_info = line_info_map.find(label.from);
            // Print line info only once.
            if (line_info != line_info_map.end() && line_info->second.source_line != previous_source_line) {
                os << "\n" << line_info->second << "\n";
                previous_source_line = line_info->second.source_line;
            }
        }
    }
};

ebpf_verifier_stats_t analyze_and_report(const analyze_params_t& params) {
    if (!params.prog && !params.cfg) {
        throw std::invalid_argument("Either prog or cfg must be provided");
    }
    ebpf_verifier_clear_before_analysis();

    if (params.info) {
        global_program_info = *params.info;
    }
    if (params.options) {
        thread_local_options = *params.options;
    }
    std::ostream& os = params.os ? *params.os : std::cout;
    try {
        cfg_t cfg = params.cfg ? std::move(*params.cfg)
                               : prepare_cfg(*params.prog, global_program_info.get(), thread_local_options.cfg_opts);
        ebpf_domain_t entry_invariant = params.entry_invariant
                                            ? ebpf_domain_t::from_constraints(params.entry_invariant->value(),
                                                                              thread_local_options.setup_constraints)
                                            : ebpf_domain_t::setup_entry(thread_local_options.setup_constraints);

        const auto invariants = run_forward_analyzer(cfg, std::move(entry_invariant));

        if (thread_local_options.print_invariants) {
            LineInfoPrinter printer{os};
            for (const label_t& label : cfg.sorted_labels()) {
                printer.print_line_info(label);
                os << "\nPre-invariant : " << invariants.pre.at(label) << "\n";
                os << cfg.get_node(label);
                os << "\nPost-invariant: " << invariants.post.at(label) << "\n";
            }
        }

        if (params.out_invariants) {
            string_invariant_map invariant_map;
            for (const auto& label : std::ranges::views::keys(*params.out_invariants)) {
                invariant_map.insert_or_assign(label, invariants.post.at(label).to_set());
            }
            *params.out_invariants = std::move(invariant_map);
        }

        const Messages messages = check_assertions_and_reachability(cfg, invariants);

        if (thread_local_options.print_failures) {
            os << "\n";
            LineInfoPrinter printer{os};
            for (const auto& [label, warnings] : messages.warnings) {
                for (const auto& msg : warnings) {
                    printer.print_line_info(label);
                    os << label << ": " << msg << "\n";
                }
            }
            for (const auto& [label, notes] : messages.info) {
                for (const auto& msg : notes) {
                    os << label << ": " << msg << "\n";
                }
            }
            os << "\n";
        }

        return ebpf_verifier_stats_t{
            .total_warnings = count_warnings(std::move(messages)),
            .max_loop_count = maximum_loop_count(invariants.post),
        };
    } catch (crab::InvalidControlFlow& e) {
        os << e.what();
    } catch (UnmarshalError& e) {
        os << e.what();
    } catch (std::logic_error& e) {
        std::cerr << e.what();
    }
    return ebpf_verifier_stats_t{.total_warnings = 1};
}

void ebpf_verifier_clear_before_analysis() {
    crab::domains::clear_global_state();
    crab::variable_t::clear_thread_local_state();
}

void ebpf_verifier_clear_thread_local_state() {
    crab::variable_t::clear_thread_local_state();
    crab::CrabStats::clear_thread_local_state();
    global_program_info.clear();
    crab::domains::clear_thread_local_state();
    crab::domains::SplitDBM::clear_thread_local_state();
}
