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
#include <tuple>
#include <vector>

#include "crab/cfg.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"

#include "asm_syntax.hpp"
#include "gpl/spec_type_descriptors.hpp"

using std::string;

using crab::linear_constraint_t;

program_info global_program_info;

// Numerical domains over integers
//using sdbm_domain_t = crab::domains::SplitDBM;
using crab::domains::ebpf_domain_t;

// Toy database to store invariants.
struct checks_db final {
    std::map<label_t, std::vector<std::string>> m_db;
    int total_warnings{};
    int total_unreachable{};

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

    checks_db() = default;
};

static checks_db generate_report(cfg_t& cfg,
                                 crab::invariant_table_t& preconditions,
                                 crab::invariant_table_t& postconditions) {
    checks_db m_db;
    for (const label_t& label : cfg.sorted_labels()) {
        basic_block_t& bb = cfg.get_node(label);

        if (global_options.print_invariants) {
            std::cout << "\n" << preconditions.at(label) << "\n";
            std::cout << bb;
            std::cout << "\n" << postconditions.at(label) << "\n";
        }

        if (std::none_of(bb.begin(), bb.end(), [](const auto& s) { return std::holds_alternative<Assert>(s); }))
            continue;
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
                m_db.add_warning(label, s);
            }
        });

        bool pre_bot = from_inv.is_bottom();

        from_inv(bb);

        if (!pre_bot && from_inv.is_bottom()) {
            m_db.add_unreachable(label, std::string("inv became bot after ") + to_string(bb.label()));
        }
    }
    return m_db;
}

template<typename F>
auto timed_execution(F f) {
    clock_t begin = clock();

    const auto& res = f();

    clock_t end = clock();

    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;
    return std::make_tuple(res, elapsed_secs);
}

static void print_report(const checks_db& db) {
    std::cout << "\n";
    for (auto [label, messages] : db.m_db) {
        std::cout << label << ":\n";
        for (const auto& msg : messages)
            std::cout << "  " << msg << "\n";
    }
    std::cout << "\n";
    std::cout << db.total_warnings << " warnings\n";
}

std::tuple<bool, double> run_ebpf_analysis(cfg_t& cfg, program_info info) {
    global_program_info = std::move(info);
    crab::domains::clear_global_state();

    auto&& [report, elapsed_secs] = timed_execution([&] {
        // Get dictionaries of preconditions and postconditions for each
        // basic block.
        auto [preconditions, postconditions] = crab::run_forward_analyzer(cfg);
        return generate_report(cfg, preconditions, postconditions);
    });

    if (global_options.print_failures) {
        print_report(report);
    }
    return {report.total_warnings == 0, elapsed_secs};
}
