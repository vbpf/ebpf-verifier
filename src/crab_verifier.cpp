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
#include <utility>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "crab/ebpf_domain.hpp"
#include "crab/cfg.hpp"
#include "crab/fwd_analyzer.hpp"

#include "asm_syntax.hpp"
#include "spec_type_descriptors.hpp"

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

    void add_warning(const label_t& label, const std::string& msg) { add(label,     msg); total_warnings++; }
    void add_unreachable(const label_t& label, const std::string& msg) { add(label, msg); total_unreachable++; }

    checks_db() = default;
};

inline int first_num(const label_t& s) {
    try {
        return boost::lexical_cast<int>(s.substr(0, s.find_first_of(":+")));
    } catch (...) {
        std::cout << "bad label:" << s << "\n";
        throw;
    }
}

static std::vector<label_t> sorted_labels(cfg_t& cfg) {
    std::vector<label_t> labels = cfg.labels();

    std::sort(labels.begin(), labels.end(), [](const string& a, const string& b) {
        if (first_num(a) < first_num(b))
            return true;
        if (first_num(a) > first_num(b))
            return false;
        return a < b;
    });
    return labels;
}

static checks_db analyze(cfg_t& cfg) {
    crab::domains::clear_global_state();

    auto [preconditions, postconditions] = crab::run_forward_analyzer(cfg);

    checks_db m_db;
    for (const label_t& label : sorted_labels(cfg)) {
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
                m_db.add_warning(label, std::string("Contradition: ") + s);
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

        for (const auto& statement : bb) {
            bool pre_bot = from_inv.is_bottom();
            std::visit(from_inv, statement);
            if (!pre_bot && from_inv.is_bottom()) {
                m_db.add_unreachable(label, "inv became bot after " + to_string(statement));
            }
        }
    }
    return m_db;
}

std::tuple<bool, double> abs_validate(cfg_t& simple_cfg, program_info info) {
    global_program_info = std::move(info);
    cfg_t& cfg = simple_cfg;

    using namespace std;
    clock_t begin = clock();

    const checks_db db = analyze(cfg);

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;

    int nwarn = db.total_warnings;

    if (global_options.print_failures) {
        std::cout << "\n";
        for (auto [label, messages] : db.m_db) {
            std::cout << label << ":\n";
            for (const auto& msg : messages)
                std::cout << "  " << msg << "\n";
        }
        std::cout << "\n";
        std::cout << db.total_warnings << " warnings\n";
    }
    return {nwarn == 0, elapsed_secs};
}
