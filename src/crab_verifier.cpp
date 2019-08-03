/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/
#include <assert.h>
#include <inttypes.h>

#include <ctime>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include <boost/lexical_cast.hpp>
#include <boost/signals2.hpp>

#include "crab/ebpf_domain.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab/split_dbm.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include "asm_syntax.hpp"
#include "config.hpp"
#include "crab_verifier.hpp"
#include "spec_type_descriptors.hpp"

using std::string;

using printer_t = boost::signals2::signal<void(const string&)>;

using crab::linear_constraint_t;

program_info global_program_info;

// Numerical domains over integers
//using sdbm_domain_t = crab::domains::SplitDBM;
using crab::domains::ebpf_domain_t;
using analyzer_t = crab::interleaved_fwd_fixpoint_iterator_t;

static auto extract_pre(analyzer_t& analyzer, cfg_t& cfg) {
    std::map<string, ebpf_domain_t> res;
    for (const auto& [label, block] : cfg)
        res.emplace(label, analyzer.get_pre(label));
    return res;
}

static auto extract_post(analyzer_t& analyzer, cfg_t& cfg) {
    std::map<string, ebpf_domain_t> res;
    for (const auto& [label, block] : cfg)
        res.emplace(label, analyzer.get_post(label));
    return res;
}

// Toy database to store invariants.
class checks_db final {
    enum class check_kind_t { Error, Warning, Redundant, Unreachable };
    std::map<label_t, std::vector<std::pair<std::string, check_kind_t>>> m_db;
    std::map<check_kind_t, int> total{
        {check_kind_t::Error, {}},
        {check_kind_t::Warning, {}},
        {check_kind_t::Redundant, {}},
        {check_kind_t::Unreachable, {}},
    };

    void add(label_t label, check_kind_t status, std::string msg) {
        m_db[label].emplace_back(msg, status);
        total[status]++;
    }
  public:

    void add_error(label_t label, std::string msg) { add(label,check_kind_t::Error, msg); }
    void add_warning(label_t label, std::string msg) { add(label,check_kind_t::Warning, msg); }
    void add_redundant(label_t label, std::string msg) { add(label,check_kind_t::Redundant, msg); }
    void add_unreachable(label_t label, std::string msg) { add(label,check_kind_t::Unreachable, msg); }

    int total_error() const { return total.at(check_kind_t::Error); }
    int total_warning() const { return total.at(check_kind_t::Warning); }
    int total_redundant() const { return total.at(check_kind_t::Redundant); }
    int total_unreachable() const { return total.at(check_kind_t::Unreachable); }
    checks_db() = default;

    void write(std::ostream& o) const {
        for (auto [label, reports] : m_db) {
            o << label << ":\n";
            for (auto [k, t] : reports)
                o << "  " << k << "\n";
        }

        std::vector<int> cnts = {total_error(), total_warning(), total_redundant(), total_unreachable()};
        int maxvlen = 0;
        for (auto c : cnts) {
            maxvlen = std::max(maxvlen, (int)std::to_string(c).size());
        }

        o << std::string((int)maxvlen - std::to_string(total_error()).size(), ' ') << total_error()
          << std::string(2, ' ') << "Number of total error checks\n";
        o << std::string((int)maxvlen - std::to_string(total_warning()).size(), ' ') << total_warning()
          << std::string(2, ' ') << "Number of total warning checks\n";
        o << std::string((int)maxvlen - std::to_string(total_redundant()).size(), ' ') << total_redundant()
          << std::string(2, ' ') << "Number of total redundant checks\n";
        o << std::string((int)maxvlen - std::to_string(total_unreachable()).size(), ' ') << total_unreachable()
          << std::string(2, ' ') << "Number of block that become unreachable\n";
    }
};

static checks_db analyze(cfg_t& cfg, printer_t& pre_printer, printer_t& post_printer) {
    crab::domains::clear_global_state();

    analyzer_t analyzer(cfg);
    analyzer.run(ebpf_domain_t::setup_entry());

    if (global_options.print_invariants) {
        pre_printer.connect([pre = extract_pre(analyzer, cfg)](const string& label) {
            ebpf_domain_t inv = pre.at(label);
            std::cout << "\n" << inv << "\n";
        });
        post_printer.connect([post = extract_post(analyzer, cfg)](const string& label) {
            ebpf_domain_t inv = post.at(label);
            std::cout << "\n" << inv << "\n";
        });
    }
    checks_db m_db;
    for (const auto& [_label, bb] : cfg) {
        std::string label = _label;
        if (std::none_of(bb.begin(), bb.end(), [](const auto& s) { return std::holds_alternative<Assert>(s); }))
            continue;
        ebpf_domain_t from_inv(analyzer.get_pre(label));
        from_inv.set_require_check([&m_db, label](auto& inv, const linear_constraint_t& cst, std::string s) {
            s = label + ": " + s;
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

inline int first_num(const label_t& s) {
    try {
        return boost::lexical_cast<int>(s.substr(0, s.find_first_of(":+")));
    } catch (...) {
        std::cout << "bad label:" << s << "\n";
        throw;
    }
}

static std::vector<string> sorted_labels(cfg_t& cfg) {
    std::vector<string> labels;
    for (const auto& [label, block] : cfg)
        labels.push_back(label);

    std::sort(labels.begin(), labels.end(), [](string a, string b) {
        if (first_num(a) < first_num(b))
            return true;
        if (first_num(a) > first_num(b))
            return false;
        return a < b;
    });
    return labels;
}

std::tuple<bool, double> abs_validate(cfg_t& simple_cfg, program_info info) {
    global_program_info = info;
    cfg_t& cfg = simple_cfg;

    printer_t pre_printer;
    printer_t post_printer;

    using namespace std;
    clock_t begin = clock();

    checks_db checks = analyze(cfg, pre_printer, post_printer);

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;

    int nwarn = checks.total_warning() + checks.total_error();
    if (global_options.print_invariants) {
        for (string label : sorted_labels(cfg)) {
            pre_printer(label);
            cfg.get_node(label).write(std::cout);
            post_printer(label);
        }
    }

    if (nwarn > 0) {
        if (global_options.print_failures) {
            checks.write(std::cout);
        }
        return {false, elapsed_secs};
    }
    return {true, elapsed_secs};
}
