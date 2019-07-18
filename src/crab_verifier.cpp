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

#include <boost/signals2.hpp>

#include "crab/array_expansion.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab/graph_config.hpp"
#include "crab/split_dbm.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include "asm_cfg.hpp"
#include "config.hpp"

#include "crab_common.hpp"
#include "crab_constraints.hpp"
#include "crab_verifier.hpp"

using std::string;

using printer_t = boost::signals2::signal<void(const string&)>;

using crab::checks_db;

// Numerical domains over integers
using sdbm_domain_t = crab::domains::SplitDBM;
using dom_t = crab::domains::array_expansion_domain<sdbm_domain_t>;
using analyzer_t = crab::interleaved_fwd_fixpoint_iterator<dom_t>;;

static auto extract_pre(analyzer_t& analyzer, cfg_t& cfg) {
    std::map<string, dom_t> res;
    for (const auto& block : cfg)
        res.emplace(block.label(), analyzer.get_pre(block.label()));
    return res;
}

static auto extract_post(analyzer_t& analyzer, cfg_t& cfg) {
    std::map<string, dom_t> res;
    for (const auto& block : cfg)
        res.emplace(block.label(), analyzer.get_post(block.label()));
    return res;
}

static checks_db analyze(cfg_t& cfg, printer_t& pre_printer, printer_t& post_printer) {
    dom_t::clear_global_state();

    type_check(cfg);
    analyzer_t analyzer(cfg);
    analyzer.run(dom_t::top());

    if (global_options.print_invariants) {
        pre_printer.connect([pre = extract_pre(analyzer, cfg)](const string& label) {
            dom_t inv = pre.at(label);
            crab::outs() << "\n" << inv << "\n";
        });
        post_printer.connect([post = extract_post(analyzer, cfg)](const string& label) {
            dom_t inv = post.at(label);
            crab::outs() << "\n" << inv << "\n";
        });
    }
    checks_db db;
    for (const basic_block_t& bb : cfg) {
        check_block(bb, analyzer.get_pre(bb.label()), db);
    }
    return db;
}

static std::vector<string> sorted_labels(cfg_t& cfg) {
    std::vector<string> labels;
    for (const auto& block : cfg)
        labels.push_back(block.label());

    std::sort(labels.begin(), labels.end(), [](string a, string b) {
        if (first_num(a) < first_num(b))
            return true;
        if (first_num(a) > first_num(b))
            return false;
        return a < b;
    });
    return labels;
}

std::tuple<bool, double> abs_validate(Cfg const& simple_cfg, program_info info) {
    variable_factory vfac;
    cfg_t cfg(entry_label());
    build_crab_cfg(cfg, vfac, simple_cfg, info);

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
            cfg.get_node(label).write(crab::outs());
            post_printer(label);
        }
    }

    if (nwarn > 0) {
        if (global_options.print_failures) {
            checks.write(crab::outs());
        }
        return {false, elapsed_secs};
    }
    return {true, elapsed_secs};
}
