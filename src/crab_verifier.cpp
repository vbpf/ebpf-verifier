/**
 *  This module is about selecting the numerical and memory domains, initiating
 *  the verification process and returning the results.
 **/
#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <functional>
#include <tuple>
#include <map>
#include <ctime>
#include <iostream>

#include <boost/signals2.hpp>

#include "crab/base_property.hpp"
#include "crab/assertion.hpp"
#include "crab/checker.hpp"

#include "config.hpp"
#include "asm_cfg.hpp"

#include "crab_domains.hpp"
#include "crab_common.hpp"
#include "crab_constraints.hpp"
#include "crab_verifier.hpp"


using std::string;

using printer_t = boost::signals2::signal<void(const string&)>;

using crab::checker::checks_db;

using dom_t = crab::domains::array_expansion_domain<crab::domain_impl::z_sdbm_domain_t>;
using analyzer_t = crab::analyzer::fwd_analyzer<crab::cfg::cfg_ref<cfg_t>, dom_t>;

static auto extract_pre(analyzer_t& analyzer)
{
    std::map<string, typename analyzer_t::abs_dom_t> res;
    for (const auto& block : analyzer.get_cfg())
        res.emplace(block.label(), analyzer.get_pre(block.label()));
    return res;
}

static auto extract_post(analyzer_t& analyzer)
{
    std::map<string, typename analyzer_t::abs_dom_t> res;
    for (const auto& block : analyzer.get_cfg())
        res.emplace(block.label(), analyzer.get_post(block.label()));
    return res;
}

static checks_db check(analyzer_t& analyzer)
{
    int verbose = global_options.print_failures ? 2 : 0;
    using checker_t = crab::checker::assert_property_checker<analyzer_t>;
    checker_t checker(verbose);

    for (auto &bb : analyzer.get_cfg()) {
        if (checker.is_interesting(bb)) {
            auto inv = analyzer[bb.label()];
            // Note: this has side effect:
            std::shared_ptr<checker_t::abs_tr_t> abs_tr = analyzer.get_abs_transformer(&inv);
            // propagate forward the invariants from the block entry
            // while checking the property
            checker.set(abs_tr.get(), {});
            for (auto &stmt : bb) {
                stmt.accept(&checker);
            }
        }
    }
    return checker.get_db();
}

static checks_db analyze(cfg_t& cfg, printer_t& pre_printer, printer_t& post_printer)
{
    dom_t::clear_global_state();

    analyzer_t analyzer(cfg);

    analyzer.run_forward();

    if (global_options.print_invariants) {
        pre_printer.connect([pre=extract_pre(analyzer)](const string& label) {
            dom_t inv = pre.at(label);
            crab::outs() << "\n" << inv << "\n";
        });
        post_printer.connect([post=extract_post(analyzer)](const string& label) {
            dom_t inv = post.at(label);
            crab::outs() << "\n" << inv << "\n";
        });
    }

    checks_db c = check(analyzer);
    return c;
}

static std::vector<string> sorted_labels(cfg_t& cfg)
{
    std::vector<string> labels;
    for (const auto& block : cfg)
        labels.push_back(block.label());

    std::sort(labels.begin(), labels.end(), [](string a, string b){
        if (first_num(a) < first_num(b)) return true;
        if (first_num(a) > first_num(b)) return false;
        return a < b;
    });
    return labels;
}

std::tuple<bool, double> abs_validate(Cfg const& simple_cfg, program_info info)
{
    variable_factory_t vfac;
    cfg_t cfg(entry_label(), crab::cfg::ARR);
    build_crab_cfg(cfg, vfac, simple_cfg, info);

    printer_t pre_printer;
    printer_t post_printer;

    using namespace std;
    clock_t begin = clock();

    checks_db checks = analyze(cfg, pre_printer, post_printer);

    clock_t end = clock();
    double elapsed_secs = double(end - begin) / CLOCKS_PER_SEC;

    int nwarn = checks.get_total_warning() + checks.get_total_error();
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
