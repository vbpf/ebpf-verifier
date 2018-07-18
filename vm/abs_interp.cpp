/*
 * Copyright 2018 VMware, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <map>

#include <boost/signals2.hpp>

#include <crab/checkers/base_property.hpp>
#include <crab/checkers/div_zero.hpp>
#include <crab/checkers/assertion.hpp>
#include <crab/checkers/checker.hpp>
#include <crab/analysis/dataflow/assumptions.hpp>

#include "crab_dom.hpp"

#include "ebpf.h"
#include "ubpf_int.h"

#include "abs_common.hpp"
#include "abs_interp.h"
#include "abs_cfg.hpp"

using printer_t = boost::signals2::signal<void(const std::string&)>;

using namespace crab::cfg;
using namespace crab::checker;
using namespace crab::analyzer;
using namespace crab::domains;
using namespace crab::domain_impl;
using cfg_ref_t = cfg_ref<cfg_t>;

extern template class dis_interval_domain<ikos::z_number, varname_t >;
extern template class interval_domain<ikos::z_number,varname_t>;
extern template class numerical_congruence_domain<z_interval_domain_t>;
extern template class term_domain<term::TDomInfo<ikos::z_number,varname_t,z_interval_domain_t> >;
extern template class term_domain<term::TDomInfo<ikos::z_number,varname_t,z_sdbm_domain_t> >;
extern template class term_domain<term::TDomInfo<ikos::z_number,varname_t,z_dis_interval_domain_t> >;
extern template class reduced_numerical_domain_product2<z_term_dis_int_t,z_sdbm_domain_t>;

// TODO: return vector of labels
auto sorted_blocks(cfg_t& cfg)
{
    std::vector<std::reference_wrapper<basic_block_t>> blocks(cfg.begin(), cfg.end());
    std::sort(blocks.begin(), blocks.end(), [](const basic_block_t& a, const basic_block_t& b){
        if (first_num(a.label()) < first_num(b.label())) return true;
        if (first_num(a.label()) > first_num(b.label())) return false;
        return a.label() < b.label();
    });
    return blocks;
}

template<typename dom_t>
static checks_db analyze(cfg_t& cfg, printer_t& printer)
{
    liveness<cfg_ref_t> live(cfg);
    live.exec();

    using analyzer_t = intra_fwd_analyzer<cfg_ref_t, dom_t>;
    analyzer_t analyzer(cfg, dom_t::top(), &live);
    analyzer.run();

    {
        std::map<std::string, dom_t> pre;
        for (const auto& block : cfg)
            pre.emplace(block.label(), analyzer[block.label()]);

        printer.connect([pre](const std::string& label) {
            auto inv = pre.at(label);
            crab::outs() << "\n" << inv << "\n";
        });
    }

    const int verbose = 2;
    using checker_t = intra_checker<analyzer_t>;
    using prop_checker_ptr = typename checker_t::prop_checker_ptr;
    checker_t checker(analyzer, {
        prop_checker_ptr(new assert_property_checker<analyzer_t>(verbose)),
        prop_checker_ptr(new div_zero_property_checker<analyzer_t>(verbose))
    });
    checker.run();
    return checker.get_all_checks();
}

static checks_db dont_analyze(cfg_t& cfg, printer_t& printer)
{
    return {};
}

struct domain_desc {
    std::string description;
    std::function<checks_db(cfg_t&, printer_t&)> analyze;
};

static const std::map<std::string, domain_desc> domains{
    { "interval"          , { "simple interval (z_interval_domain_t)", analyze<z_interval_domain_t> } },
    { "ric"               , { "numerical congruence (z_ric_domain_t)", analyze<z_ric_domain_t> } },
    { "dbm"               , { "sparse dbm (z_dbm_domain_t)", analyze<z_dbm_domain_t> } },
    { "sdbm"              , { "split dbm (z_sdbm_domain_t)", analyze<z_sdbm_domain_t> } },
    { "boxes"             , { "boxes (z_boxes_domain_t)", analyze<z_boxes_domain_t> } },
    { "disj_interval"     , { "disjoint intervals (z_dis_interval_domain_t)", analyze<z_dis_interval_domain_t> } },
    { "box_apron"         , { "boxes x apron (z_box_apron_domain_t)", analyze<z_box_apron_domain_t> } },
    { "opt_oct_apron"     , { "optional octagon x apron (z_opt_oct_apron_domain_t)", analyze<z_opt_oct_apron_domain_t> } },
    { "pk_apron"          , { "(z_pk_apron_domain_t)", analyze<z_pk_apron_domain_t> } },
    { "term"              , { "(z_term_domain_t)", analyze<z_term_domain_t> } },
    { "term_dbm"          , { "(z_term_dbm_t)", analyze<z_term_dbm_t> } },
    { "term_disj_interval", { "term x disjoint intervals (z_term_dis_int_t)", analyze<z_term_dis_int_t> } },
    { "num"               , { "term x disjoint interval x sparse dbm (z_num_domain_t)", analyze<z_num_domain_t> } },
    { "none"              , { "build CFG only, don't perform analysis", dont_analyze } },
};

void print_domains()
{
    for (auto const [name, desc] : domains)
        printf("\t%s - %s\n", name.c_str(), desc.description.c_str());
}

bool is_valid_domain(const char* domain_name)
{
    return domains.count(domain_name) > 0;
}

bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, const char* domain_name, char** errmsg)
{
    cfg_t cfg(entry_label(), ARR);
    build_cfg(cfg, {insts, insts + num_insts});

    printer_t printer;
    printer.connect([&cfg](const std::string label){
        cfg.get_node(label).write(crab::outs());
    });

    checks_db checks = domains.at(domain_name).analyze(cfg, printer);
    int nwarn = checks.get_total_warning() + checks.get_total_error();
    
    for (basic_block_t& block : sorted_blocks(cfg)) {
        printer(block.label());
    }

    if (nwarn > 0) {
        checks.write(crab::outs());
        *errmsg = ubpf_error("Assertion violation");
        return false;
    }
    return true;
}
