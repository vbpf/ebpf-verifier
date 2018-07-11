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
#include <sstream>

#include <boost/optional.hpp>
#include <boost/lexical_cast.hpp>

#include <crab/checkers/base_property.hpp>
#include <crab/checkers/div_zero.hpp>
#include <crab/checkers/assertion.hpp>
#include <crab/checkers/checker.hpp>
#include <crab/analysis/dataflow/assumptions.hpp>
#include <crab/domains/wrapped_interval_domain.hpp>
#include <crab/domains/array_sparse_graph.hpp>
#include <crab/domains/dis_intervals.hpp>
#include <crab/domains/wrapped_interval_domain.hpp>
#include <crab/domains/sparse_dbm.hpp>
#include <crab/domains/split_dbm.hpp>


#include "ebpf.h"

#include "crab_lang.hpp"
#include "crab_dom.hpp"

#include "abs_common.hpp"
//#include "abs_constraints.hpp"
#include "abs_interp.h"
#include "abs_cfg.hpp"

using namespace crab::cfg;
using namespace crab::checker;
using namespace crab::analyzer;
using namespace crab::domains;
using namespace crab::domain_impl;
using cfg_ref_t = cfg_ref<cfg_t>;

using dom_t = z_dis_interval_domain_t; // z_num_domain_t;
using analyzer_t = intra_fwd_analyzer<cfg_ref_t, dom_t>;
using checker_t = intra_checker<analyzer_t>;
using prop_checker_ptr = checker_t::prop_checker_ptr;

static int first_num(basic_block_t& b)
{
    return boost::lexical_cast<int>(b.label().substr(0, b.label().find_first_of('-')));
}

static int analyze(cfg_t& cfg)
{
    liveness<cfg_ref_t> live(cfg);
    live.exec();
    analyzer_t analyzer(cfg, dom_t::top(), &live, 1, 2, 20);
    typename analyzer_t::assumption_map_t assumptions;
    analyzer.run(label(0), assumptions);

    std::vector<std::reference_wrapper<basic_block_t>> blocks(cfg.begin(), cfg.end());
    std::sort(blocks.begin(), blocks.end(), [](basic_block_t& a, basic_block_t& b){
        return first_num(a) < first_num(b);
    });
    
    crab::outs() << "Invariants:\n";
    for (basic_block_t& block : blocks) {
        auto inv = analyzer[block.label()];
        crab::outs() << "\n" << inv << "\n";
        block.write(crab::outs());
    }

    const int verbose = 2;
    prop_checker_ptr assertions(new assert_property_checker<analyzer_t>(verbose));
    prop_checker_ptr div_zero(new div_zero_property_checker<analyzer_t>(verbose));
    checker_t checker(analyzer, {
        assertions
        , div_zero
    });
    checker.run();
    auto checks = checker.get_all_checks();
    return checks.get_total_warning() + checks.get_total_error();
    //auto &wto = analyzer.get_wto();
    //crab::outs () << "Abstract trace: " << wto << "\n";
}

bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg)
{
    cfg_t cfg(label(0), ARR);
    build_cfg(cfg, {insts, insts + num_insts});
    int nwarn = analyze(cfg);

    if (nwarn > 0) {
        *errmsg = (char*)calloc(sizeof("Assertion violation"), 1);
        strcpy(*errmsg, "Assertion violation");
        return false;
    }
    return true;
}
