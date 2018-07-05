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

#include <boost/optional.hpp>

#include <crab/checkers/base_property.hpp>
#include <crab/checkers/null.hpp>
#include <crab/checkers/div_zero.hpp>
#include <crab/checkers/assertion.hpp>
#include <crab/checkers/checker.hpp>
#include <crab/analysis/dataflow/assertion_crawler.hpp>
#include <crab/analysis/dataflow/assumptions.hpp>

#include "abs_common.hpp"
#include "abs_cst_regs.hpp"
#include "abs_interp.h"
#include "abs_cfg.hpp"

using boost::optional;

using namespace crab;
using namespace crab::cfg;
using namespace crab::cfg_impl;
using namespace crab::checker;
using namespace crab::analyzer;
using cfg_ref_t = cfg_ref<cfg_t>;

static void analyze(cfg_t& cfg)
{
    liveness<cfg_ref_t> live(cfg);
    live.exec();
    crab::outs() << cfg << "\n";
   
    using dom_t = ikos::interval_domain<ikos::z_number, varname_t>;
    using analyzer_t = intra_fwd_analyzer<cfg_ref_t, dom_t>;
    dom_t inv = dom_t::top();
    analyzer_t analyzer(cfg, inv, &live, 1, 2, 20);
    typename analyzer_t::assumption_map_t assumptions;
    analyzer.run("0", assumptions);

    crab::outs() << "Invariants:\n";
    for (auto &block : cfg) {
        auto inv = analyzer[block.label()];
        crab::outs() << crab::cfg_impl::get_label_str(block.label()) << "=" << inv << "\n";
    }

    using checker_t = crab::checker::intra_checker<analyzer_t>;
    using assert_checker_t = crab::checker::assert_property_checker<analyzer_t>;
    const int verbose = 2;
    typename checker_t::prop_checker_ptr prop(new assert_checker_t(verbose));
    checker_t checker(analyzer, {prop});
    checker.run();
    checker.show(crab::outs());
    //auto &wto = analyzer.get_wto();
    //crab::outs () << "Abstract trace: " << wto << "\n";
}

bool abs_validate(const struct ebpf_inst *insts, uint32_t num_insts, char** errmsg)
{
    cfg_t cfg(label(0));
    build_cfg(cfg, {insts, insts + num_insts});
    analyze(cfg);
    return false;
}
