#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <iostream>
#include <optional>

#include "common.hpp"
#include "crab_constraints.hpp"
#include "crab_cfg.hpp"
#include "verifier.hpp"
#include "asm.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;

void build_cfg(cfg_t& cfg, variable_factory_t& vfac, const Program& prog, ebpf_prog_type prog_type)
{
    abs_machine_t machine(prog_type, vfac);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
        entry >> cfg.insert(label(0));
    }
    Cfg simple_cfg = to_nondet(build_cfg(prog));
    for (auto const& [this_label, bb] : simple_cfg) {
        basic_block_t& this_block = cfg.insert(this_label);
        std::cout << "!: " << this_label << " -- " << bb.insts.size() << "\n";
        basic_block_t& exit = bb.insts.size() == 0 ? this_block : cfg.insert(exit_label(this_label));
        for (auto ins : bb.insts) {
            vector<basic_block_t*> outs = machine.exec(ins, this_block, cfg);
            for (basic_block_t* b : outs)
                (*b) >> exit;
        }
        if (bb.nextlist.size() == 0) {
            cfg.set_exit(exit.label());
        } else {
            for (auto label : bb.nextlist)
                exit >> cfg.insert(label);
        }
    }
    if (global_options.simplify) {
        cfg.simplify();
    }
}

vector<string> sorted_labels(cfg_t& cfg)
{
    vector<string> labels;
    for (const auto& block : cfg)
        labels.push_back(block.label());

    std::sort(labels.begin(), labels.end(), [](string a, string b){
        if (first_num(a) < first_num(b)) return true;
        if (first_num(a) > first_num(b)) return false;
        return a < b;
    });
    return labels;
}
