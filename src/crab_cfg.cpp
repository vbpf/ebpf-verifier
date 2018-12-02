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

static auto build_jump(cfg_t& cfg, pc_t pc, Label target, bool taken) -> basic_block_t&
{
    // distinguish taken and non-taken, in case we jump to the fallthrough
    // (yes, it happens).
    basic_block_t& assumption = cfg.insert(label(pc) + ":" + target + ":" + (taken ? "taken" : "not-taken"));
    cfg.get_node(exit_label(pc)) >> assumption;
    return assumption;
}

static void link(cfg_t& cfg, pc_t pc, Label target)
{
    cfg.get_node(exit_label(pc)) >> cfg.insert(target);
}

void build_cfg(cfg_t& cfg, variable_factory_t& vfac, const Program& prog, ebpf_prog_type prog_type)
{
    abs_machine_t machine(prog_type, vfac);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
        entry >> cfg.insert(label(0));
    }
    Cfg simple_cfg = build_cfg(prog);
    for (auto const& [this_label, bb] : simple_cfg) {
        pc_t pc = label_to_pc(this_label);
        for (auto ins : bb.insts) {
            basic_block_t& exit = cfg.insert(exit_label(pc));
            vector<basic_block_t*> outs = machine.exec(ins, cfg.insert(this_label), cfg);
            for (basic_block_t* b : outs)
                (*b) >> exit;
        }
        switch (bb.nextlist.size()) {
            case 0:
                cfg.set_exit(exit_label(pc));
                continue;
            case 1:
                link(cfg, pc, bb.nextlist[0]);
                break;
            case 2: {
                auto jmp = std::get<Jmp>(bb.insts.back());

                machine.jump(jmp, true, build_jump(cfg, pc, bb.nextlist[1], true),
                    cfg) >> cfg.insert(bb.nextlist[1]);

                machine.jump(jmp, false, build_jump(cfg, pc, bb.nextlist[0], false),
                    cfg) >> cfg.insert(bb.nextlist[0]);
                break;
            }
            default: assert(false);
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
