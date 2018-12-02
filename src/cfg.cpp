#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <iostream>
#include <optional>

#include "common.hpp"
#include "constraints.hpp"
#include "cfg.hpp"
#include "verifier.hpp"
#include "asm.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;

static auto get_jump(Instruction ins, pc_t pc) -> optional<pc_t>
{
    if (std::holds_alternative<Jmp>(ins)) {
        return label_to_pc(std::get<Jmp>(ins).target);
    }
    return {};
}

static auto get_fall(Instruction ins, pc_t pc) -> optional<pc_t>
{
    if (std::holds_alternative<Bin>(ins)
        && std::get<Bin>(ins).lddw) {
        return pc + 2;
    }
    if (std::holds_alternative<Exit>(ins)) {
        return {};
    }
    if (std::holds_alternative<Jmp>(ins)) {
        if (!std::get<Jmp>(ins).cond)
            return {};
    }
    return pc + 1;
}

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

bool check_raw_reachability(const Program& prog)
{
    auto& insts = prog.code;
    std::unordered_set<pc_t> unreachables;
    for (pc_t i=1; i < insts.size(); i++)
        unreachables.insert(i);

    for (pc_t pc = 0; pc < insts.size(); pc++) {
        Instruction ins = insts[pc];
        optional<pc_t> jump_target = get_jump(ins, pc);
        optional<pc_t> fall_target = get_fall(ins, pc);
        if (jump_target) {
            unreachables.erase(*jump_target);
        }
        
        if (fall_target) {
            unreachables.erase(*fall_target);
            if (*fall_target == pc + 2)
                unreachables.erase(++pc);
        }
    }
    return unreachables.size() == 0;
}

void print_stats(const Program& prog) {
    auto& insts = prog.code;
    int count = 0;
    int stores = 0;
    int loads = 0;
    int jumps = 0;
    vector<int> reaching(insts.size());
    for (pc_t pc = 0; pc < insts.size(); pc++) {
        Instruction ins = insts[pc];
        count++;
        if (std::holds_alternative<Mem>(ins)) {
            auto mem = std::get<Mem>(ins);
            if (mem.isLoad())
                loads++;
            else
                stores++;
        }
        optional<pc_t> jump_target = get_jump(ins, pc);
        optional<pc_t> fall_target = get_fall(ins, pc);
        if (jump_target) {
            reaching[*jump_target]++;
            jumps++;
        }
        if (fall_target) {
            reaching[*fall_target]++;
            pc = *fall_target - 1;
        }
    }
    int joins = 0;
    for (int n : reaching)
        if (n > 1) joins++;

    std::cout << "instructions:" << count << "\n";
    std::cout << "loads:" << loads << "\n";
    std::cout << "stores:" << stores << "\n";
    std::cout << "jumps:" << jumps << "\n";
    std::cout << "joins:" << joins << "\n";
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
