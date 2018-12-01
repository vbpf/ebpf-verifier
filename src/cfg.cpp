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


using pc_t = uint16_t;

static auto get_jump(Instruction ins, pc_t pc) -> optional<pc_t>
{
    if (std::holds_alternative<Jmp>(ins)) {
        return pc + 1 + std::get<Jmp>(ins).offset;
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

static auto build_jump(cfg_t& cfg, pc_t pc, pc_t target, bool taken) -> basic_block_t&
{
    // distinguish taken and non-taken, in case we jump to the fallthrough
    // (yes, it happens).
    basic_block_t& assumption = cfg.insert(label(pc, target) + ":" + (taken ? "taken" : "not-taken"));
    cfg.get_node(exit_label(pc)) >> assumption;
    return assumption;
}

static void link(cfg_t& cfg, pc_t pc, pc_t target)
{
    cfg.get_node(exit_label(pc)) >> cfg.insert(label(target));
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

    // TODO: move to where it should be
    if (global_options.check_raw_reachability) {
        if (!check_raw_reachability(prog)) {
            std::cerr << "No support for forests yet\n";
        }
    }

    abs_machine_t machine(prog_type, vfac);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
        entry >> cfg.insert(label(0));
    }
    auto& insts = prog.code;
    for (pc_t pc = 0; pc < insts.size(); pc++) {
        Instruction ins = insts[pc];
        vector<basic_block_t*> outs = machine.exec(ins, cfg.insert(label(pc)), cfg);
        basic_block_t& exit = cfg.insert(exit_label(pc));
        for (basic_block_t* b : outs)
            (*b) >> exit;

        if (std::holds_alternative<Exit>(ins)) {
            cfg.set_exit(exit_label(pc));
            continue;
        }

        optional<pc_t> jump_target = get_jump(ins, pc);
        optional<pc_t> fall_target = get_fall(ins, pc);
        if (jump_target) {
            if (std::holds_alternative<Jmp>(ins))  {
                auto& assumption = build_jump(cfg, pc, *jump_target, true);
                basic_block_t& out = machine.jump(std::get<Jmp>(ins), true, assumption, cfg);
                out >> cfg.insert(label(*jump_target));
            } else {
                link(cfg, pc, *jump_target);
            }
        }
        
        if (fall_target) {
            if (jump_target) {
                auto& assumption = build_jump(cfg, pc, *fall_target, false);
                basic_block_t& out = machine.jump(std::get<Jmp>(ins), false, assumption, cfg);
                out >> cfg.insert(label(*fall_target));
            } else {
                link(cfg, pc, *fall_target);
            }
            // skip imm of lddw
            pc = *fall_target - 1;
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
