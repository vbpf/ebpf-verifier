#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <iostream>
#include <optional>
#include <iostream>

#include "asm.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;


static optional<Label> get_jump(Instruction ins) {
    if (std::holds_alternative<Jmp>(ins)) {
        return std::get<Jmp>(ins).target;
    }
    return {};
}

static bool has_fall(Instruction ins) {
    if (std::holds_alternative<Exit>(ins))
        return false;

    if (std::holds_alternative<Jmp>(ins)
        && !std::get<Jmp>(ins).cond)
            return false;

    return true;
}

static void link(Cfg& cfg, Label from, Label to) {
    cfg[from].nextlist.push_back(to);
    cfg[to].prevlist.push_back(from);
}

Cfg build_cfg(const InstructionSeq& insts) {
    Cfg cfg;
    std::optional<Label> falling_from = {};
    for (const auto& [label, inst] : insts) {

        if (std::holds_alternative<Undefined>(inst))
            continue;

        // create cfg[label] if not exists
        cfg[label].insts = {inst};
        if (falling_from) {
            link(cfg, *falling_from, label);
            falling_from = {};
        }
        if (has_fall(inst))
            falling_from = label;
        auto jump_target = get_jump(inst);
        if (jump_target)
            link(cfg, label, *jump_target);
    }
    if (falling_from) throw std::invalid_argument{"fallthrough in last instruction"};
    return cfg;
}

static Condition::Op reverse(Condition::Op op) {
    switch (op) {
    case Condition::Op::EQ : return Condition::Op::NE;
    case Condition::Op::NE : return Condition::Op::EQ;

    case Condition::Op::GE : return Condition::Op::LT;
    case Condition::Op::LT : return Condition::Op::GE;
    
    case Condition::Op::SGE: return Condition::Op::SLT;
    case Condition::Op::SLT: return Condition::Op::SGE;

    case Condition::Op::LE : return Condition::Op::GT;
    case Condition::Op::GT : return Condition::Op::LE;

    case Condition::Op::SLE: return Condition::Op::SGT;
    case Condition::Op::SGT: return Condition::Op::SLE;

    case Condition::Op::SET: return Condition::Op::NSET;
    case Condition::Op::NSET: return Condition::Op::SET;
    }
}

static Condition reverse(Condition cond) {
    return {
        .op=reverse(cond.op),
        .left=cond.left,
        .right=cond.right
    };
}

static vector<Label> unique(const vector<Label>& v) {
    vector<Label> res;
    std::unique_copy(v.begin(), v.end(), std::back_inserter(res));
    return res;
}

static vector<Instruction> expand_lockadd(LockAdd lock)
{
    return {
        Mem {
            Deref {
                .width = lock.access.width,
                .basereg = lock.access.basereg,
                .offset = 0,
            },
            .value = Reg{11},
            ._is_load = true,
        },
        Bin {
            .op = Bin::Op::ADD,
            .is64 = false,
            .dst = Reg{11},
            .v = Imm(lock.access.offset),
        },
        Mem {
            Deref {
                .width = lock.access.width,
                .basereg = lock.access.basereg,
                .offset = 0,
            },
            .value = Reg{11},
            ._is_load = false,
        }
    };
}

Cfg to_nondet(const Cfg& simple_cfg) {
    Cfg res;
    for (auto const& [this_label, bb] : simple_cfg) {
        BasicBlock& newbb = res[this_label];

        for (auto ins : bb.insts) {
            if (std::holds_alternative<LockAdd>(ins))
                expand_lockadd(std::get<LockAdd>(ins));
            if (!std::holds_alternative<Jmp>(ins))
                newbb.insts.push_back(ins);
        }

        for (Label prev_label : bb.prevlist) {
            newbb.prevlist.push_back(
                unique(simple_cfg.at(prev_label).nextlist).size() > 1
                ? prev_label + ":" + this_label
                : prev_label
            );
        }
        // note the special case where we jump to fallthrough
        auto nextlist = unique(bb.nextlist);
        if (nextlist.size() == 2) {
            Label mid_label = this_label + ":";
            Condition cond = *std::get<Jmp>(bb.insts.back()).cond;
            vector<std::tuple<Label, Condition>> jumps{
                {bb.nextlist[0], reverse(cond)},
                {bb.nextlist[1], cond},
            };
            for (auto const& [next_label, cond] : jumps) {
                newbb.nextlist.push_back(mid_label + next_label);
                res[mid_label + next_label] = BasicBlock{
                    {Assume{cond}},
                    {next_label},
                    {this_label}
                };
            }
        } else {
            newbb.nextlist = nextlist;
        }
    }
    return res;
}

void print_stats(const Cfg& cfg) {
    int count = 0;
    int stores = 0;
    int loads = 0;
    int jumps = 0;
    int joins = 0;
    for (auto const& [this_label, bb] : cfg) {
        Instruction ins = bb.insts[0];
        count++;
        if (std::holds_alternative<Mem>(ins)) {
            auto mem = std::get<Mem>(ins);
            if (mem.isLoad())
                loads++;
            else
                stores++;
        }
        if (bb.prevlist.size() > 1)
            joins++;
        if (bb.nextlist.size() > 1)
            jumps++;
    }
    std::cout << "instructions:" << count << "\n";
    std::cout << "loads:" << loads << "\n";
    std::cout << "stores:" << stores << "\n";
    std::cout << "jumps:" << jumps << "\n";
    std::cout << "joins:" << joins << "\n";
}
