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

static auto get_jump(Instruction ins, pc_t pc) -> optional<Label>
{
    if (std::holds_alternative<Jmp>(ins)) {
        return std::get<Jmp>(ins).target;
    }
    return {};
}

static auto get_fall(Instruction ins, pc_t pc) -> optional<Label>
{
    if ((std::holds_alternative<Bin>(ins) && std::get<Bin>(ins).lddw)
        || std::holds_alternative<LoadMapFd>(ins))
        return std::to_string(pc + 2);

    if (std::holds_alternative<Exit>(ins))
        return {};
    if (std::holds_alternative<Undefined>(ins))
        return {};

    if (std::holds_alternative<Jmp>(ins)
        && !std::get<Jmp>(ins).cond)
            return {};

    return std::to_string(pc + 1);
}

static void link(Cfg& cfg, Label from, optional<Label> to) {
    if (to) {
        cfg[from].nextlist.push_back(*to);
        cfg[*to].prevlist.push_back(from);
    }
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

Cfg build_cfg(const Program& prog)
{
    Cfg cfg;
    for (pc_t pc = 0; pc < prog.code.size(); pc++) {
        Instruction ins = prog.code[pc];
        Label label = std::to_string(pc);

        if (std::holds_alternative<Undefined>(ins))
            continue;
        // create cfg[label] if not exists
        if (std::holds_alternative<LockAdd>(ins))
            cfg[label].insts = expand_lockadd(std::get<LockAdd>(ins));
        else
            cfg[label].insts = {ins};

        link(cfg, label, get_fall(ins, pc));
        link(cfg, label, get_jump(ins, pc));
    }
    return cfg;
}

static Condition::Op reverse(Condition::Op op)
{
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

static Condition reverse(Condition cond)
{
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

Cfg to_nondet(const Cfg& simple_cfg) {
    Cfg res;
    for (auto const& [this_label, bb] : simple_cfg) {
        BasicBlock& newbb = res[this_label];

        for (auto ins : bb.insts)
            if (!std::holds_alternative<Jmp>(ins))
                newbb.insts.push_back(ins);

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

void print_stats(const Program& prog) {
    Cfg cfg = build_cfg(prog);
    auto& insts = prog.code;
    int count = 0;
    int stores = 0;
    int loads = 0;
    int jumps = 0;
    int joins = 0;
    vector<int> reaching(insts.size());
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
