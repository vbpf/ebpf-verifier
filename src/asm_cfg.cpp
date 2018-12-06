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

#include "asm_cfg.hpp"
#include "asm_ostream.hpp"

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


Cfg Cfg::make(const InstructionSeq& insts) {
    Cfg cfg;
    const auto link = [&](Label from, Label to) {
        cfg[from].nextlist.push_back(to);
        cfg[to].prevlist.push_back(from);
    };
    std::optional<Label> falling_from = {};
    for (const auto& [label, inst] : insts) {

        if (std::holds_alternative<Undefined>(inst))
            continue;

        // create cfg[label] if not exists
        cfg.encountered(label);
        cfg[label].insts = {inst};
        if (falling_from) {
            link(*falling_from, label);
            falling_from = {};
        }
        if (has_fall(inst))
            falling_from = label;
        auto jump_target = get_jump(inst);
        if (jump_target)
            link(label, *jump_target);
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
            .access = lock.access,
            .value = Reg{11},
            ._is_load = true,
        },
        Bin {
            .op = Bin::Op::ADD,
            .is64 = true,
            .dst = Reg{11},
            .v = lock.valreg,
        },
        Mem {
            .access = lock.access,
            .value = Reg{11},
            ._is_load = false,
        }
    };
}

static int access_width(Width w)
{
    switch (w) {
        case Width::B: return 1;
        case Width::H: return 2;
        case Width::W: return 4;
        case Width::DW: return 8;
    }
	assert(false);
}

Assert extract_assertions(Instruction ins) {
    return std::visit(overloaded{
        [](auto ins) -> Assert { return {}; },
        [](Mem ins) -> Assert { 
            Assert res;
            Reg reg = ins.access.basereg;
            int width = access_width(ins.access.width);
            int offset = ins.access.offset;
            if (reg.v != 10) {
                res.holds.push_back({reg, Type::PTR});
                res.implies.emplace_back(Assert::Typeof{reg, Type::MAP   }, reg, offset, width, (Value)Imm{4098});
                res.implies.emplace_back(Assert::Typeof{reg, Type::PACKET}, reg, offset, width, (Value)Reg{15});
            }
            res.implies.emplace_back(Assert::Typeof{reg, Type::STACK }, reg, offset, width, (Value)Imm{256});
            return res;
        },
        [](Bin ins) -> Assert { 
            switch (ins.op) {
                case Bin::Op::MOV: return { };
                case Bin::Op::ADD: {
                    Assert res; 
                    if (std::holds_alternative<Reg>(ins.v)) {
                        Reg reg = std::get<Reg>(ins.v);
                        res.implies_type.emplace_back(Assert::Typeof{ins.dst, Type::PTR}, Assert::Typeof{reg, Type::NUM});
                        res.implies_type.emplace_back(Assert::Typeof{reg, Type::NUM}, Assert::Typeof{ins.dst, Type::PTR});
                    }
                    return res;
                }
                case Bin::Op::SUB:{
                    Assert res; 
                    if (std::holds_alternative<Reg>(ins.v)) {
                        Reg reg = std::get<Reg>(ins.v);
                        res.holds.push_back({reg, Type::NUM});
                    }
                    return res;
                }
                default: {
                    Assert res;
                    res.holds.push_back({ins.dst, Type::NUM});
                    return res;
                }
            }
        },
    }, ins);
}

Cfg Cfg::to_nondet() {
    Cfg res;
    for (auto const& this_label : this->keys()) {
        BasicBlock const& bb = this->at(this_label);
        res.encountered(this_label);
        BasicBlock& newbb = res[this_label];

        for (auto ins : bb.insts) {
            auto assertion = extract_assertions(ins);
            if (assertion.holds.size() > 0 || assertion.implies_type.size() > 0 || assertion.implies.size() > 0)
                newbb.insts.push_back(assertion);
            if (std::holds_alternative<LockAdd>(ins)) {
                for (auto ins : expand_lockadd(std::get<LockAdd>(ins))) {
                    newbb.insts.push_back(ins);
                }
            } else if (!std::holds_alternative<Jmp>(ins)) {
                newbb.insts.push_back(ins);
            }
        }

        for (Label prev_label : bb.prevlist) {
            newbb.prevlist.push_back(
                unique(this->at(prev_label).nextlist).size() > 1
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
                {bb.nextlist[0], cond},
                {bb.nextlist[1], reverse(cond)},
            };
            for (auto const& [next_label, cond] : jumps) {
                Label l = mid_label + next_label;
                newbb.nextlist.push_back(l);
                res.encountered(l);
                res[l] = BasicBlock{
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
    for (Label const& this_label : cfg.keys()) {
        BasicBlock const& bb = cfg.at(this_label);
        for (Instruction ins : bb.insts) {
            count++;
            if (std::holds_alternative<Mem>(ins)) {
                auto mem = std::get<Mem>(ins);
                if (mem.isLoad())
                    loads++;
                else
                    stores++;
            }
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
