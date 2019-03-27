#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <set>
#include <list>
#include <iostream>
#include <optional>
#include <iostream>

#include "asm_cfg.hpp"
#include "asm_ostream.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;
using std::set;
using std::list;

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
    const auto link = [&cfg](Label from, Label to) {
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
    assert(false);
    return {};
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

static vector<Instruction> expand_lockadd(LockAdd lock) {
    return {
        Mem {
            .access = lock.access,
            .value = Reg{11},
            .is_load = true,
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
            .is_load = false,
        }
    };
}

static vector<Instruction> do_expand_locks(vector<Instruction> const& insts) {
    vector<Instruction> res;
    for (Instruction ins : insts) {
        if (std::holds_alternative<LockAdd>(ins)) {
            for (auto ins : expand_lockadd(std::get<LockAdd>(ins))) {
                res.push_back(ins);
            }
        } else {
            res.push_back(ins);
        }
    }
    return res;
}


static Label pop(set<Label>& s) {
    Label l = *s.begin();
    s.erase(l);
    return l;
}

void Cfg::simplify() {
    set<Label> worklist(keys().begin(), keys().end());
    while (!worklist.empty()) {
        Label label = pop(worklist);
        BasicBlock& bb = graph[label];
        while (bb.nextlist.size() == 1) {
            Label next_label = bb.nextlist.back();
            BasicBlock& next_bb = graph[next_label];
            if (&next_bb == &bb || next_bb.prevlist.size() != 1) {
                break;
            }
            bb.nextlist = std::move(next_bb.nextlist);
            for (Instruction inst : next_bb.insts) {
                bb.insts.push_back(inst);
            }
            worklist.erase(next_label);
            graph.erase(next_label);

            // reconnect
            for (auto l : bb.nextlist) {
                for (auto& p : graph[l].prevlist)
                    if (p == next_label)
                        p = label;
            }
        }
    }
    ordered_labels.erase(
        std::remove_if(
            ordered_labels.begin(), ordered_labels.end(),
            [&](auto& x) { return !graph.count(x); }
        ),
        ordered_labels.end()
    );
}

Cfg Cfg::to_nondet(bool expand_locks) const {
    Cfg res;
    for (auto const& this_label : this->keys()) {
        BasicBlock const& bb = this->at(this_label);
        res.encountered(this_label);
        BasicBlock& newbb = res[this_label];

        for (auto ins : expand_locks ? do_expand_locks(bb.insts) : bb.insts) {
            if (!std::holds_alternative<Jmp>(ins)) {
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


static std::string instype(Instruction ins) {
    if (std::holds_alternative<Call>(ins)) {
        auto call = std::get<Call>(ins);
        if (call.returns_map) {
            return "call_1";
        }
        if (call.pairs.empty()) {
            if (std::all_of(call.singles.begin(), call.singles.end(), [](ArgSingle kr) { return kr.kind == ArgSingle::Kind::ANYTHING; })) {
                return "call_nomem";
            }
        }
        return "call_mem";
    } else if (std::holds_alternative<Mem>(ins)) {
        return std::get<Mem>(ins).is_load ? "load" : "store";
    } else if (std::holds_alternative<LockAdd>(ins)) {
        return "load_store";
    } else if (std::holds_alternative<Packet>(ins)) {
        return "packet_access";
    } else if (std::holds_alternative<Bin>(ins)) {
        return "arith";
    } else if (std::holds_alternative<Un>(ins)) {
        return "arith";
    } else if (std::holds_alternative<LoadMapFd>(ins)) {
        return "arith";
    } else if (std::holds_alternative<Assume>(ins)) {
        return "assume";
    } else {
        return "other";
    }
}

std::vector<std::string> Cfg::stats_headers() {
    return {
        //"instructions",
        "basic_blocks",
        "joins",
        "other",
        "jump",
        "arith",
        "load",
        "store",
        "load_store",
        "packet_access",
        "call_1",
        "call_mem",
        "call_nomem"
    };
}

std::map<std::string, int> Cfg::collect_stats() const {
    std::map<std::string, int> res;
    for (auto h : stats_headers()) {
        res[h] = 0;
    }
    res["basic_blocks"] = graph.size();
    for (Label const& this_label : keys()) {
        BasicBlock const& bb = at(this_label);
        res["instructions"] += bb.insts.size();
        for (Instruction ins : bb.insts)
            res[instype(ins)]++;
        if (bb.prevlist.size() > 1)
            res["joins"]++;
        if (bb.nextlist.size() > 1)
            res["jumps"]++;
    }
    return res;
}
