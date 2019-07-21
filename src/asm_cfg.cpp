#include <assert.h>
#include <inttypes.h>

#include <algorithm>
#include <iostream>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "asm_cfg.hpp"
#include "asm_ostream.hpp"
#include "crab_constraints.hpp"

using std::list;
using std::optional;
using std::set;
using std::string;
using std::to_string;
using std::vector;

static optional<label_t> get_jump(Instruction ins) {
    if (std::holds_alternative<Jmp>(ins)) {
        return std::get<Jmp>(ins).target;
    }
    return {};
}

static bool has_fall(Instruction ins) {
    if (std::holds_alternative<Exit>(ins))
        return false;

    if (std::holds_alternative<Jmp>(ins) && !std::get<Jmp>(ins).cond)
        return false;

    return true;
}

Cfg instruction_seq_to_cfg(const InstructionSeq& insts) {
    Cfg cfg("0");
    std::optional<label_t> falling_from = {};
    for (const auto& [label, inst] : insts) {

        if (std::holds_alternative<Undefined>(inst))
            continue;

        auto& bb = cfg.insert(label);
        bb.insert(inst);
        if (falling_from) {
            cfg.get_node(*falling_from) >> bb;
            falling_from = {};
        }
        if (has_fall(inst))
            falling_from = label;
        auto jump_target = get_jump(inst);
        if (jump_target)
            bb >> cfg.insert(*jump_target);
    }
    if (falling_from)
        throw std::invalid_argument{"fallthrough in last instruction"};
    return cfg;
}

static Condition::Op reverse(Condition::Op op) {
    switch (op) {
    case Condition::Op::EQ: return Condition::Op::NE;
    case Condition::Op::NE: return Condition::Op::EQ;

    case Condition::Op::GE: return Condition::Op::LT;
    case Condition::Op::LT: return Condition::Op::GE;

    case Condition::Op::SGE: return Condition::Op::SLT;
    case Condition::Op::SLT: return Condition::Op::SGE;

    case Condition::Op::LE: return Condition::Op::GT;
    case Condition::Op::GT: return Condition::Op::LE;

    case Condition::Op::SLE: return Condition::Op::SGT;
    case Condition::Op::SGT: return Condition::Op::SLE;

    case Condition::Op::SET: return Condition::Op::NSET;
    case Condition::Op::NSET: return Condition::Op::SET;
    }
    assert(false);
    return {};
}

static Condition reverse(Condition cond) { return {.op = reverse(cond.op), .left = cond.left, .right = cond.right}; }

template <typename T>
static vector<label_t> unique(const std::pair<T, T>& be) {
    vector<label_t> res;
    std::unique_copy(be.first, be.second, std::back_inserter(res));
    return res;
}

static vector<Instruction> expand_lockadd(LockAdd lock) {
    return {Mem{
                .access = lock.access,
                .value = Reg{11},
                .is_load = true,
            },
            Bin{
                .op = Bin::Op::ADD,
                .is64 = true,
                .dst = Reg{11},
                .v = lock.valreg,
            },
            Mem{
                .access = lock.access,
                .value = Reg{11},
                .is_load = false,
            }};
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

static label_t pop(set<label_t>& s) {
    label_t l = *s.begin();
    s.erase(l);
    return l;
}

Cfg to_nondet(const Cfg& cfg) {
    Cfg res(cfg.entry());
    for (auto const& [this_label, bb] : cfg) {
        BasicBlock& newbb = res.insert(this_label);

        for (auto ins : bb) {
            if (!std::holds_alternative<Jmp>(ins)) {
                newbb.insert(ins);
            }
        }

        auto [pb, pe] = bb.prev_blocks();
        for (label_t prev_label : vector<label_t>(pb, pe)) {
            bool is_one = unique(cfg.get_node(prev_label).next_blocks()).size() > 1;
            BasicBlock& pbb = res.insert(is_one ? prev_label + ":" + this_label : prev_label);
            pbb >> newbb;
        }
        // note the special case where we jump to fallthrough
        auto nextlist = unique(bb.next_blocks());
        if (nextlist.size() == 2) {
            label_t mid_label = this_label + ":";
            Condition cond = *std::get<Jmp>(*bb.rbegin()).cond;
            vector<std::tuple<label_t, Condition>> jumps{
                {*bb.next_blocks().first, cond},
                {*std::next(bb.next_blocks().first), reverse(cond)},
            };
            for (auto const& [next_label, cond] : jumps) {
                label_t l = mid_label + next_label;
                BasicBlock& bb = res.insert(l);
                bb.insert<Assume>(cond);
                newbb >> bb;
                bb >> res.insert(next_label);
            }
        } else {
            for (auto label : nextlist)
                newbb >> res.insert(label);
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
            if (std::all_of(call.singles.begin(), call.singles.end(),
                            [](ArgSingle kr) { return kr.kind == ArgSingle::Kind::ANYTHING; })) {
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
        if (std::get<Bin>(ins).op == Bin::Op::MOV)
            return "assign";
        return "arith";
    } else if (std::holds_alternative<Un>(ins)) {
        return "arith";
    } else if (std::holds_alternative<LoadMapFd>(ins)) {
        return "assign";
    } else if (std::holds_alternative<Assume>(ins)) {
        return "assume";
    } else {
        return "other";
    }
}

std::vector<std::string> stats_headers() {
    return {
        //"instructions",
        "basic_blocks", "joins",       "other",      "jump",          "assign",  "arith",
        "load",         "store",       "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "adjust_head", "map_in_map", "arith64",       "arith32",
    };
}

std::map<std::string, int> collect_stats(const Cfg& cfg) {
    std::map<std::string, int> res;
    for (auto h : stats_headers()) {
        res[h] = 0;
    }
    for (auto const& [this_label, _] : cfg) {
        res["basic_blocks"]++;
        BasicBlock const& bb = cfg.get_node(this_label);
        res["instructions"] += bb.size();
        for (Instruction ins : bb) {
            if (std::holds_alternative<LoadMapFd>(ins)) {
                if (std::get<LoadMapFd>(ins).mapfd == -1) {
                    res["map_in_map"] = 1;
                }
            }
            if (std::holds_alternative<Call>(ins)) {
                auto call = std::get<Call>(ins);
                if (call.func == 43 || call.func == 44)
                    res["adjust_head"] = 1;
            }
            if (std::holds_alternative<Bin>(ins)) {
                auto bin = std::get<Bin>(ins);
                res[bin.is64 ? "arith64" : "arith32"]++;
            }
            res[instype(ins)]++;
        }
        if (unique(bb.prev_blocks()).size() > 1)
            res["joins"]++;
        if (unique(bb.prev_blocks()).size() > 1)
            res["jumps"]++;
    }
    return res;
}
