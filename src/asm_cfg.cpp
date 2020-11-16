#include <cassert>

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "crab/cfg.hpp"

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

/// Convert an instruction sequence to a control-flow graph (CFG).
static cfg_t instruction_seq_to_cfg(const InstructionSeq& insts) {
    string exit_label;
    for (const auto& [label, inst] : insts) {
        if (std::holds_alternative<Exit>(inst))
            exit_label = label;
    }
    if (exit_label.empty())
        throw std::runtime_error("no exit");
    cfg_t cfg("0", exit_label);
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

/// Get the inverse of a given comparison operation.
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

/// Get the inverse of a given comparison condition.
static Condition reverse(Condition cond) { return {.op = reverse(cond.op), .left = cond.left, .right = cond.right}; }

template <typename T>
static vector<label_t> unique(const std::pair<T, T>& be) {
    vector<label_t> res;
    std::unique_copy(be.first, be.second, std::back_inserter(res));
    return res;
}

/// Get a non-deterministic version of a control-flow graph,
/// i.e., where instead of using if/else, both branches are taken
/// simultaneously, and are replaced by Assume instructions
/// immediately after the branch.
static cfg_t to_nondet(const cfg_t& cfg) {
    cfg_t res(cfg.entry(), cfg.exit());
    for (auto const& [this_label, bb] : cfg) {
        basic_block_t& newbb = res.insert(this_label);

        for (const auto& ins : bb) {
            if (!std::holds_alternative<Jmp>(ins)) {
                newbb.insert(ins);
            }
        }

        auto [pb, pe] = bb.prev_blocks();
        for (const label_t& prev_label : vector<label_t>(pb, pe)) {
            bool is_one = unique(cfg.get_node(prev_label).next_blocks()).size() > 1;
            basic_block_t& pbb = res.insert(is_one ? prev_label + ":" + this_label : prev_label);
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
            for (auto const& [next_label, cond1] : jumps) {
                label_t l = mid_label + next_label;
                basic_block_t& bb1 = res.insert(l);
                bb1.insert<Assume>(cond1);
                newbb >> bb1;
                bb1 >> res.insert(next_label);
            }
        } else {
            for (const auto& label : nextlist)
                newbb >> res.insert(label);
        }
    }
    return res;
}

/// Get the type of a given instruction.
/// Most of these type names are also statistics header labels.
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
        "basic_blocks", "joins",       "other",      "jumps",         "assign",  "arith",
        "load",         "store",       "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "adjust_head", "map_in_map", "arith64",       "arith32",
    };
}

std::map<std::string, int> collect_stats(const cfg_t& cfg) {
    std::map<std::string, int> res;
    for (const auto& h : stats_headers()) {
        res[h] = 0;
    }
    for (const auto& this_label : cfg.labels()) {
        res["basic_blocks"]++;
        basic_block_t const& bb = cfg.get_node(this_label);
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

cfg_t prepare_cfg(const InstructionSeq& prog, const program_info& info, bool simplify) {
    // Convert the instruction sequence to a deterministic control-flow graph.
    cfg_t det_cfg = instruction_seq_to_cfg(prog);

    // Annotate the CFG by adding in assertions before every memory instruction.
    explicate_assertions(det_cfg, info);

    // Translate conditional jumps to non-determinstic jumps.
    cfg_t cfg = to_nondet(det_cfg);

    // Except when debugging, combine chains of instructions into
    // basic blocks where possible, i.e., into a range of instructions
    // where there is a single entry point and a single exit point.
    // An abstract interpreter will keep values at every basic block,
    // so the fewer basic blocks we have, the less information it has to
    // keep track of.
    if (simplify) {
        cfg.simplify();
    }

    return cfg;
}
