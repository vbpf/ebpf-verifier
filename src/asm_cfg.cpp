// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cassert>

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crab_utils/debug.hpp"
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

/// Update a control-flow graph to inline function macros.
static void add_cfg_nodes(cfg_t& cfg, label_t caller_label, label_t entry_label) {
    bool first = true;

    // Get the label of the node to go to on returning from the macro.
    basic_block_t& exit_to_node = cfg.get_node(cfg.next_nodes(caller_label).front());

    // Construct the variable prefix to use for the new stack frame,
    // and store a copy in the CallLocal instruction since the instruction-specific
    // labels may only exist until the CFG is simplified.
    basic_block_t& caller_node = cfg.get_node(caller_label);
    std::string stack_frame_prefix = to_string(caller_label);
    for (auto& inst : caller_node) {
        if (std::holds_alternative<CallLocal>(inst)) {
            std::get<CallLocal>(inst).stack_frame_prefix = stack_frame_prefix;
        }
    }

    // Walk the transitive closure of CFG nodes starting at entry_label and ending at
    // any exit instruction,
    std::list<label_t> macro_labels;
    macro_labels.push_back(entry_label);
    for (auto it = macro_labels.begin(); it != macro_labels.end(); it++) {
        label_t macro_label = *it;

        // Clone the macro block into a new block with the new stack frame prefix.
        const label_t label(macro_label.from, macro_label.to, stack_frame_prefix);
        auto& bb = cfg.insert(label);
        for (auto inst : cfg.get_node(macro_label)) {
            if (std::holds_alternative<Exit>(inst)) {
                std::get<Exit>(inst).stack_frame_prefix = label.stack_frame_prefix;
            } else if (std::holds_alternative<Call>(inst)) {
                std::get<Call>(inst).stack_frame_prefix = label.stack_frame_prefix;
            }
            bb.insert(inst);
        }

        if (first) {
            // Add an edge from the caller to the new block.
            first = false;
            caller_node >> bb;
        }

        // Add an edge from any other predecessors.
        const auto& prev_macro_nodes = cfg.prev_nodes(macro_label);
        for (const auto& prev_macro_label : prev_macro_nodes) {
            const label_t prev_label(prev_macro_label.from, prev_macro_label.to, to_string(caller_label));
            const auto& labels = cfg.labels();
            if (std::find(labels.begin(), labels.end(), prev_label) != labels.end())
                cfg.get_node(prev_label) >> bb;
        }

        // Walk all successor nodes.
        const auto& next_macro_nodes = cfg.next_nodes(macro_label);
        for (const auto& next_macro_label : next_macro_nodes) {
            if (next_macro_label == cfg.exit_label()) {
                // This is an exit transition, so add edge to the block to execute
                // upon returning from the macro.
                bb >> exit_to_node;
            } else if (std::find(macro_labels.begin(), macro_labels.end(), next_macro_label) == macro_labels.end()) {
                // Push any other unprocessed successor label onto the list to be processed.
                macro_labels.push_back(next_macro_label);
            }
        }
    }

    // Remove the original edge from the caller node to its successor,
    // since processing now goes through the function macro instead.
    caller_node -= exit_to_node;

    // Finally, recurse to replace any nested function macros.
    string caller_label_str = to_string(caller_label);
    int stack_frame_depth = std::count(caller_label_str.begin(), caller_label_str.end(), STACK_FRAME_DELIMITER) + 2;
    const int MAX_CALL_STACK_FRAMES = 8;
    for (auto& macro_label : macro_labels) {
        const label_t label(macro_label.from, macro_label.to, caller_label_str);
        for (const auto inst : cfg.get_node(label)) {
            if (std::holds_alternative<CallLocal>(inst)) {
                if (stack_frame_depth >= MAX_CALL_STACK_FRAMES)
                    throw std::runtime_error{"too many call stack frames"};
                add_cfg_nodes(cfg, label, std::get<CallLocal>(inst).target);
            }
        }
    }
}

/// Convert an instruction sequence to a control-flow graph (CFG).
static cfg_t instruction_seq_to_cfg(const InstructionSeq& insts, bool must_have_exit) {
    cfg_t cfg;
    std::optional<label_t> falling_from = {};
    bool first = true;

    // Do a first pass ignoring all function macro calls.
    for (const auto& [label, inst, _] : insts) {

        if (std::holds_alternative<Undefined>(inst))
            continue;

        auto& bb = cfg.insert(label);

        if (first) {
            first = false;
            cfg.get_node(cfg.entry_label()) >> bb;
        }

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

        if (std::holds_alternative<Exit>(inst))
            bb >> cfg.get_node(cfg.exit_label());
    }
    if (falling_from) {
        if (must_have_exit)
            throw std::invalid_argument{"fallthrough in last instruction"};
        else
            cfg.get_node(*falling_from) >> cfg.get_node(cfg.exit_label());
    }

    // Now replace macros. We have to do this as a second pass so that
    // we only add new nodes that are actually reachable, based on the
    // results of the first pass.
    for (auto& [label, inst, _] : insts) {
        if (std::holds_alternative<CallLocal>(inst)) {
            add_cfg_nodes(cfg, label, std::get<CallLocal>(inst).target);
        }
    }

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
static Condition reverse(Condition cond) { return {.op = reverse(cond.op), .left = cond.left, .right = cond.right, .is64 = cond.is64}; }

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
    cfg_t res;
    for (auto const& [this_label, bb] : cfg) {
        basic_block_t& newbb = res.insert(this_label);

        for (const auto& ins : bb) {
            if (!std::holds_alternative<Jmp>(ins)) {
                newbb.insert(ins);
            }
        }

        for (const label_t& prev_label : bb.prev_blocks_set()) {
            bool is_one = cfg.get_node(prev_label).next_blocks_set().size() > 1;
            basic_block_t& pbb = res.insert(is_one ? label_t::make_jump(prev_label, this_label) : prev_label);
            pbb >> newbb;
        }
        // note the special case where we jump to fallthrough
        auto nextlist = bb.next_blocks_set();
        if (nextlist.size() == 2) {
            label_t mid_label = this_label;
            Jmp jmp = std::get<Jmp>(*bb.rbegin());

            nextlist.erase(jmp.target);
            label_t fallthrough = *nextlist.begin();

            vector<std::tuple<label_t, Condition>> jumps{
                {jmp.target, *jmp.cond},
                {fallthrough, reverse(*jmp.cond)},
            };
            for (auto const& [next_label, cond1] : jumps) {
                label_t jump_label = label_t::make_jump(mid_label, next_label);
                basic_block_t& jump_bb = res.insert(jump_label);
                jump_bb.insert<Assume>(cond1);
                newbb >> jump_bb;
                jump_bb >> res.insert(next_label);
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
        if (call.is_map_lookup) {
            return "call_1";
        }
        if (call.pairs.empty()) {
            if (std::all_of(call.singles.begin(), call.singles.end(),
                            [](ArgSingle kr) { return kr.kind == ArgSingle::Kind::ANYTHING; })) {
                return "call_nomem";
            }
        }
        return "call_mem";
    } else if (std::holds_alternative<Callx>(ins)) {
        return "callx";
    } else if (std::holds_alternative<Mem>(ins)) {
        return std::get<Mem>(ins).is_load ? "load" : "store";
    } else if (std::holds_alternative<Atomic>(ins)) {
        return "load_store";
    } else if (std::holds_alternative<Packet>(ins)) {
        return "packet_access";
    } else if (std::holds_alternative<Bin>(ins)) {
        switch (std::get<Bin>(ins).op) {
        case Bin::Op::MOV:
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: return "assign";
        default: return "arith";
        }
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
        "basic_blocks", "joins",       "other",      "jumps",         "assign",  "arith",
        "load",         "store",       "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "reallocate",  "map_in_map", "arith64",       "arith32",
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

        for (Instruction ins : bb) {
            if (std::holds_alternative<LoadMapFd>(ins)) {
                if (std::get<LoadMapFd>(ins).mapfd == -1) {
                    res["map_in_map"] = 1;
                }
            }
            if (std::holds_alternative<Call>(ins)) {
                auto call = std::get<Call>(ins);
                if (call.reallocate_packet)
                    res["reallocate"] = 1;
            }
            if (std::holds_alternative<Bin>(ins)) {
                auto const& bin = std::get<Bin>(ins);
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

cfg_t prepare_cfg(const InstructionSeq& prog, const program_info& info, bool simplify, bool must_have_exit) {
    // Convert the instruction sequence to a deterministic control-flow graph.
    cfg_t det_cfg = instruction_seq_to_cfg(prog, must_have_exit);

    // Annotate the CFG by adding in assertions before every memory instruction.
    explicate_assertions(det_cfg, info);

    // Translate conditional jumps to non-deterministic jumps.
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
