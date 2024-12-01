// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <cassert>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab/wto.hpp"

using std::optional;
using std::set;
using std::string;
using std::to_string;
using std::vector;

namespace crab {
struct cfg_builder_t final {
    cfg_t cfg;

    // TODO: ins should be inserted elsewhere
    void insert_after(const label_t& prev_label, const label_t& new_label, const GuardedInstruction& ins) {
        if (prev_label == new_label) {
            CRAB_ERROR("Cannot insert after the same label ", to_string(new_label));
        }
        std::set<label_t> prev_children;
        std::swap(prev_children, cfg.get_node(prev_label).children);

        for (const label_t& next_label : prev_children) {
            cfg.get_node(next_label).parents.erase(prev_label);
        }

        insert(new_label, ins);
        for (const label_t& next_label : prev_children) {
            add_child(prev_label, new_label);
            add_child(new_label, next_label);
        }
    }

    // TODO: ins should be inserted elsewhere
    void insert(const label_t& _label, const GuardedInstruction& ins) {
        const auto it = cfg.neighbours.find(_label);
        if (it != cfg.neighbours.end()) {
            CRAB_ERROR("Label ", to_string(_label), " already exists");
        }
        cfg.neighbours.emplace(_label, cfg_t::adjacent_t{});
        cfg.instructions.emplace(_label, ins);
    }

    // TODO: ins should be inserted elsewhere
    label_t insert_jump(const label_t& from, const label_t& to, const GuardedInstruction& ins) {
        const label_t jump_label = label_t::make_jump(from, to);
        if (cfg.contains(jump_label)) {
            CRAB_ERROR("Jump label ", to_string(jump_label), " already exists");
        }
        insert(jump_label, ins);
        add_child(from, jump_label);
        add_child(jump_label, to);
        return jump_label;
    }

    void add_child(const label_t& a, const label_t& b) {
        assert(b != label_t::entry);
        assert(a != label_t::exit);
        cfg.neighbours.at(a).children.insert(b);
        cfg.neighbours.at(b).parents.insert(a);
    }

    void remove_child(const label_t& a, const label_t& b) {
        cfg.get_node(a).children.erase(b);
        cfg.get_node(b).parents.erase(a);
    }
};
} // namespace crab

using crab::basic_block_t;
using crab::cfg_builder_t;
using crab::cfg_t;

/// Get the inverse of a given comparison operation.
static Condition::Op reverse(const Condition::Op op) {
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
static Condition reverse(const Condition& cond) {
    return {.op = reverse(cond.op), .left = cond.left, .right = cond.right, .is64 = cond.is64};
}

static bool has_fall(const Instruction& ins) {
    if (std::holds_alternative<Exit>(ins)) {
        return false;
    }

    if (const auto pins = std::get_if<Jmp>(&ins)) {
        if (!pins->cond) {
            return false;
        }
    }

    return true;
}

/// Update a control-flow graph to inline function macros.
static void add_cfg_nodes(cfg_builder_t& builder, const label_t& caller_label, const label_t& entry_label) {
    bool first = true;

    // Get the label of the node to go to on returning from the macro.
    label_t exit_to_label = builder.cfg.get_child(caller_label);

    // Construct the variable prefix to use for the new stack frame,
    // and store a copy in the CallLocal instruction since the instruction-specific
    // labels may only exist until the CFG is simplified.
    const std::string stack_frame_prefix = to_string(caller_label);
    if (const auto pcall = std::get_if<CallLocal>(&builder.cfg.instruction_at(caller_label))) {
        pcall->stack_frame_prefix = stack_frame_prefix;
    }

    // Walk the transitive closure of CFG nodes starting at entry_label and ending at
    // any exit instruction.
    std::set macro_labels{entry_label};
    std::set seen_labels{entry_label};
    while (!macro_labels.empty()) {
        label_t macro_label = *macro_labels.begin();
        macro_labels.erase(macro_label);

        if (stack_frame_prefix == macro_label.stack_frame_prefix) {
            throw crab::InvalidControlFlow{stack_frame_prefix + ": illegal recursion"};
        }

        // Clone the macro block into a new block with the new stack frame prefix.
        const label_t label{macro_label.from, macro_label.to, stack_frame_prefix};
        auto inst = builder.cfg.instruction_at(macro_label);
        if (const auto pexit = std::get_if<Exit>(&inst)) {
            pexit->stack_frame_prefix = label.stack_frame_prefix;
        } else if (const auto pcall = std::get_if<Call>(&inst)) {
            pcall->stack_frame_prefix = label.stack_frame_prefix;
        }
        builder.insert(label, {.cmd = inst});

        if (first) {
            // Add an edge from the caller to the new block.
            first = false;
            builder.add_child(caller_label, label);
        }

        // Add an edge from any other predecessors.
        for (const auto& prev_macro_nodes = builder.cfg.parents_of(macro_label);
             const auto& prev_macro_label : prev_macro_nodes) {
            const label_t prev_label(prev_macro_label.from, prev_macro_label.to, to_string(caller_label));
            if (const auto& labels = builder.cfg.labels(); std::ranges::find(labels, prev_label) != labels.end()) {
                builder.add_child(prev_label, label);
            }
        }

        // Walk all successor nodes.
        for (const auto& next_macro_nodes = builder.cfg.children_of(macro_label);
             const auto& next_macro_label : next_macro_nodes) {
            if (next_macro_label == builder.cfg.exit_label()) {
                // This is an exit transition, so add edge to the block to execute
                // upon returning from the macro.
                builder.add_child(label, exit_to_label);
            } else if (!seen_labels.contains(next_macro_label)) {
                // Push any other unprocessed successor label onto the list to be processed.
                if (!macro_labels.contains(next_macro_label)) {
                    macro_labels.insert(next_macro_label);
                }
                seen_labels.insert(macro_label);
            }
        }
    }

    // Remove the original edge from the caller node to its successor,
    // since processing now goes through the function macro instead.
    builder.remove_child(caller_label, exit_to_label);

    // Finally, recurse to replace any nested function macros.
    string caller_label_str = to_string(caller_label);
    const long stack_frame_depth = std::ranges::count(caller_label_str, STACK_FRAME_DELIMITER) + 2;
    for (const auto& macro_label : seen_labels) {
        const label_t label{macro_label.from, macro_label.to, caller_label_str};
        if (const auto pins = std::get_if<CallLocal>(&builder.cfg.instruction_at(label))) {
            if (stack_frame_depth >= MAX_CALL_STACK_FRAMES) {
                throw crab::InvalidControlFlow{"too many call stack frames"};
            }
            add_cfg_nodes(builder, label, pins->target);
        }
    }
}

/// Convert an instruction sequence to a control-flow graph (CFG).
static cfg_builder_t instruction_seq_to_cfg(const InstructionSeq& insts, const bool must_have_exit) {
    cfg_builder_t builder;

    // First add all instructions to the CFG without connecting
    for (const auto& [label, inst, _] : insts) {
        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }
        builder.insert(label, GuardedInstruction{.cmd = inst});
    }

    if (insts.size() == 0) {
        throw crab::InvalidControlFlow{"empty instruction sequence"};
    } else {
        const auto& [label, inst, _0] = insts[0];
        builder.add_child(builder.cfg.entry_label(), label);
    }

    // Do a first pass ignoring all function macro calls.
    for (size_t i = 0; i < insts.size(); i++) {
        const auto& [label, inst, _0] = insts[i];

        if (std::holds_alternative<Undefined>(inst)) {
            continue;
        }

        label_t fallthrough{builder.cfg.exit_label()};
        if (i + 1 < insts.size()) {
            fallthrough = std::get<0>(insts[i + 1]);
        } else {
            if (has_fall(inst) && must_have_exit) {
                throw crab::InvalidControlFlow{"fallthrough in last instruction"};
            }
        }
        if (const auto jmp = std::get_if<Jmp>(&inst)) {
            if (const auto cond = jmp->cond) {
                label_t target_label = jmp->target;
                if (target_label == fallthrough) {
                    builder.add_child(label, fallthrough);
                    continue;
                }
                if (!builder.cfg.contains(target_label)) {
                    throw crab::InvalidControlFlow{"jump to undefined label " + to_string(target_label)};
                }
                builder.insert_jump(label, target_label,
                                    GuardedInstruction{.cmd = Assume{.cond = *cond, .is_implicit = true}});
                builder.insert_jump(label, fallthrough,
                                    GuardedInstruction{.cmd = Assume{.cond = reverse(*cond), .is_implicit = true}});
            } else {
                builder.add_child(label, jmp->target);
            }
        } else {
            if (has_fall(inst)) {
                builder.add_child(label, fallthrough);
            }
        }
        if (std::holds_alternative<Exit>(inst)) {
            builder.add_child(label, builder.cfg.exit_label());
        }
    }

    // Now replace macros. We have to do this as a second pass so that
    // we only add new nodes that are actually reachable, based on the
    // results of the first pass.
    for (const auto& [label, inst, _] : insts) {
        if (const auto pins = std::get_if<CallLocal>(&inst)) {
            add_cfg_nodes(builder, label, pins->target);
        }
    }

    return builder;
}

cfg_t prepare_cfg(const InstructionSeq& prog, const program_info& info, const prepare_cfg_options& options) {
    thread_local_program_info.set(info);

    // Convert the instruction sequence to a deterministic control-flow graph.
    cfg_builder_t builder = instruction_seq_to_cfg(prog, options.must_have_exit);

    // Detect loops using Weak Topological Ordering (WTO) and insert counters at loop entry points. WTO provides a
    // hierarchical decomposition of the CFG that identifies all strongly connected components (cycles) and their entry
    // points. These entry points serve as natural locations for loop counters that help verify program termination.
    if (options.check_for_termination) {
        const wto_t wto{builder.cfg};
        wto.for_each_loop_head([&](const label_t& label) -> void {
            builder.insert_after(label, label_t::make_increment_counter(label),
                                 GuardedInstruction{.cmd = IncrementLoopCounter{label}});
        });
    }

    // Annotate the CFG by adding in assertions before every memory instruction.
    for (auto& [label, ins] : builder.cfg.instructions) {
        builder.cfg.set_assertions(label, get_assertions(ins.cmd, info, label));
    }
    return builder.cfg;
}

std::set<basic_block_t> basic_block_t::collect_basic_blocks(const cfg_t& cfg, const bool simplify) {
    if (!simplify) {
        std::set<basic_block_t> res;
        for (const label_t& label : cfg.labels()) {
            if (label != cfg.entry_label() && label != cfg.exit_label()) {
                res.insert(basic_block_t{label});
            }
        }
        return res;
    }

    std::set<basic_block_t> res;
    std::set<label_t> worklist;
    for (const label_t& label : cfg.labels()) {
        worklist.insert(label);
    }
    std::set<label_t> seen;
    while (!worklist.empty()) {
        label_t label = *worklist.begin();
        worklist.erase(label);
        if (seen.contains(label)) {
            continue;
        }
        seen.insert(label);

        if (cfg.in_degree(label) == 1 && cfg.num_siblings(label) == 1) {
            continue;
        }
        basic_block_t bb{label};
        while (cfg.out_degree(label) == 1) {
            const label_t& next_label = cfg.get_child(bb.last_label());

            if (seen.contains(next_label) || next_label == cfg.exit_label() || cfg.in_degree(next_label) != 1) {
                break;
            }

            if (bb.first_label() == cfg.entry_label()) {
                // Entry instruction is Undefined. We want to start with 0
                bb.m_ts.clear();
            }
            bb.m_ts.push_back(next_label);

            worklist.erase(next_label);
            seen.insert(next_label);

            label = next_label;
        }
        res.emplace(std::move(bb));
    }
    return res;
}

/// Get the type of given Instruction.
/// Most of these type names are also statistics header labels.
static std::string instype(Instruction ins) {
    if (const auto pcall = std::get_if<Call>(&ins)) {
        if (pcall->is_map_lookup) {
            return "call_1";
        }
        if (pcall->pairs.empty()) {
            if (std::ranges::all_of(pcall->singles,
                                    [](const ArgSingle kr) { return kr.kind == ArgSingle::Kind::ANYTHING; })) {
                return "call_nomem";
            }
        }
        return "call_mem";
    } else if (std::holds_alternative<Callx>(ins)) {
        return "callx";
    } else if (const auto pimm = std::get_if<Mem>(&ins)) {
        return pimm->is_load ? "load" : "store";
    } else if (std::holds_alternative<Atomic>(ins)) {
        return "load_store";
    } else if (std::holds_alternative<Packet>(ins)) {
        return "packet_access";
    } else if (const auto pins = std::get_if<Bin>(&ins)) {
        switch (pins->op) {
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
        "instructions", "joins",      "other",      "jumps",         "assign",  "arith",
        "load",         "store",      "load_store", "packet_access", "call_1",  "call_mem",
        "call_nomem",   "reallocate", "map_in_map", "arith64",       "arith32",
    };
}

std::map<std::string, int> collect_stats(const cfg_t& cfg) {
    std::map<std::string, int> res;
    for (const auto& h : stats_headers()) {
        res[h] = 0;
    }
    for (const auto& label : cfg.labels()) {
        res["instructions"]++;
        const auto cmd = cfg.instruction_at(label);
        if (const auto pins = std::get_if<LoadMapFd>(&cmd)) {
            if (pins->mapfd == -1) {
                res["map_in_map"] = 1;
            }
        }
        if (const auto pins = std::get_if<Call>(&cmd)) {
            if (pins->reallocate_packet) {
                res["reallocate"] = 1;
            }
        }
        if (const auto pins = std::get_if<Bin>(&cmd)) {
            res[pins->is64 ? "arith64" : "arith32"]++;
        }
        res[instype(cmd)]++;
        if (cfg.in_degree(label) > 1) {
            res["joins"]++;
        }
        if (cfg.out_degree(label) > 1) {
            res["jumps"]++;
        }
    }
    return res;
}

cfg_t crab::cfg_from_adjacency_list(const std::map<label_t, std::vector<label_t>>& adj_list) {
    cfg_builder_t builder;
    for (const auto& [label, children] : adj_list) {
        if (label == label_t::entry || label == label_t::exit) {
            continue;
        }
        builder.insert(label, {.cmd = Undefined{}});
    }
    for (const auto& [label, children] : adj_list) {
        for (const auto& child : children) {
            builder.add_child(label, child);
        }
    }
    return builder.cfg;
}
