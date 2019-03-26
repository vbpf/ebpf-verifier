#pragma once

#include <vector>
#include <map>

#include "asm_syntax.hpp"

struct BasicBlock {
    std::vector<Instruction> insts;
    std::vector<Label> nextlist;
    std::vector<Label> prevlist;
    std::vector<std::string> pres;
    std::vector<std::string> posts;
};

/** An eBPF Control Flow Graph.
 *
 * (not to be confused with Crab's internal cfg_t)
 *
 * A graph of basic blocs with labels ordered similarly to the original program
 * (up to unconditional branches).
 *
 */
class Cfg {
    std::map<Label, BasicBlock> graph;
    std::vector<Label> ordered_labels;

    void encountered(Label l) { ordered_labels.push_back(l); }
    Cfg() { }
    Cfg(const Cfg& _) = delete;
public:
    Cfg(Cfg&& _) = default;
    Cfg& operator=(Cfg&& _) = default;
    BasicBlock& operator[](Label l) { return graph[l]; }
    BasicBlock const& at(Label l) const { return graph.at(l); }

    std::vector<Label> const& keys() const { return ordered_labels; }

    /** Create a graph from a sequence of instructions.
     * 
     * The graph is not simplified yet.
     */
    static Cfg make(const InstructionSeq& labeled_insts);
                
    /** Create a CFG with jumps replaced by assumptions in the target location.
     */
    Cfg to_nondet(bool expand_locks) const;

    /** Replace chains in the graph with a single basic block.
     */
    void simplify();

    static std::vector<std::string> stats_headers();
    std::map<std::string, int> collect_stats() const;
};
