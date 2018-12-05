#pragma once

#include <vector>
#include <unordered_map>

#include "asm_syntax.hpp"

struct BasicBlock {
    std::vector<Instruction> insts;
    std::vector<Label> nextlist;
    std::vector<Label> prevlist;
};

class Cfg {
    std::unordered_map<Label, BasicBlock> graph;
    std::vector<Label> ordered_labels;
public:
    void encountered(Label l) { ordered_labels.push_back(l); }
    BasicBlock& operator[](Label l) { return graph[l]; }
    BasicBlock const& at(Label l) const { return graph.at(l); }
    std::vector<Label> const& keys() const { return ordered_labels; }
};

Cfg build_cfg(const InstructionSeq& labeled_insts);
             
Cfg to_nondet(const Cfg& simple_cfg);
