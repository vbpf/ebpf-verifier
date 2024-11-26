// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

/*
 * a CFG to interface with the fixpoint iterators.
 */
#include <functional>
#include <map>
#include <variant>
#include <vector>

#include "asm_syntax.hpp"
#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab_utils/num_big.hpp"
#include "spec_type_descriptors.hpp"

using printfunc = std::function<void(std::ostream&, const label_t& label)>;

class Program {
    crab::cfg_t cfg;

    crab::wto_t _wto; // cache. wto_t has mutable fields.

    std::map<label_t, Instruction> instructions;

    Program(const crab::cfg_t& cfg, const std::map<label_t, Instruction>& map)
        : cfg(cfg), _wto(cfg), instructions(map) {}

  public:
    static Program construct(const InstructionSeq& instruction_seq, const program_info& info,
                             const prepare_cfg_options& options);

    auto& wto() const { return _wto; }
    auto entry_label() const { return cfg.entry_label(); }
    auto labels() const { return cfg.labels(); }
    auto parents_of(const label_t& label) const { return cfg.parents_of(label); }
    auto children_of(const label_t& label) const { return cfg.children_of(label); }
    auto instruction_at(const label_t& label) const { return instructions.at(label); }
    std::vector<Assertion> assertions_at(const label_t& label) const;

    std::map<std::string, int> collect_stats() const;
    static std::vector<std::string> stats_headers();

    void print_dot(std::ostream& out) const;
    void print_dot(const std::string& outfile) const;
    void print_cfg(std::ostream& os, bool simplify) const;
    void print_cfg(std::ostream& os, bool simplify, const printfunc& prefunc, const printfunc& postfunc) const;
};

std::vector<Assertion> get_assertions(const Instruction& ins, const program_info& info,
                                      const std::optional<label_t>& label);
