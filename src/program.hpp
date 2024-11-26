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
#include "crab_utils/debug.hpp"
#include "crab_utils/num_big.hpp"
#include "spec_type_descriptors.hpp"

using printfunc = std::function<void(std::ostream&, const label_t& label)>;

class Program {
    crab::cfg_t cfg;
    std::map<label_t, GuardedInstruction> instructions;

    Program(const crab::cfg_t& cfg, const std::map<label_t, GuardedInstruction>& map) : cfg(cfg), instructions(map) {}

  public:
    Program(const InstructionSeq& prog, const program_info& info, const prepare_cfg_options& options);

    const crab::cfg_t& get_cfg() const { return cfg; }
    auto labels() const { return cfg.labels(); }
    auto parents_of(const label_t& label) const { return cfg.parents_of(label); }
    auto children_of(const label_t& label) const { return cfg.children(label); }
    auto instruction_at(const label_t& label) const { return instructions.at(label).cmd; }
    auto assertions_at(const label_t& label) const { return instructions.at(label).preconditions; }

    std::map<std::string, int> collect_stats() const;

    void print_dot(std::ostream& out) const;
    void print_dot(const std::string& outfile) const;
    void print_cfg(std::ostream& os, bool simplify) const;
    void print_cfg(std::ostream& os, bool simplify, const printfunc& prefunc, const printfunc& postfunc) const;
};

std::vector<std::string> stats_headers();

class InvalidControlFlow final : public std::runtime_error {
  public:
    explicit InvalidControlFlow(const std::string& what) : std::runtime_error(what) {}
};

std::vector<Assertion> get_assertions(const Instruction& ins, const program_info& info,
                                      const std::optional<label_t>& label);
