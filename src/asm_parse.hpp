// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <string>
#include <vector>

#include "asm_syntax.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"

InstructionOrConstraintsSet parse_instruction(const std::string& line,
                                              const std::map<std::string, label_t>& label_name_to_label);

/***
 * Parse a set of string form linear constraints into a vector of crab::linear_constraint_t
 *
 * @param[in] constraints A set of string form linear constraints.
 * @param[out] numeric_ranges A vector of numeric ranges that are extracted from the constraints.
 *
 * @return A vector of crab::linear_constraint_t
 * Example of string constraints include:
 * r0.type=number
 * r0.uvalue=5
 * r0.svalue=5
 */
std::vector<crab::linear_constraint_t> parse_linear_constraints(const std::set<std::string>& constraints,
                                                                std::vector<crab::interval_t>& numeric_ranges);
