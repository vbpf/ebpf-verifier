// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <tuple>
#include <vector>

#include "asm_syntax.hpp"

Instruction parse_instruction(const std::string& text);
std::vector<std::tuple<label_t, Instruction>> parse_program(std::istream& is);
