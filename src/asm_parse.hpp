// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <tuple>
#include <vector>
#include <string>

#include "asm_syntax.hpp"

Instruction parse_instruction(const std::string& text);

InstructionSeq parse_program(std::istream& is);

InstructionSeq parse_unlabeled_program(const std::string& s);
