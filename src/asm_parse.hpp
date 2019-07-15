#pragma once

#include <tuple>
#include <vector>

#include "asm_syntax.hpp"

Instruction parse_instruction(std::string text);
std::vector<std::tuple<Label, Instruction>> parse_program(std::istream &is);
