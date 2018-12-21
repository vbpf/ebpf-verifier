#pragma once

#include <istream>
#include <variant>
#include <optional>
#include <vector>
#include <string>

#include "asm_syntax.hpp"
#include "spec_type_descriptors.hpp"

std::variant<InstructionSeq, std::string> unmarshal(raw_program raw_prog);
std::variant<InstructionSeq, std::string> unmarshal(raw_program raw_prog, std::vector<std::vector<std::string>>& notes);
