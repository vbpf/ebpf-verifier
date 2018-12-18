#pragma once

#include <istream>
#include <variant>
#include <optional>
#include <vector>
#include <string>

#include "linux_ebpf.hpp"
#include "asm_syntax.hpp"

std::variant<InstructionSeq, std::string> unmarshal(raw_program raw_prog);
