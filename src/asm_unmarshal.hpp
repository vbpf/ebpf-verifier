#pragma once

#include <istream>
#include <variant>
#include <optional>
#include <vector>
#include <string>

#include "linux_ebpf.hpp"
#include "asm_syntax.hpp"

std::variant<InstructionSeq, std::string> unmarshal(std::istream& is, size_t nbytes);
inline std::variant<InstructionSeq, std::string> unmarshal(const char* p, size_t nbytes) {
    std::stringstream is{{p, p+nbytes}};
    return unmarshal(is, nbytes);
}

std::vector<LabeledInstruction> unmarshal(std::vector<ebpf_inst> const& insts);
