// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <functional>
#include <ostream>
#include <variant>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "asm_syntax.hpp"

inline std::function<int16_t(label_t)> label_to_offset(pc_t pc) {
    return [=](const label_t& label) { return label.from - pc - 1; };
}

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info);

void print(const InstructionSeq& insts, std::ostream& out, std::optional<const label_t> label_to_print,
           bool print_line_info = false);

std::string to_string(label_t const& label);

std::ostream& operator<<(std::ostream& os, Instruction const& ins);
std::string to_string(Instruction const& ins);

std::ostream& operator<<(std::ostream& os, Bin::Op op);
std::ostream& operator<<(std::ostream& os, Condition::Op op);

inline std::ostream& operator<<(std::ostream& os, Imm imm) { return os << (int64_t)imm.v; }
inline std::ostream& operator<<(std::ostream& os, Reg const& a) { return os << "r" << (int)a.v; }
inline std::ostream& operator<<(std::ostream& os, Value const& a) {
    if (std::holds_alternative<Imm>(a))
        return os << std::get<Imm>(a);
    return os << std::get<Reg>(a);
}

inline std::ostream& operator<<(std::ostream& os, Undefined const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LoadMapFd const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Bin const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Un const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Call const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Exit const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Jmp const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Packet const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Mem const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LockAdd const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assume const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assert const& a) { return os << (Instruction)a; }
std::ostream& operator<<(std::ostream& os, AssertionConstraint const& a);
std::string to_string(AssertionConstraint const& constraint);
