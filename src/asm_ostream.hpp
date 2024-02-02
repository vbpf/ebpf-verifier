// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <functional>
#include <ostream>
#include <variant>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "asm_syntax.hpp"

// We use a 16-bit offset whenever it fits in 16 bits.
inline std::function<int16_t(label_t)> label_to_offset16(pc_t pc) {
    return [=](const label_t& label) {
        int64_t offset = label.from - (int64_t)pc - 1;
        return (offset >= INT16_MIN && offset <= INT16_MAX) ? (int16_t)offset : 0;
    };
}

// We use the JA32 opcode with the offset in 'imm' when the offset
// of an unconditional jump doesn't fit in a int16_t.
inline std::function<int32_t(label_t)> label_to_offset32(pc_t pc) {
    return [=](const label_t& label) {
        int64_t offset = label.from - (int64_t)pc - 1;
        return (offset >= INT16_MIN && offset <= INT16_MAX) ? 0 : (int32_t)offset;
    };
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
inline std::ostream& operator<<(std::ostream& os, Callx const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Exit const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Jmp const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Packet const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Mem const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LockAdd const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assume const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assert const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, IncrementLoopCounter const& a) { return os << (Instruction)a; }
std::ostream& operator<<(std::ostream& os, AssertionConstraint const& a);
std::string to_string(AssertionConstraint const& constraint);
