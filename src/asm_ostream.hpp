// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <functional>
#include <ostream>
#include <variant>

#include <boost/lexical_cast.hpp>

#include "asm_syntax.hpp"
#include "crab_utils/num_safety.hpp"

// We use a 16-bit offset whenever it fits in 16 bits.
inline std::function<int16_t(label_t)> label_to_offset16(pc_t pc) {
    return [=](const label_t& label) {
        const int64_t offset = label.from - gsl::narrow<int64_t>(pc) - 1;
        const bool is16 =
            std::numeric_limits<int16_t>::min() <= offset && offset <= std::numeric_limits<int16_t>::max();
        return is16 ? gsl::narrow<int16_t>(offset) : 0;
    };
}

// We use the JA32 opcode with the offset in 'imm' when the offset
// of an unconditional jump doesn't fit in a int16_t.
inline std::function<int32_t(label_t)> label_to_offset32(const pc_t pc) {
    return [=](const label_t& label) {
        const int64_t offset = label.from - gsl::narrow<int64_t>(pc) - 1;
        const bool is16 =
            std::numeric_limits<int16_t>::min() <= offset && offset <= std::numeric_limits<int16_t>::max();
        return is16 ? 0 : gsl::narrow<int32_t>(offset);
    };
}

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info);

void print(const InstructionSeq& insts, std::ostream& out, const std::optional<const label_t>& label_to_print,
           bool print_line_info = false);

std::string to_string(label_t const& label);

std::ostream& operator<<(std::ostream& os, Command const& ins);
std::string to_string(Command const& ins);

std::ostream& operator<<(std::ostream& os, Bin::Op op);
std::ostream& operator<<(std::ostream& os, Condition::Op op);

inline std::ostream& operator<<(std::ostream& os, const Imm imm) { return os << crab::to_signed(imm.v); }
inline std::ostream& operator<<(std::ostream& os, Reg const& a) { return os << "r" << gsl::narrow<int>(a.v); }
inline std::ostream& operator<<(std::ostream& os, Value const& a) {
    if (const auto pa = std::get_if<Imm>(&a)) {
        return os << *pa;
    }
    return os << std::get<Reg>(a);
}

inline std::ostream& operator<<(std::ostream& os, Undefined const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, LoadMapFd const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Bin const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Un const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Call const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Callx const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Exit const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Jmp const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Packet const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Mem const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Atomic const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, Assume const& a) { return os << Command{a}; }
inline std::ostream& operator<<(std::ostream& os, IncrementLoopCounter const& a) { return os << Command{a}; }
std::ostream& operator<<(std::ostream& os, const Assertion& a);
std::string to_string(const Assertion& constraint);
