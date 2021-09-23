// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "crab/variable.hpp"

namespace crab {
struct label_t {
    int from; ///< Jump source, or simply index of instruction
    int to; ///< Jump target or -1

    constexpr explicit label_t(int index, int to=-1) noexcept : from(index), to(to) { }

    static constexpr label_t make_jump(const label_t& src_label, const label_t& target_label) {
        return label_t{src_label.from, target_label.from};
    }

    constexpr bool operator==(const label_t& other) const { return from == other.from && to == other.to; }
    constexpr bool operator!=(const label_t& other) const { return !(*this == other); }
    constexpr bool operator<(const label_t& other) const {
        if (this == &other) return false;
        if (*this == label_t::exit) return false;
        if (other == label_t::exit) return true;
        return from < other.from || (from == other.from && to < other.to);
    }

    // no hash; intended for use in ordered containers.

    [[nodiscard]] constexpr bool isjump() const { return to != -1; }

    friend std::ostream& operator<<(std::ostream& os, const label_t& label) {
        if (label == entry)
            return os << "entry";
        if (label == exit)
            return os << "exit";
        if (label.to == -1)
            return os << label.from;
        return os << label.from << ":" << label.to;
    }

    static const label_t entry;
    static const label_t exit;
};

inline const label_t label_t::entry{-1};
inline const label_t label_t::exit{-2};

}
using crab::label_t;

// Assembly syntax.
namespace asm_syntax {

/// Immediate argument.
struct Imm {
    uint64_t v{};
    auto operator<=>(const Imm&) const = default;
};

/// Register argument.
struct Reg {
    uint8_t v{};
    auto operator<=>(const Reg&) const = default;
};

using Value = std::variant<Imm, Reg>;

/// Binary operation.
struct Bin {
    enum class Op {
        MOV,
        ADD,
        SUB,
        MUL,
        DIV,
        MOD,
        OR,
        AND,
        LSH,
        RSH,
        ARSH,
        XOR,
    };

    Op op;
    Reg dst;      ///< Destination.
    Value v;
    bool is64{};
    bool lddw{};
    auto operator<=>(const Bin&) const = default;
};

/// Unary operation.
struct Un {
    enum class Op {
        LE16,
        LE32,
        LE64,
        NEG,
    };

    Op op{};
    Reg dst;
    auto operator<=>(const Un&) const = default;
};

/// This instruction is encoded similarly to LDDW.
/// See comment in makeLddw() at asm_unmarshal.cpp
struct LoadMapFd {
    Reg dst;
    int mapfd{};
    auto operator<=>(const LoadMapFd&) const = default;
};

struct Condition {
    enum class Op {
        EQ,
        NE,
        SET,
        NSET, // NSET does not exist in ebpf
        LT,
        LE,
        GT,
        GE,
        SLT,
        SLE,
        SGT,
        SGE,
    };

    Op op;
    Reg left;
    Value right;
    auto operator<=>(const Condition&) const = default;
};

struct Jmp {
    std::optional<Condition> cond;
    label_t target;
    auto operator<=>(const Jmp&) const = default;
};

struct ArgSingle {
    // see comments in spec_prototypes.hpp
    enum class Kind {
        MAP_FD,
        MAP_FD_PROGRAMS,
        PTR_TO_MAP_KEY,
        PTR_TO_MAP_VALUE,
        PTR_TO_CTX,
        ANYTHING,
    } kind{};
    Reg reg;
    auto operator<=>(const ArgSingle&) const = default;
};

/// Pair of arguments to a function for pointer and size.
struct ArgPair {
    enum class Kind {
        PTR_TO_MEM,
        PTR_TO_MEM_OR_NULL,
        PTR_TO_UNINIT_MEM,
    } kind{};
    Reg mem;            ///< Pointer.
    Reg size;           ///< Size of space pointed to.
    bool can_be_zero{};
    auto operator<=>(const ArgPair&) const = default;
};

struct Call {
    int32_t func{};
    std::string name;
    bool is_map_lookup{};
    bool reallocate_packet{};
    std::vector<ArgSingle> singles;
    std::vector<ArgPair> pairs;
    auto operator<=>(const Call& other) const {
        return this->func <=> other.func;
    };
    bool operator==(const Call& other) const {
        return this->func == other.func;
    }
};

struct Exit {
    auto operator<=>(const Exit&) const = default;
};

struct Deref {
    int width{};
    Reg basereg;
    int offset{};
    auto operator<=>(const Deref&) const = default;
};

/// Load/store instruction.
struct Mem {
    Deref access;
    Value value;
    bool is_load{};
    auto operator<=>(const Mem&) const = default;
};

/// A special instruction for checked access to packets; it is actually a
/// function call, and analyzed as one, e.g., by scratching caller-saved
/// registers after it is performed.
struct Packet {
    int width{};
    int offset{};
    std::optional<Reg> regoffset;
    auto operator<=>(const Packet&) const = default;
};

/// Special instruction for incrementing values inside shared memory.
struct LockAdd {
    Deref access;
    Reg valreg;
    auto operator<=>(const LockAdd&) const = default;
};

/// Not an instruction, just used for failure cases.
struct Undefined {
    int opcode{};
    auto operator<=>(const Undefined&) const = default;
};

/// When a CFG is translated to its nondeterministic form, Conditional Jump
/// instructions are replaced by two Assume instructions, immediately after
/// the branch and before each jump target.
struct Assume {
    Condition cond;
    auto operator<=>(const Assume&) const = default;
};

enum class TypeGroup {
    number,
    map_fd,
    ctx,             ///< pointer to the special memory region named 'ctx'
    packet,          ///< pointer to the packet
    stack,           ///< pointer to the stack
    shared,          ///< pointer to shared memory
    map_fd_programs, ///< reg == T_MAP_PROGRAMS
    non_map_fd,      ///< reg >= T_NUM
    mem,             ///< shared | packet | stack = reg >= T_STACK
    mem_or_num,      ///< reg >= T_NUM && reg != T_CTX
    pointer,         ///< reg >= T_CTX
    ptr_or_num,      ///< reg >= T_NUM
    stack_or_packet  ///< reg >= T_STACK && reg <= T_PACKET
};

/// Condition check whether something is a valid size.
struct ValidSize {
    Reg reg;
    bool can_be_zero{};
    auto operator<=>(const ValidSize&) const = default;
};

/// Condition check whether two registers can be compared with each other.
/// For example, one is not allowed to compare a number with a pointer,
/// or compare pointers to different memory regions.
struct Comparable {
    Reg r1;
    Reg r2;
    auto operator<=>(const Comparable&) const = default;
};

// ptr: ptr -> num : num
struct Addable {
    Reg ptr;
    Reg num;
    auto operator<=>(const Addable&) const = default;
};

struct ValidAccess {
    Reg reg;
    int offset{};
    Value width{Imm{0}};
    bool or_null{};
    auto operator<=>(const ValidAccess&) const = default;
};

/// Condition check whether something is a valid key value.
struct ValidMapKeyValue {
    Reg access_reg;
    Reg map_fd_reg;
    bool key{};
    auto operator<=>(const ValidMapKeyValue&) const = default;
};

// "if mem is not stack, val is num"
struct ValidStore {
    Reg mem;
    Reg val;
    auto operator<=>(const ValidStore&) const = default;
};

struct TypeConstraint {
    Reg reg;
    TypeGroup types;
    auto operator<=>(const TypeConstraint&) const = default;
};

struct ZeroOffset {
    Reg reg;
    auto operator<=>(const ZeroOffset&) const = default;
};

using AssertionConstraint =
    std::variant<Comparable, Addable, ValidAccess, ValidStore, ValidSize, ValidMapKeyValue, TypeConstraint, ZeroOffset>;

struct Assert {
    AssertionConstraint cst;
    Assert(AssertionConstraint cst): cst(cst) { }
    auto operator<=>(const Assert&) const = default;
};

using Instruction = std::variant<Undefined, Bin, Un, LoadMapFd, Call, Exit, Jmp, Mem, Packet, LockAdd, Assume, Assert>;

using LabeledInstruction = std::tuple<label_t, Instruction>;
using InstructionSeq = std::vector<LabeledInstruction>;

using pc_t = uint16_t;

}

using namespace asm_syntax;

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...)->overloaded<Ts...>;
