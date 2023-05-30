// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "crab/variable.hpp"
#include "spec_type_descriptors.hpp"

namespace crab {
struct label_t {
    int from; ///< Jump source, or simply index of instruction
    int to; ///< Jump target or -1

    constexpr explicit label_t(int index, int to = -1) noexcept : from(index), to(to) {}

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

} // namespace crab
using crab::label_t;

// Assembly syntax.
namespace asm_syntax {

/// Immediate argument.
struct Imm {
    uint64_t v{};
};

/// Register argument.
struct Reg {
    uint8_t v{};
};

using Value = std::variant<Imm, Reg>;

/// Binary operation.
struct Bin {
    enum class Op {
        MOV,
        ADD,
        SUB,
        MUL,
        UDIV,
        UMOD,
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
};

/// Unary operation.
struct Un {
    enum class Op {
        BE16, // dst = htobe16(dst)
        BE32, // dst = htobe32(dst)
        BE64, // dst = htobe64(dst)
        LE16, // dst = htole16(dst)
        LE32, // dst = htole32(dst)
        LE64, // dst = htole64(dst)
        NEG,  // dst = -dst
    };

    Op op;
    Reg dst;
    bool is64{};
};

/// This instruction is encoded similarly to LDDW.
/// See comment in makeLddw() at asm_unmarshal.cpp
struct LoadMapFd {
    Reg dst;
    int32_t mapfd{};
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
    bool is64{};
};

struct Jmp {
    std::optional<Condition> cond;
    label_t target;
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
};

/// Pair of arguments to a function for pointer and size.
struct ArgPair {
    enum class Kind {
        PTR_TO_READABLE_MEM,
        PTR_TO_READABLE_MEM_OR_NULL,
        PTR_TO_WRITABLE_MEM,
    } kind{};
    Reg mem;            ///< Pointer.
    Reg size;           ///< Size of space pointed to.
    bool can_be_zero{};
};

struct Call {
    int32_t func{};
    std::string name;
    bool is_map_lookup{};
    bool reallocate_packet{};
    std::vector<ArgSingle> singles;
    std::vector<ArgPair> pairs;
};

struct Exit {};

struct Deref {
    int32_t width{};
    Reg basereg;
    int32_t offset{};
};

/// Load/store instruction.
struct Mem {
    Deref access;
    Value value;
    bool is_load{};
};

/// A special instruction for checked access to packets; it is actually a
/// function call, and analyzed as one, e.g., by scratching caller-saved
/// registers after it is performed.
struct Packet {
    int32_t width{};
    int32_t offset{};
    std::optional<Reg> regoffset;
};

/// Special instruction for incrementing values inside shared memory.
struct LockAdd {
    Deref access;
    Reg valreg;
};

/// Not an instruction, just used for failure cases.
struct Undefined {
    int opcode{};
};

/// When a CFG is translated to its nondeterministic form, Conditional Jump
/// instructions are replaced by two Assume instructions, immediately after
/// the branch and before each jump target.
struct Assume {
    Condition cond;
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
    mem,             ///< shared | stack | packet = reg >= T_PACKET
    mem_or_num,      ///< reg >= T_NUM && reg != T_CTX
    pointer,         ///< reg >= T_CTX
    ptr_or_num,      ///< reg >= T_NUM
    stack_or_packet, ///< reg <= T_STACK && reg >= T_PACKET
    singleton_ptr,   ///< reg <= T_STACK && reg >= T_CTX
};

/// Condition check whether something is a valid size.
struct ValidSize {
    Reg reg;
    bool can_be_zero{};
};

/// Condition check whether two registers can be compared with each other.
/// For example, one is not allowed to compare a number with a pointer,
/// or compare pointers to different memory regions.
struct Comparable {
    Reg r1;
    Reg r2;
    bool or_r2_is_number{}; ///< true for subtraction, false for comparison
};

// ptr: ptr -> num : num
struct Addable {
    Reg ptr;
    Reg num;
};

// Condition check whether a register contains a non-zero number.
struct ValidDivisor {
    Reg reg;
};

enum class AccessType {
    compare,
    read,  // Memory pointed to must be initialized.
    write, // Memory pointed to must be writable.
};

struct ValidAccess {
    Reg reg;
    int32_t offset{};
    Value width{Imm{0}};
    bool or_null{};
    AccessType access_type{};
};

/// Condition check whether something is a valid key value.
struct ValidMapKeyValue {
    Reg access_reg;
    Reg map_fd_reg;
    bool key{};
};

// "if mem is not stack, val is num"
struct ValidStore {
    Reg mem;
    Reg val;
};

struct TypeConstraint {
    Reg reg;
    TypeGroup types;
};

/// Condition check whether something is a valid size.
struct ZeroCtxOffset {
    Reg reg;
};

using AssertionConstraint =
    std::variant<Comparable, Addable, ValidDivisor, ValidAccess, ValidStore, ValidSize, ValidMapKeyValue, TypeConstraint, ZeroCtxOffset>;

struct Assert {
    AssertionConstraint cst;
    Assert(AssertionConstraint cst): cst(cst) { }
};

using Instruction = std::variant<Undefined, Bin, Un, LoadMapFd, Call, Exit, Jmp, Mem, Packet, LockAdd, Assume, Assert>;

using LabeledInstruction = std::tuple<label_t, Instruction, std::optional<btf_line_info_t>>;
using InstructionSeq = std::vector<LabeledInstruction>;


#define DECLARE_EQ5(T, f1, f2, f3, f4, f5)                                                   \
    inline bool operator==(T const& a, T const& b) {                                         \
        return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4 && a.f5 == b.f5; \
    }
#define DECLARE_EQ3(T, f1, f2, f3) \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3; }
#define DECLARE_EQ2(T, f1, f2) \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1 && a.f2 == b.f2; }
#define DECLARE_EQ1(T, f1) \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1; }

using pc_t = uint16_t;

// Helpers:

struct InstructionVisitorPrototype {
    void operator()(Undefined const& a);
    void operator()(LoadMapFd const& a);
    void operator()(Bin const& a);
    void operator()(Un const& a);
    void operator()(Call const& a);
    void operator()(Exit const& a);
    void operator()(Jmp const& a);
    void operator()(Assume const& a);
    void operator()(Assert const& a);
    void operator()(Packet const& a);
    void operator()(Mem const& a);
    void operator()(LockAdd const& a);
};

inline bool operator==(Imm const& a, Imm const& b) { return a.v == b.v; }
inline bool operator==(Reg const& a, Reg const& b) { return a.v == b.v; }
inline bool operator==(Deref const& a, Deref const& b) {
    return a.basereg == b.basereg && a.offset == b.offset && a.width == b.width;
}
inline bool operator==(Condition const& a, Condition const& b) {
    return a.left == b.left && a.op == b.op && a.right == b.right;
}
inline bool operator==(Undefined const& a, Undefined const& b) { return a.opcode == b.opcode; }
inline bool operator==(LoadMapFd const& a, LoadMapFd const& b) { return a.dst == b.dst && a.mapfd == b.mapfd; }
inline bool operator==(Bin const& a, Bin const& b) {
    return a.op == b.op && a.dst == b.dst && a.is64 == b.is64 && a.v == b.v && a.lddw == b.lddw;
}
inline bool operator==(Un const& a, Un const& b) { return a.op == b.op && a.dst == b.dst; }
inline bool operator==(Call const& a, Call const& b) { return a.func == b.func; }
inline bool operator==(Exit const& a, Exit const& b) { return true; }
inline bool operator==(Jmp const& a, Jmp const& b) { return a.cond == b.cond && a.target == b.target; }
inline bool operator==(Packet const& a, Packet const& b) {
    return a.offset == b.offset && a.regoffset == b.regoffset && a.width == b.width;
}
inline bool operator==(Mem const& a, Mem const& b) {
    return a.access == b.access && a.value == b.value && a.is_load == b.is_load;
}
inline bool operator==(LockAdd const& a, LockAdd const& b) { return a.access == b.access && a.valreg == b.valreg; }
inline bool operator==(Assume const& a, Assume const& b) { return a.cond == b.cond; }
bool operator==(Assert const& a, Assert const& b);

DECLARE_EQ2(TypeConstraint, reg, types)
DECLARE_EQ2(ValidSize, reg, can_be_zero)
DECLARE_EQ2(Comparable, r1, r2)
DECLARE_EQ2(Addable, ptr, num)
DECLARE_EQ1(ValidDivisor, reg)
DECLARE_EQ2(ValidStore, mem, val)
DECLARE_EQ5(ValidAccess, reg, offset, width, or_null, access_type)
DECLARE_EQ3(ValidMapKeyValue, access_reg, map_fd_reg, key)
DECLARE_EQ1(ZeroCtxOffset, reg)
DECLARE_EQ1(Assert, cst)

}

using namespace asm_syntax;

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...)->overloaded<Ts...>;
