// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "crab/variable.hpp"
#include "spec_type_descriptors.hpp"

constexpr char STACK_FRAME_DELIMITER = '/';

namespace crab {
struct label_t {
    int from;                       ///< Jump source, or simply index of instruction
    int to;                         ///< Jump target or -1
    std::string stack_frame_prefix; ///< Variable prefix when calling this label.

    explicit label_t(const int index, const int to = -1, std::string stack_frame_prefix = {}) noexcept
        : from(index), to(to), stack_frame_prefix(std::move(stack_frame_prefix)) {}

    static label_t make_jump(const label_t& src_label, const label_t& target_label) {
        return label_t{src_label.from, target_label.from, target_label.stack_frame_prefix};
    }

    bool operator==(const label_t& other) const noexcept = default;

    constexpr bool operator<(const label_t& other) const {
        if (this == &other) {
            return false;
        }
        if (*this == label_t::exit) {
            return false;
        }
        if (other == label_t::exit) {
            return true;
        }
        return (stack_frame_prefix < other.stack_frame_prefix ||
                (stack_frame_prefix == other.stack_frame_prefix &&
                 (from < other.from || (from == other.from && to < other.to))));
    }

    // no hash; intended for use in ordered containers.

    [[nodiscard]]
    constexpr bool isjump() const {
        return to != -1;
    }

    [[nodiscard]]
    int call_stack_depth() const {
        // The call stack depth is the number of '/' separated components in the label,
        // which is one more than the number of '/' separated components in the prefix,
        // hence two more than the number of '/' in the prefix, if any.
        if (stack_frame_prefix.empty()) {
            return 1;
        }
        return 2 + std::ranges::count(stack_frame_prefix, STACK_FRAME_DELIMITER);
    }

    friend std::ostream& operator<<(std::ostream& os, const label_t& label) {
        if (label == entry) {
            return os << "entry";
        }
        if (label == exit) {
            return os << "exit";
        }
        if (!label.stack_frame_prefix.empty()) {
            os << label.stack_frame_prefix << STACK_FRAME_DELIMITER;
        }
        if (label.to == -1) {
            return os << label.from;
        }
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
    constexpr bool operator==(const Imm&) const = default;
};

/// Register argument.
struct Reg {
    uint8_t v{};
    constexpr bool operator==(const Reg&) const = default;
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
        SDIV,
        SMOD,
        MOVSX8,
        MOVSX16,
        MOVSX32,
    };

    Op op;
    Reg dst; ///< Destination.
    Value v;
    bool is64{};
    bool lddw{};
    constexpr bool operator==(const Bin&) const = default;
};

/// Unary operation.
struct Un {
    enum class Op {
        BE16,   // dst = htobe16(dst)
        BE32,   // dst = htobe32(dst)
        BE64,   // dst = htobe64(dst)
        LE16,   // dst = htole16(dst)
        LE32,   // dst = htole32(dst)
        LE64,   // dst = htole64(dst)
        SWAP16, // dst = bswap16(dst)
        SWAP32, // dst = bswap32(dst)
        SWAP64, // dst = bswap64(dst)
        NEG,    // dst = -dst
    };

    Op op{};
    Reg dst;
    bool is64{};
    constexpr bool operator==(const Un&) const = default;
};

/// This Command is encoded similarly to LDDW.
/// See comment in makeLddw() at asm_unmarshal.cpp
struct LoadMapFd {
    Reg dst;
    int32_t mapfd{};
    constexpr bool operator==(const LoadMapFd&) const = default;
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
    constexpr bool operator==(const Condition&) const = default;
};

struct Jmp {
    std::optional<Condition> cond;
    label_t target;
    bool operator==(const Jmp&) const = default;
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
    constexpr bool operator==(const ArgSingle&) const = default;
};

/// Pair of arguments to a function for pointer and size.
struct ArgPair {
    enum class Kind {
        PTR_TO_READABLE_MEM,
        PTR_TO_READABLE_MEM_OR_NULL,
        PTR_TO_WRITABLE_MEM,
    } kind{};
    Reg mem;  ///< Pointer.
    Reg size; ///< Size of space pointed to.
    bool can_be_zero{};
    constexpr bool operator==(const ArgPair&) const = default;
};

struct Call {
    int32_t func{};
    constexpr bool operator==(const Call& other) const { return func == other.func; }

    // TODO: move name and signature information somewhere else
    std::string name;
    bool is_map_lookup{};
    bool reallocate_packet{};
    std::vector<ArgSingle> singles;
    std::vector<ArgPair> pairs;
    std::string stack_frame_prefix; ///< Variable prefix at point of call.
};

/// Call a "function" (macro) within the same program.
struct CallLocal {
    label_t target;
    std::string stack_frame_prefix; ///< Variable prefix to be used within the call.
    bool operator==(const CallLocal& other) const noexcept = default;
};

struct Exit {
    std::string stack_frame_prefix; ///< Variable prefix to clean up when exiting.
    bool operator==(const Exit& other) const noexcept = default;
};

/// Experimental callx Command.
struct Callx {
    Reg func;
    constexpr bool operator==(const Callx&) const = default;
};

struct Deref {
    int32_t width{};
    Reg basereg;
    int32_t offset{};
    constexpr bool operator==(const Deref&) const = default;
};

/// Load/store Command.
struct Mem {
    Deref access;
    Value value;
    bool is_load{};
    constexpr bool operator==(const Mem&) const = default;
};

/// A deprecated Command for checked access to packets; it is actually a
/// function call, and analyzed as one, e.g., by scratching caller-saved
/// registers after it is performed.
struct Packet {
    int32_t width{};
    int32_t offset{};
    std::optional<Reg> regoffset;
    constexpr bool operator==(const Packet&) const = default;
};

/// Special Command for atomically updating values inside shared memory.
/// The analysis just treats an atomic operation as a series of consecutive
/// operations, and the atomicity itself is not significant.
struct Atomic {
    enum class Op {
        ADD = 0x00,
        OR = 0x40,
        AND = 0x50,
        XOR = 0xa0,
        XCHG = 0xe0,    // Only valid with fetch=true.
        CMPXCHG = 0xf0, // Only valid with fetch=true.
    };

    Op op{};
    bool fetch{};
    Deref access;
    Reg valreg;
    constexpr bool operator==(const Atomic&) const = default;
};

/// Not an Command, just used for failure cases.
struct Undefined {
    int opcode{};
    constexpr bool operator==(const Undefined&) const = default;
};

/// When a CFG is translated to its nondeterministic form, Conditional Jump
/// instructions are replaced by two Assume instructions, immediately after
/// the branch and before each jump target.
struct Assume {
    Condition cond;
    constexpr bool operator==(const Assume&) const = default;
};

struct IncrementLoopCounter {
    label_t name;
    bool operator==(const IncrementLoopCounter&) const = default;
};

using Command = std::variant<Undefined, Bin, Un, LoadMapFd, Call, CallLocal, Callx, Exit, Jmp, Mem, Packet, Atomic,
                             Assume, IncrementLoopCounter>;

/// Condition check whether something is a valid size.
struct ValidSize {
    Reg reg;
    bool can_be_zero{};
    constexpr bool operator==(const ValidSize&) const = default;
};

/// Condition check whether two registers can be compared with each other.
/// For example, one is not allowed to compare a number with a pointer,
/// or compare pointers to different memory regions.
struct Comparable {
    Reg r1;
    Reg r2;
    bool or_r2_is_number{}; ///< true for subtraction, false for comparison
    constexpr bool operator==(const Comparable&) const = default;
};

// ptr: ptr -> num : num
struct Addable {
    Reg ptr;
    Reg num;
    constexpr bool operator==(const Addable&) const = default;
};

// Condition check whether a register contains a non-zero number.
struct ValidDivisor {
    Reg reg;
    bool is_signed{};
    constexpr bool operator==(const ValidDivisor&) const = default;
};

enum class AccessType {
    compare,
    read,  // Memory pointed to must be initialized.
    write, // Memory pointed to must be writable.
};

struct ValidAccess {
    int call_stack_depth{};
    Reg reg;
    int32_t offset{};
    Value width{Imm{0}};
    bool or_null{};
    AccessType access_type{};
    constexpr bool operator==(const ValidAccess&) const = default;
};

/// Condition check whether something is a valid key value.
struct ValidMapKeyValue {
    Reg access_reg;
    Reg map_fd_reg;
    bool key{};
    constexpr bool operator==(const ValidMapKeyValue&) const = default;
};

/// Condition check whether a call is valid in the current context.
struct ValidCall {
    int32_t func{};
    std::string stack_frame_prefix; ///< Variable prefix at point of call.
    bool operator==(const ValidCall&) const = default;
};

// "if mem is not stack, val is num"
struct ValidStore {
    Reg mem;
    Reg val;
    constexpr bool operator==(const ValidStore&) const = default;
};

using crab::TypeGroup;
struct TypeConstraint {
    Reg reg;
    TypeGroup types;
    constexpr bool operator==(const TypeConstraint&) const = default;
};

struct FuncConstraint {
    Reg reg;
    constexpr bool operator==(const FuncConstraint&) const = default;
};

/// Condition check whether something is a valid size.
struct ZeroCtxOffset {
    Reg reg;
    constexpr bool operator==(const ZeroCtxOffset&) const = default;
};

struct BoundedLoopCount {
    label_t name;
    bool operator==(const BoundedLoopCount&) const = default;
    // Maximum number of loop iterations allowed during verification.
    // This prevents infinite loops while allowing reasonable bounded loops.
    // When exceeded, verification fails as the loop might not terminate.
    static constexpr int limit = 100000;
};

using Assertion = std::variant<Comparable, Addable, ValidDivisor, ValidAccess, ValidStore, ValidSize, ValidMapKeyValue,
                               ValidCall, TypeConstraint, FuncConstraint, ZeroCtxOffset, BoundedLoopCount>;

struct Instruction {
    Command cmd;
    std::vector<Assertion> preconditions;
    bool operator==(const Instruction&) const = default;
};

using LabeledInstruction = std::tuple<label_t, Instruction, std::optional<btf_line_info_t>>;
using InstructionSeq = std::vector<LabeledInstruction>;

// cpu=v4 supports 32-bit PC offsets so we need a large enough type.
using pc_t = uint32_t;

} // namespace asm_syntax

using namespace asm_syntax;

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
