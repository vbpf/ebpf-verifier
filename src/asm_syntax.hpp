#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <variant>

#include <boost/lexical_cast.hpp>

#include "crab/types.hpp"
#include "spec_type_descriptors.hpp"

namespace crab {
    using label_t = std::string;
}
using crab::label_t;

struct Imm {
    uint64_t v{};
};

struct Reg {
    uint8_t v{};
};

using Value = std::variant<Imm, Reg>;

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
    bool is64{};
    Reg dst;
    Value v;
    bool lddw{};
};

struct Un {
    enum class Op {
        LE16,
        LE32,
        LE64,
        NEG,
    };

    Op op;
    Reg dst;
};

struct LoadMapFd {
    Reg dst;
    int mapfd{};
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
};

struct Jmp {
    std::optional<Condition> cond;
    label_t target;
};

struct ArgSingle {
    // see comments in spec_prototypes.hpp
    enum class Kind {
        MAP_FD,
        PTR_TO_MAP_KEY,
        PTR_TO_MAP_VALUE,
        PTR_TO_CTX,
        ANYTHING,
    } kind;
    Reg reg;
};

struct ArgPair {
    enum class Kind {
        PTR_TO_MEM,
        PTR_TO_MEM_OR_NULL,
        PTR_TO_UNINIT_MEM,
    } kind;
    Reg mem;
    Reg size;
    bool can_be_zero;
};

struct Call {
    int32_t func{};
    std::string name;
    bool pkt_access{};
    bool returns_map{};
    std::vector<ArgSingle> singles;
    std::vector<ArgPair> pairs;
};

struct Exit {};

struct Deref {
    int width{};
    Reg basereg;
    int offset{};
};

struct Mem {
    Deref access;
    Value value;
    bool is_load{};
};

struct Packet {
    int width{};
    int offset{};
    std::optional<Reg> regoffset;
};

struct LockAdd {
    Deref access;
    Reg valreg;
};

struct Undefined {
    int opcode{};
};

struct Assume {
    Condition cond;
};

enum {
    T_UNINIT = -6,
    T_MAP = -5,
    T_NUM = -4,
    T_CTX = -3,
    T_STACK = -2,
    T_PACKET = -1,
    T_SHARED = 0
};

enum class TypeGroup {
    num,
    map_fd,
    ctx,
    packet,
    stack,
    shared,
    non_map_fd, // reg >= T_NUM
    mem, // shared | packet | stack = reg >= T_STACK
    mem_or_num, // reg >= T_NUM && reg != T_CTX
    ptr, // reg >= T_CTX
    ptr_or_num, // reg >= T_NUM
    stack_or_packet // reg >= T_STACK && reg <= T_PACKET
};


struct ValidSize {
    Reg reg;
    bool can_be_zero{};
};

struct Comparable {
    Reg r1;
    Reg r2;
};

// ptr: ptr -> num : num
struct Addable {
    Reg ptr;
    Reg num;
};

struct ValidAccess {
    Reg reg;
    int offset{};
    Value width{Imm{0}};
    bool or_null{};
};

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

using AssertionConstraint = std::variant<Comparable, Addable, ValidAccess, ValidStore, ValidSize, ValidMapKeyValue, TypeConstraint>;

struct Assert {
    AssertionConstraint cst;
    bool satisfied = false;
};

#define DECLARE_EQ6(T, f1, f2, f3, f4, f5, f6)                                                                         \
    inline bool operator==(T const& a, T const& b) {                                                                   \
        return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4 && a.f5 == b.f5 && a.f6 == b.f6;           \
    }
#define DECLARE_EQ5(T, f1, f2, f3, f4, f5)                                                                             \
    inline bool operator==(T const& a, T const& b) {                                                                   \
        return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4 && a.f5 == b.f5;                           \
    }
#define DECLARE_EQ4(T, f1, f2, f3, f4)                                                                                 \
    inline bool operator==(T const& a, T const& b) {                                                                   \
        return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4;                                           \
    }
#define DECLARE_EQ3(T, f1, f2, f3)                                                                                     \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3; }
#define DECLARE_EQ2(T, f1, f2)                                                                                         \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1 && a.f2 == b.f2; }
#define DECLARE_EQ1(T, f1)                                                                                             \
    inline bool operator==(T const& a, T const& b) { return a.f1 == b.f1; }
#define DECLARE_EQ0(T)                                                                                                 \
    inline bool operator==(T const& a, T const& b) { return true; }

using Instruction = std::variant<Undefined, Bin, Un, LoadMapFd, Call, Exit, Jmp, Mem, Packet, LockAdd, Assume, Assert>;

using LabeledInstruction = std::tuple<label_t, Instruction>;
using InstructionSeq = std::vector<LabeledInstruction>;

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
// DECLARE_EQ1(OnlyZeroIfNum, reg)
DECLARE_EQ2(ValidSize, reg, can_be_zero)
DECLARE_EQ2(Comparable, r1, r2)
DECLARE_EQ2(Addable, ptr, num)
DECLARE_EQ2(ValidStore, mem, val)
DECLARE_EQ4(ValidAccess, reg, offset, width, or_null)
DECLARE_EQ3(ValidMapKeyValue, access_reg, map_fd_reg, key)
DECLARE_EQ1(Assert, cst)

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...)->overloaded<Ts...>;
