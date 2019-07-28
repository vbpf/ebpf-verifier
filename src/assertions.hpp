#pragma once

#include <bitset>

#include "asm_cfg.hpp"
#include "spec_type_descriptors.hpp"

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

void explicate_assertions(Cfg& cfg, program_info info);

// struct OnlyZeroIfNum {
//     Reg reg;
// };

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
    Value width;
    bool or_null{};
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

struct Assertion {
    std::variant<Comparable, Addable, ValidAccess, ValidStore, ValidSize, TypeConstraint> cst;
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

DECLARE_EQ2(TypeConstraint, reg, types)
// DECLARE_EQ1(OnlyZeroIfNum, reg)
DECLARE_EQ2(ValidSize, reg, can_be_zero)
DECLARE_EQ2(Comparable, r1, r2)
DECLARE_EQ2(Addable, ptr, num)
DECLARE_EQ2(ValidStore, mem, val)
DECLARE_EQ4(ValidAccess, reg, offset, width, or_null)
DECLARE_EQ1(Assertion, cst)
