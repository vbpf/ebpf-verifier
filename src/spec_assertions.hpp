#pragma once

#include <bitset>

#include "asm_cfg.hpp"
#include "spec_type_descriptors.hpp"

enum {
    T_UNINIT = -6,
    T_NUM = -5,
    T_MAP = -4,
    T_CTX = -3,
    T_STACK = -2,
    T_DATA = -1,
    T_SHARED = 0
};

using Types = std::bitset<NMAPS + NONMAPS>;

namespace TypeSet {
static Types single(int n) {
    Types res;
    if (n < 0)
        return res.set(res.size() + n);
    else
        return res.set(n);
}

const Types all = Types{}.set();
const Types num = single(T_NUM);
const Types fd = single(T_MAP);
const Types ctx = single(T_CTX);
const Types packet = single(T_DATA);
const Types stack = single(T_STACK);
const Types maps = (num | fd | ctx | packet | stack).flip();
const Types mem = maps | packet | stack;
const Types ptr = mem | ctx;
const Types nonfd = ptr | num;
} // namespace TypeSet

void explicate_assertions(Cfg& cfg, program_info info);

struct OnlyZeroIfNum {
    Reg reg;
};

struct ValidSize {
    Reg reg;
    bool can_be_zero{};
};

struct Comparable {
    Reg r1;
    Reg r2;
};

struct ValidAccess {
    Reg reg;
    int offset{};
    Value width;
    bool or_null{};
};

struct TypeConstraint {
    struct RT {
        Reg reg;
        Types types;
    };
    RT then;
    std::optional<RT> given;
    TypeConstraint(RT then) : then{then} {}
    TypeConstraint(RT then, RT given) : then{then}, given{given} {}
};

struct Assertion {
    std::variant<Comparable, ValidAccess, ValidSize, OnlyZeroIfNum, TypeConstraint> cst;
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

DECLARE_EQ2(TypeConstraint::RT, reg, types)
DECLARE_EQ2(TypeConstraint, given, then)
DECLARE_EQ1(OnlyZeroIfNum, reg)
DECLARE_EQ2(ValidSize, reg, can_be_zero)
DECLARE_EQ2(Comparable, r1, r2)
DECLARE_EQ4(ValidAccess, reg, offset, width, or_null)
DECLARE_EQ1(Assertion, cst)
