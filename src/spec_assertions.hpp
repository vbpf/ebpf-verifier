#pragma once

#include "asm_cfg.hpp"
#include <boost/dynamic_bitset.hpp>

enum {
    T_UNINIT = -6,
    T_CTX = -5,
    T_STACK = -4,
    T_DATA = -3,
    T_NUM = -2,
    T_MAP_STRUCT = -1,
    T_MAP = 0,
};

using Types = boost::dynamic_bitset<>;

struct TypeSet {
    const size_t nonmaps = 5;
    const size_t nmaps;
    TypeSet(size_t nmaps) : nmaps{nmaps} { }
    size_t size() const { return nmaps + nonmaps; };

    Types single(int n) const {
        Types res{size()};
        if (n < 0)
            return res.set(size()+n);
        else 
            return res.set(n);
    }

    Types map_types() const {
        Types res{size()};
        res.set();
        for (size_t i=0; i < nonmaps; i++)
            res.reset(nmaps + i);
        return res;
    }

    Types all() const { return Types{size()}.set(); }
    Types num() const { return single(T_NUM); }
    Types map_struct() const { return single(T_MAP_STRUCT); }
    Types ctx() const { return single(T_CTX); }
    Types packet() const { return single(T_DATA); }
    Types stack() const { return single(T_STACK); }
    Types ptr() const { return (num() | map_struct()).flip(); }
};

 
void explicate_assertions(Cfg& cfg, std::vector<size_t> maps_sizes);

class Assertion {
public:
    struct False { };
    struct True { };

    struct LinearConstraint {
        Condition::Op op;
        Reg reg;
        int offset;
        Value width;
        Value v;
    };
    struct TypeConstraint {
        Reg reg;
        Types types;
        Assertion implies(LinearConstraint cst) {
            return {*this, cst};
        }
        Assertion impliesType(TypeConstraint cst) {
            return {*this, cst};
        }
    };
    using Conclusion = std::variant<TypeConstraint, LinearConstraint, False>;
    using Given = std::variant<TypeConstraint, True>;

    Given given;
    Conclusion then;
    Assertion(Given given, Conclusion then) : given{given}, then{then} { }
    Assertion(Conclusion then) : given{True{}}, then{then} { }
};
#define DECLARE_EQ5(T, f1, f2, f3, f4, f5) \
    inline bool operator==(T const& a, T const& b){ return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4 && a.f5 == b.f5; }
#define DECLARE_EQ4(T, f1, f2, f3, f4) \
    inline bool operator==(T const& a, T const& b){ return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3 && a.f4 == b.f4; }
#define DECLARE_EQ3(T, f1, f2, f3) \
    inline bool operator==(T const& a, T const& b){ return a.f1 == b.f1 && a.f2 == b.f2 && a.f3 == b.f3; }
#define DECLARE_EQ2(T, f1, f2) \
    inline bool operator==(T const& a, T const& b){ return a.f1 == b.f1 && a.f2 == b.f2; }
#define DECLARE_EQ1(T, f1) \
    inline bool operator==(T const& a, T const& b){ return a.f1 == b.f1; }
#define DECLARE_EQ0(T) \
    inline bool operator==(T const& a, T const& b){ return true; }

DECLARE_EQ0(Assertion::True)
DECLARE_EQ0(Assertion::False)
DECLARE_EQ2(Assertion::TypeConstraint, reg, types)
DECLARE_EQ5(Assertion::LinearConstraint, op, reg, offset, width, v)
DECLARE_EQ2(Assertion, given, then)

