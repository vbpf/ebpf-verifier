#include <vector>
#include <iostream>

#include <assert.h>

#include "ai_dom_set.hpp"

#include "spec_assertions.hpp"
#include "ai_dom_rcp.hpp"
#include "asm_ostream.hpp"

void RCP_domain::operator+=(const RCP_domain& rhs) {
    for (size_t t=0; t < maps.size(); t++) {
        maps[t] = (num + rhs.maps[t]) | (maps[t] + rhs.num);
    }
    ctx = (num + rhs.ctx) | (ctx + rhs.num);
    stack = (num + rhs.stack) | (stack + rhs.num);
    packet = (num + rhs.packet) | (packet + rhs.num);

    num.exec(Bin::Op::ADD, rhs.num);
    // assert !fd and !o.fd
}

void RCP_domain::operator-=(const RCP_domain& rhs) {
    if (this == &rhs) {
        to_bot();
        num = NumDom(0);
        return;
    }
    num.exec(Bin::Op::SUB, rhs.num);
    for (size_t t=0; t < rhs.maps.size(); t++) {
        num |= maps[t] - rhs.maps[t];
    }
    num |= ctx - rhs.ctx;
    num |= stack - rhs.stack;
    num |= packet - rhs.packet;

    for (size_t t=0; t < maps.size(); t++) {
        maps[t] -= rhs.num;
    }
    packet -= rhs.num;
    stack -= rhs.num;
    ctx -= rhs.num;
    // assert !fd and !o.fd
}

void RCP_domain::assume(RCP_domain& then_reg, Types then_types, const RCP_domain& where_reg, Types where_types) {
    assert(then_reg.valid_types(then_types));
    assert(then_reg.valid_types(where_types));
    if (where_reg.is_of_type(where_types))
        assume(then_reg, then_types);
}

void RCP_domain::assume(RCP_domain& reg, Types t) {
    assert(reg.valid_types(t));
    reg.pointwise_if(t.flip(), [](auto& a){ a.to_bot(); });
}

void RCP_domain::assume(RCP_domain& left, Condition::Op op, const RCP_domain& right, Types where_types) {
    assert(left.valid_types(where_types));
    left.pointwise_if(where_types, right,
        [op](auto& a, const auto& b){
            a.assume(op, b);
        });
}

bool RCP_domain::satisfied(const RCP_domain& then_reg, Types then_types, const RCP_domain& where_reg, Types where_types) {
    assert(then_reg.valid_types(then_types));
    assert(then_reg.valid_types(where_types));
    return !where_reg.is_of_type(where_types) || then_reg.is_of_type(then_types);
}

bool RCP_domain::satisfied(const RCP_domain& r, Types t) {
    assert(r.valid_types(t));
    return r.is_of_type(t);
}

bool RCP_domain::satisfied(const RCP_domain& left, Condition::Op op, const RCP_domain& right, Types where_types) {
    if (!left.is_of_type(where_types)) return true;
    // for simplicity, assume unpriviledged: cannot compare different types
    // so only satisfied it's the same single type in both arguments
    // if (where_types.count() != 1) { std::cout << "More than 1: " << where_types << "\n"; return false; }
    if (!right.is_of_type(where_types)) return false;
    return left.pointwise_all_pairs(where_types, right,
                [op](const auto& a, const auto& b) { return a.satisfied(op, b); });
}
