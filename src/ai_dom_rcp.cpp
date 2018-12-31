#include <vector>
#include <iostream>

#include "ai_dom_set.hpp"

#include "spec_assertions.hpp"
#include "ai_dom_rcp.hpp"

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
    // assert !fd and !o.fd
}

void RCP_domain::assume(RCP_domain& then_reg, Types then_type, const RCP_domain& where_reg, Types where_type) {
    if (where_reg.is_of_type(where_type))
        assume(then_reg, then_type);
}

void RCP_domain::assume(RCP_domain& reg, Types t) {
    reg.pointwise_if(t.flip(), [](auto& a){ a.to_bot(); });
}

void RCP_domain::assume(RCP_domain& left, Condition::Op op, const RCP_domain& right, Types where_types) {
    left.pointwise_if(where_types, right,
        [op](auto& a, const auto& b){ a.assume(op, b); });
}

RCP_domain RCP_domain::maps_from_fds() const {
    auto res = *this;
    for (size_t i=0; i < fd.fds.size(); i++)
        if (fd.fds[i]) {
            res.maps[i] = 0;
        }
    res.fd.to_bot();
    return res;
}
