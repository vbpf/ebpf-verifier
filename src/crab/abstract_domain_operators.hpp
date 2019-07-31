#pragma once

#include <variant>

#include "crab/types.hpp"

/* Types for abstract domain operations */

namespace crab {
// Enumeration type for basic arithmetic operations
// Do not modify the order.
enum class arith_binop_t { ADD, SUB, MUL, SDIV, UDIV, SREM, UREM };

inline std::ostream& operator<<(std::ostream& o, arith_binop_t op) {
    switch (op) {
    case arith_binop_t::ADD: o << "+"; break;
    case arith_binop_t::SUB: o << "-"; break;
    case arith_binop_t::MUL: o << "*"; break;
    case arith_binop_t::SDIV: o << "/"; break;
    case arith_binop_t::UDIV: o << "/_u"; break;
    case arith_binop_t::SREM: o << "%"; break;
    case arith_binop_t::UREM: o << "%"; break;
    }
    return o;
}

// Enumeration type for bitwise operations
enum class bitwise_binop_t { AND, OR, XOR, SHL, LSHR, ASHR };

inline std::ostream& operator<<(std::ostream& o, bitwise_binop_t op) {
    switch (op) {
    case bitwise_binop_t::AND: o << "&"; break;
    case bitwise_binop_t::OR: o << "|"; break;
    case bitwise_binop_t::XOR: o << "^"; break;
    case bitwise_binop_t::SHL: o << "<<"; break;
    case bitwise_binop_t::LSHR: o << ">>_l"; break;
    case bitwise_binop_t::ASHR: o << ">>_l"; break;
    }
    return o;
}

using binop_t = std::variant<arith_binop_t, bitwise_binop_t>;

inline std::ostream& operator<<(std::ostream& o, binop_t op) {
    return std::visit([&](auto top) -> std::ostream& { return o << top; }, op);
}

} // end namespace crab
