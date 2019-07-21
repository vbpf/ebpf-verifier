#pragma once

//#include "crab/linear_constraints.hpp"
#include "crab/types.hpp"

/* Types for abstract domain operations */

namespace crab {
// Enumeration type for basic arithmetic operations
// Do not modify the order.
enum operation_t { OP_ADDITION, OP_SUBTRACTION, OP_MULTIPLICATION, OP_SDIV, OP_UDIV, OP_SREM, OP_UREM };

inline crab_os& operator<<(crab_os& o, operation_t op) {
    switch (op) {
    case OP_ADDITION: o << "+"; break;
    case OP_SUBTRACTION: o << "-"; break;
    case OP_MULTIPLICATION: o << "*"; break;
    case OP_SDIV: o << "/"; break;
    case OP_UDIV: o << "/_u"; break;
    case OP_SREM: o << "%"; break;
    default: o << "%_u"; break;
    }
    return o;
}

// Enumeration type for bitwise operations
enum bitwise_operation_t { OP_AND, OP_OR, OP_XOR, OP_SHL, OP_LSHR, OP_ASHR };

inline crab_os& operator<<(crab_os& o, bitwise_operation_t op) {
    switch (op) {
    case OP_AND: o << "&"; break;
    case OP_OR: o << "|"; break;
    case OP_XOR: o << "^"; break;
    case OP_SHL: o << "<<"; break;
    case OP_LSHR: o << ">>_l"; break;
    default: o << ">>_a"; break;
    }
    return o;
}

/**
 * Convert CFG operations into abstract domain operations
 **/
template <>
inline std::optional<operation_t> conv_op(binary_operation_t op) {
    switch (op) {
    case BINOP::ADD: return OP_ADDITION;
    case BINOP::SUB: return OP_SUBTRACTION;
    case BINOP::MUL: return OP_MULTIPLICATION;
    case BINOP::SDIV: return OP_SDIV;
    case BINOP::UDIV: return OP_UDIV;
    case BINOP::SREM: return OP_SREM;
    case BINOP::UREM: return OP_UREM;
    default: return std::optional<operation_t>();
    }
}

template <>
inline std::optional<bitwise_operation_t> conv_op(binary_operation_t op) {
    switch (op) {
    case BINOP::AND: return OP_AND;
    case BINOP::OR: return OP_OR;
    case BINOP::XOR: return OP_XOR;
    case BINOP::SHL: return OP_SHL;
    case BINOP::LSHR: return OP_LSHR;
    case BINOP::ASHR: return OP_ASHR;
    default: return std::optional<bitwise_operation_t>();
    }
}

} // end namespace crab
