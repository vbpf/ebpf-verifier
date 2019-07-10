#pragma once

#include "crab/types.hpp"
#include "crab/linear_constraints.hpp"

/* Types for abstract domain operations */

namespace ikos {
    // Enumeration type for basic arithmetic operations
    // Do not modify the order.
    typedef enum {
      OP_ADDITION,
      OP_SUBTRACTION,
      OP_MULTIPLICATION,
      OP_SDIV, 
      OP_UDIV, 
      OP_SREM, 
      OP_UREM
    } operation_t;
    
    inline crab::crab_os& operator<<(crab::crab_os&o, operation_t op) {
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
    typedef enum  { 
      OP_AND, 
      OP_OR, 
      OP_XOR, 
      OP_SHL, 
      OP_LSHR, 
      OP_ASHR
    } bitwise_operation_t;
    
    inline crab::crab_os& operator<<(crab::crab_os&o, bitwise_operation_t op) {
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
}

namespace crab {
namespace domains {
  
    // Enumeration type for cast operations
    typedef enum  { 
      OP_TRUNC, 
      OP_SEXT, 
      OP_ZEXT 
    } int_conv_operation_t;
    
    inline crab::crab_os& operator<<(crab::crab_os&o, int_conv_operation_t op) {
      switch (op) {
      case OP_TRUNC: o << "trunc"; break;
      case OP_SEXT : o << "sext"; break;
      default: /*OP_ZEXT*/ o << "zext"; break;
      }
      return o;
    }

  } // end namespace domains

  /**
   * Convert CFG operations into abstract domain operations
   **/
  template<>
  inline boost::optional<ikos::operation_t> conv_op(binary_operation_t op) {
    switch (op) {
    case BINOP_ADD: return ikos::OP_ADDITION;
    case BINOP_SUB: return ikos::OP_SUBTRACTION;
    case BINOP_MUL: return ikos::OP_MULTIPLICATION;
    case BINOP_SDIV: return ikos::OP_SDIV;
    case BINOP_UDIV: return ikos::OP_UDIV;
    case BINOP_SREM: return ikos::OP_SREM;
    case BINOP_UREM: return ikos::OP_UREM;
    default: return boost::optional<ikos::operation_t>();
    }
  }

  template<>
  inline boost::optional<ikos::bitwise_operation_t> conv_op(binary_operation_t op) {     
    switch (op) {
    case BINOP_AND: return ikos::OP_AND;
    case BINOP_OR: return ikos::OP_OR;
    case BINOP_XOR: return ikos::OP_XOR;
    case BINOP_SHL: return ikos::OP_SHL;
    case BINOP_LSHR: return ikos::OP_LSHR;
    case BINOP_ASHR: return ikos::OP_ASHR;
    default: return boost::optional<ikos::bitwise_operation_t>();
    }
  }

  template<>
  inline boost::optional<domains::int_conv_operation_t> conv_op(cast_operation_t op) {     
    switch (op) {
    case CAST_TRUNC: return domains::OP_TRUNC;
    case CAST_SEXT:  return domains::OP_SEXT;
    case CAST_ZEXT: return domains::OP_ZEXT;
    default: return boost::optional<domains::int_conv_operation_t>();
    }
  }
  
  
  
} // end namespace crab
