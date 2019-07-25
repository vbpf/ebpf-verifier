#pragma once

#include <iostream>
#include <sstream>

#include "crab/linear_constraints.hpp"
#include "crab/types.hpp"
#include "crab/abstract_domain_operators.hpp"

namespace crab {

struct debug_info {
    std::string msg{};
    int line{-2};
    int col{-2};

    bool operator<(const debug_info& other) const { return msg < other.msg && line < other.line && col < other.col; }

    bool operator==(const debug_info& other) const { return msg == other.msg && line == other.line && col == other.col; }

    bool has_debug() const { return line > -2 || col > -2; }
};

inline std::ostream& operator<<(std::ostream& o, const debug_info& l) {
    o << l.msg <<"\n"
      << "Line  : " << l.line << "\n"
      << "Column: " << l.col << "\n";
    return o;
}

/*
  Numerical statements
*/

struct binary_op_t {
    variable_t lhs;
    binop_t op;
    linear_expression_t left;
    linear_expression_t right;
    bool finite_width{};
};

struct assign_t {
    variable_t lhs;
    linear_expression_t rhs;
};

struct assume_t {
    linear_constraint_t constraint;
};

struct havoc_t {
    variable_t lhs;
};

// select x, c, e1, e2:
//    if c > 0 then x=e1 else x=e2
//
// Note that a select instruction is not strictly needed and can be
// simulated by splitting blocks. However, frontends like LLVM can
// generate many select instructions so we prefer to support
// natively to avoid a blow up in the size of the CFG.
struct select_t {
    variable_t lhs;
    linear_constraint_t cond;
    linear_expression_t left;
    linear_expression_t right;
};

struct assert_t {
    linear_constraint_t constraint;
    debug_info debug;
};

/*
  Array statements
*/

// Each of these statements requires an element size, that is, the
// number of bytes that are being accessed. If the front-end is
// LLVM, then the element size is always known at compilation
// time. However, with other front-ends (e.g., BPF programs) the
// element size is stored in a variable so that's why the type of
// the element size is not just a constant integer but it can also
// be a variable.

struct array_store_t {
    // forall i \in [lb,ub) % elem_size :: arr[i] := val
    data_kind_t array;
    linear_expression_t index;
    linear_expression_t elem_size; //! size in bytes
    linear_expression_t value;
};

struct array_store_range_t {
    data_kind_t array;
    linear_expression_t index;
    linear_expression_t width;
    linear_expression_t value;
};

struct array_load_t {
    variable_t lhs;
    data_kind_t array;
    linear_expression_t elem_size; //! size in bytes
    linear_expression_t index;
};

struct array_havoc_t {
    data_kind_t array;
    linear_expression_t elem_size; //! size in bytes
    linear_expression_t index;
};

using new_statement_t =
    std::variant<binary_op_t, assign_t, assume_t, select_t, assert_t, havoc_t,
                 array_store_t, array_store_range_t, array_load_t, array_havoc_t>;

std::ostream& operator<<(std::ostream& os, const new_statement_t& a);

} // namespace crab