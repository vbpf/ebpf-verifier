#include "crab/linear_constraints.hpp"
#include "crab/cfg.hpp"

namespace crab {

namespace dsl_syntax {

struct basic_block_builder {
    basic_block_t& bb;

    basic_block_builder(basic_block_t& bb) : bb(bb) { }
    /// To build statements

    basic_block_t& operator*() { return bb; }
    basic_block_t* operator->() { return &bb; }

    template <typename T, typename... Args>
    void insert(Args&&... args) {
        bb.insert<T>(std::forward<Args>(args)...);
    }

    void add(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::ADD, op1, op2); }

    void add(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::ADD, op1, op2); }

    void sub(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SUB, op1, op2); }

    void sub(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SUB, op1, op2); }

    void mul(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::MUL, op1, op2); }

    void mul(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::MUL, op1, op2); }

    // signed division
    void div(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SDIV, op1, op2); }

    void div(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SDIV, op1, op2); }

    // unsigned division
    void udiv(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::UDIV, op1, op2); }

    void udiv(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::UDIV, op1, op2); }

    // signed rem
    void rem(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SREM, op1, op2); }

    void rem(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SREM, op1, op2); }

    // unsigned rem
    void urem(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::UREM, op1, op2); }

    void urem(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::UREM, op1, op2); }

    void bitwise_and(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::AND, op1, op2); }

    void bitwise_and(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::AND, op1, op2); }

    void bitwise_or(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::OR, op1, op2); }

    void bitwise_or(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::OR, op1, op2); }

    void bitwise_xor(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::XOR, op1, op2); }

    void bitwise_xor(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::XOR, op1, op2); }

    void shl(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::SHL, op1, op2); }

    void shl(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::SHL, op1, op2); }

    void lshr(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::LSHR, op1, op2); }

    void lshr(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::LSHR, op1, op2); }

    void ashr(variable_t lhs, variable_t op1, variable_t op2) { insert<binary_op_t>(lhs, BINOP::ASHR, op1, op2); }

    void ashr(variable_t lhs, variable_t op1, number_t op2) { insert<binary_op_t>(lhs, BINOP::ASHR, op1, op2); }

    void assign(variable_t lhs, linear_expression_t rhs) { insert<assign_t>(lhs, rhs); }

    void assume(linear_constraint_t cst) { insert<assume_t>(cst); }

    void havoc(variable_t lhs) { insert<havoc_t>(lhs); }

    void select(variable_t lhs, variable_t v, linear_expression_t e1, linear_expression_t e2) {
        linear_constraint_t cond(exp_gte(v, 1));
        insert<select_t>(lhs, cond, e1, e2);
    }

    void select(variable_t lhs, linear_constraint_t cond, linear_expression_t e1, linear_expression_t e2) {
        insert<select_t>(lhs, cond, e1, e2);
    }

    void assertion(linear_constraint_t cst, debug_info di = {}) { insert<assert_t>(cst, di); }

    void array_store(variable_t arr, linear_expression_t idx, linear_expression_t v, linear_expression_t elem_size) {
        insert<array_store_t>(arr, elem_size, idx, idx, v);
    }

    void array_store_range(variable_t arr, linear_expression_t lb_idx, linear_expression_t ub_idx,
                           linear_expression_t v, linear_expression_t elem_size) {
        insert<array_store_t>(arr, elem_size, lb_idx, ub_idx, v);
    }

    void array_load(variable_t lhs, variable_t arr, linear_expression_t idx, linear_expression_t elem_size) {
        insert<array_load_t>(lhs, arr, elem_size, idx);
    }
};


inline linear_expression_t operator*(number_t n, variable_t x) { return {n, x}; }

inline linear_expression_t operator*(int n, variable_t x) { return linear_expression_t(number_t(n), x); }

inline linear_expression_t operator*(variable_t x, number_t n) { return linear_expression_t(n, x); }

inline linear_expression_t operator*(variable_t x, int n) { return linear_expression_t(number_t(n), x); }

inline linear_expression_t operator*(number_t n, const linear_expression_t& e) { return e.operator*(n); }

inline linear_expression_t operator*(int n, const linear_expression_t& e) { return e.operator*(n); }

inline linear_expression_t operator+(variable_t x, number_t n) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(variable_t x, int n) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(number_t n, variable_t x) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(int n, variable_t x) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(variable_t x, variable_t y) { return linear_expression_t(x).operator+(y); }

inline linear_expression_t operator+(number_t n, const linear_expression_t& e) { return e.operator+(n); }

inline linear_expression_t operator+(int n, const linear_expression_t& e) { return e.operator+(n); }

inline linear_expression_t operator+(variable_t x, const linear_expression_t& e) { return e.operator+(x); }

inline linear_expression_t operator-(variable_t x, number_t n) { return var_sub(x, n); }

inline linear_expression_t operator-(variable_t x, int n) { return linear_expression_t(x).operator-(n); }

inline linear_expression_t operator-(number_t n, variable_t x) {
    return linear_expression_t(number_t(-1), x).operator+(n);
}

inline linear_expression_t operator-(int n, variable_t x) { return linear_expression_t(number_t(-1), x).operator+(n); }

inline linear_expression_t operator-(variable_t x, variable_t y) { return linear_expression_t(x).operator-(y); }

inline linear_expression_t operator-(number_t n, const linear_expression_t& e) {
    return linear_expression_t(n).operator-(e);
}

inline linear_expression_t operator-(int n, const linear_expression_t& e) {
    return linear_expression_t(number_t(n)).operator-(e);
}

inline linear_expression_t operator-(variable_t x, const linear_expression_t& e) {
    return linear_expression_t(number_t(1), x).operator-(e);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(e - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(int n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(x - e, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, number_t n) {
    return linear_constraint_t(x - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, int n) {
    return linear_constraint_t(x - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(number_t n, variable_t x) {
    return linear_constraint_t(n - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(int n, variable_t x) {
    return linear_constraint_t(n - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, int n) {
    return linear_constraint_t(n - e, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(x - e, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, number_t n) {
    return linear_constraint_t(n - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, int n) {
    return linear_constraint_t(n - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(number_t n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(int n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, variable_t y) {
    return linear_constraint_t(y - x, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e2 - e1, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(e - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(int n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(x - e, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, number_t n) {
    return linear_constraint_t(x - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, int n) {
    return linear_constraint_t(x - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(number_t n, variable_t x) {
    return linear_constraint_t(n - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(int n, variable_t x) {
    return linear_constraint_t(n - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, linear_constraint_t::STRICT_INEQUALITY);
}

// inline bool operator>(number_t n, int x) { return n.operator>(x); }

inline linear_constraint_t operator>(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const linear_expression_t& e, int n) {
    return linear_constraint_t(n - e, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(x - e, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, number_t n) {
    return linear_constraint_t(n - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, int n) {
    return linear_constraint_t(n - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(number_t n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(int n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, variable_t y) {
    return linear_constraint_t(y - x, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e2 - e1, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(e - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, number_t n) {
    return linear_constraint_t(x - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, int n) {
    return linear_constraint_t(x - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(number_t n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(int n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, linear_constraint_t::EQUALITY);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(e - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, number_t n) {
    return linear_constraint_t(x - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, int n) {
    return linear_constraint_t(x - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(number_t n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(int n, variable_t x) {
    return linear_constraint_t(x - n, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, linear_constraint_t::DISEQUATION);
}

inline linear_constraint_t operator!=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, linear_constraint_t::DISEQUATION);
}
} // end namespace dsl_syntax

} // end namespace crab