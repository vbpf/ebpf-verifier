// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <utility>

#include "crab/cfg.hpp"
#include "crab/linear_constraints.hpp"

namespace crab::dsl_syntax {

inline linear_expression_t operator*(const number_t& n, variable_t x) { return {n, x}; }

inline linear_expression_t operator*(int n, variable_t x) { return linear_expression_t(number_t(n), x); }

inline linear_expression_t operator*(variable_t x, const number_t& n) { return linear_expression_t(n, x); }

inline linear_expression_t operator*(variable_t x, int n) { return linear_expression_t(number_t(n), x); }

inline linear_expression_t operator*(const number_t& n, const linear_expression_t& e) { return e.operator*(n); }

inline linear_expression_t operator*(int n, const linear_expression_t& e) { return e.operator*(n); }

inline linear_expression_t operator+(variable_t x, number_t n) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(variable_t x, int n) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(number_t n, variable_t x) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(int n, variable_t x) { return linear_expression_t(x).operator+(n); }

inline linear_expression_t operator+(variable_t x, variable_t y) { return linear_expression_t(x).operator+(y); }

inline linear_expression_t operator+(number_t n, const linear_expression_t& e) { return e.operator+(n); }

inline linear_expression_t operator+(int n, const linear_expression_t& e) { return e.operator+(n); }

inline linear_expression_t operator+(variable_t x, const linear_expression_t& e) { return e.operator+(x); }

inline linear_expression_t operator-(variable_t x, const number_t& n) { return var_sub(x, n); }

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

inline linear_constraint_t operator<=(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(int n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(x - e, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, int n) {
    return linear_constraint_t(x - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(number_t n, variable_t x) {
    return linear_constraint_t(n - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(int n, variable_t x) {
    return linear_constraint_t(n - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, int n) {
    return linear_constraint_t(n - e, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(x - e, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, number_t n) {
    return linear_constraint_t(n - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, int n) {
    return linear_constraint_t(n - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(int n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(variable_t x, variable_t y) {
    return linear_constraint_t(y - x, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator>=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e2 - e1, cst_kind::INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(int n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(x - e, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, int n) {
    return linear_constraint_t(x - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(number_t n, variable_t x) {
    return linear_constraint_t(n - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(int n, variable_t x) {
    return linear_constraint_t(n - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, cst_kind::STRICT_INEQUALITY);
}

// inline bool operator>(number_t n, int x) { return n.operator>(x); }

inline linear_constraint_t operator>(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const linear_expression_t& e, int n) {
    return linear_constraint_t(n - e, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(x - e, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, number_t n) {
    return linear_constraint_t(n - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, int n) {
    return linear_constraint_t(n - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(int n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(variable_t x, variable_t y) {
    return linear_constraint_t(y - x, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator>(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e2 - e1, cst_kind::STRICT_INEQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, int n) {
    return linear_constraint_t(x - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(int n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, cst_kind::EQUALITY);
}

inline linear_constraint_t operator==(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, cst_kind::EQUALITY);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, int n) {
    return linear_constraint_t(x - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(int n, variable_t x) {
    return linear_constraint_t(x - n, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, cst_kind::DISEQUATION);
}

inline linear_constraint_t operator!=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, cst_kind::DISEQUATION);
}
} // end namespace crab
