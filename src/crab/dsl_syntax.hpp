// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <utility>

#include "crab/cfg.hpp"
#include "crab/linear_constraint.hpp"

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

inline linear_expression_t operator-(variable_t x, const number_t& n) { return linear_expression_t(x).operator-(n); }

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
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(int n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(x - e, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(variable_t x, int n) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(number_t n, variable_t x) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(int n, variable_t x) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, int n) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(x - e, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(variable_t x, number_t n) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(variable_t x, int n) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(int n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(variable_t x, variable_t y) {
    return linear_constraint_t(y - x, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator>=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e2 - e1, constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO);
}

inline linear_constraint_t operator<(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(number_t n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(int n, const linear_expression_t& e) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(x - e, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(variable_t x, int n) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(number_t n, variable_t x) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(int n, variable_t x) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator<(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::LESS_THAN_ZERO);
}

// inline bool operator>(number_t n, int x) { return n.operator>(x); }

inline linear_constraint_t operator>(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(const linear_expression_t& e, int n) {
    return linear_constraint_t(n - e, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(x - e, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(variable_t x, number_t n) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(variable_t x, int n) {
    return linear_constraint_t(n - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(int n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(variable_t x, variable_t y) {
    return linear_constraint_t(y - x, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator>(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e2 - e1, constraint_kind_t::LESS_THAN_ZERO);
}

inline linear_constraint_t operator==(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(variable_t x, int n) {
    return linear_constraint_t(x - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(int n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t equals(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator==(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::EQUALS_ZERO);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, const number_t& n) {
    return linear_constraint_t(e - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, int n) {
    return linear_constraint_t(e - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(const number_t& n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(int n, const linear_expression_t& e) {
    return linear_constraint_t(e - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(const linear_expression_t& e, variable_t x) {
    return linear_constraint_t(e - x, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(variable_t x, const linear_expression_t& e) {
    return linear_constraint_t(e - x, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(variable_t x, const number_t& n) {
    return linear_constraint_t(x - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(variable_t x, int n) {
    return linear_constraint_t(x - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(const number_t& n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(int n, variable_t x) {
    return linear_constraint_t(x - n, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, constraint_kind_t::NOT_ZERO);
}

inline linear_constraint_t operator!=(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, constraint_kind_t::NOT_ZERO);
}
} // end namespace crab
