#include "crab/cfg.hpp"
#include "crab/linear_constraints.hpp"

namespace crab {

namespace dsl_syntax {

inline linear_expression_t operator*(number_t n, variable_t x) { return {n, x}; }


inline linear_expression_t operator*(variable_t x, number_t n) { return linear_expression_t(n, x); }


inline linear_expression_t operator*(number_t n, const linear_expression_t& e) { return e.operator*(n); }


inline linear_expression_t operator+(variable_t x, number_t n) { return linear_expression_t(x).operator+(n); }


inline linear_expression_t operator+(number_t n, variable_t x) { return linear_expression_t(x).operator+(n); }


inline linear_expression_t operator+(variable_t x, variable_t y) { return linear_expression_t(x).operator+(y); }

inline linear_expression_t operator+(number_t n, const linear_expression_t& e) { return e.operator+(n); }


inline linear_expression_t operator+(variable_t x, const linear_expression_t& e) { return e.operator+(x); }

inline linear_expression_t operator-(variable_t x, number_t n) { return var_sub(x, n); }


inline linear_expression_t operator-(number_t n, variable_t x) {
    return linear_expression_t(number_t(-1), x).operator+(n);
}


inline linear_expression_t operator-(variable_t x, variable_t y) { return linear_expression_t(x).operator-(y); }

inline linear_expression_t operator-(number_t n, const linear_expression_t& e) {
    return linear_expression_t(n).operator-(e);
}


inline linear_expression_t operator-(variable_t x, const linear_expression_t& e) {
    return linear_expression_t(number_t(1), x).operator-(e);
}

inline linear_constraint_t operator<=(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(e - n, linear_constraint_t::INEQUALITY);
}

inline linear_constraint_t operator<=(number_t n, const linear_expression_t& e) {
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


inline linear_constraint_t operator<=(number_t n, variable_t x) {
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


inline linear_constraint_t operator>=(number_t n, const linear_expression_t& e) {
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


inline linear_constraint_t operator>=(number_t n, variable_t x) {
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


inline linear_constraint_t operator<(number_t n, const linear_expression_t& e) {
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


inline linear_constraint_t operator<(number_t n, variable_t x) {
    return linear_constraint_t(n - x, linear_constraint_t::STRICT_INEQUALITY);
}


inline linear_constraint_t operator<(variable_t x, variable_t y) {
    return linear_constraint_t(x - y, linear_constraint_t::STRICT_INEQUALITY);
}

inline linear_constraint_t operator<(const linear_expression_t& e1, const linear_expression_t& e2) {
    return linear_constraint_t(e1 - e2, linear_constraint_t::STRICT_INEQUALITY);
}


inline linear_constraint_t operator>(const linear_expression_t& e, number_t n) {
    return linear_constraint_t(n - e, linear_constraint_t::STRICT_INEQUALITY);
}


inline linear_constraint_t operator>(number_t n, const linear_expression_t& e) {
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


inline linear_constraint_t operator>(number_t n, variable_t x) {
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


inline linear_constraint_t operator==(number_t n, const linear_expression_t& e) {
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


inline linear_constraint_t operator==(number_t n, variable_t x) {
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


inline linear_constraint_t operator!=(number_t n, const linear_expression_t& e) {
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


inline linear_constraint_t operator!=(number_t n, variable_t x) {
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
