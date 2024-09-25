// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/interval.hpp"

namespace crab {

// Signed division. eBPF has no instruction for this.
interval_t interval_t::operator/(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        number_t c = *n;
        if (c == number_t{1}) {
            return *this;
        } else if (c > number_t{0}) {
            return interval_t(_lb / bound_t{c}, _ub / bound_t{c});
        } else if (c < number_t{0}) {
            return interval_t(_ub / bound_t{c}, _lb / bound_t{c});
        } else {
            // The eBPF ISA defines division by 0 as resulting in 0.
            return interval_t(number_t(0));
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l(x._lb, bound_t(-1));
        interval_t u(bound_t(1), x._ub);
        return (operator/(l) | operator/(u) | interval_t(number_t(0)));
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l(_lb, bound_t(-1));
        interval_t u(bound_t(1), _ub);
        return ((l / x) | (u / x) | interval_t(number_t(0)));
    } else {
        // Neither the dividend nor the divisor contains 0
        interval_t a =
            (_ub < number_t{0})
                ? (*this + ((x._ub < number_t{0}) ? (x + interval_t(number_t(1))) : (interval_t(number_t(1)) - x)))
                : *this;
        bound_t ll = a._lb / x._lb;
        bound_t lu = a._lb / x._ub;
        bound_t ul = a._ub / x._lb;
        bound_t uu = a._ub / x._ub;
        return interval_t(std::min({ll, lu, ul, uu}), std::max({ll, lu, ul, uu}));
    }
}

// Signed division.
interval_t interval_t::SDiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to_int64()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            number_t c{n->cast_to_sint64()};
            if (c == 1) {
                return *this;
            } else if (c != 0) {
                return interval_t(_lb / bound_t{c}, _ub / bound_t{c});
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t(number_t(0));
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l(x._lb, bound_t(-1));
        interval_t u(bound_t(1), x._ub);
        return (SDiv(l) | SDiv(u) | interval_t(number_t(0)));
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l(_lb, bound_t(-1));
        interval_t u(bound_t(1), _ub);
        return (l.SDiv(x) | u.SDiv(x) | interval_t(number_t(0)));
    } else {
        // Neither the dividend nor the divisor contains 0
        interval_t a =
            (_ub < number_t{0})
                ? (*this + ((x._ub < number_t{0}) ? (x + interval_t(number_t(1))) : (interval_t(number_t(1)) - x)))
                : *this;
        bound_t ll = a._lb / x._lb;
        bound_t lu = a._lb / x._ub;
        bound_t ul = a._ub / x._lb;
        bound_t uu = a._ub / x._ub;
        return interval_t(std::min({ll, lu, ul, uu}), std::max({ll, lu, ul, uu}));
    }
}

// Unsigned division.
interval_t interval_t::UDiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to_int64()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            number_t c{n->cast_to_uint64()};
            if (c == 1) {
                return *this;
            } else if (c > number_t{0}) {
                return interval_t(_lb.UDiv(bound_t{c}), _ub.UDiv(bound_t{c}));
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t(number_t(0));
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l(x._lb, bound_t(-1));
        interval_t u(bound_t(1), x._ub);
        return UDiv(l) | UDiv(u) | interval_t(number_t(0));
    }
    if (contains(0)) {
        // The dividend contains 0.
        interval_t l(_lb, bound_t(-1));
        interval_t u(bound_t(1), _ub);
        return l.UDiv(x) | u.UDiv(x) | interval_t(number_t(0));
    }
    // Neither the dividend nor the divisor contains 0
    interval_t a =
        (_ub < number_t{0})
            ? (*this + ((x._ub < number_t{0}) ? (x + interval_t(number_t(1))) : (interval_t(number_t(1)) - x)))
            : *this;
    bound_t ll = a._lb.UDiv(x._lb);
    bound_t lu = a._lb.UDiv(x._ub);
    bound_t ul = a._ub.UDiv(x._lb);
    bound_t uu = a._ub.UDiv(x._ub);
    return interval_t(std::min({ll, lu, ul, uu}), std::max({ll, lu, ul, uu}));
}

// Signed remainder (modulo).
interval_t interval_t::SRem(const interval_t& x) const {
    // note that the sign of the divisor does not matter

    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto dividend = singleton()) {
        if (const auto divisor = x.singleton()) {
            if (*divisor == 0) {
                return interval_t(*dividend);
            }
            return interval_t(*dividend % *divisor);
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l(x._lb, bound_t(-1));
        interval_t u(bound_t(1), x._ub);
        return SRem(l) | SRem(u) | *this;
    }
    if (x.ub().is_finite() && x.lb().is_finite()) {
        number_t min_divisor = min(abs(*x.lb().number()), abs(*x.ub().number()));
        number_t max_divisor = max(abs(*x.lb().number()), abs(*x.ub().number()));

        if (ub() < min_divisor && -lb() < min_divisor) {
            // The modulo operation won't change the destination register.
            return *this;
        }

        if (lb() < number_t{0}) {
            if (ub() > number_t{0}) {
                return interval_t(-(max_divisor - 1), max_divisor - 1);
            } else {
                return interval_t(-(max_divisor - 1), number_t{0});
            }
        }
        return interval_t(number_t{0}, max_divisor - 1);
    }
    // Divisor has infinite range, so result can be anything between the dividend and zero.
    return *this | interval_t(number_t(0));
}

// Unsigned remainder (modulo).
interval_t interval_t::URem(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        number_t c = *n;
        if (c > number_t{0}) {
            return interval_t(_lb.URem(bound_t{c}), _ub.URem(bound_t{c}));
        }
        // The eBPF ISA defines modulo 0 as being unchanged.
        return *this;
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l(x._lb, bound_t(-1));
        interval_t u(bound_t(1), x._ub);
        return URem(l) | URem(u) | *this;
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l(_lb, bound_t(-1));
        interval_t u(bound_t(1), _ub);
        return l.URem(x) | u.URem(x) | *this;
    } else {
        // Neither the dividend nor the divisor contains 0
        if (x._lb.is_infinite() || x._ub.is_infinite()) {
            // Divisor is infinite. A "negative" dividend could result in anything except
            // a value between the upper bound and 0, so set to top.  A "positive" dividend
            // could result in anything between 0 and the dividend - 1.
            return (_ub < number_t{0}) ? top() : ((*this - interval_t(number_t{1})) | interval_t(number_t(0)));
        } else if (_ub.is_finite() && (_ub.number()->cast_to_uint64() < x._lb.number()->cast_to_uint64())) {
            // Dividend lower than divisor, so the dividend is the remainder.
            return *this;
        } else {
            number_t max_divisor{x._ub.number()->cast_to_uint64()};
            return interval_t(number_t{0}, max_divisor - 1);
        }
    }
}

// Do a bitwise-AND between two uvalue intervals.
interval_t interval_t::And(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    assert(is_top() || (lb() >= number_t{0}));
    assert(x.is_top() || (x.lb() >= number_t{0}));

    if (const auto left = singleton()) {
        if (const auto right = x.singleton()) {
            return interval_t(*left & *right);
        }
    }
    if (x == interval_t{std::numeric_limits<uint32_t>::max()}) {
        // Handle bitwise-AND with UINT32_MAX, which we do for 32-bit operations.
        if (const auto width = finite_size()) {
            const number_t lb32_n = lb().number()->truncate_to<uint32_t>();
            const number_t ub32_n = ub().number()->truncate_to<uint32_t>();
            if (width->fits_uint32() && lb32_n < ub32_n && lb32_n + width->truncate_to<uint32_t>() == ub32_n) {
                return interval_t{lb32_n, ub32_n};
            }
        }
        return full<uint32_t>();
    }
    if (x.contains(std::numeric_limits<uint64_t>::max())) {
        return truncate_to<uint64_t>();
    } else if (!is_top() && !x.is_top()) {
        return interval_t(number_t{0}, std::min(ub(), x.ub()));
    } else if (!x.is_top()) {
        return interval_t(number_t{0}, x.ub());
    } else if (!is_top()) {
        return interval_t(number_t{0}, ub());
    } else {
        return top();
    }
}

interval_t interval_t::Or(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return interval_t(*left_op | *right_op);
        }
    }
    if (lb() >= number_t{0} && x.lb() >= number_t{0}) {
        if (const auto left_ub = ub().number()) {
            if (const auto right_ub = x.ub().number()) {
                const number_t m = *left_ub > *right_ub ? *left_ub : *right_ub;
                return interval_t(number_t{0}, m.fill_ones());
            }
        }
        return interval_t(number_t{0}, bound_t::plus_infinity());
    }
    return top();
}

interval_t interval_t::Xor(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return interval_t(*left_op ^ *right_op);
        }
    }
    return Or(x);
}

interval_t interval_t::Shl(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const number_t k = *shift;
        if (k < number_t{0}) {
            // CRAB_ERROR("lshr shift operand cannot be negative");
            return top();
        }
        // Some crazy linux drivers generate shl instructions with
        // huge shifts.  We limit the number of times the loop is run
        // to avoid wasting too much time on it.
        if (k <= 128) {
            number_t factor = 1;
            for (int i = 0; k > i; i++) {
                factor *= 2;
            }
            return this->operator*(interval_t{factor});
        }
    }
    return top();
}

interval_t interval_t::AShr(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const number_t k = *shift;
        if (k < number_t{0}) {
            // CRAB_ERROR("ashr shift operand cannot be negative");
            return top();
        }
        // Some crazy linux drivers generate ashr instructions with
        // huge shifts.  We limit the number of times the loop is run
        // to avoid wasting too much time on it.
        if (k <= 128) {
            number_t factor = 1;
            for (int i = 0; k > i; i++) {
                factor *= 2;
            }
            return this->operator/(interval_t{factor});
        }
    }
    return top();
}

interval_t interval_t::LShr(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto shift = x.singleton()) {
        const number_t k = *shift;
        if (k < number_t{0}) {
            // CRAB_ERROR("lshr shift operand cannot be negative");
            return top();
        }
        // Some crazy linux drivers generate lshr instructions with
        // huge shifts.  We limit the number of times the loop is run
        // to avoid wasting too much time on it.
        if (k <= 128) {
            if (lb() >= number_t{0} && ub().is_finite() && shift) {
                const number_t lb = *this->lb().number();
                const number_t ub = *this->ub().number();
                return interval_t(lb >> k, ub >> k);
            }
        }
    }
    return top();
}

} // namespace crab
