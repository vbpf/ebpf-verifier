// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/interval.hpp"

namespace crab {

// Signed division. eBPF has no instruction for this.
interval_t interval_t::operator/(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        if (std::optional<number_t> n = x.singleton()) {
            number_t c = *n;
            if (c == 1) {
                return *this;
            } else if (c > 0) {
                return interval_t(_lb / bound_t{c}, _ub / bound_t{c});
            } else if (c < 0) {
                return interval_t(_ub / bound_t{c}, _lb / bound_t{c});
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t(number_t(0));
            }
        }
        // Divisor is not a singleton
        using z_interval = interval_t;
        if (x[0]) {
            // The divisor contains 0.
            z_interval l(x._lb, z_bound(-1));
            z_interval u(z_bound(1), x._ub);
            return (operator/(l) | operator/(u) | z_interval(number_t(0)));
        } else if (operator[](0)) {
            // The dividend contains 0.
            z_interval l(_lb, z_bound(-1));
            z_interval u(z_bound(1), _ub);
            return ((l / x) | (u / x) | z_interval(number_t(0)));
        } else {
            // Neither the dividend nor the divisor contains 0
            z_interval a = (_ub < 0)
                               ? (*this + ((x._ub < 0) ? (x + z_interval(number_t(1))) : (z_interval(number_t(1)) - x)))
                               : *this;
            bound_t ll = a._lb / x._lb;
            bound_t lu = a._lb / x._ub;
            bound_t ul = a._ub / x._lb;
            bound_t uu = a._ub / x._ub;
            return interval_t(bound_t::min(ll, lu, ul, uu), bound_t::max(ll, lu, ul, uu));
        }
    }
}

// Unsigned division
interval_t interval_t::UDiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        std::optional<number_t> n = x.singleton();
        if (n && n->fits_cast_to_int64()) {
            number_t c((unsigned long long)n->cast_to_uint64());
            if (c == 1) {
                return *this;
            } else if (c > 0) {
                return interval_t(_lb.UDiv(bound_t{c}), _ub.UDiv(bound_t{c}));
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t(number_t(0));
            }
        }
        // Divisor is not a singleton
        using z_interval = interval_t;
        if (x[0]) {
            // The divisor contains 0.
            z_interval l(x._lb, z_bound(-1));
            z_interval u(z_bound(1), x._ub);
            return (UDiv(l) | UDiv(u) | z_interval(number_t(0)));
        } else if (operator[](0)) {
            // The dividend contains 0.
            z_interval l(_lb, z_bound(-1));
            z_interval u(z_bound(1), _ub);
            return (l.UDiv(x) | u.UDiv(x) | z_interval(number_t(0)));
        } else {
            // Neither the dividend nor the divisor contains 0
            z_interval a = (_ub < 0)
                               ? (*this + ((x._ub < 0) ? (x + z_interval(number_t(1))) : (z_interval(number_t(1)) - x)))
                               : *this;
            bound_t ll = a._lb.UDiv(x._lb);
            bound_t lu = a._lb.UDiv(x._ub);
            bound_t ul = a._ub.UDiv(x._lb);
            bound_t uu = a._ub.UDiv(x._ub);
            return interval_t(bound_t::min(ll, lu, ul, uu), bound_t::max(ll, lu, ul, uu));
        }
    }
}

// Signed remainder (modulo). eBPF has no instruction for this.
interval_t interval_t::SRem(const interval_t& x) const {
    // note that the sign of the divisor does not matter

    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else if (singleton() && x.singleton()) {
        number_t dividend = *singleton();
        number_t divisor = *x.singleton();

        if (divisor == 0) {
            return interval_t(dividend);
        }

        return interval_t(dividend % divisor);
    } else if (x[0]) {
        // The divisor contains 0.
        interval_t l(x._lb, z_bound(-1));
        interval_t u(z_bound(1), x._ub);
        return SRem(l) | SRem(u) | *this;
    } else if (x.ub().is_finite() && x.lb().is_finite()) {
        number_t min_divisor = min(abs(*x.lb().number()), abs(*x.ub().number()));
        number_t max_divisor = max(abs(*x.lb().number()), abs(*x.ub().number()));

        if (ub() < min_divisor && -lb() < min_divisor) {
            // The modulo operation won't change the destination register.
            return *this;
        }

        if (lb() < 0) {
            if (ub() > 0) {
                return interval_t(-(max_divisor - 1), max_divisor - 1);
            } else {
                return interval_t(-(max_divisor - 1), 0);
            }
        } else {
            return interval_t(0, max_divisor - 1);
        }
    } else {
        // Divisor has infinite range, so result can be anything between the dividend and zero.
        return *this | interval_t(number_t(0));
    }
}

// Unsigned remainder (modulo).
interval_t interval_t::URem(const interval_t& x) const {

    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        // Divisor is a singleton:
        //   the linear interval solver can perform many divisions where
        //   the divisor is a singleton interval. We optimize for this case.
        if (std::optional<number_t> n = x.singleton()) {
            number_t c = *n;
            if (c > 0) {
                return interval_t(_lb.UMod(bound_t{c}), _ub.UMod(bound_t{c}));
            } else {
                // The eBPF ISA defines modulo 0 as being unchanged.
                return *this;
            }
        }
        // Divisor is not a singleton
        using z_interval = interval_t;
        if (x[0]) {
            // The divisor contains 0.
            z_interval l(x._lb, z_bound(-1));
            z_interval u(z_bound(1), x._ub);
            return (URem(l) | URem(u) | *this);
        } else if (operator[](0)) {
            // The dividend contains 0.
            z_interval l(_lb, z_bound(-1));
            z_interval u(z_bound(1), _ub);
            return (l.URem(x) | u.URem(x) | *this);
        } else {
            // Neither the dividend nor the divisor contains 0
            if (x._lb.is_infinite() || x._ub.is_infinite()) {
                // Divisor is infinite. A "negative" dividend could result in anything except
                // a value between the upper bound and 0, so set to top.  A "positive" dividend
                // could result in anything between 0 and the dividend - 1.
                return (_ub < 0) ? top() : ((*this - 1) | interval_t(number_t(0)));
            } else if (_ub.number()->cast_to_uint64() < x._lb.number()->cast_to_uint64()) {
                // Dividend lower than divisor, so the dividend is the remainder.
                return *this;
            } else {
                number_t max_divisor = number_t((unsigned long long)x._ub.number()->cast_to_uint64());
                return interval_t(0, max_divisor - 1);
            }
        }
    }
}

interval_t interval_t::And(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        std::optional<number_t> left_op = singleton();
        std::optional<number_t> right_op = x.singleton();

        if (left_op && right_op) {
            return interval_t((*left_op) & (*right_op));
        } else if (lb() >= 0 && x.lb() >= 0) {
            return interval_t(0, bound_t::min(ub(), x.ub()));
        } else {
            return top();
        }
    }
}

interval_t interval_t::Or(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        std::optional<number_t> left_op = singleton();
        std::optional<number_t> right_op = x.singleton();

        if (left_op && right_op) {
            return interval_t((*left_op) | (*right_op));
        } else if (lb() >= 0 && x.lb() >= 0) {
            std::optional<number_t> left_ub = ub().number();
            std::optional<number_t> right_ub = x.ub().number();

            if (left_ub && right_ub) {
                number_t m = (*left_ub > *right_ub ? *left_ub : *right_ub);
                return interval_t(0, m.fill_ones());
            } else {
                return interval_t(0, bound_t::plus_infinity());
            }
        } else {
            return top();
        }
    }
}

interval_t interval_t::Xor(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        std::optional<number_t> left_op = singleton();
        std::optional<number_t> right_op = x.singleton();

        if (left_op && right_op) {
            return interval_t((*left_op) ^ (*right_op));
        } else {
            return Or(x);
        }
    }
}

interval_t interval_t::Shl(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        if (std::optional<number_t> shift = x.singleton()) {
            number_t k = *shift;
            if (k < 0) {
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
                return (*this) * factor;
            }
        }
        return top();
    }
}

interval_t interval_t::AShr(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        if (std::optional<number_t> shift = x.singleton()) {
            number_t k = *shift;
            if (k < 0) {
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
                return (*this) / factor;
            }
        }
        return top();
    }
}

interval_t interval_t::LShr(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    } else {
        if (std::optional<number_t> shift = x.singleton()) {
            number_t k = *shift;
            if (k < 0) {
                // CRAB_ERROR("lshr shift operand cannot be negative");
                return top();
            }
            // Some crazy linux drivers generate lshr instructions with
            // huge shifts.  We limit the number of times the loop is run
            // to avoid wasting too much time on it.
            if (k <= 128) {
                if (lb() >= 0 && ub().is_finite() && shift) {
                    number_t lb = *this->lb().number();
                    number_t ub = *this->ub().number();
                    return interval_t(lb >> k, ub >> k);
                }
            }
        }
        return top();
    }
}

} // namespace crab
