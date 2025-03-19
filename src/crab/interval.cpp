// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/interval.hpp"

namespace crab {

static interval_t make_dividend_when_both_nonzero(const interval_t& dividend, const interval_t& divisor) {
    if (dividend.ub() >= 0) {
        return dividend;
    }
    if (divisor.ub() < 0) {
        return dividend + divisor + interval_t{1};
    }
    return dividend + interval_t{1} - divisor;
}

interval_t interval_t::operator*(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    const auto [clb, cub] = std::minmax({
        _lb * x._lb,
        _lb * x._ub,
        _ub * x._lb,
        _ub * x._ub,
    });
    return interval_t{clb, cub};
}

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
        if (c == 1) {
            return *this;
        } else if (c > 0) {
            return interval_t{_lb / c, _ub / c};
        } else if (c < 0) {
            return interval_t{_ub / c, _lb / c};
        } else {
            // The eBPF ISA defines division by 0 as resulting in 0.
            return interval_t{0};
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return operator/(l) | operator/(u) | interval_t{0};
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return (l / x) | (u / x) | interval_t{0};
    } else {
        // Neither the dividend nor the divisor contains 0
        interval_t a = make_dividend_when_both_nonzero(*this, x);
        const auto [clb, cub] = std::minmax({
            a._lb / x._lb,
            a._lb / x._ub,
            a._ub / x._lb,
            a._ub / x._ub,
        });
        return interval_t{clb, cub};
    }
}

// Signed division.
interval_t interval_t::SDiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to<int64_t>()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            number_t c{n->cast_to<int64_t>()};
            if (c == 1) {
                return *this;
            } else if (c != 0) {
                return interval_t{_lb / c, _ub / c};
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t{0};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return SDiv(l) | SDiv(u) | interval_t{0};
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return l.SDiv(x) | u.SDiv(x) | interval_t{0};
    } else {
        // Neither the dividend nor the divisor contains 0
        interval_t a = make_dividend_when_both_nonzero(*this, x);
        const auto [clb, cub] = std::minmax({
            a._lb / x._lb,
            a._lb / x._ub,
            a._ub / x._lb,
            a._ub / x._ub,
        });
        return interval_t{clb, cub};
    }
}

// Unsigned division.
interval_t interval_t::UDiv(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto n = x.singleton()) {
        if (n->fits_cast_to<int64_t>()) {
            // Divisor is a singleton:
            //   the linear interval solver can perform many divisions where
            //   the divisor is a singleton interval. We optimize for this case.
            number_t c{n->cast_to<uint64_t>()};
            if (c == 1) {
                return *this;
            } else if (c > 0) {
                return interval_t{_lb.UDiv(c), _ub.UDiv(c)};
            } else {
                // The eBPF ISA defines division by 0 as resulting in 0.
                return interval_t{0};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return UDiv(l) | UDiv(u) | interval_t{0};
    }
    if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return l.UDiv(x) | u.UDiv(x) | interval_t{0};
    }
    // Neither the dividend nor the divisor contains 0
    interval_t a = make_dividend_when_both_nonzero(*this, x);
    const auto [clb, cub] = std::minmax({
        a._lb.UDiv(x._lb),
        a._lb.UDiv(x._ub),
        a._ub.UDiv(x._lb),
        a._ub.UDiv(x._ub),
    });
    return interval_t{clb, cub};
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
                return interval_t{*dividend};
            }
            return interval_t{*dividend % *divisor};
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return SRem(l) | SRem(u) | *this;
    }
    if (x.ub().is_finite() && x.lb().is_finite()) {
        auto [xlb, xub] = x.pair_number();
        const auto [min_divisor, max_divisor] = std::minmax({xlb.abs(), xub.abs()});

        if (ub() < min_divisor && -lb() < min_divisor) {
            // The modulo operation won't change the destination register.
            return *this;
        }

        if (lb() < 0) {
            if (ub() > 0) {
                return interval_t{-(max_divisor - 1), max_divisor - 1};
            } else {
                return interval_t{-(max_divisor - 1), 0};
            }
        }
        return interval_t{0, max_divisor - 1};
    }
    // Divisor has infinite range, so result can be anything between the dividend and zero.
    return *this | interval_t{0};
}

// Unsigned remainder (modulo).
interval_t interval_t::URem(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto dividend = singleton()) {
        if (const auto divisor = x.singleton()) {
            if (dividend->fits_cast_to<uint64_t>() && divisor->fits_cast_to<uint64_t>()) {
                // The BPF ISA defines modulo by 0 as resulting in the original value.
                if (*divisor == 0) {
                    return interval_t{*dividend};
                }
                uint64_t dividend_val = dividend->cast_to<uint64_t>();
                uint64_t divisor_val = divisor->cast_to<uint64_t>();
                return interval_t{dividend_val % divisor_val};
            }
        }
    }
    if (x.contains(0)) {
        // The divisor contains 0.
        interval_t l{x._lb, -1};
        interval_t u{1, x._ub};
        return URem(l) | URem(u) | *this;
    } else if (contains(0)) {
        // The dividend contains 0.
        interval_t l{_lb, -1};
        interval_t u{1, _ub};
        return l.URem(x) | u.URem(x) | *this;
    } else {
        // Neither the dividend nor the divisor contains 0
        if (x._lb.is_infinite() || x._ub.is_infinite()) {
            // Divisor is infinite. A "negative" dividend could result in anything except
            // a value between the upper bound and 0, so set to top.  A "positive" dividend
            // could result in anything between 0 and the dividend - 1.
            return _ub < 0 ? top() : (*this - interval_t{1}) | interval_t{0};
        } else if (_ub.is_finite() && _ub.number()->cast_to<uint64_t>() < x._lb.number()->cast_to<uint64_t>()) {
            // Dividend lower than divisor, so the dividend is the remainder.
            return *this;
        } else {
            number_t max_divisor{x._ub.number()->cast_to<uint64_t>()};
            return interval_t{0, max_divisor - 1};
        }
    }
}

// Do a bitwise-AND between two uvalue intervals.
interval_t interval_t::And(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    assert(is_top() || (lb() >= 0));
    assert(x.is_top() || (x.lb() >= 0));

    if (const auto left = singleton()) {
        if (const auto right = x.singleton()) {
            return interval_t{*left & *right};
        }
    }
    if (x == interval_t{std::numeric_limits<uint32_t>::max()}) {
        // Handle bitwise-AND with std::numeric_limits<uint32_t>::max(), which we do for 32-bit operations.
        if (const auto width = finite_size()) {
            const number_t lb32_n = lb().number()->truncate_to<uint32_t>();
            const number_t ub32_n = ub().number()->truncate_to<uint32_t>();
            if (width->fits<uint32_t>() && lb32_n < ub32_n && lb32_n + width->truncate_to<uint32_t>() == ub32_n) {
                return interval_t{lb32_n, ub32_n};
            }
        }
        return full<uint32_t>();
    }
    if (x.contains(std::numeric_limits<uint64_t>::max())) {
        return truncate_to<uint64_t>();
    } else if (!is_top() && !x.is_top()) {
        return interval_t{0, std::min(ub(), x.ub())};
    } else if (!x.is_top()) {
        return interval_t{0, x.ub()};
    } else if (!is_top()) {
        return interval_t{0, ub()};
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
            return interval_t{*left_op | *right_op};
        }
    }
    if (lb() >= 0 && x.lb() >= 0) {
        if (const auto left_ub = ub().number()) {
            if (const auto right_ub = x.ub().number()) {
                return interval_t{0, std::max(*left_ub, *right_ub).fill_ones()};
            }
        }
        return interval_t{0, bound_t::plus_infinity()};
    }
    return top();
}

interval_t interval_t::Xor(const interval_t& x) const {
    if (is_bottom() || x.is_bottom()) {
        return bottom();
    }
    if (const auto left_op = singleton()) {
        if (const auto right_op = x.singleton()) {
            return interval_t{*left_op ^ *right_op};
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
        if (k < 0) {
            return top();
        }
        // Some crazy linux drivers generate shl instructions with huge shifts.
        // We limit the number of times the loop is run to avoid wasting too much time on it.
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
        if (k < 0) {
            return top();
        }
        // Some crazy linux drivers generate ashr instructions with huge shifts.
        // We limit the number of times the loop is run to avoid wasting too much time on it.
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
        if (*shift > 0 && lb() >= 0 && ub().is_finite()) {
            const auto [lb, ub] = this->pair_number();
            return interval_t{lb >> *shift, ub >> *shift};
        }
    }
    return top();
}

// idea: use uvalue and svalue to be more precise
interval_t interval_t::sign_extend(const int bits) const {
    if (bits >= 64) {
        CRAB_ERROR("Invalid width ", bits);
    }

    const interval_t full_range = signed_int(bits);
    if (size() >= full_range.size()) {
        return full_range;
    }

    const auto sext = [bits](const int64_t x) -> int64_t {
        const int shift = 64 - bits;
        // Work with unsigned values to avoid undefined behavior on shifts.
        return keep_signed<int64_t>(to_unsigned(x) << shift) >> shift;
    };

    // int64_t is guaranteed to hold {_lb, _ub}.
    const auto [_lb, _ub] = pair<int64_t>();
    const int64_t lb_sext = sext(_lb);
    const int64_t ub_sext = sext(_ub);

    // If the sign–extended endpoints are in order, no wrap occurred.
    if (lb_sext <= ub_sext) {
        return interval_t{lb_sext, ub_sext};
    }

    // lb_sext > ub_sext, so we have a wrapped interval.
    // When the lower bound is zero, use the sign-extension of the upper bound as the lower endpoint.
    // Example: [0b000, 0b100] (i.e., [0, 4]) sign-extends to [-4, 3]
    //   sext(0) = 0, sext(4) = -4 -> wrapped -> result = [-4, 3]
    if (lb_sext == 0) {
        return interval_t{ub_sext, full_range._ub};
    }
    // Otherwise, the wrapped interval covers the full signed range.
    // Example: [0b001, 0b101] (i.e., [1, 5]) sign-extends to [1, -3],
    // but 0b100 is in the range, and so does 0b011, so the result is [-4, 3]
    return full_range;
}
} // namespace crab
