// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 *
 * A simple class for representing intervals and performing interval arithmetic.
 *
 ******************************************************************************/

#pragma once

#include <optional>
#include <utility>

#include "crab_utils/bignums.hpp"
#include "crab_utils/stats.hpp"

namespace crab {

class bound_t final {
  private:
    bool _is_infinite;
    number_t _n;

  private:

    bound_t(bool is_infinite, const number_t& n) : _is_infinite(is_infinite), _n(n) {
        if (is_infinite) {
            if (n > 0)
                _n = 1;
            else
                _n = -1;
        }
    }

  public:
    static bound_t min(const bound_t& x, const bound_t& y) { return (x.operator<=(y) ? x : y); }

    static bound_t min(const bound_t& x, const bound_t& y, const bound_t& z) { return min(x, min(y, z)); }

    static bound_t min(const bound_t& x, const bound_t& y, const bound_t& z, const bound_t& t) { return min(x, min(t, y, z)); }

    static bound_t max(const bound_t& x, const bound_t& y) { return (x.operator<=(y) ? y : x); }

    static bound_t max(const bound_t& x, const bound_t& y, const bound_t& z) { return max(x, max(y, z)); }

    static bound_t max(const bound_t& x, const bound_t& y, const bound_t& z, const bound_t& t) { return max(x, max(t, y, z)); }

    static bound_t plus_infinity() { return bound_t(true, 1); }

    static bound_t minus_infinity() { return bound_t(true, -1); }

  public:
    explicit bound_t(const std::string& s) : _n(1) {
        if (s == "+oo") {
            _is_infinite = true;
        } else if (s == "-oo") {
            _is_infinite = true;
            _n = -1;
        } else {
            _is_infinite = false;
            _n = number_t(s);
        }
    }

    bound_t(number_t n) : _is_infinite(false), _n(std::move(n)) {}

    bound_t(const bound_t& o) = default;

    bound_t& operator=(const bound_t& o) {
        if (this != &o) {
            _is_infinite = o._is_infinite;
            _n = o._n;
        }
        return *this;
    }

    [[nodiscard]] bool is_infinite() const { return _is_infinite; }

    [[nodiscard]] bool is_finite() const { return !_is_infinite; }

    [[nodiscard]] bool is_plus_infinity() const { return (is_infinite() && _n > 0); }

    [[nodiscard]] bool is_minus_infinity() const { return (is_infinite() && _n < 0); }

    bound_t operator-() const { return bound_t(_is_infinite, -_n); }

    bound_t operator+(const bound_t& x) const {
        if (is_finite() && x.is_finite()) {
            return bound_t(_n + x._n);
        } else if (is_finite() && x.is_infinite()) {
            return x;
        } else if (is_infinite() && x.is_finite()) {
            return *this;
        } else if (_n == x._n) {
            return *this;
        } else {
            CRAB_ERROR("Bound: undefined operation -oo + +oo");
        }
    }

    bound_t& operator+=(const bound_t& x) { return operator=(operator+(x)); }

    bound_t operator-(const bound_t& x) const { return operator+(x.operator-()); }

    bound_t& operator-=(const bound_t& x) { return operator=(operator-(x)); }

    bound_t operator*(const bound_t& x) const {
        if (x._n == 0)
            return x;
        else if (_n == 0)
            return *this;
        else
            return bound_t(_is_infinite || x._is_infinite, _n * x._n);
    }

    bound_t& operator*=(const bound_t& x) { return operator=(operator*(x)); }

    bound_t operator/(const bound_t& x) const {
        if (x._n == 0) {
            CRAB_ERROR("Bound: division by zero");
        } else if (is_finite() && x.is_finite()) {
            return bound_t(false, _n / x._n);
        } else if (is_finite() && x.is_infinite()) {
            if (_n > 0) {
                return x;
            } else if (_n == 0) {
                return *this;
            } else {
                return x.operator-();
            }
        } else if (is_infinite() && x.is_finite()) {
            if (x._n > 0) {
                return *this;
            } else {
                return operator-();
            }
        } else {
            return bound_t(true, _n * x._n);
        }
    }

    [[nodiscard]] bound_t UDiv(const bound_t& x) const {
        if (x._n == 0) {
            CRAB_ERROR("Bound: division by zero");
        } else if (is_finite() && x.is_finite()) {
            number_t dividend = (_n >= 0) ? _n : number_t{_n.cast_to_uint64()};
            number_t divisor = (x._n >= 0) ? x._n : number_t{x._n.cast_to_uint64()};
            return bound_t(false, dividend / divisor);
        } else if (is_finite() && x.is_infinite()) {
            return number_t{0};
        } else {
            return plus_infinity();
        }
    }

    [[nodiscard]] bound_t UMod(const bound_t& x) const {
        if (x._n == 0) {
            CRAB_ERROR("Bound: modulo zero");
        } else if (is_finite() && x.is_finite()) {
            number_t dividend = (_n >= 0) ? _n : number_t{_n.cast_to_uint64()};
            number_t divisor = (x._n >= 0) ? x._n : number_t{x._n.cast_to_uint64()};
            return bound_t(false, dividend % divisor);
        } else if (is_finite() && x.is_infinite()) {
            return *this;
        } else {
            return plus_infinity();
        }
    }

    bound_t& operator/=(const bound_t& x) { return operator=(operator/(x)); }

    bool operator<(const bound_t& x) const { return !operator>=(x); }

    bool operator>(const bound_t& x) const { return !operator<=(x); }

    bool operator==(const bound_t& x) const { return (_is_infinite == x._is_infinite && _n == x._n); }

    bool operator!=(const bound_t& x) const { return !operator==(x); }

    /*	operator<= and operator>= use a somewhat optimized implementation.
     *	results include up to 20% improvements in performance in the octagon domain
     *	over a more naive implementation.
     */
    bool operator<=(const bound_t& x) const {
        if (_is_infinite xor x._is_infinite) {
            if (_is_infinite) {
                return _n < 0;
            }
            return x._n > 0;
        }
        return _n <= x._n;
    }

    bool operator>=(const bound_t& x) const {
        if (_is_infinite xor x._is_infinite) {
            if (_is_infinite) {
                return _n > 0;
            }
            return x._n < 0;
        }
        return _n >= x._n;
    }

    [[nodiscard]] bound_t abs() const {
        if (operator>=(number_t{0})) {
            return *this;
        } else {
            return operator-();
        }
    }

    [[nodiscard]] std::optional<number_t> number() const {
        if (is_infinite()) {
            return {};
        } else {
            return {_n};
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const bound_t& b) {
        if (b.is_plus_infinity()) {
            o << "+oo";
        } else if (b.is_minus_infinity()) {
            o << "-oo";
        } else {
            o << b._n;
        }
        return o;
    }

}; // class bound

using z_bound = bound_t;

class interval_t final {
  private:
    bound_t _lb;
    bound_t _ub;

  public:
    static interval_t top() { return interval_t(bound_t::minus_infinity(), bound_t::plus_infinity()); }

    static interval_t bottom() { return interval_t(); }

    [[nodiscard]] std::optional<number_t> finite_size() const { return (_ub - _lb).number(); }

  private:
    interval_t() : _lb(number_t{0}), _ub(-1) {}

    static number_t abs(const number_t& x) { return x < 0 ? -x : x; }

    static number_t max(const number_t& x, const number_t& y) { return x.operator<=(y) ? y : x; }

    static number_t min(const number_t& x, const number_t& y) { return x.operator<(y) ? x : y; }

  public:
    interval_t(const bound_t& lb, const bound_t& ub) : _lb(lb > ub ? bound_t{number_t{0}}  : lb),
                                                       _ub(lb > ub ? bound_t{-1} : ub) {
    }

    explicit interval_t(const bound_t& b) : _lb(b.is_infinite() ? bound_t{number_t{0}}  : b),
                                            _ub(b.is_infinite() ? bound_t{-1} : b) {
    }

    explicit interval_t(const number_t& n) : _lb(n), _ub(n) {}

    interval_t(const interval_t& i) = default;

    interval_t& operator=(const interval_t& i) = default;

    [[nodiscard]] bound_t lb() const { return _lb; }

    [[nodiscard]] bound_t ub() const { return _ub; }

    [[nodiscard]] bool is_bottom() const { return (_lb > _ub); }

    [[nodiscard]] bool is_top() const { return (_lb.is_infinite() && _ub.is_infinite()); }

    bool operator==(const interval_t& x) const {
        if (is_bottom()) {
            return x.is_bottom();
        } else {
            return (_lb == x._lb) && (_ub == x._ub);
        }
    }

    bool operator!=(const interval_t& x) const { return !operator==(x); }

    bool operator<=(const interval_t& x) const {
        if (is_bottom()) {
            return true;
        } else if (x.is_bottom()) {
            return false;
        } else {
            return (x._lb <= _lb) && (_ub <= x._ub);
        }
    }

    interval_t operator|(const interval_t& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return interval_t(bound_t::min(_lb, x._lb), bound_t::max(_ub, x._ub));
        }
    }

    interval_t operator&(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t(bound_t::max(_lb, x._lb), bound_t::min(_ub, x._ub));
        }
    }

    [[nodiscard]] interval_t widen(const interval_t& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return interval_t(x._lb < _lb ? bound_t::minus_infinity() : _lb,
                              _ub < x._ub ? bound_t::plus_infinity() : _ub);
        }
    }

    template <typename Thresholds>
    interval_t widening_thresholds(interval_t x, const Thresholds& ts) {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            bound_t lb = (x._lb < _lb ? ts.get_prev(x._lb) : _lb);
            bound_t ub = (_ub < x._ub ? ts.get_next(x._ub) : _ub);
            return interval_t(lb, ub);
        }
    }

    [[nodiscard]] interval_t narrow(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t(_lb.is_infinite() && x._lb.is_finite() ? x._lb : _lb,
                              _ub.is_infinite() && x._ub.is_finite() ? x._ub : _ub);
        }
    }

    interval_t operator+(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t(_lb + x._lb, _ub + x._ub);
        }
    }

    interval_t& operator+=(const interval_t& x) { return operator=(operator+(x)); }

    interval_t operator-() const {
        if (is_bottom()) {
            return bottom();
        } else {
            return interval_t(-_ub, -_lb);
        }
    }

    interval_t operator-(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t(_lb - x._ub, _ub - x._lb);
        }
    }

    interval_t& operator-=(const interval_t& x) { return operator=(operator-(x)); }

    interval_t operator*(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            bound_t ll = _lb * x._lb;
            bound_t lu = _lb * x._ub;
            bound_t ul = _ub * x._lb;
            bound_t uu = _ub * x._ub;
            return interval_t(bound_t::min(ll, lu, ul, uu), bound_t::max(ll, lu, ul, uu));
        }
    }

    interval_t& operator*=(const interval_t& x) { return operator=(operator*(x)); }

    interval_t operator/(const interval_t& x) const;

    interval_t& operator/=(const interval_t& x) { return operator=(operator/(x)); }

    [[nodiscard]] bool is_singleton() const { return _lb == _ub; }

    [[nodiscard]] std::optional<number_t> singleton() const {
        if (!is_bottom() && _lb == _ub) {
            return _lb.number();
        } else {
            return std::optional<number_t>();
        }
    }

    bool operator[](const number_t& n) const {
        if (is_bottom()) {
            return false;
        } else {
            bound_t b(n);
            return (_lb <= b) && (b <= _ub);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const interval_t& interval) {
        if (interval.is_bottom()) {
            o << "_|_";
        } else {
            o << "[" << interval._lb << ", " << interval._ub << "]";
        }
        return o;
    }

    // division and remainder operations

    [[nodiscard]] interval_t UDiv(const interval_t& x) const;

    [[nodiscard]] interval_t SRem(const interval_t& x) const;

    [[nodiscard]] interval_t URem(const interval_t& x) const;

    // bitwise operations
    [[nodiscard]] interval_t And(const interval_t& x) const;

    [[nodiscard]] interval_t Or(const interval_t& x) const;

    [[nodiscard]] interval_t Xor(const interval_t& x) const;

    [[nodiscard]] interval_t Shl(const interval_t& x) const;

    [[nodiscard]] interval_t LShr(const interval_t& x) const;

    [[nodiscard]] interval_t AShr(const interval_t& x) const;

    [[nodiscard]] interval_t truncate_to_sint(bool is64) const {
        interval_t new_interval = *this;
        if (!(*this <= interval_t::signed_int(is64))) {
            if (auto size = finite_size()) {
                auto llb = lb().number()->truncate_to_signed_finite_width(is64 ? 64 : 32);
                auto lub = ub().number()->truncate_to_signed_finite_width(is64 ? 64 : 32);
                if ((llb <= lub) && (is64 ? size->fits_sint64() : size->fits_sint32())) {
                    // Interval can be accurately represented in 64 bits.
                    new_interval = interval_t{llb, lub};
                } else {
                    new_interval = interval_t::signed_int(is64);
                }
            } else {
                new_interval = interval_t::signed_int(is64);
            }
        }
        return new_interval;
    }

    [[nodiscard]] interval_t truncate_to_uint(bool is64) const {
        interval_t new_interval = *this;
        if (!(*this <= interval_t::unsigned_int(is64))) {
            if (auto size = finite_size()) {
                auto llb = lb().number()->truncate_to_unsigned_finite_width(is64 ? 64 : 32);
                auto lub = ub().number()->truncate_to_unsigned_finite_width(is64 ? 64 : 32);
                if ((llb <= lub) && (is64 ? size->fits_uint64() : size->fits_uint32())) {
                    // Interval can be accurately represented in 64 bits.
                    new_interval = interval_t{llb, lub};
                } else {
                    new_interval = interval_t::unsigned_int(is64);
                }
            } else {
                new_interval = interval_t::unsigned_int(is64);
            }
        }
        return new_interval;
    }

    // Return a non-negative interval in the range [0, INT_MAX],
    // which can be represented as both an svalue and a uvalue.
    static interval_t nonnegative_int(bool is64) {
        if (is64) {
            return {number_t{0}, number_t{std::numeric_limits<int64_t>::max()}};
        } else {
            return {number_t{0}, number_t{std::numeric_limits<int32_t>::max()}};
        }
    }
    // Return an interval in the range [INT_MIN, -1], which can only
    // be represented as an svalue.  The uvalue equivalent using the same
    // bits would be unsigned_high().
    static interval_t negative_int(bool is64) {
        if (is64) {
            return {number_t{std::numeric_limits<int64_t>::min()}, number_t{-1}};
        } else {
            return {number_t{std::numeric_limits<int32_t>::min()}, number_t{-1}};
        }
    }
    // Return an interval in the range [INT_MIN, INT_MAX] which can only
    // be represented as an svalue.
    static interval_t signed_int(bool is64) {
        if (is64) {
            return {number_t{std::numeric_limits<int64_t>::min()}, number_t{std::numeric_limits<int64_t>::max()}};
        } else {
            return {number_t{std::numeric_limits<int32_t>::min()}, number_t{std::numeric_limits<int32_t>::max()}};
        }
    }
    // Return an interval in the range [0, UINT_MAX] which can only be
    // represented as a uvalue.
    static interval_t unsigned_int(bool is64) {
        if (is64) {
            return {number_t{0}, number_t{std::numeric_limits<uint64_t>::max()}};
        } else {
            return {number_t{0}, number_t{std::numeric_limits<uint32_t>::max()}};
        }
    }
    // Return an interval in the range [INT_MAX+1, UINT_MAX], which can only
    // be represented as a uvalue.  The svalue equivalent using the same
    // bits would be negative_int().
    static interval_t unsigned_high(bool is64) {
        if (is64) {
            return {number_t{std::numeric_limits<int64_t>::max()} + 1, number_t{std::numeric_limits<uint64_t>::max()}};
        } else {
            return {number_t{std::numeric_limits<int32_t>::max()} + 1, number_t{std::numeric_limits<uint32_t>::max()}};
        }
    }

    [[nodiscard]] std::string to_string() const;
}; //  class interval

namespace interval_operators {

inline interval_t operator+(const number_t& c, const interval_t& x) { return interval_t(c) + x; }

inline interval_t operator+(const interval_t& x, const number_t& c) { return x + interval_t(c); }

inline interval_t operator*(const number_t& c, const interval_t& x) { return interval_t(c) * x; }

inline interval_t operator*(const interval_t& x, const number_t& c) { return x * interval_t(c); }

inline interval_t operator/(const number_t& c, const interval_t& x) { return interval_t(c) / x; }

inline interval_t operator/(const interval_t& x, const number_t& c) { return x / interval_t(c); }

inline interval_t operator-(const number_t& c, const interval_t& x) { return interval_t(c) - x; }

inline interval_t operator-(const interval_t& x, const number_t& c) { return x - interval_t(c); }

}

inline interval_t trim_interval(const interval_t& i, const interval_t& j) {
    if (std::optional<number_t> c = j.singleton()) {
        if (i.lb() == bound_t{*c}) {
            return interval_t(bound_t{*c + 1}, i.ub());
        } else if (i.ub() == bound_t{*c}) {
            return interval_t(i.lb(), bound_t{*c - 1});
        } else if (i.is_top() && (*c == 0)) {
            return {number_t{1}, number_t{std::numeric_limits<uint64_t>::max()}};
        }
    }
    return i;
}


} // namespace crab

std::string to_string(const crab::interval_t& interval);
