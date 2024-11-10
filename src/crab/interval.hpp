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

#include "crab_utils/num_big.hpp"
#include "crab_utils/num_extended.hpp"
#include "crab_utils/stats.hpp"

namespace crab {

using bound_t = extended_number;

class interval_t final {
    bound_t _lb;
    bound_t _ub;

  public:
    static interval_t top() { return interval_t{bound_t::minus_infinity(), bound_t::plus_infinity()}; }

    static interval_t bottom() { return interval_t{}; }

    [[nodiscard]]
    std::optional<number_t> finite_size() const {
        return (_ub - _lb).number();
    }

  private:
    interval_t() : _lb(number_t{0}), _ub(-1) {}

  public:
    interval_t(const bound_t& lb, const bound_t& ub)
        : _lb(lb > ub ? bound_t{number_t{0}} : lb), _ub(lb > ub ? bound_t{-1} : ub) {}

    template <std::integral T>
    interval_t(T lb, T ub) : _lb(bound_t{lb}), _ub(bound_t{ub}) {
        if (lb > ub) {
            _lb = bound_t{number_t{0}};
            _ub = bound_t{-1};
        }
    }

    template <is_enum T>
    interval_t(T lb, T ub) : _lb(bound_t{lb}), _ub(bound_t{ub}) {
        if (lb > ub) {
            _lb = bound_t{number_t{0}};
            _ub = bound_t{-1};
        }
    }
    explicit interval_t(const bound_t& b)
        : _lb(b.is_infinite() ? bound_t{number_t{0}} : b), _ub(b.is_infinite() ? bound_t{-1} : b) {}

    explicit interval_t(const number_t& n) : _lb(n), _ub(n) {}
    explicit interval_t(std::integral auto n) : _lb(n), _ub(n) {}

    interval_t(const interval_t& i) = default;

    interval_t& operator=(const interval_t& i) = default;

    [[nodiscard]]
    bound_t lb() const {
        return _lb;
    }

    [[nodiscard]]
    bound_t ub() const {
        return _ub;
    }

    [[nodiscard]]
    std::tuple<bound_t, bound_t> pair() const {
        return {_lb, _ub};
    }

    template <std::integral T>
    [[nodiscard]]
    std::tuple<T, T> pair() const {
        return {_lb.narrow<T>(), _ub.narrow<T>()};
    }

    [[nodiscard]]
    std::tuple<number_t, number_t> pair_number() const {
        return {_lb.number().value(), _ub.number().value()};
    }

    template <std::integral T>
    [[nodiscard]]
    std::tuple<T, T> bound(T lb, T ub) const {
        const interval_t b = interval_t{lb, ub} & *this;
        if (b.is_bottom()) {
            CRAB_ERROR("Cannot convert bottom to tuple");
        }
        return {b._lb.narrow<T>(), b._ub.narrow<T>()};
    }

    template <is_enum T>
    [[nodiscard]]
    std::tuple<T, T> bound(T elb, T eub) const {
        using C = std::underlying_type_t<T>;
        auto [lb, ub] = bound(static_cast<C>(elb), static_cast<C>(eub));
        return {static_cast<T>(lb), static_cast<T>(ub)};
    }

    [[nodiscard]]
    bool is_bottom() const {
        return _lb > _ub;
    }

    [[nodiscard]]
    bool is_top() const {
        return _lb.is_infinite() && _ub.is_infinite();
    }

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
            return interval_t{std::min(_lb, x._lb), std::max(_ub, x._ub)};
        }
    }

    interval_t operator&(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{std::max(_lb, x._lb), std::min(_ub, x._ub)};
        }
    }

    [[nodiscard]]
    interval_t widen(const interval_t& x) const {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            return interval_t{x._lb < _lb ? bound_t::minus_infinity() : _lb,
                              _ub < x._ub ? bound_t::plus_infinity() : _ub};
        }
    }

    template <typename Thresholds>
    interval_t widening_thresholds(interval_t x, const Thresholds& ts) {
        if (is_bottom()) {
            return x;
        } else if (x.is_bottom()) {
            return *this;
        } else {
            bound_t lb = x._lb < _lb ? ts.get_prev(x._lb) : _lb;
            bound_t ub = _ub < x._ub ? ts.get_next(x._ub) : _ub;
            return interval_t{lb, ub};
        }
    }

    [[nodiscard]]
    interval_t narrow(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{_lb.is_infinite() && x._lb.is_finite() ? x._lb : _lb,
                              _ub.is_infinite() && x._ub.is_finite() ? x._ub : _ub};
        }
    }

    interval_t operator+(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{_lb + x._lb, _ub + x._ub};
        }
    }

    interval_t& operator+=(const interval_t& x) { return operator=(operator+(x)); }

    interval_t operator-() const {
        if (is_bottom()) {
            return bottom();
        } else {
            return interval_t{-_ub, -_lb};
        }
    }

    interval_t operator-(const interval_t& x) const {
        if (is_bottom() || x.is_bottom()) {
            return bottom();
        } else {
            return interval_t{_lb - x._ub, _ub - x._lb};
        }
    }

    interval_t& operator-=(const interval_t& x) { return operator=(operator-(x)); }

    interval_t operator*(const interval_t& x) const;

    interval_t& operator*=(const interval_t& x) { return operator=(operator*(x)); }

    interval_t operator/(const interval_t& x) const;

    interval_t& operator/=(const interval_t& x) { return operator=(operator/(x)); }

    bound_t size() const {
        if (is_bottom()) {
            return bound_t{number_t{0}};
        }
        return _ub - _lb;
    }

    [[nodiscard]]
    bool is_singleton() const {
        return _lb == _ub;
    }

    [[nodiscard]]
    std::optional<number_t> singleton() const {
        if (!is_bottom() && _lb == _ub) {
            return _lb.number();
        } else {
            return std::optional<number_t>();
        }
    }

    bool contains(const number_t& n) const {
        if (is_bottom()) {
            return false;
        }
        const bound_t b{n};
        return _lb <= b && b <= _ub;
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

    [[nodiscard]]
    interval_t SDiv(const interval_t& x) const;

    [[nodiscard]]
    interval_t UDiv(const interval_t& x) const;

    [[nodiscard]]
    interval_t SRem(const interval_t& x) const;

    [[nodiscard]]
    interval_t URem(const interval_t& x) const;

    // bitwise operations
    [[nodiscard]]
    interval_t And(const interval_t& x) const;

    [[nodiscard]]
    interval_t Or(const interval_t& x) const;

    [[nodiscard]]
    interval_t Xor(const interval_t& x) const;

    [[nodiscard]]
    interval_t Shl(const interval_t& x) const;

    [[nodiscard]]
    interval_t LShr(const interval_t& x) const;

    [[nodiscard]]
    interval_t AShr(const interval_t& x) const;

    interval_t truncate_to_sint(bool is64) const = delete;
    [[nodiscard]]
    interval_t truncate_to_sint(const int width) const {
        switch (width) {
        case 8: return truncate_to<int8_t>();
        case 16: return truncate_to<int16_t>();
        case 32: return truncate_to<int32_t>();
        case 64: return truncate_to<int64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    interval_t truncate_to_uint(bool is64) const = delete;
    [[nodiscard]]
    interval_t truncate_to_uint(const int width) const {
        switch (width) {
        case 8: return truncate_to<uint8_t>();
        case 16: return truncate_to<uint16_t>();
        case 32: return truncate_to<uint32_t>();
        case 64: return truncate_to<uint64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    template <std::integral T>
    [[nodiscard]]
    interval_t truncate_to() const {
        if (*this <= full<T>()) {
            return *this;
        }
        if (const auto size = finite_size()) {
            if (size->fits<T>()) {
                T llb = lb().number()->truncate_to<T>();
                T lub = ub().number()->truncate_to<T>();
                if (llb <= lub) {
                    // Interval can be accurately represented in 64 width.
                    return interval_t{llb, lub};
                }
            }
        }
        return full<T>();
    }

    interval_t signed_int(bool is64) const = delete;
    // Return an interval in the range [INT_MIN, INT_MAX] which can only
    // be represented as an svalue.
    static interval_t signed_int(const int width) {
        switch (width) {
        case 8: return full<int8_t>();
        case 16: return full<int16_t>();
        case 32: return full<int32_t>();
        case 64: return full<int64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    interval_t unsigned_int(bool is64) const = delete;
    // Return an interval in the range [0, UINT_MAX] which can only be
    // represented as a uvalue.
    static interval_t unsigned_int(const int width) {
        switch (width) {
        case 8: return full<uint8_t>();
        case 16: return full<uint16_t>();
        case 32: return full<uint32_t>();
        case 64: return full<uint64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    interval_t nonnegative(bool is64) const = delete;
    // Return a non-negative interval in the range [0, INT_MAX],
    // which can be represented as both an svalue and a uvalue.
    static interval_t nonnegative(const int width) {
        switch (width) {
        case 8: return nonnegative<int8_t>();
        case 16: return nonnegative<int16_t>();
        case 32: return nonnegative<int32_t>();
        case 64: return nonnegative<int64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    interval_t negative(bool is64) const = delete;
    // Return a negative interval in the range [INT_MIN, -1],
    // which can be represented as both an svalue and a uvalue.
    static interval_t negative(const int width) {
        switch (width) {
        case 8: return negative<int8_t>();
        case 16: return negative<int16_t>();
        case 32: return negative<int32_t>();
        case 64: return negative<int64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    template <std::integral T>
    static interval_t nonnegative() {
        return {number_t{0}, number_t{std::numeric_limits<T>::max()}};
    }

    template <std::integral T>
    static interval_t negative() {
        return {number_t{std::numeric_limits<T>::min()}, number_t{-1}};
    }

    template <std::integral T>
    static interval_t full() {
        return {number_t{std::numeric_limits<T>::min()}, number_t{std::numeric_limits<T>::max()}};
    }

    template <std::unsigned_integral T>
    static interval_t high() {
        return interval_t{number_t{std::numeric_limits<std::make_signed_t<T>>::max()} + 1,
                          number_t{std::numeric_limits<T>::max()}};
    }

    interval_t unsigned_high(bool is64) const = delete;
    // Return an interval in the range [INT_MAX+1, UINT_MAX], which can only
    // be represented as a uvalue.
    // The svalue equivalent using the same width would be negative().
    static interval_t unsigned_high(const int width) {
        switch (width) {
        case 8: return high<uint8_t>();
        case 16: return high<uint16_t>();
        case 32: return high<uint32_t>();
        case 64: return high<uint64_t>();
        default: CRAB_ERROR("Invalid width ", width);
        }
    }

    [[nodiscard]]
    std::string to_string() const;
}; //  class interval

namespace interval_operators {

inline interval_t operator+(const number_t& c, const interval_t& x) { return interval_t{c} + x; }

inline interval_t operator+(const interval_t& x, const number_t& c) { return x + interval_t{c}; }

inline interval_t operator*(const number_t& c, const interval_t& x) { return interval_t{c} * x; }

inline interval_t operator*(const interval_t& x, const number_t& c) { return x * interval_t{c}; }

inline interval_t operator/(const number_t& c, const interval_t& x) { return interval_t{c} / x; }

inline interval_t operator/(const interval_t& x, const number_t& c) { return x / interval_t{c}; }

inline interval_t operator-(const number_t& c, const interval_t& x) { return interval_t{c} - x; }

inline interval_t operator-(const interval_t& x, const number_t& c) { return x - interval_t{c}; }

} // namespace interval_operators

} // namespace crab

std::string to_string(const crab::interval_t& interval) noexcept;
