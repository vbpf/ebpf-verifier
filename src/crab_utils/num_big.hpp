// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <climits>
#include <sstream>
#include <string>
#include <utility>

#include <boost/functional/hash.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include "debug.hpp"
using boost::multiprecision::cpp_int;

namespace crab {

template <typename T>
concept is_enum = std::is_enum_v<T>;

template <std::integral T>
using swap_signedness = std::conditional_t<std::is_signed_v<T>, std::make_unsigned_t<T>, std::make_signed_t<T>>;

class number_t final {
    cpp_int _n{nullptr};

  public:
    number_t() = default;
    number_t(cpp_int n) : _n(std::move(n)) {}
    number_t(std::integral auto n) : _n{n} {}
    number_t(is_enum auto n) : _n{static_cast<int64_t>(n)} {}
    explicit number_t(const std::string& s) { _n = cpp_int(s); }

    template <std::integral T>
    explicit operator T() const {
        if (!fits<T>()) {
            CRAB_ERROR("number_t ", _n, " does not fit into ", typeid(T).name());
        }
        return static_cast<T>(_n);
    }

    explicit operator cpp_int() const { return _n; }

    [[nodiscard]]
    friend std::size_t hash_value(const number_t& z) {
        return boost::hash_value(z._n.str());
    }

    template <std::integral T>
    [[nodiscard]]
    bool fits() const {
        return std::numeric_limits<T>::min() <= _n && _n <= std::numeric_limits<T>::max();
    }

    template <std::integral T>
    [[nodiscard]]
    bool fits_cast_to() const {
        return fits<T>() || fits<swap_signedness<T>>();
    }

    template <std::integral T>
    [[nodiscard]]
    T cast_to() const {
        if (fits<T>()) {
            return static_cast<T>(_n);
        }
        using Q = swap_signedness<T>;
        if (fits<Q>()) {
            return static_cast<T>(static_cast<Q>(_n));
        }
        CRAB_ERROR("number_t ", _n, " does not fit into ", typeid(T).name());
    }

    // Allow casting to intX_t as needed for finite width operations.
    [[nodiscard]]
    number_t cast_to_sint(const int width) const {
        switch (width) {
        case 0: return *this; // No finite width.
        case 8: return cast_to<int8_t>();
        case 16: return cast_to<int16_t>();
        case 32: return cast_to<int32_t>();
        case 64: return cast_to<int64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow casting to uintX_t as needed for finite width operations.
    [[nodiscard]]
    number_t cast_to_uint(const int width) const {
        switch (width) {
        case 0: return *this; // No finite width.
        case 8: return cast_to<uint8_t>();
        case 16: return cast_to<uint16_t>();
        case 32: return cast_to<uint32_t>();
        case 64: return cast_to<uint64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    template <std::integral T>
    T truncate_to() const {
        using U = std::make_unsigned_t<T>;
        constexpr U mask = std::numeric_limits<U>::max();
        return static_cast<T>(static_cast<U>(_n & mask));
    }

    // Allow truncating to int32_t or int64_t as needed for finite width operations.
    // Unlike casting, truncating will not throw a crab error if the number doesn't fit.
    [[nodiscard]]
    number_t truncate_to_sint(const int width) const {
        switch (width) {
        case 0: return *this; // No finite width.
        case 8: return truncate_to<int8_t>();
        case 16: return truncate_to<int16_t>();
        case 32: return truncate_to<int32_t>();
        case 64: return truncate_to<int64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow truncating to uint32_t or uint64_t as needed for finite width operations.
    // Unlike casting, truncating will not throw a crab error if the number doesn't fit.
    [[nodiscard]]
    number_t truncate_to_uint(const int width) const {
        switch (width) {
        case 0: return *this; // No finite width.
        case 8: return truncate_to<uint8_t>();
        case 16: return truncate_to<uint16_t>();
        case 32: return truncate_to<uint32_t>();
        case 64: return truncate_to<uint64_t>();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    number_t operator+(const number_t& x) const { return number_t(_n + x._n); }

    number_t operator*(const number_t& x) const { return number_t(_n * x._n); }

    number_t operator-(const number_t& x) const { return number_t(_n - x._n); }

    number_t operator-() const { return number_t(-_n); }

    number_t operator/(const number_t& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [1]");
        }
        return number_t(_n / x._n);
    }

    number_t operator%(const number_t& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [2]");
        }
        return number_t(_n % x._n);
    }

    number_t& operator+=(const number_t& x) {
        _n += x._n;
        return *this;
    }

    number_t& operator*=(const number_t& x) {
        _n *= x._n;
        return *this;
    }

    number_t& operator-=(const number_t& x) {
        _n -= x._n;
        return *this;
    }

    number_t& operator/=(const number_t& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [3]");
        }
        _n /= x._n;
        return *this;
    }

    number_t& operator%=(const number_t& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("number_t: division by zero [4]");
        }
        _n %= x._n;
        return *this;
    }

    number_t& operator--() & {
        --_n;
        return *this;
    }

    number_t& operator++() & {
        ++_n;
        return *this;
    }

    number_t operator++(int) & {
        number_t r(*this);
        ++*this;
        return r;
    }

    number_t operator--(int) & {
        number_t r(*this);
        --*this;
        return r;
    }

    bool operator==(const number_t& x) const { return _n == x._n; }

    bool operator!=(const number_t& x) const { return _n != x._n; }

    bool operator<(const number_t& x) const { return _n < x._n; }

    bool operator<=(const number_t& x) const { return _n <= x._n; }

    bool operator>(const number_t& x) const { return _n > x._n; }

    bool operator>=(const number_t& x) const { return _n >= x._n; }

    number_t operator&(const number_t& x) const { return number_t(_n & x._n); }

    number_t operator|(const number_t& x) const { return number_t(_n | x._n); }

    number_t operator^(const number_t& x) const { return number_t(_n ^ x._n); }

    number_t operator<<(const number_t& x) const {
        if (x < 0) {
            CRAB_ERROR("Shift amount cannot be negative");
        }
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("number_t ", x._n, " does not fit into an int32");
        }
        return number_t(_n << static_cast<int32_t>(x));
    }

    number_t operator>>(const number_t& x) const {
        if (x < 0) {
            CRAB_ERROR("Shift amount cannot be negative");
        }
        if (!x.fits<int32_t>()) {
            CRAB_ERROR("number_t ", x._n, " does not fit into an int32");
        }
        return number_t(_n >> static_cast<int32_t>(x));
    }

    [[nodiscard]]
    number_t fill_ones() const {
        if (_n.is_zero()) {
            return number_t(static_cast<signed long long>(0));
        }
        return number_t{(cpp_int(1) << (msb(_n) + 1)) - 1};
    }

    friend std::ostream& operator<<(std::ostream& o, const number_t& z) { return o << z._n.str(); }

    [[nodiscard]]
    std::string to_string() const;
};
// class number_t

} // namespace crab
