// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <climits>
#include <iostream>
#include <sstream>
#include <string>

#include <boost/functional/hash.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <utility>

#include "debug.hpp"
using boost::multiprecision::cpp_int;

namespace crab {

class z_number final {
  private:
    cpp_int _n{nullptr};

  public:
    z_number() = default;
    z_number(cpp_int n) : _n(std::move(n)) {}
    explicit z_number(const std::string& s) { _n = cpp_int(s); }

    z_number(signed long long int n) { _n = n; }
    z_number(unsigned long long int n) { _n = n; }
    z_number(unsigned long int n) { _n = n; }
    z_number(int n) { _n = n; }
    z_number(unsigned int n) { _n = n; }
    z_number(long n) { _n = n; }

    // overloaded typecast operators
    explicit operator int64_t() const {
        if (!fits_sint64()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed 64-bit integer");
        } else {
            return (int64_t)_n;
        }
    }

    explicit operator uint64_t() const {
        if (!fits_uint64()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into an unsigned 64-bit integer");
        } else {
            return (uint64_t)_n;
        }
    }

    explicit operator int32_t() const {
        if (!fits_sint32()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed integer");
        } else {
            return (int)_n;
        }
    }

    explicit operator uint32_t() const {
        if (!fits_uint32()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into an unsigned integer");
        } else {
            return (unsigned int)_n;
        }
    }

    explicit operator cpp_int() const { return _n; }

    [[nodiscard]] std::size_t hash() const {
        boost::hash<std::string> hasher;
        return hasher(_n.str());
    }

    [[nodiscard]] bool fits_sint32() const {
        return ((_n >= INT_MIN) && (_n <= INT_MAX));
    }

    [[nodiscard]] bool fits_uint32() const { return ((_n >= 0) && (_n <= UINT_MAX)); }

    [[nodiscard]] bool fits_sint64() const {
        // "long long" is always 64-bits, whereas "long" varies
        // (see https://en.cppreference.com/w/cpp/language/types)
        // so make sure we use 64-bit numbers.
        return ((_n >= LLONG_MIN) && (_n <= LLONG_MAX));
    }

    [[nodiscard]] bool fits_uint64() const { return ((_n >= 0) && (_n <= ULLONG_MAX)); }

    [[nodiscard]] bool fits_cast_to_int64() const { return fits_uint64() || fits_sint64(); }

    [[nodiscard]] uint64_t cast_to_uint64() const {
        if (fits_uint64()) {
            return (uint64_t)_n;
        } else if (fits_sint64()) {
            // Convert 64 bits from int64_t to uint64_t.
            return (uint64_t)(int64_t)_n;
        } else {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into an unsigned 64-bit integer");
        }
    }

    [[nodiscard]] uint64_t truncate_to_uint64() const {
        if (fits_sint64()) {
            // Convert 64 bits from int64_t to uint64_t.
            return (uint64_t)(int64_t)_n;
        } else {
            // Truncate to fit into an unsigned 64-bit integer.
            return (uint64_t)_n;
        }
    }

    [[nodiscard]] uint64_t cast_to_uint32() const {
        if (fits_uint32()) {
            return (uint32_t)_n;
        } else if (fits_sint32()) {
            // Convert 32 bits from int32_t to uint32_t.
            return (uint32_t)(int32_t)_n;
        } else {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into an unsigned 32-bit integer");
        }
    }

    [[nodiscard]] uint64_t truncate_to_uint32() const {
        return (uint32_t)truncate_to_uint64();
    }

    // For 64-bit operations, get the value as a signed 64-bit integer.
    [[nodiscard]] int64_t cast_to_sint64() const {
        if (fits_sint64()) {
            return (int64_t)_n;
        } else if (fits_uint64()) {
            // Convert 64 bits from uint64_t to int64_t.
            return (int64_t)(uint64_t)_n;
        } else {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed 64-bit integer");
        }
    }

    // For 64-bit operations, get the value as a signed 64-bit integer.
    [[nodiscard]] int64_t truncate_to_sint64() const {
        if (fits_sint64()) {
            return (int64_t)_n;
        } else {
            // z_number does not fit into a signed 64-bit integer, so truncate it to fit.
            return (int64_t)(uint64_t)_n;
        }
    }

    // For 32-bit operations, get the low 32 bits as a signed integer.
    [[nodiscard]] int32_t cast_to_sint32() const {
        return (int32_t)cast_to_sint64();
    }

    // For 32-bit operations, get the low 32 bits as a signed integer.
    [[nodiscard]] int32_t truncate_to_sint32() const {
        return (int32_t)truncate_to_sint64();
    }

    // Allow casting to int32_t or int64_t as needed for finite width operations.
    [[nodiscard]] z_number cast_to_signed_finite_width(int finite_width) const {
        switch (finite_width) {
        case 0: return *this; // No finite width.
        case 32: return cast_to_sint32();
        case 64: return cast_to_sint64();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow casting to uint32_t or uint64_t as needed for finite width operations.
    [[nodiscard]] z_number cast_to_unsigned_finite_width(int finite_width) const {
        switch (finite_width) {
        case 0: return *this; // No finite width.
        case 32: return cast_to_uint32();
        case 64: return cast_to_uint64();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow truncating to int32_t or int64_t as needed for finite width operations.
    // Unlike casting, truncating will not throw a crab error if the number doesn't fit.
    [[nodiscard]] z_number truncate_to_signed_finite_width(int finite_width) const {
        switch (finite_width) {
        case 0: return *this; // No finite width.
        case 32: return truncate_to_sint32();
        case 64: return truncate_to_sint64();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    // Allow truncating to uint32_t or uint64_t as needed for finite width operations.
    // Unlike casting, truncating will not throw a crab error if the number doesn't fit.
    [[nodiscard]] z_number truncate_to_unsigned_finite_width(int finite_width) const {
        switch (finite_width) {
        case 0: return *this; // No finite width.
        case 32: return truncate_to_uint32();
        case 64: return truncate_to_uint64();
        default: CRAB_ERROR("invalid finite width");
        }
    }

    z_number operator+(const z_number& x) const {
        return z_number(_n + x._n);
    }

    z_number operator*(const z_number& x) const { return z_number(_n * x._n); }

    z_number operator-(const z_number& x) const { return z_number(_n - x._n); }

    z_number operator-() const { return z_number(-_n); }

    z_number operator/(const z_number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [1]");
        } else {
            return z_number(_n / x._n);
        }
    }

    z_number operator%(const z_number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [2]");
        } else {
            return z_number(_n % x._n);
        }
    }

    z_number& operator+=(const z_number& x) {
        _n += x._n;
        return *this;
    }

    z_number& operator*=(const z_number& x) {
        _n *= x._n;
        return *this;
    }

    z_number& operator-=(const z_number& x) {
        _n -= x._n;
        return *this;
    }

    z_number& operator/=(const z_number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [3]");
        } else {
            _n /= x._n;
            return *this;
        }
    }

    z_number& operator%=(const z_number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [4]");
        } else {
            _n %= x._n;
            return *this;
        }
    }

    z_number& operator--() & {
        _n--;
        return *this;
    }

    z_number& operator++() & {
        _n++;
        return *this;
    }

    z_number operator++(int) & {
        z_number r(*this);
        ++(*this);
        return r;
    }

    z_number operator--(int) & {
        z_number r(*this);
        --(*this);
        return r;
    }

    bool operator==(const z_number& x) const {
        return (_n == x._n);
    }

    bool operator!=(const z_number& x) const { return (_n != x._n); }

    bool operator<(const z_number& x) const { return (_n < x._n); }

    bool operator<=(const z_number& x) const { return (_n <= x._n); }

    bool operator>(const z_number& x) const { return (_n > x._n); }

    bool operator>=(const z_number& x) const { return (_n >= x._n); }

    z_number operator&(const z_number& x) const { return z_number(_n & x._n); }

    z_number operator|(const z_number& x) const { return z_number(_n | x._n); }

    z_number operator^(const z_number& x) const { return z_number(_n ^ x._n); }

    z_number operator<<(z_number x) const {
        if (!x.fits_sint32()) {
            CRAB_ERROR("z_number ", x._n.str(), " does not fit into an int32");
        }
        return z_number(_n << (int32_t)x);
    }

    z_number operator>>(z_number x) const {
        if (!x.fits_sint32()) {
            CRAB_ERROR("z_number ", x._n.str(), " does not fit into an int32");
        }
        return z_number(_n >> (int32_t)x);
    }

    [[nodiscard]] z_number fill_ones() const {
        if (_n.is_zero()) {
            return z_number((signed long long)0);
        }

        z_number result;
        for (result = 1; result < *this; result = result * 2 + 1)
            ;
        return result;
    }

    friend std::ostream& operator<<(std::ostream& o, const z_number& z) {
        return o << z._n.str();
    }

    [[nodiscard]] std::string to_string() const;
};
// class z_number

using number_t = z_number;

inline std::size_t hash_value(const z_number& z) { return z.hash(); }
} // namespace crab
