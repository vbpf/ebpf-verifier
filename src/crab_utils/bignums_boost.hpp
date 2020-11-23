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
    z_number(int n) { _n = n; }
    z_number(unsigned int n) { _n = n; }
    z_number(long n) { _n = n; }

    // overloaded typecast operators
    explicit operator long() const {
        if (!fits_slong()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed long integer");
        } else {
            return (long)_n;
        }
    }

    explicit operator int() const {
        if (!fits_sint()) {
            CRAB_ERROR("z_number ", _n.str(), " does not fit into a signed integer");
        } else {
            return (int)_n;
        }
    }

    explicit operator cpp_int() const { return _n; }

    [[nodiscard]] std::size_t hash() const {
        boost::hash<std::string> hasher;
        return hasher(_n.str());
    }

    [[nodiscard]] bool fits_sint() const {
        return ((_n >= INT_MIN) && (_n <= INT_MAX));
    }

    [[nodiscard]] bool fits_slong() const {
        return ((_n >= LONG_MIN) && (_n <= LONG_MAX));
    }

    z_number operator+(const z_number& x) const {
        return z_number(_n + x._n);
    }

    z_number operator+(int x) const { return operator+(z_number(x)); }

    z_number operator*(const z_number& x) const { return z_number(_n * x._n); }

    z_number operator*(int x) const { return operator*(z_number(x)); }

    z_number operator-(const z_number& x) const { return z_number(_n - x._n); }

    z_number operator-(int x) const { return operator-(z_number(x)); }

    z_number operator-() const { return z_number(-_n); }

    z_number operator/(const z_number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [1]");
        } else {
            return z_number(_n / x._n);
        }
    }

    z_number operator/(int x) const { return operator/(z_number(x)); }

    z_number operator%(const z_number& x) const {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [2]");
        } else {
            return z_number(_n % x._n);
        }
    }

    z_number operator%(int x) const { return operator%(z_number(x)); }

    z_number& operator+=(const z_number& x) {
        _n += x._n;
        return *this;
    }

    z_number& operator+=(int x) { return operator+=(z_number(x)); }

    z_number& operator*=(const z_number& x) {
        _n *= x._n;
        return *this;
    }

    z_number& operator*=(int x) { return operator*=(z_number(x)); }

    z_number& operator-=(const z_number& x) {
        _n -= x._n;
        return *this;
    }

    z_number& operator-=(int x) { return operator-=(z_number(x)); }

    z_number& operator/=(const z_number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [3]");
        } else {
            _n /= x._n;
            return *this;
        }
    }

    z_number& operator/=(int x) { return operator/=(z_number(x)); }

    z_number& operator%=(const z_number& x) {
        if (x._n.is_zero()) {
            CRAB_ERROR("z_number: division by zero [4]");
        } else {
            _n %= x._n;
            return *this;
        }
    }

    z_number& operator%=(int x) { return operator%=(z_number(x)); }

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

    bool operator==(int x) const { return operator==(z_number(x)); }

    bool operator!=(const z_number& x) const { return (_n != x._n); }

    bool operator!=(int x) const { return operator!=(z_number(x)); }

    bool operator<(const z_number& x) const { return (_n < x._n); }

    bool operator<(int x) const { return operator<(z_number(x)); }

    bool operator<=(const z_number& x) const { return (_n <= x._n); }

    bool operator<=(int x) const { return operator<=(z_number(x)); }

    bool operator>(const z_number& x) const { return (_n > x._n); }

    bool operator>(int x) const { return operator>(z_number(x)); }

    bool operator>=(const z_number& x) const { return (_n >= x._n); }

    bool operator>=(int x) const { return operator>=(z_number(x)); }

    z_number operator&(const z_number& x) const { return z_number(_n & x._n); }

    z_number operator&(int x) const { return z_number(_n & x); }

    z_number operator|(const z_number& x) const { return z_number(_n | x._n); }

    z_number operator|(int x) const { return z_number(_n | x); }

    z_number operator^(const z_number& x) const { return z_number(_n ^ x._n); }

    z_number operator^(int x) const { return z_number(_n ^ x); }

    z_number operator<<(z_number x) const {
        if (!x.fits_sint()) {
            CRAB_ERROR("z_number ", x._n.str(), " does not fit into an int");
        }
        return z_number(_n << (int)x);
    }

    z_number operator<<(int x) const { return z_number(_n << x); }

    z_number operator>>(z_number x) const {
        if (!x.fits_sint()) {
            CRAB_ERROR("z_number ", x._n.str(), " does not fit into an int");
        }
        return z_number(_n >> (int)x);
    }

    z_number operator>>(int x) const { return z_number(_n >> x); }

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

}; // class z_number

using number_t = z_number;

inline std::size_t hash_value(const z_number& z) { return z.hash(); }

} // namespace crab
