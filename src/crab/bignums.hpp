/*******************************************************************************
 *
 * Implementation of bignums based on GMP, the Gnu Multiple Precision Arithmetic
 * Library (http://gmplib.org).
 *
 * Author: Arnaud J. Venet (arnaud.j.venet@nasa.gov)
 *
 * Contributors: Jorge A. Navas (jorge.navas@sri.com)
 *
 * Notices:
 *
 * Copyright (c) 2011-2014 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Disclaimers:
 *
 * No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF
 * ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED
 * TO, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS,
 * ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL BE
 * ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM TO
 * THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
 * ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS,
 * RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS
 * RESULTING FROM USE OF THE SUBJECT SOFTWARE.  FURTHER, GOVERNMENT AGENCY
 * DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY SOFTWARE,
 * IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
 *
 * Waiver and Indemnity:  RECIPIENT AGREES TO WAIVE ANY AND ALL CLAIMS AGAINST
 * THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL
 * AS ANY PRIOR RECIPIENT.  IF RECIPIENT'S USE OF THE SUBJECT SOFTWARE RESULTS
 * IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES OR LOSSES ARISING FROM SUCH
 * USE, INCLUDING ANY DAMAGES FROM PRODUCTS BASED ON, OR RESULTING FROM,
 * RECIPIENT'S USE OF THE SUBJECT SOFTWARE, RECIPIENT SHALL INDEMNIFY AND HOLD
 * HARMLESS THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS,
 * AS WELL AS ANY PRIOR RECIPIENT, TO THE EXTENT PERMITTED BY LAW.
 * RECIPIENT'S SOLE REMEDY FOR ANY SUCH MATTER SHALL BE THE IMMEDIATE,
 * UNILATERAL TERMINATION OF THIS AGREEMENT.
 *
 ******************************************************************************/

#pragma once

#include <climits>
#include <iostream>
#include <sstream>
#include <string>

#include <boost/functional/hash.hpp>
#include <utility>

#include <gmpxx.h>

#include "crab/debug.hpp"

namespace crab {

// GMP can convert directly from/to signed/unsigned long and
// signed/unsigned int. However, the C++11 standard only guarantees:
//
//  - unsigned/signed int  >= 16 bits.
//  - unsigned/signed long >= 32 bits.
//

// TODO/FIXME:
//
// We don't have a conversion from GMP numbers to 64-bit integers,
// because GMP cannot convert directly from/to int64_t or
// uint64_t. For that, we need to use mpz_export and mpz_import but
// they are significantly more expensive.
//
// Note that the actual size of **long** integer varies depending on
// the architecture and OS (see e.g.,
// https://en.cppreference.com/w/cpp/language/types). For instance,
// both Linux and mac OS on an Intel 64, the size of long integers is
// 8 bytes. But for Windows on Intel 64, the size is 4 bytes.

class z_number final {
  private:
    mpz_class _n{0};

  public:
    z_number() = default;
    explicit z_number(mpz_class n) : _n(std::move(n)) {}

    z_number(signed long long int n) : _n((signed long int)n) {
        if (n > LONG_MAX) {
            CRAB_ERROR(n, " cannot fit into a signed long int: use another mpz_class constructor");
        }
    }

    explicit z_number(const std::string& s) {
        try {
            _n = s;
        } catch (std::invalid_argument& e) {
            CRAB_ERROR("z_number: invalid string in constructor", s);
        }
    }

    // overloaded typecast operators
    explicit operator long() const {
        if (_n.fits_slong_p()) {
            return _n.get_si();
        } else {
            CRAB_ERROR("mpz_class ", _n.get_str(), " does not fit into a signed long integer");
        }
    }

    explicit operator int() const {
        if (_n.fits_sint_p()) {
            // get_si returns a signed long so we cast it to int
            return (int)_n.get_si();
        } else {
            CRAB_ERROR("mpz_class ", _n.get_str(), " does not fit into a signed integer");
        }
    }

    explicit operator mpz_class() const { return _n; }

    std::size_t hash() const {
        boost::hash<std::string> hasher;
        return hasher(_n.get_str());
    }

    bool fits_sint() const { return _n.fits_sint_p(); }

    bool fits_slong() const { return _n.fits_slong_p(); }

    z_number operator+(const z_number& x) const {
        mpz_class r = _n + x._n;
        return z_number(r);
    }

    z_number operator+(int x) const { return operator+(z_number(x)); }

    z_number operator*(const z_number& x) const {
        mpz_class r = _n * x._n;
        return z_number(r);
    }

    z_number operator*(int x) const { return operator*(z_number(x)); }

    z_number operator-(const z_number& x) const {
        mpz_class r = _n - x._n;
        return z_number(r);
    }

    z_number operator-(int x) const { return operator-(z_number(x)); }

    z_number operator-() const {
        mpz_class r = -_n;
        return z_number(r);
    }

    z_number operator/(const z_number& x) const {
        if (x._n == 0) {
            CRAB_ERROR("z_number: division by zero [1]");
        } else {
            mpz_class r = _n / x._n;
            return z_number(r);
        }
    }

    z_number operator/(int x) const { return operator/(z_number(x)); }

    z_number operator%(const z_number& x) const {
        if (x._n == 0) {
            CRAB_ERROR("z_number: division by zero [2]");
        } else {
            mpz_class r = _n % x._n;
            return z_number(r);
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
        if (x._n == 0) {
            CRAB_ERROR("z_number: division by zero [3]");
        } else {
            _n /= x._n;
            return *this;
        }
    }

    z_number& operator/=(int x) { return operator/=(z_number(x)); }

    z_number& operator%=(const z_number& x) {
        if (x._n == 0) {
            CRAB_ERROR("z_number: division by zero [4]");
        } else {
            _n %= x._n;
            return *this;
        }
    }

    z_number& operator%=(int x) { return operator%=(z_number(x)); }

    z_number& operator--() & {
        --(_n);
        return *this;
    }

    z_number& operator++() & {
        ++(_n);
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

    bool operator==(const z_number& x) const { return _n == x._n; }
    bool operator==(int x) const { return operator==(z_number(x)); }

    bool operator!=(const z_number& x) const { return _n != x._n; }
    bool operator!=(int x) const { return operator!=(z_number(x)); }

    bool operator<(const z_number& x) const { return _n < x._n; }

    bool operator<(int x) const { return operator<(z_number(x)); }

    bool operator<=(const z_number& x) const { return _n <= x._n; }
    bool operator<=(int x) const { return operator<=(z_number(x)); }

    bool operator>(const z_number& x) const { return _n > x._n; }
    bool operator>(int x) const { return operator>(z_number(x)); }

    bool operator>=(const z_number& x) const { return _n >= x._n; }
    bool operator>=(int x) const { return operator>=(z_number(x)); }

    z_number operator&(const z_number& x) const { return z_number(_n & x._n); }
    z_number operator&(int x) const { return operator&(z_number(x)); }

    z_number operator|(const z_number& x) const { return z_number(_n | x._n); }
    z_number operator|(int x) const { return operator|(z_number(x)); }

    z_number operator^(const z_number& x) const { return z_number(_n ^ x._n); }
    z_number operator^(int x) const { return operator^(z_number(x)); }

    z_number operator<<(z_number x) const {
        mpz_t tmp;
        mpz_init(tmp);
        mpz_mul_2exp(tmp, _n.get_mpz_t(), mpz_get_ui(x._n.get_mpz_t()));
        mpz_class result(tmp);
        return z_number(result);
    }

    z_number operator<<(int x) const { return operator<<(z_number(x)); }

    z_number operator>>(z_number x) const {
        mpz_class tmp(_n);
        return z_number(tmp.operator>>=(mpz_get_ui(x._n.get_mpz_t())));
    }
    z_number operator>>(int x) const { return operator>>(z_number(x)); }

    z_number fill_ones() const {
        assert(_n >= 0);
        if (_n == 0) {
            return z_number(0);
        }

        mpz_class result;
        for (result = 1; result < _n; result = 2 * result + 1)
            ;
        return z_number(result);
    }

    void write(std::ostream& o) const { o << _n.get_str(); }

}; // class z_number

using number_t = z_number;

inline std::ostream& operator<<(std::ostream& o, const z_number& z) {
    z.write(o);
    return o;
}

inline std::size_t hash_value(const z_number& z) { return z.hash(); }

} // namespace crab
