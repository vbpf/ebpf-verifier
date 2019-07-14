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

#include "crab/os.hpp"

#include <boost/functional/hash.hpp>
#include <gmpxx.h>

namespace ikos {

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

class z_number {
  private:
    mpz_class _n;

  public:
    z_number(mpz_class n);

    // The mpz_class constructor can take any standard C++ type except
    // long long.
    static z_number from_ulong(unsigned long n);

    // The mpz_class constructor can take any standard C++ type except
    // long long.
    static z_number from_slong(signed long n);

    // overloaded typecast operators
    explicit operator long() const;

    explicit operator int() const;

    explicit operator mpz_class() const;

    z_number();

    z_number(std::string s);

    z_number(signed long long int n);

    std::string get_str() const;

    std::size_t hash() const;

    bool fits_sint() const;

    bool fits_slong() const;

    z_number operator+(z_number x) const;

    z_number operator*(z_number x) const;

    z_number operator-(z_number x) const;

    z_number operator-() const;

    z_number operator/(z_number x) const;

    z_number operator%(z_number x) const;

    z_number &operator+=(z_number x);

    z_number &operator*=(z_number x);

    z_number &operator-=(z_number x);

    z_number &operator/=(z_number x);

    z_number &operator%=(z_number x);

    z_number &operator--();

    z_number &operator++();

    z_number operator++(int);

    z_number operator--(int);

    bool operator==(z_number x) const;

    bool operator!=(z_number x) const;

    bool operator<(z_number x) const;

    bool operator<=(z_number x) const;

    bool operator>(z_number x) const;

    bool operator>=(z_number x) const;

    z_number operator&(z_number x) const;

    z_number operator|(z_number x) const;

    z_number operator^(z_number x) const;

    z_number operator<<(z_number x) const;

    z_number operator>>(z_number x) const;

    z_number fill_ones() const;

    void write(crab::crab_os &o) const;

}; // class z_number

using number_t = z_number;

inline crab::crab_os &operator<<(crab::crab_os &o, const z_number &z) {
    z.write(o);
    return o;
}

inline std::size_t hash_value(const z_number &z) { return z.hash(); }

} // namespace ikos
