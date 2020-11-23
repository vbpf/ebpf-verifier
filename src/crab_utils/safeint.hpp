// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

/**
 *  Safe signed integers.
 **/

#include <cstdint>
#include <limits>
#ifndef __GNUC__
#include <boost/multiprecision/cpp_int.hpp>
#endif

#include "crab_utils/bignums.hpp"

namespace crab {

class safe_i64 {

    // Current implementation is based on
    // https://blog.regehr.org/archives/1139 using wider integers.

#ifdef __GNUC__
    // TODO/FIXME: the current code compiles assuming the type __int128
    // exists. Both clang and gcc supports __int128 if the targeted
    // architecture is x86/64, but it won't work with 32 bits.
    using wideint_t = __int128;
#else
    using wideint_t = boost::multiprecision::int128_t;
#endif

    [[nodiscard]] static int64_t get_max() { return std::numeric_limits<int64_t>::max(); }
    [[nodiscard]] static int64_t get_min() { return std::numeric_limits<int64_t>::min(); }

    static int checked_add(int64_t a, int64_t b, int64_t* rp) {
        wideint_t lr = (wideint_t)a + (wideint_t)b;
        *rp = static_cast<int64_t>(lr);
        return lr > get_max() || lr < get_min();
    }

    static int checked_sub(int64_t a, int64_t b, int64_t* rp) {
        wideint_t lr = (wideint_t)a - (wideint_t)b;
        *rp = static_cast<int64_t>(lr);
        return lr > get_max() || lr < get_min();
    }
    static int checked_mul(int64_t a, int64_t b, int64_t* rp) {
        wideint_t lr = (wideint_t)a * (wideint_t)b;
        *rp = static_cast<int64_t>(lr);
        return lr > get_max() || lr < get_min();
    }
    static int checked_div(int64_t a, int64_t b, int64_t* rp) {
        wideint_t lr = (wideint_t)a / (wideint_t)b;
        *rp = static_cast<int64_t>(lr);
        return lr > get_max() || lr < get_min();
    }

  public:
    safe_i64() : m_num(0) {}

    safe_i64(int64_t num) : m_num(num) {}

    safe_i64(const z_number& n) : m_num((long)n) {}

    operator long() const{ return (long)m_num; }

    // TODO: output parameters whether operation overflows
    safe_i64 operator+(safe_i64 x) const{
        int64_t z;
        int err = checked_add(m_num, x.m_num, &z);
        if (err) {
            CRAB_ERROR("Integer overflow during addition");
        }
        return safe_i64(z);
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator-(safe_i64 x) const{
        int64_t z;
        int err = checked_sub(m_num, x.m_num, &z);
        if (err) {
            CRAB_ERROR("Integer overflow during subtraction");
        }
        return safe_i64(z);
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator*(safe_i64 x) const{
        int64_t z;
        int err = checked_mul(m_num, x.m_num, &z);
        if (err) {
            CRAB_ERROR("Integer overflow during multiplication");
        }
        return safe_i64(z);
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator/(safe_i64 x) const{
        int64_t z;
        int err = checked_div(m_num, x.m_num, &z);
        if (err) {
            CRAB_ERROR("Integer overflow during multiplication");
        }
        return safe_i64(z);
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator-() const { return safe_i64(0) - *this; }


    // TODO: output parameters whether operation overflows
    safe_i64& operator+=(safe_i64 x){
        int err = checked_add(m_num, x.m_num, &m_num);
        if (err) {
            CRAB_ERROR("Integer overflow during addition");
        }
        return *this;
    }

    // TODO: output parameters whether operation overflows
    safe_i64& operator-=(safe_i64 x) {
        int err = checked_sub(m_num, x.m_num, &m_num);
        if (err) {
            CRAB_ERROR("Integer overflow during subtraction");
        }
        return *this;
    }

    bool operator==(safe_i64 x) const { return m_num == x.m_num; }

    bool operator!=(safe_i64 x) const { return m_num != x.m_num; }

    bool operator<(safe_i64 x) const { return m_num < x.m_num; }

    bool operator<=(safe_i64 x) const { return m_num <= x.m_num; }

    bool operator>(safe_i64 x) const { return m_num > x.m_num; }

    bool operator>=(safe_i64 x) const{ return m_num >= x.m_num; }

    friend std::ostream& operator<<(std::ostream& o, const safe_i64& n) { return o << n.m_num; }

  private:
    int64_t m_num;
};

} // end namespace crab
