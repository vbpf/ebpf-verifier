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

    [[nodiscard]] static constexpr int64_t get_max() { return std::numeric_limits<int64_t>::max(); }
    [[nodiscard]] static constexpr int64_t get_min() { return std::numeric_limits<int64_t>::min(); }

    static std::optional<int64_t> checked_add(int64_t a, int64_t b) {
        wideint_t lr = (wideint_t)a + (wideint_t)b;
        if (lr > get_max() || lr < get_min())
            return {};
        return static_cast<int64_t>(lr);
    }

    static std::optional<int64_t> checked_sub(int64_t a, int64_t b) {
        wideint_t lr = (wideint_t)a - (wideint_t)b;
        if (lr > get_max() || lr < get_min())
            return {};
        return static_cast<int64_t>(lr);
    }
    static std::optional<int64_t> checked_mul(int64_t a, int64_t b) {
        wideint_t lr = (wideint_t)a * (wideint_t)b;
        if (lr > get_max() || lr < get_min())
            return {};
        return static_cast<int64_t>(lr);
    }
    static std::optional<int64_t> checked_div(int64_t a, int64_t b) {
        wideint_t lr = (wideint_t)a / (wideint_t)b;
        if (lr > get_max() || lr < get_min())
            return {};
        return static_cast<int64_t>(lr);
    }

  public:
    safe_i64() : m_num(0) {}

    safe_i64(int64_t num) : m_num(num) {}

    safe_i64(const z_number& n) : m_num((int64_t)n) {}

    operator int64_t() const { return (int64_t)m_num; }

    // TODO: output parameters whether operation overflows
    safe_i64 operator+(safe_i64 x) const{
        if (auto z = checked_add(m_num, x.m_num)) {
            return safe_i64(*z);
        }
        CRAB_ERROR("Integer overflow during addition");
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator-(safe_i64 x) const {
        if (auto z = checked_sub(m_num, x.m_num)) {
            return safe_i64(*z);
        }
        CRAB_ERROR("Integer overflow during subtraction");
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator*(safe_i64 x) const {
        if (auto z = checked_mul(m_num, x.m_num)) {
            return safe_i64(*z);
        }
        CRAB_ERROR("Integer overflow during multiplication");
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator/(safe_i64 x) const{
        if (auto z = checked_div(m_num, x.m_num)) {
            return safe_i64(*z);
        }
        CRAB_ERROR("Integer overflow during division");
    }

    // TODO: output parameters whether operation overflows
    safe_i64 operator-() const { return safe_i64(0) - *this; }


    // TODO: output parameters whether operation overflows
    safe_i64& operator+=(safe_i64 x) {
        return *this = *this + x;
    }

    // TODO: output parameters whether operation overflows
    safe_i64& operator-=(safe_i64 x) {
        return *this = *this - x;
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
