#pragma once

/**
 *  Safe signed integers.
 **/

#include "crab/bignums.hpp"
#include <cstdint>

namespace crab {

class safe_i64 {

    // Current implementation is based on
    // https://blog.regehr.org/archives/1139 using wider integers.

    // TODO/FIXME: the current code compiles assuming the type __int128
    // exists. Both clang and gcc supports __int128 if the targeted
    // architecture is x86/64, but it wont' work with 32 bits.
    typedef __int128 wideint_t;

    inline int64_t get_max() const;
    inline int64_t get_min() const;

    int checked_add(int64_t a, int64_t b, int64_t *rp) const;
    int checked_sub(int64_t a, int64_t b, int64_t *rp) const;
    int checked_mul(int64_t a, int64_t b, int64_t *rp) const;
    int checked_div(int64_t a, int64_t b, int64_t *rp) const;

  public:
    safe_i64();

    safe_i64(int64_t num);

    safe_i64(ikos::z_number n);

    operator long() const;

    // TODO: output parameters whether operation overflows
    safe_i64 operator+(safe_i64 x) const;

    // TODO: output parameters whether operation overflows
    safe_i64 operator-(safe_i64 x) const;

    // TODO: output parameters whether operation overflows
    safe_i64 operator*(safe_i64 x) const;

    // TODO: output parameters whether operation overflows
    safe_i64 operator/(safe_i64 x) const;

    // TODO: output parameters whether operation overflows
    safe_i64 operator-() const;

    // TODO: output parameters whether operation overflows
    safe_i64 &operator+=(safe_i64 x);

    // TODO: output parameters whether operation overflows
    safe_i64 &operator-=(safe_i64 x);

    bool operator==(safe_i64 x) const;

    bool operator!=(safe_i64 x) const;

    bool operator<(safe_i64 x) const;

    bool operator<=(safe_i64 x) const;

    bool operator>(safe_i64 x) const;

    bool operator>=(safe_i64 x) const;

    void write(crab::crab_os &os) const;

    friend crab_os &operator<<(crab_os &o, const safe_i64 &n) {
        n.write(o);
        return o;
    }

  private:
    int64_t m_num;
};

} // end namespace crab
