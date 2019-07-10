#pragma once

/**
 *  A class for small, arbitrary-precision unsigned integers.
 **/

#include "crab/bignums.hpp"
#include <cstdint>

namespace crab {

class wrapint {

  public:
    // bitwidth cannot be greater than 64 so even a char can represent
    // all possible bitwidths. However, using uint64_t avoids uintended
    // cast to smaller types that lead to unintended overflows.
    typedef uint64_t bitwidth_t;

  private:
    uint64_t _n;       // 0 <= _n <= 2^_width - 1
    bitwidth_t _width; // 1 <= _width <= 64
    uint64_t _mod;     // 0 if _width=64 otherwise 2^_width

    static const uint64_t mod_8 = 256;
    static const uint64_t mod_16 = 65536;
    static const uint64_t mod_32 = 4294967296;

    void sanity_check_bitwidth() const;

    void sanity_check_bitwidths(const wrapint &other) const;

    void compute_mod();

    wrapint(uint64_t n, bitwidth_t width, uint64_t mod);

  public:
    wrapint(uint64_t n, bitwidth_t width);

    wrapint(ikos::z_number n, bitwidth_t width);

    wrapint(ikos::q_number n, bitwidth_t width);

    wrapint(std::string s, bitwidth_t width);

    bitwidth_t get_bitwidth() const;

    // Needed because wrapint has limited precision
    static bool fits_wrapint(ikos::z_number n, bitwidth_t width);

    // Needed because wrapint has limited precision
    static bool fits_wrapint(ikos::q_number n, bitwidth_t width);

    // return true iff most significant bit is 1.
    bool msb() const;

    // return 01111...1
    static wrapint get_signed_max(bitwidth_t w);

    // return 1000....0
    static wrapint get_signed_min(bitwidth_t w);

    // return 1111....1
    static wrapint get_unsigned_max(bitwidth_t w);

    // return 0000....0
    static wrapint get_unsigned_min(bitwidth_t w);

    // return the wrapint as an unsigned number
    std::string get_unsigned_str() const;

    // return the wrapint as a signed number
    std::string get_signed_str() const;

    uint64_t get_uint64_t() const;

    // return the wrapint as an unsigned big number
    ikos::z_number get_unsigned_bignum() const;

    // return the wrapint as a signed big number
    ikos::z_number get_signed_bignum() const;

    bool is_zero() const;

    wrapint operator+(wrapint x) const;

    wrapint operator*(wrapint x) const;

    wrapint operator-(wrapint x) const;

    wrapint operator-() const;

    // signed division
    wrapint operator/(wrapint x) const;

    // signed division: rounding towards 0
    wrapint sdiv(wrapint x) const;

    // unsigned division: rounding towards 0
    wrapint udiv(wrapint x) const;

    // signed remainder
    wrapint operator%(wrapint x) const;

    // signed rem: is the remainder of the signed division so rounding
    // also towards 0.
    wrapint srem(wrapint x) const;

    // unsigned rem: is the remainder of unsigned division so rounding
    // also towards 0.
    wrapint urem(wrapint x) const;

    wrapint &operator+=(wrapint x);

    wrapint &operator*=(wrapint x);

    wrapint &operator-=(wrapint x);

    wrapint &operator--();

    wrapint &operator++();

    wrapint operator++(int);

    wrapint operator--(int);

    bool operator==(wrapint x) const;

    bool operator!=(wrapint x) const;

    bool operator<(wrapint x) const;

    bool operator<=(wrapint x) const;

    bool operator>(wrapint x) const;

    bool operator>=(wrapint x) const;

    wrapint operator&(wrapint x) const;

    wrapint operator|(wrapint x) const;

    wrapint operator^(wrapint x) const;

    wrapint operator<<(wrapint x) const;

    // logical right shift: blanks filled by 0's
    wrapint lshr(wrapint x) const;

    // arithmetic right shift
    wrapint ashr(wrapint x) const;

    wrapint sext(bitwidth_t bits_to_add) const;

    wrapint zext(bitwidth_t bits_to_add) const;

    wrapint keep_lower(bitwidth_t bits_to_keep) const;

    void write(crab::crab_os &o) const;

}; // class wrapint

inline crab::crab_os &operator<<(crab::crab_os &o, const wrapint &z) {
    z.write(o);
    return o;
}

} // end namespace crab
