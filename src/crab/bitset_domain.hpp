// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <bitset>

#include "gpl/spec_type_descriptors.hpp" // for STACK_SIZE

class bitset_domain_t final {
  private:
    using bits_t = std::bitset<STACK_SIZE>;
    bits_t non_numerical_bytes;

  public:
    bitset_domain_t() { non_numerical_bytes.set(); }

    bitset_domain_t(bits_t non_numerical_bytes) : non_numerical_bytes{non_numerical_bytes} {}

    void set_to_top() { non_numerical_bytes.set(); }

    void set_to_bottom() { non_numerical_bytes.reset(); }

    [[nodiscard]] bool is_top() const { return non_numerical_bytes.all(); }

    [[nodiscard]] bool is_bottom() const { return false; }

    bool operator<=(const bitset_domain_t& other) {
        return (non_numerical_bytes | other.non_numerical_bytes) == other.non_numerical_bytes;
    }

    bool operator==(const bitset_domain_t& other) { return non_numerical_bytes == other.non_numerical_bytes; }

    void operator|=(const bitset_domain_t& other) { non_numerical_bytes |= other.non_numerical_bytes; }

    bitset_domain_t operator|(bitset_domain_t&& other) {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    bitset_domain_t operator|(const bitset_domain_t& other) {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    bitset_domain_t operator&(const bitset_domain_t& other) {
        return non_numerical_bytes & other.non_numerical_bytes;
    }

    bitset_domain_t widen(const bitset_domain_t& other) {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    bitset_domain_t narrow(const bitset_domain_t& other) {
        return non_numerical_bytes & other.non_numerical_bytes;
    }

    std::pair<bool, bool> uniformity(int lb, int width) {
        bool only_num = true;
        bool only_non_num = true;
        for (int j = 0; j < width; j++) {
            bool b = non_numerical_bytes[lb + j];
            only_num &= !b;
            only_non_num &= b;
        }
        return std::make_pair(only_num, only_non_num);
    }

    void reset(int lb, int n) {
        for (int i = 0; i < n; i++) {
            non_numerical_bytes.reset(lb + i);
        }
    }

    void havoc(int lb, int width) {
        for (int i = 0; i < width; i++) {
            non_numerical_bytes.set(lb + i);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const bitset_domain_t& array);
};
