// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <cassert>
#include <bitset>

#include "spec_type_descriptors.hpp" // for EBPF_STACK_SIZE

class bitset_domain_t final {
  private:
    using bits_t = std::bitset<EBPF_STACK_SIZE>;
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

    std::pair<bool, bool> uniformity(size_t lb, int width) {
        bool only_num = true;
        bool only_non_num = true;
        for (int j = 0; j < width; j++) {
            bool b = non_numerical_bytes[lb + j];
            only_num &= !b;
            only_non_num &= b;
        }
        return std::make_pair(only_num, only_non_num);
    }

    void reset(size_t lb, int n) {
        for (int i = 0; i < n; i++) {
            non_numerical_bytes.reset(lb + i);
        }
    }

    void havoc(size_t lb, int width) {
        for (int i = 0; i < width; i++) {
            non_numerical_bytes.set(lb + i);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const bitset_domain_t& array);

    // Test whether all values in the range [lb,ub) are numerical.
    bool all_num(int lb, int ub) {
        assert(lb < ub);
        if (lb < 0 || ub > (int)non_numerical_bytes.size())
            return false;

        for (int i = lb; i < ub; i++)
            if (non_numerical_bytes[i])
                return false;
        return true;
    }
};
