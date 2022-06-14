// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once
#include <cassert>
#include <bitset>

#include "string_constraints.hpp"
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

    [[nodiscard]] string_invariant to_set() const;

    bool operator<=(const bitset_domain_t& other) const {
        return (non_numerical_bytes | other.non_numerical_bytes) == other.non_numerical_bytes;
    }

    bool operator==(const bitset_domain_t& other) const { return non_numerical_bytes == other.non_numerical_bytes; }

    void operator|=(const bitset_domain_t& other) { non_numerical_bytes |= other.non_numerical_bytes; }

    bitset_domain_t operator|(bitset_domain_t&& other) const {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    bitset_domain_t operator|(const bitset_domain_t& other) const {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    bitset_domain_t operator&(const bitset_domain_t& other) const {
        return non_numerical_bytes & other.non_numerical_bytes;
    }

    [[nodiscard]]
    bitset_domain_t widen(const bitset_domain_t& other) const {
        return non_numerical_bytes | other.non_numerical_bytes;
    }

    [[nodiscard]]
    bitset_domain_t narrow(const bitset_domain_t& other) const {
        return non_numerical_bytes & other.non_numerical_bytes;
    }

    [[nodiscard]]
    std::pair<bool, bool> uniformity(size_t lb, int width) const {
        width = std::min(width, (int)(EBPF_STACK_SIZE - lb));
        bool only_num = true;
        bool only_non_num = true;
        for (int j = 0; j < width; j++) {
            if (lb + j >= non_numerical_bytes.size()) {
                throw std::runtime_error("bitset index out of range");
            }
            bool b = non_numerical_bytes[lb + j];
            only_num &= !b;
            only_non_num &= b;
        }
        return std::make_pair(only_num, only_non_num);
    }

    // Get the number of bytes, starting at lb, known to be numbers.
    [[nodiscard]] int all_num_width(size_t lb) const {
        size_t ub = lb;
        while ((ub < EBPF_STACK_SIZE) && !non_numerical_bytes[ub])
            ub++;
        return (int)(ub - lb);
    }

    void reset(size_t lb, int n) {
        n = std::min(n, (int)(EBPF_STACK_SIZE - lb));
        for (int i = 0; i < n; i++) {
            non_numerical_bytes.reset(lb + i);
        }
    }

    void havoc(size_t lb, int width) {
        width = std::min(width, (int)(EBPF_STACK_SIZE - lb));
        for (int i = 0; i < width; i++) {
            non_numerical_bytes.set(lb + i);
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const bitset_domain_t& array);

    // Test whether all values in the range [lb,ub) are numerical.
    [[nodiscard]]
    bool all_num(int lb, int ub) const {
        assert(lb < ub);
        lb = std::max(lb, 0);
        ub = std::min(ub, EBPF_STACK_SIZE);
        if (lb < 0 || ub > (int)non_numerical_bytes.size())
            return false;

        for (int i = lb; i < ub; i++)
            if (non_numerical_bytes[i])
                return false;
        return true;
    }
};
