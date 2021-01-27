// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "bitset_domain.hpp"
#include <ostream>

std::ostream& operator<<(std::ostream& o, const bitset_domain_t& b) {
    o << "Numbers -> {";
    bool first = true;
    for (int i = -EBPF_STACK_SIZE; i < 0; i++) {
        if (b.non_numerical_bytes[EBPF_STACK_SIZE + i])
            continue;
        if (!first)
            o << ", ";
        first = false;
        o << "[" << i;
        int j = i + 1;
        for (; j < 0; j++)
            if (b.non_numerical_bytes[EBPF_STACK_SIZE + j])
                break;
        if (j > i + 1)
            o << "..." << j - 1;
        o << "]";
        i = j;
    }
    o << "}";
    return o;
}
