// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
/*******************************************************************************
 * Array expansion domain
 *
 * For a given array, map sequences of consecutive bytes to cells
 * consisting of a triple <offset, size, var> where:
 *
 * - offset is an unsigned number
 * - size is an unsigned number
 * - var is a scalar variable that represents the content of
 *   a[offset, ..., offset + size - 1]
 *
 * The domain is general enough to represent any possible sequence of
 * consecutive bytes including sequences of bytes starting at the same
 * offsets but different sizes, overlapping sequences starting at
 * different offsets, etc. However, there are some cases that have
 * been implemented in an imprecise manner:
 *
 * (1) array store/load with a non-constant index are conservatively ignored.
 * (2) array load from a cell that overlaps with other cells return top.
 ******************************************************************************/

#pragma once

#include <functional>
#include <optional>
#include <utility>

#include "crab/variable.hpp"
#include "crab/split_dbm.hpp"

#include "crab/bitset_domain.hpp"

namespace crab::domains {

// Numerical abstract domain.
using NumAbsDomain = SplitDBM;

void clear_global_state();

class array_domain_t final {
    bitset_domain_t num_bytes;

  public:
    array_domain_t() = default;

    array_domain_t(const bitset_domain_t& num_bytes) : num_bytes(num_bytes) { }

    void set_to_top();
    void set_to_bottom();
    [[nodiscard]] bool is_bottom() const;
    [[nodiscard]] bool is_top() const;

    bool operator<=(const array_domain_t& other) const;
    bool operator==(const array_domain_t& other) const;

    void operator|=(const array_domain_t& other);

    array_domain_t operator|(const array_domain_t& other) const;
    array_domain_t operator&(const array_domain_t& other) const;
    array_domain_t widen(const array_domain_t& other) const;
    array_domain_t widening_thresholds(const array_domain_t& other, const iterators::thresholds_t& ts) const;
    array_domain_t narrow(const array_domain_t& other) const;

    friend std::ostream& operator<<(std::ostream& o, const array_domain_t& dom);
    [[nodiscard]] string_invariant to_set() const;

    bool all_num(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub);
    [[nodiscard]] int min_all_num_size(const NumAbsDomain& inv, variable_t offset) const;

    std::optional<linear_expression_t> load(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& i, int width);
    std::optional<variable_t> store(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx, const linear_expression_t& elem_size,
                                    const linear_expression_t& val);
    std::optional<variable_t> store_type(NumAbsDomain& inv,
                                         const linear_expression_t& idx,
                                         const linear_expression_t& elem_size,
                                         const linear_expression_t& val);
    std::optional<variable_t> store_type(NumAbsDomain& inv,
                                         const linear_expression_t& idx,
                                         const linear_expression_t& elem_size,
                                         const Reg& reg);
    void havoc(NumAbsDomain& inv, data_kind_t kind, const linear_expression_t& idx, const linear_expression_t& elem_size);

    // Perform array stores over an array segment
    void store_numbers(NumAbsDomain& inv, variable_t _idx, variable_t _width);

    void initialize_numbers(int lb, int width) { num_bytes.reset(lb, width); }
};

}
