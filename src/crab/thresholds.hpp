// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <climits>
#include <map>

#include <boost/range/iterator_range.hpp>

#include "crab/cfg.hpp"
#include "crab/interval.hpp"
#include "crab/wto.hpp"

namespace crab::inline iterators {

/**
    Class that represents a set of thresholds used by the widening operator
**/

class thresholds_t final {
    std::vector<bound_t> m_thresholds{bound_t::minus_infinity(), number_t{0}, bound_t::plus_infinity()};
    const size_t m_capacity;

  public:
    explicit thresholds_t(const size_t capacity = UINT_MAX) : m_capacity(capacity) {}

    [[nodiscard]]
    size_t size() const {
        return m_thresholds.size();
    }

    void add(const bound_t& v);

    friend std::ostream& operator<<(std::ostream& o, const thresholds_t& t);
};

/**
   Collect thresholds per wto cycle (i.e. loop)
**/
class wto_thresholds_t final {
    cfg_t& m_cfg;
    // maximum number of thresholds
    size_t m_max_size;
    // keep a set of thresholds per wto head
    std::map<label_t, thresholds_t> m_head_to_thresholds;
    // the top of the stack is the current wto head
    std::vector<label_t> m_stack;

    void get_thresholds(const basic_block_t& bb, thresholds_t& thresholds) const;

  public:
    wto_thresholds_t(cfg_t& cfg, const size_t max_size) : m_cfg(cfg), m_max_size(max_size) {}

    void operator()(const label_t& vertex);

    void operator()(const std::shared_ptr<wto_cycle_t>& cycle);

    friend std::ostream& operator<<(std::ostream& o, const wto_thresholds_t& t);
};

} // namespace crab::inline iterators
