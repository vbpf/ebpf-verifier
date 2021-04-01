// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>
#include <algorithm>
#include <climits>

#include <boost/range/iterator_range.hpp>

#include "crab/cfg.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/wto.hpp"
#include "crab_utils/debug.hpp"

namespace crab {

inline namespace iterators {

/**
    Class that represents a set of thresholds used by the widening operator
**/

class thresholds_t final {

  private:
    std::vector<bound_t> m_thresholds;
    size_t m_size;

  public:
    explicit thresholds_t(size_t size = UINT_MAX) : m_size(size) {
        m_thresholds.push_back(bound_t::minus_infinity());
        m_thresholds.emplace_back(0);
        m_thresholds.push_back(bound_t::plus_infinity());
    }

    size_t size() const { return m_thresholds.size(); }

    void add(bound_t v1);

    friend std::ostream& operator<<(std::ostream& o, const thresholds_t& t);
};

/**
   Collect thresholds per wto cycle (i.e. loop)
**/
class wto_thresholds_t final {
  private:
    // the cfg
    cfg_t& m_cfg;
    // maximum number of thresholds
    size_t m_max_size;
    // keep a set of thresholds per wto head
    std::map<label_t, thresholds_t> m_head_to_thresholds;
    // the top of the stack is the current wto head
    std::vector<label_t> m_stack;

    void get_thresholds(const basic_block_t& bb, thresholds_t& thresholds) const;

  public:
    wto_thresholds_t(cfg_t& cfg, size_t max_size) : m_cfg(cfg), m_max_size(max_size) {}

    void operator()(const label_t& vertex);

    void operator()(std::shared_ptr<wto_cycle_t>& cycle);

    friend std::ostream& operator<<(std::ostream& o, const wto_thresholds_t& t);

}; // class wto_thresholds_t

} // end namespace iterators
} // end namespace crab
