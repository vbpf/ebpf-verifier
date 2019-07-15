#pragma once

#include "crab/cfg.hpp"
#include "crab/cfg_bgl.hpp" // needed by wto.hpp
#include "crab/debug.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/wto.hpp"

#include <boost/range/iterator_range.hpp>
#include <boost/unordered_map.hpp>

#include <algorithm>
#include <climits>

namespace crab {

namespace iterators {

/**
    Class that represents a set of thresholds used by the widening operator
**/

class thresholds_t {

  private:
    std::vector<bound_t> m_thresholds;
    unsigned int m_size;

  public:
    thresholds_t(int size = UINT_MAX) : m_size(size) {
        m_thresholds.push_back(bound_t::minus_infinity());
        m_thresholds.push_back(0);
        m_thresholds.push_back(bound_t::plus_infinity());
    }

    unsigned size() const { return m_thresholds.size(); }

    void add(bound_t v1);

    bound_t get_next(bound_t v1) const;

    bound_t get_prev(bound_t v1) const;

    void write(crab_os &o) const;
};

inline crab_os &operator<<(crab_os &o, const thresholds_t &t) {
    t.write(o);
    return o;
}

/**
   Collect thresholds per wto cycle (i.e. loop)
**/
class wto_thresholds_t : public ikos::wto_component_visitor<cfg_ref_t> {

  public:
    using wto_vertex_t = ikos::wto_vertex<cfg_ref_t>;
    using wto_cycle_t = ikos::wto_cycle<cfg_ref_t>;

  private:
    // the cfg
    cfg_ref_t m_cfg;
    // maximum number of thresholds
    size_t m_max_size;
    // keep a set of thresholds per wto head
    boost::unordered_map<basic_block_label_t, thresholds_t> m_head_to_thresholds;
    // the top of the stack is the current wto head
    std::vector<basic_block_label_t> m_stack;

    using basic_block_t = typename cfg_ref_t::basic_block_t;

    // using select_t = crab::select_stmt<number_t,varname_t>;

    void extract_bounds(const linear_expression_t &e, bool is_strict, std::vector<number_t> &lb_bounds,
                        std::vector<number_t> &ub_bounds) const;

    void get_thresholds(const basic_block_t &bb, thresholds_t &thresholds) const;

  public:
    wto_thresholds_t(cfg_ref_t cfg, size_t max_size) : m_cfg(cfg), m_max_size(max_size) {}

    void visit(wto_vertex_t &vertex);

    void visit(wto_cycle_t &cycle);

    void write(crab::crab_os &o) const;

}; // class wto_thresholds_t

inline crab::crab_os &operator<<(crab::crab_os &o, const wto_thresholds_t &t) {
    t.write(o);
    return o;
}

} // end namespace iterators
} // end namespace crab
