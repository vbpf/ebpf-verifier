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

    void add(bound_t v1) {
        if (m_thresholds.size() < m_size) {
            bound_t v = (v1);
            if (std::find(m_thresholds.begin(), m_thresholds.end(), v) == m_thresholds.end()) {
                auto ub = std::upper_bound(m_thresholds.begin(), m_thresholds.end(), v);

                // don't add consecutive thresholds
                if (v > 0) {
                    auto prev = ub;
                    --prev;
                    if (prev != m_thresholds.begin()) {
                        if (*prev + 1 == v) {
                            *prev = v;
                            return;
                        }
                    }
                } else if (v < 0) {
                    if (*ub - 1 == v) {
                        *ub = v;
                        return;
                    }
                }

                m_thresholds.insert(ub, v);
            }
        }
    }

    bound_t get_next(bound_t v1) const {
        if (v1.is_plus_infinity())
            return v1;
        bound_t v = (v1);
        bound_t t = m_thresholds[m_thresholds.size() - 1];
        auto ub = std::upper_bound(m_thresholds.begin(), m_thresholds.end(), v);
        if (ub != m_thresholds.end())
            t = *ub;
        return (t);
    }

    bound_t get_prev(bound_t v1) const {
        if (v1.is_minus_infinity())
            return v1;
        bound_t v = (v1);
        auto lb = std::lower_bound(m_thresholds.begin(), m_thresholds.end(), v);
        if (lb != m_thresholds.end()) {
            --lb;
            if (lb != m_thresholds.end()) {
                return (*lb);
            }
        }
        return (m_thresholds[0]);
    }

    void write(crab_os &o) const {
        o << "{";
        for (typename std::vector<bound_t>::const_iterator it = m_thresholds.begin(), et = m_thresholds.end();
             it != et;) {
            bound_t b(*it);
            b.write(o);
            ++it;
            if (it != m_thresholds.end())
                o << ",";
        }
        o << "}";
    }
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
    using thresholds_map_t = boost::unordered_map<basic_block_label_t, thresholds_t>;

  private:
    // the cfg
    cfg_ref_t m_cfg;
    // maximum number of thresholds
    size_t m_max_size;
    // keep a set of thresholds per wto head
    thresholds_map_t m_head_to_thresholds;
    // the top of the stack is the current wto head
    std::vector<basic_block_label_t> m_stack;

    using basic_block_t = typename cfg_ref_t::basic_block_t;

    // using select_t = crab::select_stmt<number_t,varname_t>;

    void extract_bounds(const linear_expression_t &e, bool is_strict, std::vector<number_t> &lb_bounds,
                        std::vector<number_t> &ub_bounds) const {
        if (e.size() == 1) {
            auto const &kv = *(e.begin());
            number_t coeff = kv.first;
            variable_t var = kv.second;
            number_t k = -e.constant();
            if (coeff > 0) {
                // e is c*var <= k and c > 0  <---> var <= k/coeff
                ub_bounds.push_back(!is_strict ? k / coeff : (k / coeff) - 1);
                return;
            } else if (coeff < 0) {
                // e is c*var <= k  and c < 0 <---> var >= k/coeff
                lb_bounds.push_back(!is_strict ? k / coeff : (k / coeff) + 1);
                return;
            }
        }
    }

    void get_thresholds(const basic_block_t &bb, thresholds_t &thresholds) const {

        std::vector<number_t> lb_bounds, ub_bounds;
        for (auto const &i : boost::make_iterator_range(bb.begin(), bb.end())) {
            if (i.is_assume()) {
                auto a = static_cast<const assume_t *>(&i);
                linear_constraint_t cst = a->constraint();
                if (cst.is_inequality() || cst.is_strict_inequality()) {
                    extract_bounds(cst.expression(), cst.is_strict_inequality(), lb_bounds, ub_bounds);
                }
            }
            // else if (i.is_select()) {
            //   auto s = static_cast<const select_t*>(&i);
            //   linear_constraint_t cst = s->cond();
            //   if (cst.is_inequality() || cst.is_strict_inequality()) {
            //     extract_bounds(cst.expression(), cst.is_strict_inequality(),
            // 		      lb_bounds, ub_bounds);
            //   }
            // }
        }

        // Assuming that the variable is incremented/decremented by
        // some constant k, then we want to adjust the threshold to
        // +/- k so that we have more chance to stabilize in one
        // iteration after widening has been applied.
        int k = 1;
        for (auto n : lb_bounds) {
            thresholds.add(bound_t(n - k));
        }

        for (auto n : ub_bounds) {
            thresholds.add(bound_t(n + k));
        }
    }

  public:
    wto_thresholds_t(cfg_ref_t cfg, size_t max_size) : m_cfg(cfg), m_max_size(max_size) {}

    void visit(wto_vertex_t &vertex) {
        if (m_stack.empty())
            return;

        basic_block_label_t head = m_stack.back();
        auto it = m_head_to_thresholds.find(head);
        if (it != m_head_to_thresholds.end()) {
            thresholds_t &thresholds = it->second;
            typename cfg_ref_t::basic_block_t &bb = m_cfg.get_node(vertex.node());
            get_thresholds(bb, thresholds);
        } else {
            CRAB_ERROR("No head found while gathering thresholds");
        }
    }

    void visit(wto_cycle_t &cycle) {
        thresholds_t thresholds(m_max_size);
        typename cfg_ref_t::basic_block_t &bb = m_cfg.get_node(cycle.head());
        get_thresholds(bb, thresholds);

#if 1
        // XXX: if we want to consider constants from loop
        // initializations
        for (auto pre : boost::make_iterator_range(bb.prev_blocks())) {
            if (pre != cycle.head()) {
                typename cfg_ref_t::basic_block_t &pred_bb = m_cfg.get_node(pre);
                get_thresholds(pred_bb, thresholds);
            }
        }
#endif

        m_head_to_thresholds.insert(std::make_pair(cycle.head(), thresholds));
        m_stack.push_back(cycle.head());
        for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
            it->accept(this);
        }
        m_stack.pop_back();
    }

    const thresholds_map_t &get_thresholds_map() const { return m_head_to_thresholds; }

    void write(crab::crab_os &o) const {
        for (auto &kv : m_head_to_thresholds) {
            o << crab::get_label_str(kv.first) << "=" << kv.second << "\n";
        }
    }

}; // class wto_thresholds_t

inline crab::crab_os &operator<<(crab::crab_os &o, const wto_thresholds_t &t) {
    t.write(o);
    return o;
}

} // end namespace iterators
} // end namespace crab
