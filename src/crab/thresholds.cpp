#include "crab/thresholds.hpp"
#include "crab/cfg.hpp"

namespace crab {

inline namespace iterators {

void thresholds_t::add(bound_t v1) {
    if (m_thresholds.size() < m_size) {
        bound_t v = (v1);
        if (std::find(m_thresholds.begin(), m_thresholds.end(), v) == m_thresholds.end()) {
            auto ub = std::upper_bound(m_thresholds.begin(), m_thresholds.end(), v);

            // don't add consecutive thresholds
            if (v > 0) {
                auto prev = ub;
                --prev;
                if (prev != m_thresholds.begin()) {
                    if (*prev + (bound_t)1 == v) {
                        *prev = v;
                        return;
                    }
                }
            } else if (v < 0) {
                if (*ub - (bound_t)1 == v) {
                    *ub = v;
                    return;
                }
            }

            m_thresholds.insert(ub, v);
        }
    }
}

bound_t thresholds_t::get_next(bound_t v1) const {
    if (v1.is_plus_infinity())
        return v1;
    bound_t v = (v1);
    bound_t t = m_thresholds[m_thresholds.size() - 1];
    auto ub = std::upper_bound(m_thresholds.begin(), m_thresholds.end(), v);
    if (ub != m_thresholds.end())
        t = *ub;
    return (t);
}

bound_t thresholds_t::get_prev(bound_t v1) const {
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

void thresholds_t::write(std::ostream& o) const {
    o << "{";
    for (typename std::vector<bound_t>::const_iterator it = m_thresholds.begin(), et = m_thresholds.end(); it != et;) {
        bound_t b(*it);
        b.write(o);
        ++it;
        if (it != m_thresholds.end())
            o << ",";
    }
    o << "}";
}

void wto_thresholds_t::extract_bounds(const linear_expression_t& e, bool is_strict, std::vector<number_t>& lb_bounds,
                                      std::vector<number_t>& ub_bounds) const {
    if (e.size() == 1) {
        auto [var, coeff] = *e.begin();
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

void wto_thresholds_t::get_thresholds(const basic_block_t& bb, thresholds_t& thresholds) const {

    // std::vector<number_t> lb_bounds, ub_bounds;
    // for (auto const& i : boost::make_iterator_range(bb.begin(), bb.end())) {
    //     if (std::holds_alternative<Assume>(i)) {
    //         auto cst = std::get<Assume>(i).cond;
    //         if (is_inequality(cst.op) || is_inequality(cst.op)) {
    //             extract_bounds(cst.expression(), is_inequality(cst.op), lb_bounds, ub_bounds);
    //         }
    //     }
    // }

    // // Assuming that the variable is incremented/decremented by
    // // some constant k, then we want to adjust the threshold to
    // // +/- k so that we have more chance to stabilize in one
    // // iteration after widening has been applied.
    // int k = 1;
    // for (auto n : lb_bounds) {
    //     thresholds.add(bound_t(n - k));
    // }

    // for (auto n : ub_bounds) {
    //     thresholds.add(bound_t(n + k));
    // }
}

void wto_thresholds_t::visit(wto_vertex_t& vertex) {
    if (m_stack.empty())
        return;

    label_t head = m_stack.back();
    auto it = m_head_to_thresholds.find(head);
    if (it != m_head_to_thresholds.end()) {
        thresholds_t& thresholds = it->second;
        auto& bb = m_cfg.get_node(vertex.node());
        get_thresholds(bb, thresholds);
    } else {
        CRAB_ERROR("No head found while gathering thresholds");
    }
}

void wto_thresholds_t::visit(wto_cycle_t& cycle) {
    thresholds_t thresholds(m_max_size);
    auto& bb = m_cfg.get_node(cycle.head());
    get_thresholds(bb, thresholds);

    // XXX: if we want to consider constants from loop
    // initializations
    for (auto pre : boost::make_iterator_range(bb.prev_blocks())) {
        if (pre != cycle.head()) {
            auto& pred_bb = m_cfg.get_node(pre);
            get_thresholds(pred_bb, thresholds);
        }
    }

    m_head_to_thresholds.insert(std::make_pair(cycle.head(), thresholds));
    m_stack.push_back(cycle.head());
    for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
        it->accept(this);
    }
    m_stack.pop_back();
}

void wto_thresholds_t::write(std::ostream& o) const {
    for (auto& [label, th] : m_head_to_thresholds) {
        o << label << "=" << th << "\n";
    }
}
} // namespace iterators

} // namespace crab
