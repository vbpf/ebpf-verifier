// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
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
            if (v > number_t{0}) {
                auto prev = ub;
                --prev;
                if (prev != m_thresholds.begin()) {
                    if (*prev + number_t{1} == v) {
                        *prev = v;
                        return;
                    }
                }
            } else if (v < number_t{0}) {
                if (*ub - number_t{1} == v) {
                    *ub = v;
                    return;
                }
            }

            m_thresholds.insert(ub, v);
        }
    }
}

std::ostream& operator<<(std::ostream& o, const thresholds_t& t) {
    o << "{";
    for (typename std::vector<bound_t>::const_iterator it = t.m_thresholds.begin(), et = t.m_thresholds.end(); it != et;) {
        bound_t b(*it);
        o << b;
        ++it;
        if (it != t.m_thresholds.end())
            o << ",";
    }
    o << "}";
    return o;
}

void wto_thresholds_t::get_thresholds(const basic_block_t& bb, thresholds_t& thresholds) const {

}

void wto_thresholds_t::operator()(const label_t& vertex) {
    if (m_stack.empty())
        return;

    label_t head = m_stack.back();
    auto it = m_head_to_thresholds.find(head);
    if (it != m_head_to_thresholds.end()) {
        thresholds_t& thresholds = it->second;
        basic_block_t& bb = m_cfg.get_node(vertex);
        get_thresholds(bb, thresholds);
    } else {
        CRAB_ERROR("No head found while gathering thresholds");
    }
}

void wto_thresholds_t::operator()(std::shared_ptr<wto_cycle_t>& cycle) {
    thresholds_t thresholds(m_max_size);
    auto& bb = m_cfg.get_node(cycle->head());
    get_thresholds(bb, thresholds);

    // XXX: if we want to consider constants from loop
    // initializations
    for (auto pre : boost::make_iterator_range(bb.prev_blocks())) {
        if (pre != cycle->head()) {
            auto& pred_bb = m_cfg.get_node(pre);
            get_thresholds(pred_bb, thresholds);
        }
    }

    m_head_to_thresholds.insert(std::make_pair(cycle->head(), thresholds));
    m_stack.push_back(cycle->head());
    for (auto& component : *cycle) {
        std::visit(*this, *component);
    }
    m_stack.pop_back();
}

std::ostream& operator<<(std::ostream& o, const wto_thresholds_t& t) {
    for (auto& [label, th] : t.m_head_to_thresholds) {
        o << label << "=" << th << "\n";
    }
    return o;
}
} // namespace iterators

} // namespace crab
