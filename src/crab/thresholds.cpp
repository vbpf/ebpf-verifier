// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include "crab/thresholds.hpp"
#include "crab/cfg.hpp"

namespace crab::inline iterators {

void thresholds_t::add(bound_t v1) {
    if (m_thresholds.size() < m_capacity) {
        const bound_t v = (v1);
        if (std::ranges::find(m_thresholds, v) == m_thresholds.end()) {
            const auto ub = std::ranges::upper_bound(m_thresholds, v);

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
    for (auto it = t.m_thresholds.begin(), et = t.m_thresholds.end(); it != et;) {
        bound_t b(*it);
        o << b;
        ++it;
        if (it != t.m_thresholds.end()) {
            o << ",";
        }
    }
    o << "}";
    return o;
}

void wto_thresholds_t::get_thresholds(const basic_block_t& bb, thresholds_t& thresholds) const {}

void wto_thresholds_t::operator()(const label_t& vertex) {
    if (m_stack.empty()) {
        return;
    }

    const label_t head = m_stack.back();
    const auto it = m_head_to_thresholds.find(head);
    if (it != m_head_to_thresholds.end()) {
        thresholds_t& thresholds = it->second;
        const basic_block_t& bb = m_cfg.get_node(vertex);
        get_thresholds(bb, thresholds);
    } else {
        CRAB_ERROR("No head found while gathering thresholds");
    }
}

void wto_thresholds_t::operator()(const std::shared_ptr<wto_cycle_t>& cycle) {
    thresholds_t thresholds(m_max_size);
    const auto& bb = m_cfg.get_node(cycle->head());
    get_thresholds(bb, thresholds);

    // XXX: if we want to consider constants from loop
    // initializations
    for (const auto& pre : boost::make_iterator_range(bb.prev_blocks())) {
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
} // namespace crab::inline iterators
