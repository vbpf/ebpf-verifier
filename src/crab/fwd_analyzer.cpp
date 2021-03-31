// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <utility>
#include <variant>

#include "crab/cfg.hpp"
#include "crab/wto.hpp"

#include "crab_verifier_job.hpp"

namespace crab {

using domains::ebpf_domain_t;

// Simple visitor to check if node is a member of the wto component.
class member_component_visitor final {
    label_t _node;
    bool _found;

  public:
    explicit member_component_visitor(label_t node) : _node(node), _found(false) {}

    void operator()(const label_t& vertex) {
        if (!_found) {
            _found = (vertex == _node);
        }
    }

    void operator()(const std::shared_ptr<wto_cycle_t>& c) {
        if (!_found) {
            _found = (c->head() == _node);
            if (!_found) {
                for (const auto& component : *c) {
                    if (_found)
                        break;
                    std::visit(*this, *component);
                }
            }
        }
    }

    [[nodiscard]] bool is_member() const { return _found; }
};

std::pair<invariant_table_t, invariant_table_t> interleaved_fwd_fixpoint_iterator_t::analyze()
{
    for (auto& c : _wto) {
        std::visit(*this, *c);
    }
    return std::make_pair(_pre, _post);
}

void interleaved_fwd_fixpoint_iterator_t::operator()(const label_t& node) {
    /** decide whether skip vertex or not **/
    if (_skip && (node == _cfg.entry_label())) {
        _skip = false;
    }
    if (_skip) {
        return;
    }

    ebpf_domain_t pre = node == _cfg.entry_label() ? get_pre(node) : join_all_prevs(node);

    set_pre(node, pre);
    transform_to_post(node, pre);
}

void interleaved_fwd_fixpoint_iterator_t::operator()(const std::shared_ptr<wto_cycle_t>& cycle) {
    label_t head = cycle->head();

    /** decide whether to skip cycle or not **/
    bool entry_in_this_cycle = false;
    if (_skip) {
        // We only skip the analysis of cycle if _entry is not a
        // component of it, included nested components.
        member_component_visitor vis(_cfg.entry_label());
        vis(cycle);
        entry_in_this_cycle = vis.is_member();
        _skip = !entry_in_this_cycle;
        if (_skip) {
            return;
        }
    }

    ebpf_domain_t pre = ebpf_domain_t::bottom();
    if (entry_in_this_cycle) {
        pre = get_pre(_cfg.entry_label());
    } else {
        wto_nesting_t cycle_nesting = _wto.nesting(head);
        for (const label_t& prev : _cfg.prev_nodes(head)) {
            if (!(_wto.nesting(prev) > cycle_nesting)) {
                pre |= get_post(prev);
            }
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Increasing iteration sequence with widening
        set_pre(head, pre);
        transform_to_post(head, pre);
        for (auto& component : *cycle) {
            std::visit(*this, *component);
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (new_pre <= pre) {
            // Post-fixpoint reached
            set_pre(head, new_pre);
            pre = std::move(new_pre);
            break;
        } else {
            pre = extrapolate(head, iteration, pre, new_pre);
        }
    }

    if (this->_descending_iterations == 0) {
        // no narrowing
        return;
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Decreasing iteration sequence with narrowing
        transform_to_post(head, pre);

        for (auto& component : *cycle) {
            std::visit(*this, *component);
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (pre <= new_pre) {
            // No more refinement possible(pre == new_pre)
            break;
        } else {
            if (iteration > _descending_iterations)
                break;
            pre = refine(head, iteration, pre, new_pre);
            set_pre(head, pre);
        }
    }
}

} // namespace crab
