// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#include <utility>
#include <variant>

#include "crab/cfg.hpp"
#include "crab/wto.hpp"

#include "crab/ebpf_domain.hpp"
#include "crab/fwd_analyzer.hpp"

namespace crab {

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

    void operator()(std::shared_ptr<wto_cycle_t>& c) {
        if (!_found) {
            _found = (c->head() == _node);
            if (!_found) {
                for (auto& component : *c) {
                    if (_found)
                        break;
                    std::visit(*this, *component);
                }
            }
        }
    }

    [[nodiscard]] bool is_member() const { return _found; }
};

class interleaved_fwd_fixpoint_iterator_t final {
    using iterator = typename invariant_table_t::iterator;

    cfg_t& _cfg;
    wto_t _wto;
    invariant_table_t _pre, _post;

    /// number of iterations until triggering widening
    const unsigned int _widening_delay{1};

    /// number of narrowing iterations. If the narrowing operator is
    /// indeed a narrowing operator this parameter is not
    /// needed. However, there are abstract domains for which an actual
    /// narrowing operation is not available so we must enforce
    /// termination.
    const unsigned int _descending_iterations;

    /// Used to skip the analysis until _entry is found
    bool _skip{true};

    /// Whether the domain tracks instruction count; the invariants are somewhat easier to read without it
    /// Generally corresponds to the check_termination flag in ebpf_verifier_options_t
    const bool check_termination;

  private:
    inline void set_pre(const label_t& label, const ebpf_domain_t& v) { _pre[label] = v; }

    inline void transform_to_post(const label_t& label, ebpf_domain_t pre) {
        basic_block_t& bb = _cfg.get_node(label);
        pre(bb, check_termination);
        _post[label] = std::move(pre);
    }

    [[nodiscard]]
    ebpf_domain_t extrapolate(const label_t& node, unsigned int iteration, ebpf_domain_t before,
                              const ebpf_domain_t& after) const {
        if (iteration <= _widening_delay) {
            return before | after;
        } else {
            return before.widen(after);
        }
    }

    static ebpf_domain_t refine(const label_t& node, unsigned int iteration, ebpf_domain_t before,
                                const ebpf_domain_t& after) {
        if (iteration == 1) {
            return before & after;
        } else {
            return before.narrow(after);
        }
    }

    ebpf_domain_t join_all_prevs(const label_t& node) {
        ebpf_domain_t res = ebpf_domain_t::bottom();
        for (const label_t& prev : _cfg.prev_nodes(node)) {
            res |= get_post(prev);
        }
        return res;
    }

  public:
    explicit interleaved_fwd_fixpoint_iterator_t(cfg_t& cfg, unsigned int descending_iterations, bool check_termination)
        : _cfg(cfg), _wto(cfg), _descending_iterations(descending_iterations), check_termination(check_termination) {
        for (const auto& label : _cfg.labels()) {
            _pre.emplace(label, ebpf_domain_t::bottom());
            _post.emplace(label, ebpf_domain_t::bottom());
        }
    }

    ebpf_domain_t get_pre(const label_t& node) { return _pre.at(node); }

    ebpf_domain_t get_post(const label_t& node) { return _post.at(node); }

    void operator()(const label_t& vertex);

    void operator()(std::shared_ptr<wto_cycle_t>& cycle);

    friend std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(cfg_t& cfg, const ebpf_domain_t& entry_inv, bool check_termination);
};

std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(cfg_t& cfg, const ebpf_domain_t& entry_inv, bool check_termination) {
    // Go over the CFG in weak topological order (accounting for loops).
    constexpr unsigned int descending_iterations = 2000000;
    interleaved_fwd_fixpoint_iterator_t analyzer(cfg, descending_iterations, check_termination);
    analyzer.set_pre(cfg.entry_label(), entry_inv);
    for (auto& component : analyzer._wto) {
        std::visit(analyzer, *component);
    }
    return std::make_pair(analyzer._pre, analyzer._post);
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

void interleaved_fwd_fixpoint_iterator_t::operator()(std::shared_ptr<wto_cycle_t>& cycle) {
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
            wto_component_t c = *component;
            if (!std::holds_alternative<label_t>(c) || (std::get<label_t>(c) != head))
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
            wto_component_t c = *component;
            if (!std::holds_alternative<label_t>(c) || (std::get<label_t>(c) != head))
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
