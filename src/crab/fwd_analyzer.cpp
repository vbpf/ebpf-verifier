#include "crab/fwd_analyzer.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

using domains::ebpf_domain_t;

// Simple visitor to check if node is a member of the wto component.
class member_component_visitor : public wto_component_visitor_t {
    label_t _node;
    bool _found;

  public:
    member_component_visitor(label_t node) : _node(node), _found(false) {}

    void visit(wto_vertex_t& c) {
        if (!_found) {
            _found = (c.node() == _node);
        }
    }

    void visit(wto_cycle_t& c) {
        if (!_found) {
            _found = (c.head() == _node);
            if (!_found) {
                for (auto& x : c) {
                    if (_found)
                        break;
                    x.accept(this);
                }
            }
        }
    }

    bool is_member() const { return _found; }
};

void interleaved_fwd_fixpoint_iterator_t::visit(wto_vertex_t& vertex) {
    label_t node = vertex.node();

    /** decide whether skip vertex or not **/
    if (_skip && (node == _cfg.entry())) {
        _skip = false;
    }
    if (_skip) {
        return;
    }

    ebpf_domain_t pre = node == _cfg.entry() ? get_pre(node) : join_all_prevs(node);

    set_pre(node, pre);
    set_post(node, pre.transform(_cfg.get_node(node)));
}

void interleaved_fwd_fixpoint_iterator_t::visit(wto_cycle_t& cycle) {
    label_t head = cycle.head();

    /** decide whether skip cycle or not **/
    bool entry_in_this_cycle = false;
    if (_skip) {
        // We only skip the analysis of cycle is _entry is not a
        // component of it, included nested components.
        member_component_visitor vis(_cfg.entry());
        cycle.accept(&vis);
        entry_in_this_cycle = vis.is_member();
        _skip = !entry_in_this_cycle;
        if (_skip) {
            return;
        }
    }

    ebpf_domain_t pre = ebpf_domain_t::bottom();
    if (entry_in_this_cycle) {
        pre = get_pre(_cfg.entry());
    } else {
        wto_nesting_t cycle_nesting = _wto.nesting(head);
        for (label_t prev : _cfg.prev_nodes(head)) {
            if (!(_wto.nesting(prev) > cycle_nesting)) {
                pre |= get_post(prev);
            }
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // keep track of how many times the cycle is visited by the fixpoint
        cycle.increment_fixpo_visits();

        // Increasing iteration sequence with widening
        set_pre(head, pre);
        set_post(head, pre.transform(_cfg.get_node(head)));
        for (auto& x : cycle) {
            x.accept(this);
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (new_pre <= pre) {
            // Post-fixpoint reached
            set_pre(head, new_pre);
            pre = std::move(new_pre);
            break;
        } else {
            pre = extrapolate(head, iteration, pre, std::move(new_pre));
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Decreasing iteration sequence with narrowing
        set_post(head, pre.transform(_cfg.get_node(head)));

        for (auto& x : cycle) {
            x.accept(this);
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (pre <= new_pre) {
            // No more refinement possible(pre == new_pre)
            break;
        } else {
            pre = refine(head, iteration, pre, std::move(new_pre));
            set_pre(head, pre);
        }
    }
}

} // namespace crab
