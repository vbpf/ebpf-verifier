#include "crab/fwd_analyzer.hpp"

#include <utility>

#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/wto.hpp"

#include "crab/ebpf_domain.hpp"

namespace crab {

using domains::ebpf_domain_t;

// Simple visitor to check if node is a member of the wto component.
class member_component_visitor final : public wto_component_visitor_t {
    label_t _node;
    bool _found;

  public:
    explicit member_component_visitor(label_t node) : _node(std::move(node)), _found(false) {}

    void visit(wto_vertex_t& c) override {
        if (!_found) {
            _found = (c.node() == _node);
        }
    }

    void visit(wto_cycle_t& c) override {
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

class interleaved_fwd_fixpoint_iterator_t final : public wto_component_visitor_t{
  public:

  private:
    using thresholds_t = iterators::thresholds_t;
    using wto_thresholds_t = iterators::wto_thresholds_t;
    using iterator = typename invariant_table_t::iterator;
    using const_iterator = typename invariant_table_t::const_iterator;

    cfg_t& _cfg;
    wto_t _wto;
    invariant_table_t _pre, _post;
    // number of iterations until triggering widening
    const unsigned int _widening_delay{1};
    // Used to skip the analysis until _entry is found
    bool _skip{true};

  private:

    inline void set_pre(const label_t& label, const ebpf_domain_t& v) { _pre[label] = v; }

    inline void transform_to_post(const label_t& label, ebpf_domain_t pre) {
        for (const Instruction& statement : _cfg.get_node(label)) {
            std::visit(pre, statement);
        }
        _post[label] = std::move(pre);
    }

    ebpf_domain_t extrapolate(const label_t& node, unsigned int iteration, ebpf_domain_t before, const ebpf_domain_t& after) {
        if (iteration <= _widening_delay) {
            return before | after;
        } else {
            return before.widen(after);
        }
    }

    static ebpf_domain_t refine(const label_t& node, unsigned int iteration, ebpf_domain_t before, const ebpf_domain_t& after) {
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
    explicit interleaved_fwd_fixpoint_iterator_t(cfg_t& cfg) : _cfg(cfg), _wto(cfg) {
        for (auto& [label, _] : _cfg) {
            _pre.emplace(label, ebpf_domain_t::bottom());
            _post.emplace(label, ebpf_domain_t::bottom());
        }
        _pre[this->_cfg.entry()] = ebpf_domain_t::setup_entry();
    }

    ebpf_domain_t get_pre(const label_t& node) { return _pre.at(node); }

    ebpf_domain_t get_post(const label_t& node) { return _post.at(node); }

    void visit(wto_vertex_t& vertex) override;

    void visit(wto_cycle_t& cycle) override;

    friend std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(cfg_t& cfg);
};

std::pair<invariant_table_t, invariant_table_t> run_forward_analyzer(cfg_t& cfg) {
    interleaved_fwd_fixpoint_iterator_t analyzer(cfg);
    analyzer._wto.accept(&analyzer);
    return std::make_pair(analyzer._pre, analyzer._post);
}

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
    transform_to_post(node, pre);
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
        for (const label_t& prev : _cfg.prev_nodes(head)) {
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
        transform_to_post(head, pre);
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
            pre = extrapolate(head, iteration, pre, new_pre);
        }
    }

    for (unsigned int iteration = 1;; ++iteration) {
        // Decreasing iteration sequence with narrowing
        transform_to_post(head, pre);

        for (auto& x : cycle) {
            x.accept(this);
        }
        ebpf_domain_t new_pre = join_all_prevs(head);
        if (pre <= new_pre) {
            // No more refinement possible(pre == new_pre)
            break;
        } else {
            pre = refine(head, iteration, pre, new_pre);
            set_pre(head, pre);
        }
    }
}

} // namespace crab
