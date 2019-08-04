#pragma once

#include <unordered_map>

#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"
#include "crab/wto.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

using domains::ebpf_domain_t;

class interleaved_fwd_fixpoint_iterator_t final : public wto_component_visitor_t{
  public:
    using invariant_table_t = std::unordered_map<label_t, ebpf_domain_t>;

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

    inline void set_pre(label_t label, const ebpf_domain_t& v) { _pre[label] = v; }

    inline void transform_to_post(label_t label, ebpf_domain_t pre) {
        for (const Instruction& statement : _cfg.get_node(label)) {
            std::visit(pre, statement);
        }
        _post[label] = std::move(pre);
    }

    ebpf_domain_t extrapolate(label_t node, unsigned int iteration, ebpf_domain_t before, ebpf_domain_t after) {
        if (iteration <= _widening_delay) {
            return before | after;
        } else {
            return before.widen(after);
        }
    }

    ebpf_domain_t refine(label_t node, unsigned int iteration, ebpf_domain_t before, ebpf_domain_t after) {
        if (iteration == 1) {
            return before & after;
        } else {
            return before.narrow(after);
        }
    }

    ebpf_domain_t join_all_prevs(label_t node) {
        ebpf_domain_t res = ebpf_domain_t::bottom();
        for (label_t prev : _cfg.prev_nodes(node)) {
            res |= get_post(prev);
        }
        return res;
    }
  public:
    interleaved_fwd_fixpoint_iterator_t(cfg_t& cfg) : _cfg(cfg), _wto(cfg) {
        for (auto& [label, _] : _cfg) {
            _pre.emplace(label, ebpf_domain_t::bottom());
            _post.emplace(label, ebpf_domain_t::bottom());
        }
        _pre[this->_cfg.entry()] = ebpf_domain_t::setup_entry();
    }

    ebpf_domain_t get_pre(label_t node) { return _pre.at(node); }

    ebpf_domain_t get_post(label_t node) { return _post.at(node); }

    void visit(wto_vertex_t& vertex);

    void visit(wto_cycle_t& cycle);

    void run() {
        this->_wto.accept(this);
    }
};

} // namespace crab
