// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>
#include <tuple>

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

using domains::ebpf_domain_t;
using invariant_table_t = std::map<label_t, ebpf_domain_t>;

class interleaved_fwd_fixpoint_iterator_t final {
    using iterator = typename invariant_table_t::iterator;
    friend crab_verifier_job_t;

    crab_verifier_job_t* _job;
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

    [[nodiscard]] ebpf_domain_t extrapolate(const label_t& node, unsigned int iteration, ebpf_domain_t before,
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
    explicit interleaved_fwd_fixpoint_iterator_t(cfg_t& cfg, crab_verifier_job_t* job, unsigned int descending_iterations,
                                                 bool check_termination)
        : _cfg(cfg), _wto(cfg), _job(job), _descending_iterations(descending_iterations),
          check_termination(check_termination) {
        for (const auto& label : _cfg.labels()) {
            _pre.emplace(label, ebpf_domain_t::bottom());
            _post.emplace(label, ebpf_domain_t::bottom());
        }
        _pre[this->_cfg.entry_label()] = ebpf_domain_t::setup_entry(check_termination, job);
    }

    ebpf_domain_t get_pre(const label_t& node) { return _pre.at(node); }

    ebpf_domain_t get_post(const label_t& node) { return _post.at(node); }

    void operator()(const label_t& vertex);

    void operator()(const std::shared_ptr<wto_cycle_t>& cycle);

    std::pair<invariant_table_t, invariant_table_t> analyze();
};

} // namespace crab
