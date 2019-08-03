#pragma once

#include <unordered_map>

#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"
#include "crab/wto.hpp"

namespace crab {

using domains::ebpf_domain_t;

class wto_iterator_t;

class wto_processor_t;

class interleaved_fwd_fixpoint_iterator_t final {
    friend class wto_iterator_t;

  public:
    using assumption_map_t = std::unordered_map<label_t, ebpf_domain_t>;
    using invariant_table_t = std::unordered_map<label_t, ebpf_domain_t>;

  private:
    using thresholds_t = iterators::thresholds_t;
    using wto_thresholds_t = iterators::wto_thresholds_t;

  private:
    using iterator = typename invariant_table_t::iterator;
    using const_iterator = typename invariant_table_t::const_iterator;

    cfg_t& _cfg;
    wto_t _wto;
    invariant_table_t _pre, _post;
    // number of iterations until triggering widening
    const unsigned int _widening_delay;

  private:
    void set(invariant_table_t& table, label_t node, const ebpf_domain_t& v) {
        std::pair<iterator, bool> res = table.emplace(std::make_pair(node, v));
        if (!res.second) {
            res.first->second = std::move(v);
        }
    }

    inline void set_pre(label_t node, const ebpf_domain_t& v) { this->set(this->_pre, node, v); }

    inline void set_post(label_t node, const ebpf_domain_t& v) { this->set(this->_post, node, v); }

    ebpf_domain_t get(invariant_table_t& table, label_t n) {
        typename invariant_table_t::iterator it = table.find(n);
        if (it != table.end()) {
            return it->second;
        } else {
            return ebpf_domain_t::bottom();
        }
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

  public:
    interleaved_fwd_fixpoint_iterator_t(cfg_t& cfg) : _cfg(cfg), _wto(cfg), _widening_delay(1) {}

    ebpf_domain_t get_pre(label_t node) { return this->get(this->_pre, node); }

    ebpf_domain_t get_post(label_t node) { return this->get(this->_post, node); }

    void run(ebpf_domain_t init);
}; // class interleaved_fwd_fixpoint_iterator_t

class wto_iterator_t final : public wto_component_visitor_t {
  public:
    using assumption_map_t = typename interleaved_fwd_fixpoint_iterator_t::assumption_map_t;

  private:
    interleaved_fwd_fixpoint_iterator_t* _iterator;
    // Initial entry point of the analysis
    label_t _entry;
    const assumption_map_t* _assumptions;
    // Used to skip the analysis until _entry is found
    bool _skip;

    inline ebpf_domain_t strengthen(label_t n, ebpf_domain_t inv) {
        CrabStats::count("Fixpo.strengthen");
        ScopedCrabStats __st__("Fixpo.strengthen");

        if (_assumptions) {
            auto it = _assumptions->find(n);
            if (it != _assumptions->end()) {
                inv = inv & it->second;
            }
        }
        return inv;
    }

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
                    for (typename wto_cycle_t::iterator it = c.begin(), et = c.end(); it != et; ++it) {
                        if (_found)
                            break;
                        it->accept(this);
                    }
                }
            }
        }

        bool is_member() const { return _found; }
    };

  public:
    wto_iterator_t(interleaved_fwd_fixpoint_iterator_t* iterator, label_t entry)
        : _iterator(iterator), _entry(entry), _assumptions(nullptr), _skip(true) {}

    wto_iterator_t(interleaved_fwd_fixpoint_iterator_t* iterator, label_t entry, const assumption_map_t* assumptions)
        : _iterator(iterator), _entry(entry), _assumptions(assumptions), _skip(true) {}

    void visit(wto_vertex_t& vertex) {
        label_t node = vertex.node();

        /** decide whether skip vertex or not **/
        if (_skip && (node == _entry)) {
            _skip = false;
        }
        if (_skip) {
            CRAB_VERBOSE_IF(2, std::cout << "** Skipped analysis of  " << node << "\n");
            return;
        }

        ebpf_domain_t pre;
        if (node == _entry) {
            pre = this->_iterator->get_pre(node);
            if (_assumptions) { // no necessary but it might avoid copies
                pre = strengthen(node, pre);
                this->_iterator->set_pre(node, pre);
            }
        } else {
            auto prev_nodes = this->_iterator->_cfg.prev_nodes(node);
            CrabStats::resume("Fixpo.join_predecessors");
            pre = ebpf_domain_t::bottom();
            for (label_t prev : prev_nodes) {
                pre |= this->_iterator->get_post(prev);
            }
            CrabStats::stop("Fixpo.join_predecessors");
            if (_assumptions) { // no necessary but it might avoid copies
                pre = strengthen(node, pre);
            }
            this->_iterator->set_pre(node, pre);
        }

        CRAB_VERBOSE_IF(4, std::cout << "PRE Invariants:\n" << pre << "\n");
        CrabStats::resume("Fixpo.analyze_block");
        ebpf_domain_t post = pre.transform(this->_iterator->_cfg.get_node(node));
        CrabStats::stop("Fixpo.analyze_block");
        CRAB_VERBOSE_IF(3, std::cout << "POST Invariants:\n" << post << "\n");
        this->_iterator->set_post(node, post);
    }

    void visit(wto_cycle_t& cycle) {
        label_t head = cycle.head();

        /** decide whether skip cycle or not **/
        bool entry_in_this_cycle = false;
        if (_skip) {
            // We only skip the analysis of cycle is _entry is not a
            // component of it, included nested components.
            member_component_visitor vis(_entry);
            cycle.accept(&vis);
            entry_in_this_cycle = vis.is_member();
            _skip = !entry_in_this_cycle;
            if (_skip) {
                CRAB_VERBOSE_IF(2, std::cout << "** Skipped analysis of WTO cycle rooted at  " << head << "\n");
                return;
            }
        }

        auto prev_nodes = this->_iterator->_cfg.prev_nodes(head);
        ebpf_domain_t pre = ebpf_domain_t::bottom();
        wto_nesting_t cycle_nesting = this->_iterator->_wto.nesting(head);

        if (entry_in_this_cycle) {
            CRAB_VERBOSE_IF(2, std::cout << "Skipped predecessors of " << head << "\n");
            pre = _iterator->get_pre(_entry);
        } else {
            CrabStats::count("Fixpo.join_predecessors");
            ScopedCrabStats __st__("Fixpo.join_predecessors");
            for (label_t prev : prev_nodes) {
                if (!(this->_iterator->_wto.nesting(prev) > cycle_nesting)) {
                    pre |= this->_iterator->get_post(prev);
                }
            }
        }
        if (_assumptions) { // no necessary but it might avoid copies
            pre = strengthen(head, pre);
        }

        for (unsigned int iteration = 1;; ++iteration) {
            // keep track of how many times the cycle is visited by the fixpoint
            cycle.increment_fixpo_visits();

            // Increasing iteration sequence with widening
            this->_iterator->set_pre(head, pre);
            CRAB_VERBOSE_IF(4, std::cout << "PRE Invariants:\n" << pre << "\n");
            CrabStats::resume("Fixpo.analyze_block");
            ebpf_domain_t post = pre.transform(this->_iterator->_cfg.get_node(head));
            CrabStats::stop("Fixpo.analyze_block");
            CRAB_VERBOSE_IF(3, std::cout << "POST Invariants:\n" << post << "\n");

            this->_iterator->set_post(head, post);
            for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
                it->accept(this);
            }
            CrabStats::resume("Fixpo.join_predecessors");
            ebpf_domain_t new_pre = ebpf_domain_t::bottom();
            for (label_t prev : prev_nodes) {
                new_pre |= this->_iterator->get_post(prev);
            }
            CrabStats::stop("Fixpo.join_predecessors");
            CrabStats::resume("Fixpo.check_fixpoint");
            bool fixpoint_reached = new_pre <= pre;
            CrabStats::stop("Fixpo.check_fixpoint");
            if (fixpoint_reached) {
                // Post-fixpoint reached
                this->_iterator->set_pre(head, new_pre);
                pre = new_pre;
                break;
            } else {
                pre = this->_iterator->extrapolate(head, iteration, pre, new_pre);
            }
        }

        for (unsigned int iteration = 1;; ++iteration) {
            // Decreasing iteration sequence with narrowing

            CRAB_VERBOSE_IF(4, std::cout << "PRE Invariants:\n" << pre << "\n");
            CrabStats::resume("Fixpo.analyze_block");
            ebpf_domain_t post = pre.transform(this->_iterator->_cfg.get_node(head));
            this->_iterator->set_post(head, post);
            CrabStats::stop("Fixpo.analyze_block");
            CRAB_VERBOSE_IF(3, std::cout << "POST Invariants:\n" << post << "\n");

            for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
                it->accept(this);
            }
            CrabStats::resume("Fixpo.join_predecessors");
            ebpf_domain_t new_pre = ebpf_domain_t::bottom();
            for (label_t prev : prev_nodes) {
                new_pre |= this->_iterator->get_post(prev);
            }
            CrabStats::stop("Fixpo.join_predecessors");
            CrabStats::resume("Fixpo.check_fixpoint");
            bool no_more_refinement = pre <= new_pre;
            CrabStats::stop("Fixpo.check_fixpoint");
            if (no_more_refinement) {
                // No more refinement possible(pre == new_pre)
                break;
            } else {
                pre = this->_iterator->refine(head, iteration, pre, new_pre);
                this->_iterator->set_pre(head, pre);
            }
        }
    }

}; // class wto_iterator_t

inline void interleaved_fwd_fixpoint_iterator_t::run(ebpf_domain_t init) {
    this->set_pre(this->_cfg.entry(), init);
    wto_iterator_t iterator(this, this->_cfg.entry());
    this->_wto.accept(&iterator);
}

} // namespace crab
