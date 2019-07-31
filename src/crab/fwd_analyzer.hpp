#pragma once

#include <memory>

#include <unordered_map>

#include "crab/abs_transformer.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"
#include "crab/wto.hpp"

namespace crab {

template <typename AbsDomain>
class wto_iterator;

template <typename AbsDomain>
class wto_processor;

template <typename AbsDomain>
class interleaved_fwd_fixpoint_iterator final {
    template <typename AbsDom>
    friend class wto_iterator;

  public:
    using wto_t = wto<cfg_t>;
    using assumption_map_t = std::unordered_map<label_t, AbsDomain>;
    using invariant_table_t = std::unordered_map<label_t, AbsDomain>;

  private:
    using wto_iterator_t = wto_iterator<AbsDomain>;
    using wto_processor_t = wto_processor<AbsDomain>;
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
    void set(invariant_table_t& table, label_t node, const AbsDomain& v) {
        std::pair<iterator, bool> res = table.emplace(std::make_pair(node, v));
        if (!res.second) {
            res.first->second = std::move(v);
        }

    }

    inline void set_pre(label_t node, const AbsDomain& v) { this->set(this->_pre, node, v); }

    inline void set_post(label_t node, const AbsDomain& v) { this->set(this->_post, node, v); }

    AbsDomain get(invariant_table_t& table, label_t n) {
        typename invariant_table_t::iterator it = table.find(n);
        if (it != table.end()) {
            return it->second;
        } else {
            return AbsDomain::bottom();
        }
    }

    AbsDomain extrapolate(label_t node, unsigned int iteration, AbsDomain before, AbsDomain after) {
        if (iteration <= _widening_delay) {
            return before | after;
        } else {
            return before.widen(after);
        }
    }

    AbsDomain refine(label_t node, unsigned int iteration, AbsDomain before, AbsDomain after) {
        if (iteration == 1) {
            return before & after;
        } else {
            return before.narrow(after);
        }
    }

  public:
    interleaved_fwd_fixpoint_iterator(cfg_t& cfg)
        : _cfg(cfg), _wto(cfg), _widening_delay(1) {
    }

    AbsDomain get_pre(label_t node) { return this->get(this->_pre, node); }

    AbsDomain get_post(label_t node) { return this->get(this->_post, node); }

    void run(AbsDomain init) {
        this->set_pre(this->_cfg.entry(), init);
        wto_iterator_t iterator(this, this->_cfg.entry());
        this->_wto.accept(&iterator);
    }
}; // class interleaved_fwd_fixpoint_iterator

template <typename AbsDomain>
class wto_iterator final : public wto_component_visitor<cfg_t> {
  public:
    using interleaved_iterator_t = interleaved_fwd_fixpoint_iterator<AbsDomain>;
    using wto_vertex_t = wto_vertex<cfg_t>;
    using wto_cycle_t = wto_cycle<cfg_t>;
    using wto_t = wto<cfg_t>;
    using wto_nesting_t = typename wto_t::wto_nesting_t;
    using assumption_map_t = typename interleaved_iterator_t::assumption_map_t;

  private:
    interleaved_iterator_t* _iterator;
    // Initial entry point of the analysis
    label_t _entry;
    const assumption_map_t* _assumptions;
    // Used to skip the analysis until _entry is found
    bool _skip;

    inline AbsDomain strengthen(label_t n, AbsDomain inv) {
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
    class member_component_visitor : public wto_component_visitor<cfg_t> {
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
    wto_iterator(interleaved_iterator_t* iterator, label_t entry)
        : _iterator(iterator), _entry(entry), _assumptions(nullptr), _skip(true) {}

    wto_iterator(interleaved_iterator_t* iterator, label_t entry, const assumption_map_t* assumptions)
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

        AbsDomain pre;
        if (node == _entry) {
            pre = this->_iterator->get_pre(node);
            if (_assumptions) { // no necessary but it might avoid copies
                pre = strengthen(node, pre);
                this->_iterator->set_pre(node, pre);
            }
        } else {
            auto prev_nodes = this->_iterator->_cfg.prev_nodes(node);
            CrabStats::resume("Fixpo.join_predecessors");
            pre = AbsDomain::bottom();
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
        AbsDomain post = transform(this->_iterator->_cfg.get_node(node), pre);
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
                CRAB_VERBOSE_IF(2, std::cout << "** Skipped analysis of WTO cycle rooted at  " << head
                                          << "\n");
                return;
            }
        }

        auto prev_nodes = this->_iterator->_cfg.prev_nodes(head);
        AbsDomain pre = AbsDomain::bottom();
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
            AbsDomain post = transform(this->_iterator->_cfg.get_node(head), pre);
            CrabStats::stop("Fixpo.analyze_block");
            CRAB_VERBOSE_IF(3, std::cout << "POST Invariants:\n" << post << "\n");

            this->_iterator->set_post(head, post);
            for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
                it->accept(this);
            }
            CrabStats::resume("Fixpo.join_predecessors");
            AbsDomain new_pre = AbsDomain::bottom();
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
            AbsDomain post = transform(this->_iterator->_cfg.get_node(head), pre);
            this->_iterator->set_post(head, post);
            CrabStats::stop("Fixpo.analyze_block");
            CRAB_VERBOSE_IF(3, std::cout << "POST Invariants:\n" << post << "\n");

            for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
                it->accept(this);
            }
            CrabStats::resume("Fixpo.join_predecessors");
            AbsDomain new_pre = AbsDomain::bottom();
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

}; // class wto_iterator

template <typename AbsDomain>
class wto_processor final : public wto_component_visitor<cfg_t> {
  public:
    using interleaved_iterator_t = interleaved_fwd_fixpoint_iterator<AbsDomain>;
    using wto_vertex_t = wto_vertex<cfg_t>;
    using wto_cycle_t = wto_cycle<cfg_t>;

  private:
    interleaved_iterator_t* _iterator;

  public:
    wto_processor(interleaved_iterator_t* iterator) : _iterator(iterator) {}

    void visit(wto_vertex_t& vertex) {
        CrabStats::count("Fixpo.process_invariants");
        ScopedCrabStats __st__("Fixpo.process_invariants");

        label_t node = vertex.node();
    }

    void visit(wto_cycle_t& cycle) {
        CrabStats::count("Fixpo.process_invariants");
        ScopedCrabStats __st__("Fixpo.process_invariants");

        label_t head = cycle.head();
        for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
            it->accept(this);
        }
    }

}; // class wto_processor

} // namespace crab
