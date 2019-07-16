#pragma once

#include <memory>

#include <unordered_map>

#include "crab/types.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/cfg.hpp"
#include "crab/wto.hpp"
#include "crab/abs_transformer.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"

namespace ikos {

using crab::basic_block_label_t;
using crab::cfg_ref_t;

template <typename AbsDomain>
class wto_iterator;

template <typename AbsDomain>
class wto_processor;

template <typename AbsDomain>
class interleaved_fwd_fixpoint_iterator {

    friend class wto_iterator<AbsDomain>;

  public:
    using wto_t = wto<cfg_ref_t>;
    using assumption_map_t = std::unordered_map<basic_block_label_t, AbsDomain>;
    using invariant_table_t = std::unordered_map<basic_block_label_t, AbsDomain>;

    virtual void analyze(crab::basic_block_label_t, AbsDomain&) = 0;
    virtual void process_pre(crab::basic_block_label_t, AbsDomain) = 0;
    virtual void process_post(crab::basic_block_label_t, AbsDomain) = 0;

  private:
    using wto_iterator_t = wto_iterator<AbsDomain>;
    using wto_processor_t = wto_processor<AbsDomain>;
    using thresholds_t = crab::iterators::thresholds_t;
    using wto_thresholds_t = crab::iterators::wto_thresholds_t;

  protected:
    using iterator = typename invariant_table_t::iterator;
    using const_iterator = typename invariant_table_t::const_iterator;

    cfg_ref_t _cfg;
    wto_t _wto;
    invariant_table_t _pre, _post;
    // number of iterations until triggering widening
    unsigned int _widening_delay;
    // number of narrowing iterations. If the narrowing operator is
    // indeed a narrowing operator this parameter is not
    // needed. However, there are abstract domains for which an actual
    // narrowing operation is not available so we must enforce
    // termination.
    unsigned int _descending_iterations;
    // enable post-processing of the invariants
    bool _enable_processor;

  private:
    void set(invariant_table_t& table, basic_block_label_t node, const AbsDomain& v) {
        crab::CrabStats::count("Fixpo.invariant_table.update");
        crab::ScopedCrabStats __st__("Fixpo.invariant_table.update");

        std::pair<typename invariant_table_t::iterator, bool> res = table.emplace(std::make_pair(node, v));
        if (!res.second) {
            (res.first)->second = std::move(v);
        }
    }

    inline void set_pre(basic_block_label_t node, const AbsDomain& v) { this->set(this->_pre, node, v); }

    inline void set_post(basic_block_label_t node, const AbsDomain& v) { this->set(this->_post, node, v); }

    AbsDomain get(invariant_table_t& table, basic_block_label_t n) {
        crab::CrabStats::count("Fixpo.invariant_table.lookup");
        crab::ScopedCrabStats __st__("Fixpo.invariant_table.lookup");

        typename invariant_table_t::iterator it = table.find(n);
        if (it != table.end()) {
            return it->second;
        } else {
            return AbsDomain::bottom();
        }
    }

    AbsDomain extrapolate(basic_block_label_t node, unsigned int iteration, AbsDomain before,
                              AbsDomain after) {
        crab::CrabStats::count("Fixpo.extrapolate");
        crab::ScopedCrabStats __st__("Fixpo.extrapolate");

        if (iteration <= _widening_delay) {
            auto widen_res = before | after;
            CRAB_VERBOSE_IF(3, crab::outs() << "Prev   : " << before << "\n"
                                            << "Current: " << after << "\n"
                                            << "Res    : " << widen_res << "\n");
            return widen_res;
        } else {
            CRAB_VERBOSE_IF(3, crab::outs() << "Prev   : " << before << "\n"
                                            << "Current: " << after << "\n");

            auto widen_res = before.widen(after);
            CRAB_VERBOSE_IF(3, crab::outs() << "Res    : " << widen_res << "\n");
            return widen_res;
        }
    }

    AbsDomain refine(basic_block_label_t node, unsigned int iteration, AbsDomain before, AbsDomain after) {
        crab::CrabStats::count("Fixpo.refine");
        crab::ScopedCrabStats __st__("Fixpo.refine");

        if (iteration == 1) {
            auto narrow_res = before & after;
            CRAB_VERBOSE_IF(3, crab::outs() << "Prev   : " << before << "\n"
                                            << "Current: " << after << "\n"
                                            << "Res    : " << narrow_res << "\n");
            return narrow_res;
        } else {
            auto narrow_res = before.narrow(after);
            CRAB_VERBOSE_IF(3, crab::outs() << "Prev   : " << before << "\n"
                                            << "Current: " << after << "\n"
                                            << "Res    : " << narrow_res << "\n");
            return narrow_res;
        }
    }

    void initialize_thresholds(size_t jump_set_size) {}

  public:
    interleaved_fwd_fixpoint_iterator(cfg_ref_t cfg, const wto_t* wto, unsigned int widening_delay,
                                      unsigned int descending_iterations, size_t jump_set_size,
                                      bool enable_processor = true)
        : _cfg(cfg), _wto(!wto ? cfg : *wto), _widening_delay(widening_delay),
          _descending_iterations(descending_iterations), _enable_processor(enable_processor) {
        initialize_thresholds(jump_set_size);
    }

    virtual ~interleaved_fwd_fixpoint_iterator() {}

    cfg_ref_t get_cfg() const { return this->_cfg; }

    const wto_t& get_wto() const { return this->_wto; }

    AbsDomain get_pre(basic_block_label_t node) { return this->get(this->_pre, node); }

    AbsDomain get_post(basic_block_label_t node) { return this->get(this->_post, node); }

    const invariant_table_t& get_pre_invariants() const { return this->_pre; }

    const invariant_table_t& get_post_invariants() const { return this->_post; }

    void run(AbsDomain init) {
        crab::ScopedCrabStats __st__("Fixpo");
        this->set_pre(this->_cfg.entry(), init);
        wto_iterator_t iterator(this);
        this->_wto.accept(&iterator);
        if (_enable_processor) {
            wto_processor_t processor(this);
            this->_wto.accept(&processor);
        }
        CRAB_VERBOSE_IF(2, crab::outs() << "Wto:\n" << _wto << "\n");
    }

    void run(basic_block_label_t entry, AbsDomain init, const assumption_map_t& assumptions) {
        crab::ScopedCrabStats __st__("Fixpo");
        this->set_pre(entry, init);
        wto_iterator_t iterator(this, entry, &assumptions);
        this->_wto.accept(&iterator);
        if (_enable_processor) {
            wto_processor_t processor(this);
            this->_wto.accept(&processor);
        }
        CRAB_VERBOSE_IF(2, crab::outs() << "Wto:\n" << _wto << "\n");
    }

    void clear() {
        this->_pre.clear();
        this->_post.clear();
    }

}; // class interleaved_fwd_fixpoint_iterator

template <typename AbsDomain>
class wto_iterator : public wto_component_visitor<cfg_ref_t> {

  public:
    using interleaved_iterator_t = interleaved_fwd_fixpoint_iterator<AbsDomain>;
    using wto_vertex_t = wto_vertex<cfg_ref_t>;
    using wto_cycle_t = wto_cycle<cfg_ref_t>;
    using wto_t = wto<cfg_ref_t>;
    using wto_nesting_t = typename wto_t::wto_nesting_t;
    using assumption_map_t = typename interleaved_iterator_t::assumption_map_t;

  private:
    interleaved_iterator_t* _iterator;
    // Initial entry point of the analysis
    basic_block_label_t _entry;
    const assumption_map_t* _assumptions;
    // Used to skip the analysis until _entry is found
    bool _skip;

    inline AbsDomain strengthen(basic_block_label_t n, AbsDomain inv) {
        crab::CrabStats::count("Fixpo.strengthen");
        crab::ScopedCrabStats __st__("Fixpo.strengthen");

        if (_assumptions) {
            auto it = _assumptions->find(n);
            if (it != _assumptions->end()) {
                CRAB_VERBOSE_IF(3, crab::outs() << "Before assumption at " << n << ":" << inv << "\n");

                inv = inv & it->second;
                CRAB_VERBOSE_IF(3, crab::outs() << "After assumption at " << n << ":" << inv << "\n");
            }
        }
        return inv;
    }

    // Simple visitor to check if node is a member of the wto component.
    class member_component_visitor : public wto_component_visitor<cfg_ref_t> {
        basic_block_label_t _node;
        bool _found;

      public:
        member_component_visitor(basic_block_label_t node) : _node(node), _found(false) {}

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
    wto_iterator(interleaved_iterator_t* iterator)
        : _iterator(iterator), _entry(_iterator->get_cfg().entry()), _assumptions(nullptr), _skip(true) {}

    wto_iterator(interleaved_iterator_t* iterator, basic_block_label_t entry, const assumption_map_t* assumptions)
        : _iterator(iterator), _entry(entry), _assumptions(assumptions), _skip(true) {}

    void visit(wto_vertex_t& vertex) {
        basic_block_label_t node = vertex.node();

        /** decide whether skip vertex or not **/
        if (_skip && (node == _entry)) {
            _skip = false;
        }
        if (_skip) {
            CRAB_VERBOSE_IF(2, crab::outs() << "** Skipped analysis of  " << crab::get_label_str(node) << "\n");
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
            crab::CrabStats::resume("Fixpo.join_predecessors");
            pre = AbsDomain::bottom();
            for (basic_block_label_t prev : prev_nodes) {
                pre |= this->_iterator->get_post(prev);
            }
            crab::CrabStats::stop("Fixpo.join_predecessors");
            if (_assumptions) { // no necessary but it might avoid copies
                pre = strengthen(node, pre);
            }
            this->_iterator->set_pre(node, pre);
        }

        CRAB_VERBOSE_IF(4, crab::outs() << "PRE Invariants:\n" << pre << "\n");
        crab::CrabStats::resume("Fixpo.analyze_block");
        AbsDomain post(pre);
        this->_iterator->analyze(node, post);
        crab::CrabStats::stop("Fixpo.analyze_block");
        CRAB_VERBOSE_IF(3, crab::outs() << "POST Invariants:\n" << post << "\n");
        this->_iterator->set_post(node, post);
    }

    void visit(wto_cycle_t& cycle) {
        basic_block_label_t head = cycle.head();

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
                CRAB_VERBOSE_IF(2, crab::outs() << "** Skipped analysis of WTO cycle rooted at  "
                                                << crab::get_label_str(head) << "\n");
                return;
            }
        }

        auto prev_nodes = this->_iterator->_cfg.prev_nodes(head);
        AbsDomain pre = AbsDomain::bottom();
        wto_nesting_t cycle_nesting = this->_iterator->_wto.nesting(head);

        if (entry_in_this_cycle) {
            CRAB_VERBOSE_IF(2, crab::outs() << "Skipped predecessors of " << crab::get_label_str(head) << "\n");
            pre = _iterator->get_pre(_entry);
        } else {
            crab::CrabStats::count("Fixpo.join_predecessors");
            crab::ScopedCrabStats __st__("Fixpo.join_predecessors");
            for (basic_block_label_t prev : prev_nodes) {
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
            CRAB_VERBOSE_IF(4, crab::outs() << "PRE Invariants:\n" << pre << "\n");
            crab::CrabStats::resume("Fixpo.analyze_block");
            AbsDomain post(pre);
            this->_iterator->analyze(head, post);
            crab::CrabStats::stop("Fixpo.analyze_block");
            CRAB_VERBOSE_IF(3, crab::outs() << "POST Invariants:\n" << post << "\n");

            this->_iterator->set_post(head, post);
            for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
                it->accept(this);
            }
            crab::CrabStats::resume("Fixpo.join_predecessors");
            AbsDomain new_pre = AbsDomain::bottom();
            for (basic_block_label_t prev : prev_nodes) {
                new_pre |= this->_iterator->get_post(prev);
            }
            crab::CrabStats::stop("Fixpo.join_predecessors");
            crab::CrabStats::resume("Fixpo.check_fixpoint");
            bool fixpoint_reached = new_pre <= pre;
            crab::CrabStats::stop("Fixpo.check_fixpoint");
            if (fixpoint_reached) {
                // Post-fixpoint reached
                this->_iterator->set_pre(head, new_pre);
                pre = new_pre;
                break;
            } else {
                pre = this->_iterator->extrapolate(head, iteration, pre, new_pre);
            }
        }

        if (this->_iterator->_descending_iterations == 0) {
            // no narrowing
            return;
        }

        for (unsigned int iteration = 1;; ++iteration) {
            // Decreasing iteration sequence with narrowing

            CRAB_VERBOSE_IF(4, crab::outs() << "PRE Invariants:\n" << pre << "\n");
            crab::CrabStats::resume("Fixpo.analyze_block");
            AbsDomain post(pre);
            this->_iterator->analyze(head, post);
            this->_iterator->set_post(head, post);
            crab::CrabStats::stop("Fixpo.analyze_block");
            CRAB_VERBOSE_IF(3, crab::outs() << "POST Invariants:\n" << post << "\n");

            for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
                it->accept(this);
            }
            crab::CrabStats::resume("Fixpo.join_predecessors");
            AbsDomain new_pre = AbsDomain::bottom();
            for (basic_block_label_t prev : prev_nodes) {
                new_pre |= this->_iterator->get_post(prev);
            }
            crab::CrabStats::stop("Fixpo.join_predecessors");
            crab::CrabStats::resume("Fixpo.check_fixpoint");
            bool no_more_refinement = pre <= new_pre;
            crab::CrabStats::stop("Fixpo.check_fixpoint");
            if (no_more_refinement) {
                // No more refinement possible(pre == new_pre)
                break;
            } else {
                if (iteration > this->_iterator->_descending_iterations)
                    break;
                pre = this->_iterator->refine(head, iteration, pre, new_pre);
                this->_iterator->set_pre(head, pre);
            }
        }
    }

}; // class wto_iterator

template <typename AbsDomain>
class wto_processor : public wto_component_visitor<cfg_ref_t> {

  public:
    using interleaved_iterator_t = interleaved_fwd_fixpoint_iterator<AbsDomain>;
    using wto_vertex_t = wto_vertex<cfg_ref_t>;
    using wto_cycle_t = wto_cycle<cfg_ref_t>;

  private:
    interleaved_iterator_t* _iterator;

  public:
    wto_processor(interleaved_iterator_t* iterator) : _iterator(iterator) {}

    void visit(wto_vertex_t& vertex) {
        crab::CrabStats::count("Fixpo.process_invariants");
        crab::ScopedCrabStats __st__("Fixpo.process_invariants");

        basic_block_label_t node = vertex.node();
        this->_iterator->process_pre(node, this->_iterator->get_pre(node));
        this->_iterator->process_post(node, this->_iterator->get_post(node));
    }

    void visit(wto_cycle_t& cycle) {
        crab::CrabStats::count("Fixpo.process_invariants");
        crab::ScopedCrabStats __st__("Fixpo.process_invariants");

        basic_block_label_t head = cycle.head();
        this->_iterator->process_pre(head, this->_iterator->get_pre(head));
        this->_iterator->process_post(head, this->_iterator->get_post(head));
        for (typename wto_cycle_t::iterator it = cycle.begin(); it != cycle.end(); ++it) {
            it->accept(this);
        }
    }

}; // class wto_processor

} // namespace ikos

namespace crab {

namespace analyzer {

/**
 * Implementation of an intra-procedural forward analysis.
 *
 * Perform a standard forward flow-sensitive analysis. AbsTr
 * defines the abstract transfer functions as well as which
 * operations are modeled.
 **/
template <typename AbsDomain>
class fwd_analyzer final : private ikos::interleaved_fwd_fixpoint_iterator<AbsDomain> {
  public:
    using abs_tr_t = intra_abs_transformer<AbsDomain>;
    using abs_dom_t = AbsDomain;

  private:
    using fixpo_iterator_t = ikos::interleaved_fwd_fixpoint_iterator<abs_dom_t>;

  public:
    using invariant_map_t = typename fixpo_iterator_t::invariant_table_t;
    using assumption_map_t = typename fixpo_iterator_t::assumption_map_t;
    using wto_t = typename fixpo_iterator_t::wto_t;
    using iterator = typename fixpo_iterator_t::iterator;
    using const_iterator = typename fixpo_iterator_t::const_iterator;

  private:
    abs_dom_t m_init;
    std::shared_ptr<abs_tr_t> m_abs_tr; // the abstract transformer

    //! Given a basic block and the invariant at the entry it produces
    //! the invariant at the exit of the block.
    void analyze(basic_block_label_t node, abs_dom_t& inv) {
        auto& b = this->get_cfg().get_node(node);
        // XXX: set takes a reference to inv so no copies here
        m_abs_tr->set(&inv);
        for (auto& s : b) {
            s.accept(m_abs_tr.get());
        }
    }

    void process_pre(basic_block_label_t node, abs_dom_t inv) {}
    void process_post(basic_block_label_t node, abs_dom_t inv) {}

  public:
    fwd_analyzer(cfg_ref_t cfg)
        : fixpo_iterator_t(cfg, nullptr, 1, UINT_MAX, 0, false /*disable processor*/), m_init(AbsDomain::top()),
          m_abs_tr(std::make_shared<abs_tr_t>(&m_init)) {
        type_check(this->_cfg);
    }

    //! Trigger the fixpoint computation
    void run_forward() {
        // XXX: inv was created before the static data is initialized
        //      so it won't contain that data.
        this->run(*m_abs_tr->get());
    }

    cfg_ref_t get_cfg() const { return this->_cfg; }

    const invariant_map_t& get_pre_invariants() const { return this->_pre; }

    const invariant_map_t& get_post_invariants() const { return this->_post; }

    iterator pre_begin() { return this->_pre.begin(); }
    iterator pre_end() { return this->_pre.end(); }
    const_iterator pre_begin() const { return this->_pre.begin(); }
    const_iterator pre_end() const { return this->_pre.end(); }

    iterator post_begin() { return this->_post.begin(); }
    iterator post_end() { return this->_post.end(); }
    const_iterator post_begin() const { return this->_post.begin(); }
    const_iterator post_end() const { return this->_post.end(); }

    //! Return the invariants that hold at the entry of b
    inline abs_dom_t operator[](basic_block_label_t b) const { return get_pre(b); }

    //! Return the invariants that hold at the entry of b
    abs_dom_t get_pre(basic_block_label_t b) const {
        auto it = this->_pre.find(b);
        if (it == this->_pre.end()) {
            return abs_dom_t::bottom();
            // if the basic block is not in the invariant table it must
            // be because it was not reached by the analysis. We
            // returned top but it never had real effect because
            // process_pre made sure that all unreachable blocks were in
            // the invariant table with a bottom invariant. This was
            // just a waste of space.
            //
            // return abs_dom_t::top();
        } else {
            return it->second;
        }
    }

    //! Return the invariants that hold at the exit of b
    abs_dom_t get_post(basic_block_label_t b) const {
        auto it = this->_post.find(b);
        if (it == this->_post.end()) {
            return abs_dom_t::bottom();
            // return abs_dom_t::top();
        } else {
            return it->second;
        }
    }

    //! Return the WTO of the CFG. The WTO contains also how many
    //! times each head was visited by the fixpoint iterator.
    const wto_t& get_wto() const { return fixpo_iterator_t::get_wto(); }

    // clear all invariants (pre and post)
    void clear() {
        this->_pre.clear();
        this->_post.clear();
    }

    void set_abs_transformer(abs_dom_t* inv) { m_abs_tr->set(inv); }
    std::shared_ptr<abs_tr_t> get_abs_transformer() { return m_abs_tr; }
};

} // namespace analyzer
} // namespace crab
