#pragma once

#include "crab/abs_transformer.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/interleaved_fixpoint_iterator.hpp"
#include "crab/types.hpp"

#include "boost/range/algorithm/set_algorithm.hpp"
#include <memory>

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
class fwd_analyzer
    : private ikos::interleaved_fwd_fixpoint_iterator<typename intra_abs_transformer<AbsDomain>::abs_dom_t> {
  public:
    using abs_tr_t = intra_abs_transformer<AbsDomain>;
    using abs_dom_t = typename abs_tr_t::abs_dom_t;

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
    void analyze(basic_block_label_t node, abs_dom_t &inv) {
        auto &b = this->get_cfg().get_node(node);
        // XXX: set takes a reference to inv so no copies here
        m_abs_tr->set(&inv);
        for (auto &s : b) {
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

    const invariant_map_t &get_pre_invariants() const { return this->_pre; }

    const invariant_map_t &get_post_invariants() const { return this->_post; }

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
    const wto_t &get_wto() const { return fixpo_iterator_t::get_wto(); }

    // clear all invariants (pre and post)
    void clear() {
        this->_pre.clear();
        this->_post.clear();
    }

    void set_abs_transformer(abs_dom_t *inv) { m_abs_tr->set(inv); }
    std::shared_ptr<abs_tr_t> get_abs_transformer() { return m_abs_tr; }
};

} // namespace analyzer
} // namespace crab
