#pragma once

#include "crab/abs_transformer.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/interleaved_fixpoint_iterator.hpp"
#include "crab/var_factory.hpp"

#include "boost/range/algorithm/set_algorithm.hpp"
#include <memory>

namespace crab {

namespace analyzer {

/**
 * Only for internal use.
 * Implementation of an intra-procedural forward analysis.
 *
 * Perform a standard forward flow-sensitive analysis. AbsTr
 * defines the abstract transfer functions as well as which
 * operations are modeled.
 **/
template <typename CFG, typename AbsTr>
class fwd_analyzer : private ikos::interleaved_fwd_fixpoint_iterator<CFG, typename AbsTr::abs_dom_t> {
  public:
    using cfg_t = CFG;
    using basic_block_label_t = typename CFG::basic_block_label_t;
    using varname_t = typename CFG::varname_t;
    using variable_t = typename CFG::variable_t;
    using abs_dom_t = typename AbsTr::abs_dom_t;
    using abs_tr_t = AbsTr;

  private:
    using fixpo_iterator_t = ikos::interleaved_fwd_fixpoint_iterator<CFG, abs_dom_t>;

  public:
    using invariant_map_t = typename fixpo_iterator_t::invariant_table_t;
    using assumption_map_t = typename fixpo_iterator_t::assumption_map_t;
    using wto_t = typename fixpo_iterator_t::wto_t;
    using iterator = typename fixpo_iterator_t::iterator;
    using const_iterator = typename fixpo_iterator_t::const_iterator;

  private:
    abs_tr_t *m_abs_tr; // the abstract transformer

    //! Given a basic block and the invariant at the entry it produces
    //! the invariant at the exit of the block.
    void analyze(basic_block_label_t node, abs_dom_t &inv) {
        auto &b = this->get_cfg().get_node(node);
        // XXX: set takes a reference to inv so no copies here
        m_abs_tr->set(&inv);
        for (auto &s : b) {
            s.accept(m_abs_tr);
        }
    }

    void process_pre(basic_block_label_t node, abs_dom_t inv) {}
    void process_post(basic_block_label_t node, abs_dom_t inv) {}

  public:
    fwd_analyzer(CFG cfg, const wto_t *wto, abs_tr_t *abs_tr,
                 // fixpoint parameters
                 unsigned int widening_delay, unsigned int descending_iters, size_t jump_set_size)

        : fixpo_iterator_t(cfg, wto, widening_delay, descending_iters, jump_set_size, false /*disable processor*/),
          m_abs_tr(abs_tr) {
        CRAB_VERBOSE_IF(1, get_msg_stream() << "Type checking CFG ... ";);
        crab::CrabStats::resume("CFG type checking");
        crab::cfg::type_checker<CFG> tc(this->_cfg);
        tc.run();
        crab::CrabStats::stop("CFG type checking");
        CRAB_VERBOSE_IF(1, get_msg_stream() << "OK\n";);
    }

    //! Trigger the fixpoint computation
    void run_forward() {
        // ugly hook to initialize some global state. This needs to be
        // fixed properly.
        domains::array_sgraph_domain_traits<abs_dom_t>::do_initialization(this->get_cfg());

        // XXX: inv was created before the static data is initialized
        //      so it won't contain that data.
        this->run(*m_abs_tr->get());
    }

    void run_forward(basic_block_label_t entry, const assumption_map_t &assumptions) {
        // ugly hook to initialize some global state. This needs to be
        // fixed properly.
        domains::array_sgraph_domain_traits<abs_dom_t>::do_initialization(this->get_cfg());

        // XXX: inv was created before the static data is initialized
        //      so it won't contain that data.
        this->run(entry, *m_abs_tr->get(), assumptions);
    }

    CFG get_cfg() const { return this->_cfg; }

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
};

/**
 * Wrapper for fwd_analyzer_class.
 *
 * The main difference with fwd_analyzer class is that here we
 * create an abstract transformer instance while fwd_analyzer does
 * not.
 **/
template <typename CFG, typename AbsDomain, typename AbsTr>
class intra_fwd_analyzer_wrapper {
    using fwd_analyzer_t = fwd_analyzer<CFG, AbsTr>;

  public:
    using abs_dom_t = AbsDomain;
    using cfg_t = CFG;
    using basic_block_label_t = typename CFG::basic_block_label_t;
    using varname_t = typename CFG::varname_t;
    using number_t = typename CFG::number_t;
    using stmt_t = typename CFG::statement_t;
    using abs_tr_t = typename fwd_analyzer_t::abs_tr_t;
    using wto_t = typename fwd_analyzer_t::wto_t;
    using assumption_map_t = typename fwd_analyzer_t::assumption_map_t;
    using invariant_map_t = typename fwd_analyzer_t::invariant_map_t;
    using iterator = typename fwd_analyzer_t::iterator;
    using const_iterator = typename fwd_analyzer_t::const_iterator;

  private:
    abs_dom_t m_init;
    std::shared_ptr<abs_tr_t> m_abs_tr;
    fwd_analyzer_t m_analyzer;

  public:
    intra_fwd_analyzer_wrapper(CFG cfg,
                               // fixpoint parameters
                               unsigned int widening_delay = 1, unsigned int descending_iters = UINT_MAX,
                               size_t jump_set_size = 0)
        : m_init(AbsDomain::top()), m_abs_tr(std::make_shared<abs_tr_t>(&m_init)),
          m_analyzer(cfg, nullptr, &*m_abs_tr, nullptr, widening_delay, descending_iters, jump_set_size) {}

    intra_fwd_analyzer_wrapper(CFG cfg, AbsDomain init,
                               // avoid precompute wto if already available
                               const wto_t *wto = nullptr,
                               // fixpoint parameters
                               unsigned int widening_delay = 1, unsigned int descending_iters = UINT_MAX,
                               size_t jump_set_size = 0)
        : m_init(init), m_abs_tr(std::make_shared<abs_tr_t>(&m_init)),
          m_analyzer(cfg, wto, &*m_abs_tr, widening_delay, descending_iters, jump_set_size) {}

    void run() { m_analyzer.run_forward(); }

    void run(basic_block_label_t entry, const assumption_map_t &assumptions) {
        m_analyzer.run_forward(entry, assumptions);
    }

    iterator pre_begin() { return m_analyzer.pre_begin(); }
    iterator pre_end() { return m_analyzer.pre_end(); }
    const_iterator pre_begin() const { return m_analyzer.pre_begin(); }
    const_iterator pre_end() const { return m_analyzer.pre_end(); }

    iterator post_begin() { return m_analyzer.post_begin(); }
    iterator post_end() { return m_analyzer.post_end(); }
    const_iterator post_begin() const { return m_analyzer.post_begin(); }
    const_iterator post_end() const { return m_analyzer.post_end(); }

    const invariant_map_t &get_pre_invariants() const { return m_analyzer.get_pre_invariants(); }

    const invariant_map_t &get_post_invariants() const { return m_analyzer.get_post_invariants(); }

    abs_dom_t operator[](basic_block_label_t b) const { return m_analyzer[b]; }

    abs_dom_t get_pre(basic_block_label_t b) const { return m_analyzer.get_pre(b); }

    abs_dom_t get_post(basic_block_label_t b) const { return m_analyzer.get_post(b); }

    const wto_t &get_wto() const { return m_analyzer.get_wto(); }

    void clear() { m_analyzer.clear(); }

    /** Extra API for checkers **/

    CFG get_cfg() { return m_analyzer.get_cfg(); }

    std::shared_ptr<abs_tr_t> get_abs_transformer(abs_dom_t *inv) {
        m_abs_tr->set(inv);
        return m_abs_tr;
    }

    void get_safe_assertions(std::set<const stmt_t *> &out) const {}
};

/**
 * External api
 **/
template <typename CFG, typename AbsDomain>
using intra_fwd_analyzer = intra_fwd_analyzer_wrapper<CFG, AbsDomain, intra_abs_transformer<AbsDomain>>;

} // namespace analyzer
} // namespace crab
