#pragma once

/**
 * Specialized fixpoint iterators for kill-gen problems.
 **/

#include "crab/cfg.hpp" // for cfg_impl::get_label_str
#include "crab/cfg_bgl.hpp"
#include "crab/debug.hpp"
#include "crab/killgen_domain.hpp"
#include "crab/sccg.hpp"
#include "crab/stats.hpp"
#include "crab/topo_order.hpp"

namespace crab {
namespace iterators {

// API for a kill-gen analysis operations
template <class CFG, class Dom>
class killgen_operations_api {

  public:
    typedef typename CFG::basic_block_label_t basic_block_label_t;
    typedef Dom killgen_domain_t;

  protected:
    CFG m_cfg;

  public:
    killgen_operations_api(CFG cfg) : m_cfg(cfg) {}

    virtual ~killgen_operations_api() {}

    // whether forward or backward analysis
    virtual bool is_forward() = 0;

    // initial state
    virtual Dom entry() = 0;

    // (optional) initialization for the fixpoint
    virtual void init_fixpoint() = 0;

    // confluence operator
    virtual Dom merge(Dom, Dom) = 0;

    // analyze a basic block
    virtual Dom analyze(basic_block_label_t, Dom) = 0;

    // analysis name
    virtual std::string name() = 0;
};

// A simple fixpoint for a killgen analysis
template <class CFG, class AnalysisOps>
class killgen_fixpoint_iterator {

  public:
    typedef typename CFG::basic_block_label_t basic_block_label_t;
    typedef typename AnalysisOps::killgen_domain_t killgen_domain_t;
    typedef boost::unordered_map<basic_block_label_t, killgen_domain_t> inv_map_t;
    typedef typename inv_map_t::iterator iterator;
    typedef typename inv_map_t::const_iterator const_iterator;

  protected:
    CFG m_cfg;
    inv_map_t m_in_map;
    inv_map_t m_out_map;

  private:
    AnalysisOps m_analysis;

    /**
     * run_bwd_fixpo(G) is in theory equivalent to
     * run_fwd_fixpo(reverse(G)).
     *  However, weak_rev_topo_sort(G) != weak_topo_sort(reverse(G))
     *  For instance, for a G=(V,E) where
     *   V= {v1,v2, v3, v4, v5},
     *   E= {(v1,v2), (v1,v3), (v2,v4), (v4,v1), (v3,v5)}
     *  (1) weak_rev_topo_sort(cfg)=[v5,v3,v4,v2,v1]
     *  (2) weak_topo_sort(reverse(cfg))=[v5,v3,v2,v4,v1] or even
     *      worse [v5,v3,v1,v4,v2] if vertices in the same scc are
     *      traversed in preorder.
     *  For a backward analysis, (1) will converge faster.
     *  For all of this, we decide not to reverse graphs and have
     *  two dual versions for the forward and backward analyses.
     **/

    void run_fwd_fixpo(std::vector<typename CFG::node_t> &order, unsigned &iterations) {

        order = crab::analyzer::graph_algo::weak_topo_sort(m_cfg);
        assert((int)order.size() == std::distance(m_cfg.begin(), m_cfg.end()));
        bool change = true;
        iterations = 0;
        while (change) {
            change = false;
            ++iterations;
            for (auto &n : order) {
                auto in = m_analysis.entry();
                for (auto p : m_cfg.prev_nodes(n))
                    in = m_analysis.merge(in, m_out_map[p]);
                auto old_out = m_out_map[n];
                auto out = m_analysis.analyze(n, in);
                if (!(out <= old_out)) {
                    m_out_map[n] = m_analysis.merge(out, old_out);
                    change = true;
                } else
                    m_in_map[n] = in;
            }
        }
    }

    void run_bwd_fixpo(std::vector<typename CFG::node_t> &order, unsigned &iterations) {

        order = crab::analyzer::graph_algo::weak_rev_topo_sort(m_cfg);
        assert((int)order.size() == std::distance(m_cfg.begin(), m_cfg.end()));
        bool change = true;
        iterations = 0;
        while (change) {
            change = false;
            ++iterations;
            for (auto &n : order) {
                auto out = m_analysis.entry();
                for (auto p : m_cfg.next_nodes(n))
                    out = m_analysis.merge(out, m_in_map[p]);
                auto old_in = m_in_map[n];
                auto in = m_analysis.analyze(n, out);
                if (!(in <= old_in)) {
                    m_in_map[n] = m_analysis.merge(in, old_in);
                    change = true;
                } else
                    m_out_map[n] = out;
            }
        }
    }

  public:
    killgen_fixpoint_iterator(CFG cfg) : m_cfg(cfg), m_analysis(m_cfg) {}

    void release_memory() {
        m_in_map.clear();
        m_out_map.clear();
    }

    void run() {
        crab::ScopedCrabStats __st__(m_analysis.name());

        m_analysis.init_fixpoint();

        std::vector<typename CFG::node_t> order;
        unsigned iterations = 0;

        if (m_analysis.is_forward()) {
            run_fwd_fixpo(order, iterations);
        } else {
            run_bwd_fixpo(order, iterations);
        }

        CRAB_LOG(m_analysis.name(), crab::outs() << "fixpoint ordering={"; bool first = true; for (auto &v
                                                                                                   : order) {
            if (!first)
                crab::outs() << ",";
            first = false;
            crab::outs() << cfg_impl::get_label_str(v);
        } crab::outs() << "}\n";);

        CRAB_LOG(m_analysis.name(), crab::outs() << m_analysis.name() << ": "
                                                 << "fixpoint reached in " << iterations << " iterations.\n");

        CRAB_LOG(m_analysis.name(), crab::outs() << m_analysis.name() << " sets:\n"; for (auto n
                                                                                          : boost::make_iterator_range(
                                                                                              m_cfg.label_begin(),
                                                                                              m_cfg.label_end())) {
            crab::outs() << cfg_impl::get_label_str(n) << " "
                         << "IN=" << m_in_map[n] << " "
                         << "OUT=" << m_out_map[n] << "\n";
        } crab::outs() << "\n";);
    }

    iterator in_begin() { return m_in_map.begin(); }
    iterator in_end() { return m_in_map.end(); }
    const_iterator in_begin() const { return m_in_map.begin(); }
    const_iterator in_end() const { return m_in_map.end(); }

    iterator out_begin() { return m_out_map.begin(); }
    iterator out_end() { return m_out_map.end(); }
    const_iterator out_begin() const { return m_out_map.begin(); }
    const_iterator out_end() const { return m_out_map.end(); }
};

} // end namespace iterators
} // end namespace crab
