#pragma once

#include "crab/cdg.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/killgen_domain.hpp"
#include "crab/killgen_fixpoint_iterator.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include <boost/range/iterator_range.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>

/**
 *  Dataflow analysis that for each block b it computes facts <i,V>
 *  meaning that there exists a path emanating from b that will reach
 *  assertion with id=i and its evaluation depends on the set of
 *  variables V.
 *
 *  These dataflow facts are useful at least for:
 *
 *  - Computing the set of unjustified assumptions when proving a
 *    particular assertion, and
 *
 *  - Performing slicing by havoc'ing statements that cannot affect
 *    any assertion.
 *
 *  TODO:
 *  - Consider only integer instructions ignoring the heap.
 **/

namespace crab {

namespace analyzer {

using namespace crab::iterators;
using namespace crab::domains;
using namespace crab::cfg;

// A wrapper to an assert statement
template <typename CFG>
struct assert_wrapper {

    using assert_t = typename statement_visitor<typename CFG::number_t, typename CFG::varname_t>::assert_t;
    using basic_block_label_t = typename CFG::basic_block_label_t;
    using this_type = assert_wrapper<CFG>;

    // unique identifier for the assert statement needed for being
    // used as key
    index_t id;
    // basic block where the assert statement is located
    basic_block_label_t bbl;
    // the assert statement
    assert_t *a;

    /// pointers to some global datastructures
    using assert_map_t = boost::unordered_map<assert_t *, this_type>;
    using cdg_t = boost::unordered_map<basic_block_label_t, std::vector<basic_block_label_t>>;
    // map assertions to their wrappers
    assert_map_t *assert_map_ptr;
    // control-dependency graph
    const cdg_t *cdg_ptr;

    assert_wrapper(index_t _id, basic_block_label_t _bbl, assert_t *_a, assert_map_t *am, const cdg_t *cdg)
        : id(_id), bbl(_bbl), a(_a), assert_map_ptr(am), cdg_ptr(cdg) {}

    assert_t *get() { return a; }
    const assert_t *get() const { return a; }
    index_t index() const { return id; }
    bool operator==(this_type o) const { return id == o.id; }
    bool operator<(this_type o) const { return id < o.id; }
    void write(crab::crab_os &o) const { o << "\"" << *a << "\""; }
};

template <typename CFG>
inline crab::crab_os &operator<<(crab::crab_os &o, const assert_wrapper<CFG> &w) {
    w.write(o);
    return o;
}

template <typename CFG>
class assertion_crawler;

// Define the operations of the dataflow analysis
template <class CFG>
class assertion_crawler_operations
    : public killgen_operations_api<
          CFG, separate_killgen_domain<assert_wrapper<CFG>, flat_killgen_domain<typename CFG::variable_t>>> {

    friend class assertion_crawler<CFG>;

  public:
    using assert_wrapper_t = assert_wrapper<CFG>;
    using var_dom_t = flat_killgen_domain<typename CFG::variable_t>;
    // -- key type: map an assertion to a set of variables
    using separate_domain_t = separate_killgen_domain<assert_wrapper_t, var_dom_t>;

  private:
    using killgen_operations_api_t = killgen_operations_api<CFG, separate_domain_t>;
    using basic_block_label_t = typename CFG::basic_block_label_t;
    using basic_block_t = typename CFG::basic_block_t;
    using V = typename CFG::varname_t;
    using N = typename CFG::number_t;

    // map each stmt assertion to a unique identifier
    using assert_t = typename assert_wrapper_t::assert_t;
    using assert_map_t = boost::unordered_map<assert_t *, assert_wrapper_t>;

    // control-dependency graph
    // map a CFG block to the set of blocks which control-dependent on it.
    using cdg_t = boost::unordered_map<basic_block_label_t, std::vector<basic_block_label_t>>;

    // set of uses and definitions of an instruction
    using live_t = crab::cfg::live<N, V>;

    class transfer_function : public statement_visitor<N, V> {

        using bin_op_t = typename statement_visitor<N, V>::bin_op_t;
        using assign_t = typename statement_visitor<N, V>::assign_t;
        using assume_t = typename statement_visitor<N, V>::assume_t;
        using select_t = typename statement_visitor<N, V>::select_t;
        using assert_t = typename statement_visitor<N, V>::assert_t;
        using int_cast_t = typename statement_visitor<N, V>::int_cast_t;
        using havoc_t = typename statement_visitor<N, V>::havoc_t;
        using unreach_t = typename statement_visitor<N, V>::unreach_t;
        using variable_t = typename CFG::variable_t;

        // Helper that applies function F to each pair's value of the
        // separate domain_t.
        template <typename F>
        struct apply_separate : public std::unary_function<separate_domain_t, separate_domain_t> {
            using this_type = apply_separate<F>;
            using function_type = std::binary_function<assert_wrapper_t, var_dom_t, std::pair<var_dom_t, bool>>;
            static_assert(std::is_base_of<function_type, F>::value, "Function must be subclass of type F");
            F f;

          public:
            apply_separate(F _f) : f(_f) {}
            apply_separate(const this_type &o) : f(o.f) {}

            separate_domain_t operator()(separate_domain_t inv) { // XXX: separate_domain_t cannot be modified in-place
                typedef std::pair<typename separate_domain_t::key_type, typename separate_domain_t::value_type>
                    value_type;

                if (inv.is_bottom())
                    return inv;

                std::vector<value_type> kvs;
                kvs.reserve(std::distance(inv.begin(), inv.end()));
                for (auto const &kv : inv)
                    kvs.push_back(value_type(kv.first, kv.second));

                for (auto &kv : kvs) {
                    auto p = f(kv.first, kv.second);
                    if (p.second)
                        inv.set(kv.first, p.first);
                }
                return inv;
            }
        };

        /** Add data-dependencies **/
        class add_data_deps : public std::binary_function<assert_wrapper_t, var_dom_t, std::pair<var_dom_t, bool>> {
            var_dom_t uses;
            var_dom_t defs;

          public:
            add_data_deps(const live_t &l) : uses(var_dom_t::bottom()), defs(var_dom_t::bottom()) {
                for (auto v : boost::make_iterator_range(l.uses_begin(), l.uses_end()))
                    uses += v;
                for (auto v : boost::make_iterator_range(l.defs_begin(), l.defs_end()))
                    defs += v;
            }

            add_data_deps(const add_data_deps &o) : uses(o.uses), defs(o.defs) {}

            std::pair<var_dom_t, bool> operator()(assert_wrapper_t /*w*/, var_dom_t d) {
                bool change = false;

                if (defs.is_bottom() && !uses.is_bottom() && !(uses & d).is_bottom()) {
                    d += uses;
                    change = true;
                }
                if (!(d & defs).is_bottom()) {
                    d -= defs;
                    d += uses;
                    change = true;
                }
                return std::make_pair(d, change);
            }
        };

        /** Add control-dependencies **/
        class add_control_deps : public std::binary_function<assert_wrapper_t, var_dom_t, std::pair<var_dom_t, bool>> {
            const cdg_t &cdg;
            const std::vector<basic_block_label_t> &roots;

            var_dom_t uses;

            // return true if we find a path in cdg from root to target
            // FIXME: do caching for the queries
            bool reach(basic_block_label_t root, basic_block_label_t target,
                       boost::unordered_set<basic_block_label_t> &visited) {
                if (root == target)
                    return true;

                // break cycles
                if (visited.find(root) != visited.end())
                    return false;

                visited.insert(root);
                auto it = cdg.find(root);
                if (it == cdg.end())
                    return false;

                for (auto child : it->second) {
                    if (reach(child, target, visited))
                        return true;
                }
                return false;
            }

            bool reach(basic_block_label_t target) {
                boost::unordered_set<basic_block_label_t> visited;
                for (auto r : roots)
                    if (reach(r, target, visited))
                        return true;
                return false;
            }

          public:
            add_control_deps(const cdg_t &_cdg, const std::vector<basic_block_label_t> &_roots, const live_t &l)
                : cdg(_cdg), roots(_roots), uses(var_dom_t::bottom()) {
                for (auto v : boost::make_iterator_range(l.uses_begin(), l.uses_end()))
                    uses += v;
            }

            add_control_deps(const add_data_deps &o) : cdg(o.cdg), roots(o.roots), uses(o.uses) {}

            std::pair<var_dom_t, bool> operator()(assert_wrapper_t w, var_dom_t d) {
                bool change = false;
                if (reach(w.bbl)) {
                    d += uses;
                    change = true;
                }

                return std::make_pair(d, change);
            }
        };

        /** Remove data-dependencies **/
        class remove_deps : public std::binary_function<assert_wrapper_t, var_dom_t, std::pair<var_dom_t, bool>> {
            var_dom_t vars;

          public:
            remove_deps(variable_t v) : vars(var_dom_t::bottom()) { vars += v; }

            remove_deps(const std::vector<variable_t> &vs) : vars(var_dom_t::bottom()) {
                for (auto v : vs) {
                    vars += v;
                }
            }

            remove_deps(const remove_deps &o) : vars(o.vars) {}

            std::pair<var_dom_t, bool> operator()(assert_wrapper_t /*w*/, var_dom_t d) {
                bool change = false;
                if (!(d & vars).is_bottom()) {
                    d -= vars;
                    change = true;
                }
                return std::make_pair(d, change);
            }
        };

        using apply_add_data_t = apply_separate<add_data_deps>;
        using apply_add_control_t = apply_separate<add_control_deps>;
        using apply_remove_t = apply_separate<remove_deps>;

        // dataflow solution: map blocks to pairs of assertion id and
        //                    set of variables.
        separate_domain_t _inv;
        // map each assertion to a unique identifier
        assert_map_t &_assert_map;
        // control-dependence graph
        const cdg_t &_cdg;
        // parent basic block (XXX: needed because crab statements do
        // not have a back pointer to their basic blocks)
        basic_block_t &_bb;

      public:
        transfer_function(separate_domain_t inv, const cdg_t &g, assert_map_t &am, basic_block_t &bb)
            : _inv(inv), _assert_map(am), _cdg(g), _bb(bb) {}

        separate_domain_t inv() { return _inv; }

        void visit(bin_op_t &s) {
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tBEFORE: " << _inv << "\n");
            apply_add_data_t f(add_data_deps(s.get_live()));
            _inv = f(_inv);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "\tAFTER " << _inv << "\n";);
        }

        void visit(assign_t &s) {
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tBEFORE: " << _inv << "\n");
            apply_add_data_t f(add_data_deps(s.get_live()));
            _inv = f(_inv);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "\tAFTER " << _inv << "\n";);
        }

        void visit(assume_t &s) {
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tBEFORE: " << _inv << "\n");
            // -- add data dependencies
            apply_add_data_t df(add_data_deps(s.get_live()));
            _inv = df(_inv);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "\tAFTER data-dep " << _inv << "\n";);

            // -- add control dependencies
            for (auto const &pred : boost::make_iterator_range(_bb.prev_blocks())) {
                // it->second is the set of basic blocks that control
                // dependent on s' block
                auto it = _cdg.find(/*_bb*/ pred);
                if (it != _cdg.end()) {
                    auto const &children = it->second;
                    CRAB_LOG(
                        "assertion-crawler-step-control", crab::outs() << "{"; for (auto &c
                                                                                    : children) {
                            crab::outs() << c << ";";
                        } crab::outs() << "} control-dependent on "
                                       << pred << "\n";);
                    apply_add_control_t cf(add_control_deps(_cdg, children, s.get_live()));
                    _inv = cf(_inv);
                    CRAB_LOG("assertion-crawler-step-control", crab::outs() << "\tAFTER control-dep " << _inv << "\n";);
                }
            }
        }

        void visit(select_t &s) {
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tBEFORE: " << _inv << "\n");
            apply_add_data_t f(add_data_deps(s.get_live()));
            _inv = f(_inv);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "\tAFTER " << _inv << "\n";);
        }

        void visit(assert_t &s) {
            auto it = _assert_map.find(&s);
            if (it != _assert_map.end())
                return;

            var_dom_t vdom = var_dom_t::bottom();
            auto const &l = s.get_live();
            for (auto v : boost::make_iterator_range(l.uses_begin(), l.uses_end())) {
                vdom += v;
            }

            unsigned id = _assert_map.size();
            assert_wrapper_t val(id, _bb.label(), &s, &_assert_map, &_cdg);
            _assert_map.insert(typename assert_map_t::value_type(&s, val));
            _inv.set(val, vdom);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tAdded " << vdom << "\n";);
        }

        void visit(unreach_t &) { _inv = separate_domain_t::bottom(); }

        void visit(havoc_t &s) {
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tBEFORE: " << _inv << "\n");
            apply_remove_t f(remove_deps(s.variable()));
            _inv = f(_inv);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "\tAFTER " << _inv << "\n";);
        }

        void visit(int_cast_t &s) {
            CRAB_LOG("assertion-crawler-step", crab::outs() << "*** " << s << "\n"
                                                            << "\tBEFORE: " << _inv << "\n");
            apply_add_data_t f(add_data_deps(s.get_live()));
            _inv = f(_inv);
            CRAB_LOG("assertion-crawler-step", crab::outs() << "\tAFTER " << _inv << "\n";);
        }
    };

  private:
    // global datastructure for the whole analysis of the CFG
    assert_map_t _assert_map;
    cdg_t _cdg;

  public:
    assertion_crawler_operations(CFG cfg) : killgen_operations_api_t(cfg) {}

    virtual bool is_forward() override { return false; }

    virtual std::string name() override { return "assertion-crawler"; }

    virtual void init_fixpoint() override {
        crab::ScopedCrabStats __st__("Control-Dependency Graph");
        crab::analyzer::graph_algo::control_dep_graph(this->m_cfg, _cdg);
    }

    virtual separate_domain_t entry() override { return separate_domain_t::bottom(); }

    virtual separate_domain_t merge(separate_domain_t d1, separate_domain_t d2) override { return d1 | d2; }

    virtual separate_domain_t analyze(basic_block_label_t bb_id, separate_domain_t out) override {
        auto &bb = this->m_cfg.get_node(bb_id);
        transfer_function vis(out, _cdg, _assert_map, bb);
        for (auto &s : boost::make_iterator_range(bb.rbegin(), bb.rend())) {
            s.accept(&vis);
        }
        return vis.inv();
    }
};

/**
 * The assertion crawler dataflow analysis
 *
 * Compute for each basic block b a set of facts (i,V) such that
 * there exists a path from b that will check assertion i and its
 * evaluation depends on the set of variables V.
 **/
template <class CFG>
class assertion_crawler : public boost::noncopyable,
                          public crab::iterators::killgen_fixpoint_iterator<CFG, assertion_crawler_operations<CFG>> {

  public:
    using basic_block_label_t = typename CFG::basic_block_label_t;
    using varname_t = typename CFG::varname_t;

  private:
    using fixpo_t = crab::iterators::killgen_fixpoint_iterator<CFG, assertion_crawler_operations<CFG>>;

  public:
    // map assertions to a set of variables
    using separate_domain_t = typename assertion_crawler_operations<CFG>::separate_domain_t;

  private:
    boost::unordered_map<basic_block_label_t, separate_domain_t> m_map;

  public:
    assertion_crawler(CFG cfg) : fixpo_t(cfg) {}

    void exec() {
        this->run();
        for (auto p : boost::make_iterator_range(this->out_begin(), this->out_end())) {
            m_map.insert(std::make_pair(p.first, p.second));
        }
        this->release_memory();
    }

    // return the dataflow facts that hold at the exit of block bb
    const separate_domain_t &get_assertions(basic_block_label_t bb) {
        auto it = m_map.find(bb);
        if (it == m_map.end())
            CRAB_ERROR("Basic block ", bb, " not found");
        return it->second;
    }

    // return the dataflow facts of the pre-state at each program point in bb
    void get_assertions(basic_block_label_t b, std::map<typename CFG::statement_t *, separate_domain_t> &res) {
        auto it = m_map.find(b);
        if (it != m_map.end()) {
            if (!it->second.is_bottom()) {
                auto kv = *(it->second.begin());
                auto &bb = this->m_cfg.get_node(b);
                typename assertion_crawler_operations<CFG>::transfer_function vis(it->second, *(kv.first.cdg_ptr),
                                                                                  *(kv.first.assert_map_ptr), bb);
                for (auto &s : boost::make_iterator_range(bb.rbegin(), bb.rend())) {
                    // -- post-state
                    // auto out = vis.inv ();
                    // res.insert(std::make_pair(&s,out));
                    // s.accept (&vis);
                    // -- pre-state
                    s.accept(&vis);
                    auto in = vis.inv();
                    res.insert(std::make_pair(&s, in));
                }
            }
        }
    }

    void write(crab_os &o) const {
        o << "Assertion Crawler Analysis \n";

        // Print invariants in DFS to enforce a fixed order
        std::set<basic_block_label_t> visited;
        std::vector<basic_block_label_t> worklist;
        worklist.push_back(this->m_cfg.entry());
        visited.insert(this->m_cfg.entry());
        while (!worklist.empty()) {
            auto cur_label = worklist.back();
            worklist.pop_back();

            auto it = m_map.find(cur_label);
            assert(it != m_map.end());
            auto inv = it->second;
            crab::outs() << crab::cfg_impl::get_label_str(cur_label) << "=" << inv << "\n";

            auto const &cur_node = this->m_cfg.get_node(cur_label);
            for (auto const kid_label : boost::make_iterator_range(cur_node.next_blocks())) {
                if (visited.insert(kid_label).second) {
                    worklist.push_back(kid_label);
                }
            }
        }

        // for (auto &kv: m_map) {
        //   o << "Block " << kv.first << "\n";
        //   #if 1
        //   o << "\t" << kv.second << "\n";
        //   #else
        //   std::map<typename CFG::statement_t*, separate_domain_t> pp_map;
        //   get_assertions(kv.first, pp_map);
        //   for (auto &kv: pp_map) {
        //     o << "\t" << *(kv.first) << " --> " << kv.second << "\n";
        //   }
        //   #endif
        // }
    }
};

template <typename CFG>
inline crab_os &operator<<(crab_os &o, const assertion_crawler<CFG> &ac) {
    ac.write(o);
    return o;
}

} // namespace analyzer
} // namespace crab
