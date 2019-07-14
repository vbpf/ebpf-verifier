/*******************************************************************************
 *
 * Difference Bound Matrix domain based on the paper "Exploiting
 * Sparsity in Difference-Bound Matrices" by Gange, Navas, Schachte,
 * Sondergaard, and Stuckey published in SAS'16.

 * A re-engineered implementation of the Difference Bound Matrix
 * domain, which maintains bounds and relations separately.
 *
 * Closure operations based on the paper "Fast and Flexible Difference
 * Constraint Propagation for DPLL(T)" by Cotton and Maler.
 *
 * Author: Graeme Gange (gkgange@unimelb.edu.au)
 *
 * Contributors: Jorge A. Navas (jorge.navas@sri.com)
 ******************************************************************************/

#pragma once

#include "crab/abstract_domain.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/backward_assign_operations.hpp"
#include "crab/debug.hpp"
#include "crab/graph_config.hpp"
#include "crab/graph_ops.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include <boost/container/flat_map.hpp>
#include <boost/unordered_set.hpp>
#include <optional>

//#define CHECK_POTENTIAL
//#define SDBM_NO_NORMALIZE

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"

namespace crab {

namespace domains {

class SplitDBM final : public ikos::writeable {
  public:
    using linear_constraint_system_t = ikos::linear_constraint_system<number_t, varname_t>;
    using linear_constraint_t = ikos::linear_constraint<number_t, varname_t>;
    using linear_expression_t = ikos::linear_expression<number_t, varname_t>;

    using constraint_kind_t = typename linear_constraint_t::kind_t;
    using interval_t = interval<number_t>;

  private:
    using variable_vector_t = std::vector<variable_t>;
    using bound_t = bound<number_t>;

    using Params = SafeInt64DefaultParams;
    using Wt = typename Params::Wt;
    using graph_t = typename Params::graph_t;
    using vert_id = typename graph_t::vert_id;
    using vert_map_t = boost::container::flat_map<variable_t, vert_id>;
    using vmap_elt_t = typename vert_map_t::value_type;
    using rev_map_t = std::vector<std::optional<variable_t>>;
    using GrOps = GraphOps<graph_t>;
    using GrPerm = GraphPerm<graph_t>;
    using edge_vector = typename GrOps::edge_vector;
    // < <x, y>, k> == x - y <= k.
    using diffcst_t = std::pair<std::pair<variable_t, variable_t>, Wt>;
    using vert_set_t = boost::unordered_set<vert_id>;

  private:
    //================
    // Domain data
    //================
    // GKG: ranges are now maintained in the graph
    vert_map_t vert_map; // Mapping from variables to vertices
    rev_map_t rev_map;
    graph_t g;                 // The underlying relation graph
    std::vector<Wt> potential; // Stored potential for the vertex
    vert_set_t unstable;
    bool _is_bottom;

    class Wt_max {
      public:
        Wt_max() {}
        Wt apply(const Wt &x, const Wt &y) { return std::max(x, y); }
        bool default_is_absorbing() { return true; }
    };

    class Wt_min {
      public:
        Wt_min() {}
        Wt apply(const Wt &x, const Wt &y) { return std::min(x, y); }
        bool default_is_absorbing() { return false; }
    };

    vert_id get_vert(variable_t v);

    vert_id get_vert(graph_t &g, vert_map_t &vmap, rev_map_t &rmap, std::vector<Wt> &pot, variable_t v);

    template <class G, class P>
    inline void check_potential(G &g, P &p, unsigned line) {}

    class vert_set_wrap_t {
      public:
        vert_set_wrap_t(const vert_set_t &_vs) : vs(_vs) {}

        bool operator[](vert_id v) const { return vs.find(v) != vs.end(); }
        const vert_set_t &vs;
    };

    // Evaluate the potential value of a variable.
    Wt pot_value(variable_t v) {
        auto it = vert_map.find(v);
        if (it != vert_map.end())
            return potential[(*it).second];
        return ((Wt)0);
    }

    Wt pot_value(variable_t v, std::vector<Wt> &potential) {
        auto it = vert_map.find(v);
        if (it != vert_map.end())
            return potential[(*it).second];
        return ((Wt)0);
    }

    // Evaluate an expression under the chosen potentials
    Wt eval_expression(linear_expression_t e, bool overflow) {
        Wt v(convert_NtoW(e.constant(), overflow));
        if (overflow) {
            return Wt(0);
        }

        for (auto p : e) {
            Wt coef = convert_NtoW(p.first, overflow);
            if (overflow) {
                return Wt(0);
            }
            v += (pot_value(p.second) - potential[0]) * coef;
        }
        return v;
    }

    interval_t eval_interval(linear_expression_t e) {
        interval_t r = e.constant();
        for (auto p : e)
            r += p.first * operator[](p.second);
        return r;
    }

    interval_t compute_residual(linear_expression_t e, variable_t pivot) {
        interval_t residual(-e.constant());
        for (typename linear_expression_t::iterator it = e.begin(); it != e.end(); ++it) {
            variable_t v = it->second;
            if (v.index() != pivot.index()) {
                residual = residual - (interval_t(it->first) * this->operator[](v));
            }
        }
        return residual;
    }

    /**
     *  Turn an assignment into a set of difference constraints.
     *
     *  Given v := a*x + b*y + k, where a,b >= 0, we generate the
     *  difference constraints:
     *
     *  if extract_upper_bounds
     *     v - x <= ub((a-1)*x + b*y + k)
     *     v - y <= ub(a*x + (b-1)*y + k)
     *  else
     *     x - v <= lb((a-1)*x + b*y + k)
     *     y - v <= lb(a*x + (b-1)*y + k)
     **/
    void diffcsts_of_assign(variable_t x, linear_expression_t exp,
                            /* if true then process the upper
                               bounds, else the lower bounds */
                            bool extract_upper_bounds,
                            /* foreach {v, k} \in diff_csts we have
                               the difference constraint v - k <= k */
                            std::vector<std::pair<variable_t, Wt>> &diff_csts);

    // Turn an assignment into a set of difference constraints.
    void diffcsts_of_assign(variable_t x, linear_expression_t exp, std::vector<std::pair<variable_t, Wt>> &lb,
                            std::vector<std::pair<variable_t, Wt>> &ub) {
        diffcsts_of_assign(x, exp, true, ub);
        diffcsts_of_assign(x, exp, false, lb);
    }

    /**
     * Turn a linear inequality into a set of difference
     * constraints.
     **/
    void diffcsts_of_lin_leq(const linear_expression_t &exp,
                             /* difference contraints */
                             std::vector<diffcst_t> &csts,
                             /* x >= lb for each {x,lb} in lbs */
                             std::vector<std::pair<variable_t, Wt>> &lbs,
                             /* x <= ub for each {x,ub} in ubs */
                             std::vector<std::pair<variable_t, Wt>> &ubs);

    bool add_linear_leq(const linear_expression_t &exp);

    // x != n
    void add_univar_disequation(variable_t x, number_t n);

    void add_disequation(linear_expression_t e) {
        // XXX: similar precision as the interval domain

        for (typename linear_expression_t::iterator it = e.begin(); it != e.end(); ++it) {
            variable_t pivot = it->second;
            interval_t i = compute_residual(e, pivot) / interval_t(it->first);
            if (auto k = i.singleton()) {
                add_univar_disequation(pivot, *k);
            }
        }
        return;
    }

    interval_t get_interval(variable_t x) { return get_interval(vert_map, g, x); }

    interval_t get_interval(vert_map_t &m, graph_t &r, variable_t x) {
        auto it = m.find(x);
        if (it == m.end()) {
            return interval_t::top();
        }
        vert_id v = (*it).second;
        interval_t x_out = interval_t(r.elem(v, 0) ? -number_t(r.edge_val(v, 0)) : bound_t::minus_infinity(),
                                      r.elem(0, v) ? number_t(r.edge_val(0, v)) : bound_t::plus_infinity());
        return x_out;
    }

    // Resore potential after an edge addition
    bool repair_potential(vert_id src, vert_id dest) { return GrOps::repair_potential(g, potential, src, dest); }

    // Restore closure after a single edge addition
    void close_over_edge(vert_id ii, vert_id jj);

    // return true if edge from x to y with weight k is unsatisfiable
    bool is_unsat_edge(vert_id x, vert_id y, Wt k);

    // return true iff cst is unsatisfiable without modifying the DBM
    bool is_unsat(linear_constraint_t cst);

  public:
    SplitDBM(bool is_bottom = false) : _is_bottom(is_bottom) {
        g.growTo(1); // Allocate the zero vector
        potential.push_back(Wt(0));
        rev_map.push_back(std::nullopt);
    }

    // FIXME: Rewrite to avoid copying if o is _|_
    SplitDBM(const SplitDBM &o)
        : vert_map(o.vert_map), rev_map(o.rev_map), g(o.g), potential(o.potential), unstable(o.unstable),
          _is_bottom(false) {
        crab::CrabStats::count(getDomainName() + ".count.copy");
        crab::ScopedCrabStats __st__(getDomainName() + ".copy");

        if (o._is_bottom)
            set_to_bottom();

        if (!_is_bottom)
            assert(g.size() > 0);
    }

    SplitDBM(SplitDBM &&o)
        : vert_map(std::move(o.vert_map)), rev_map(std::move(o.rev_map)), g(std::move(o.g)),
          potential(std::move(o.potential)), unstable(std::move(o.unstable)), _is_bottom(o._is_bottom) {
        crab::CrabStats::count(getDomainName() + ".count.copy");
        crab::ScopedCrabStats __st__(getDomainName() + ".copy");
    }

    SplitDBM(vert_map_t &&_vert_map, rev_map_t &&_rev_map, graph_t &&_g, std::vector<Wt> &&_potential,
             vert_set_t &&_unstable)
        : vert_map(std::move(_vert_map)), rev_map(std::move(_rev_map)), g(std::move(_g)),
          potential(std::move(_potential)), unstable(std::move(_unstable)), _is_bottom(false) {

        crab::CrabStats::count(getDomainName() + ".count.copy");
        crab::ScopedCrabStats __st__(getDomainName() + ".copy");

        CRAB_LOG("zones-split-size", auto p = size();
                 crab::outs() << "#nodes = " << p.first << " #edges=" << p.second << "\n";);

        assert(g.size() > 0);
    }

    SplitDBM &operator=(const SplitDBM &o) {
        crab::CrabStats::count(getDomainName() + ".count.copy");
        crab::ScopedCrabStats __st__(getDomainName() + ".copy");

        if (this != &o) {
            if (o._is_bottom) {
                set_to_bottom();
            } else {
                _is_bottom = false;
                vert_map = o.vert_map;
                rev_map = o.rev_map;
                g = o.g;
                potential = o.potential;
                unstable = o.unstable;
                assert(g.size() > 0);
            }
        }
        return *this;
    }

    SplitDBM &operator=(SplitDBM &&o) {
        crab::CrabStats::count(getDomainName() + ".count.copy");
        crab::ScopedCrabStats __st__(getDomainName() + ".copy");

        if (o._is_bottom) {
            set_to_bottom();
        } else {
            _is_bottom = false;
            vert_map = std::move(o.vert_map);
            rev_map = std::move(o.rev_map);
            g = std::move(o.g);
            potential = std::move(o.potential);
            unstable = std::move(o.unstable);
        }
        return *this;
    }

    void set_to_top() {
        SplitDBM abs(false);
        std::swap(*this, abs);
    }

    void set_to_bottom() {
        vert_map.clear();
        rev_map.clear();
        g.clear();
        potential.clear();
        unstable.clear();
        _is_bottom = true;
    }

    // void set_to_bottom() {
    // 	SplitDBM abs(true);
    // 	std::swap(*this, abs);
    // }

    bool is_bottom() { return _is_bottom; }

    static SplitDBM top() {
        SplitDBM abs;
        abs.set_to_top();
        return abs;
    }

    static SplitDBM bottom() {
        SplitDBM abs;
        abs.set_to_bottom();
        return abs;
    }

    bool is_top() {
        if (_is_bottom)
            return false;
        return g.is_empty();
    }

    bool operator<=(SplitDBM o);

    // FIXME: can be done more efficient
    void operator|=(SplitDBM o) { *this = *this | o; }

    SplitDBM operator|(SplitDBM o);

    SplitDBM operator||(SplitDBM o);

    SplitDBM widening_thresholds(SplitDBM o, const iterators::thresholds<number_t> &ts) {
        // TODO: use thresholds
        return (*this || o);
    }

    SplitDBM operator&(SplitDBM o);

    SplitDBM operator&&(SplitDBM o);

    void normalize();

    void minimize() {}

    void operator-=(variable_t v);

    void assign(variable_t x, linear_expression_t e);

    void apply(operation_t op, variable_t x, variable_t y, variable_t z);

    void apply(operation_t op, variable_t x, variable_t y, number_t k);

    void backward_assign(variable_t x, linear_expression_t e, SplitDBM inv) {
        crab::domains::BackwardAssignOps<SplitDBM>::assign(*this, x, e, inv);
    }

    void backward_apply(operation_t op, variable_t x, variable_t y, number_t z, SplitDBM inv) {
        crab::domains::BackwardAssignOps<SplitDBM>::apply(*this, op, x, y, z, inv);
    }

    void backward_apply(operation_t op, variable_t x, variable_t y, variable_t z, SplitDBM inv) {
        crab::domains::BackwardAssignOps<SplitDBM>::apply(*this, op, x, y, z, inv);
    }

    void operator+=(linear_constraint_t cst);

    void operator+=(linear_constraint_system_t csts) {
        if (is_bottom())
            return;

        for (auto cst : csts) {
            operator+=(cst);
        }
    }

    interval_t operator[](variable_t x) {
        crab::CrabStats::count(getDomainName() + ".count.to_intervals");
        crab::ScopedCrabStats __st__(getDomainName() + ".to_intervals");

        // if (is_top())    return interval_t::top();

        if (is_bottom()) {
            return interval_t::bottom();
        } else {
            return get_interval(vert_map, g, x);
        }
    }

    void set(variable_t x, interval_t intv);

    // int_cast_operators_api

    void apply(int_conv_operation_t /*op*/, variable_t dst, variable_t src) {
        // since reasoning about infinite precision we simply assign and
        // ignore the widths.
        assign(dst, src);
    }

    // bitwise_operators_api
    void apply(bitwise_operation_t op, variable_t x, variable_t y, variable_t z);

    void apply(bitwise_operation_t op, variable_t x, variable_t y, number_t k);


    void project(const variable_vector_t &variables);

    void forget(const variable_vector_t &variables);

    void expand(variable_t x, variable_t y);

    void rename(const variable_vector_t &from, const variable_vector_t &to);

    void extract(const variable_t &x, linear_constraint_system_t &csts, bool only_equalities);

    // -- begin array_sgraph_domain_helper_traits

    // -- end array_sgraph_domain_helper_traits

    // Output function
    void write(crab_os &o);

    linear_constraint_system_t to_linear_constraint_system();

    // return number of vertices and edges
    std::pair<std::size_t, std::size_t> size() const { return {g.size(), g.num_edges()}; }

    static std::string getDomainName() { return "SplitDBM"; }

}; // class SplitDBM

} // namespace domains
} // namespace crab

#pragma GCC diagnostic pop
