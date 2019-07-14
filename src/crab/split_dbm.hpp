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
#include <optional>
#include <boost/unordered_set.hpp>

//#define CHECK_POTENTIAL
//#define SDBM_NO_NORMALIZE

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"

namespace crab {

namespace domains {

class SplitDBM final : public abstract_domain<SplitDBM> {

    using Params = SafeInt64DefaultParams;
    using abstract_domain_t = abstract_domain<SplitDBM>;

    using typename abstract_domain_t::variable_vector_t;
  public:


    using linear_constraint_system_t = ikos::linear_constraint_system<number_t, varname_t>;
    using linear_constraint_t = ikos::linear_constraint<number_t, varname_t>;
    using linear_expression_t = ikos::linear_expression<number_t, varname_t>;
    using variable_t = ikos::variable<number_t, varname_t>;

    using constraint_kind_t = typename linear_constraint_t::kind_t;
    using interval_t = interval<number_t>;

  private:
    using bound_t = bound<number_t>;
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

  protected:
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

    vert_id get_vert(variable_t v) {
        auto it = vert_map.find(v);
        if (it != vert_map.end())
            return (*it).second;

        vert_id vert(g.new_vertex());
        vert_map.insert(vmap_elt_t(v, vert));
        // Initialize
        assert(vert <= rev_map.size());
        if (vert < rev_map.size()) {
            potential[vert] = Wt(0);
            rev_map[vert] = v;
        } else {
            potential.push_back(Wt(0));
            rev_map.push_back(v);
        }
        vert_map.insert(vmap_elt_t(v, vert));

        assert(vert != 0);

        return vert;
    }

    vert_id get_vert(graph_t &g, vert_map_t &vmap, rev_map_t &rmap, std::vector<Wt> &pot, variable_t v) {
        auto it = vmap.find(v);
        if (it != vmap.end())
            return (*it).second;

        vert_id vert(g.new_vertex());
        vmap.insert(vmap_elt_t(v, vert));
        // Initialize
        assert(vert <= rmap.size());
        if (vert < rmap.size()) {
            pot[vert] = Wt(0);
            rmap[vert] = v;
        } else {
            pot.push_back(Wt(0));
            rmap.push_back(v);
        }
        vmap.insert(vmap_elt_t(v, vert));

        return vert;
    }

    template <class G, class P>
    inline void check_potential(G &g, P &p, unsigned line) {

    }

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
    bool is_unsat_edge(vert_id x, vert_id y, Wt k) {

        typename graph_t::mut_val_ref_t w;
        if (g.lookup(y, x, &w)) {
            return ((w.get() + k) < Wt(0));
        } else {
            interval_t intv_x = interval_t::top();
            interval_t intv_y = interval_t::top();
            if (g.elem(0, x) || g.elem(x, 0)) {
                intv_x = interval_t(g.elem(x, 0) ? -number_t(g.edge_val(x, 0)) : bound_t::minus_infinity(),
                                    g.elem(0, x) ? number_t(g.edge_val(0, x)) : bound_t::plus_infinity());
            }
            if (g.elem(0, y) || g.elem(y, 0)) {
                intv_y = interval_t(g.elem(y, 0) ? -number_t(g.edge_val(y, 0)) : bound_t::minus_infinity(),
                                    g.elem(0, y) ? number_t(g.edge_val(0, y)) : bound_t::plus_infinity());
            }
            if (intv_x.is_top() || intv_y.is_top()) {
                return false;
            } else {
                return (!((intv_y - intv_x).lb() <= (number_t)k));
            }
        }
    }

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

    // We should probably use the magical rvalue ownership semantics stuff.
    SplitDBM(vert_map_t &_vert_map, rev_map_t &_rev_map, graph_t &_g, std::vector<Wt> &_potential,
              vert_set_t &_unstable)
        : vert_map(_vert_map), rev_map(_rev_map), g(_g), potential(_potential), unstable(_unstable), _is_bottom(false) {

        crab::CrabStats::count(getDomainName() + ".count.copy");
        crab::ScopedCrabStats __st__(getDomainName() + ".copy");

        CRAB_WARN("Non-moving constructor.");
        assert(g.size() > 0);
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

    SplitDBM operator&&(SplitDBM o) {
        crab::CrabStats::count(getDomainName() + ".count.narrowing");
        crab::ScopedCrabStats __st__(getDomainName() + ".narrowing");

        if (is_bottom() || o.is_bottom())
            return SplitDBM::bottom();
        else if (is_top())
            return o;
        else {
            CRAB_LOG("zones-split", crab::outs() << "Before narrowing:\n"
                                                 << "DBM 1\n"
                                                 << *this << "\n"
                                                 << "DBM 2\n"
                                                 << o << "\n");

            // FIXME: Implement properly
            // Narrowing as a no-op should be sound.
            normalize();
            SplitDBM res(*this);

            CRAB_LOG("zones-split", crab::outs() << "Result narrowing:\n" << res << "\n");
            return res;
        }
    }

    void normalize() {
        crab::CrabStats::count(getDomainName() + ".count.normalize");
        crab::ScopedCrabStats __st__(getDomainName() + ".normalize");

        // dbm_canonical(_dbm);
        // Always maintained in normal form, except for widening
        if (unstable.size() == 0)
            return;

        edge_vector delta;
        // GrOps::close_after_widen(g, potential, vert_set_wrap_t(unstable), delta);
        // GKG: Check
        SubGraph<graph_t> g_excl(g, 0);
        GrOps::close_after_widen(g_excl, potential, vert_set_wrap_t(unstable), delta);
        // Retrive variable bounds
        GrOps::close_after_assign(g, potential, 0, delta);

        GrOps::apply_delta(g, delta);

        unstable.clear();
    }

    void minimize() {}

    void operator-=(variable_t v) {
        crab::CrabStats::count(getDomainName() + ".count.forget");
        crab::ScopedCrabStats __st__(getDomainName() + ".forget");

        if (is_bottom())
            return;
        normalize();

        auto it = vert_map.find(v);
        if (it != vert_map.end()) {
            CRAB_LOG("zones-split", crab::outs() << "Before forget " << it->second << ": " << g << "\n");
            g.forget(it->second);
            CRAB_LOG("zones-split", crab::outs() << "After: " << g << "\n");
            rev_map[it->second] = std::nullopt;
            vert_map.erase(v);
        }
    }

    void assign(variable_t x, linear_expression_t e);


    void apply(operation_t op, variable_t x, variable_t y, variable_t z) {
        crab::CrabStats::count(getDomainName() + ".count.apply");
        crab::ScopedCrabStats __st__(getDomainName() + ".apply");

        if (is_bottom()) {
            return;
        }

        normalize();

        switch (op) {
        case OP_ADDITION:
            assign(x, y + z);
            return;
        case OP_SUBTRACTION:
            assign(x, y - z);
            return;
        // For the rest of operations, we fall back on intervals.
        case OP_MULTIPLICATION:
            set(x, get_interval(y) * get_interval(z));
            break;
        case OP_SDIV:
            set(x, get_interval(y) / get_interval(z));
            break;
        case OP_UDIV:
            set(x, get_interval(y).UDiv(get_interval(z)));
            break;
        case OP_SREM:
            set(x, get_interval(y).SRem(get_interval(z)));
            break;
        case OP_UREM:
            set(x, get_interval(y).URem(get_interval(z)));
            break;
        default:
            CRAB_ERROR("Operation ", op, " not supported");
        }

        CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << y << op << z << "\n" << *this << "\n");
    }

    void apply(operation_t op, variable_t x, variable_t y, number_t k) {
        crab::CrabStats::count(getDomainName() + ".count.apply");
        crab::ScopedCrabStats __st__(getDomainName() + ".apply");

        if (is_bottom()) {
            return;
        }

        normalize();

        switch (op) {
        case OP_ADDITION:
            assign(x, y + k);
            return;
        case OP_SUBTRACTION:
            assign(x, y - k);
            return;
        case OP_MULTIPLICATION:
            assign(x, k * y);
            return;
        // For the rest of operations, we fall back on intervals.
        case OP_SDIV:
            set(x, get_interval(y) / interval_t(k));
            break;
        case OP_UDIV:
            set(x, get_interval(y).UDiv(interval_t(k)));
            break;
        case OP_SREM:
            set(x, get_interval(y).SRem(interval_t(k)));
            break;
        case OP_UREM:
            set(x, get_interval(y).URem(interval_t(k)));
            break;
        default:
            CRAB_ERROR("Operation ", op, " not supported");
        }

        CRAB_LOG("zones-split", crab::outs() << "---" << x << ":=" << y << op << k << "\n" << *this << "\n");
    }

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

    void set(variable_t x, interval_t intv) {
        crab::CrabStats::count(getDomainName() + ".count.assign");
        crab::ScopedCrabStats __st__(getDomainName() + ".assign");

        if (is_bottom())
            return;

        if (intv.is_bottom()) {
            set_to_bottom();
            return;
        }

        this->operator-=(x);

        if (intv.is_top()) {
            return;
        }

        vert_id v = get_vert(x);
        bool overflow;
        if (intv.ub().is_finite()) {
            Wt ub = convert_NtoW(*(intv.ub().number()), overflow);
            if (overflow) {
                return;
            }
            potential[v] = potential[0] + ub;
            g.set_edge(0, ub, v);
        }
        if (intv.lb().is_finite()) {
            Wt lb = convert_NtoW(*(intv.lb().number()), overflow);
            if (overflow) {
                return;
            }
            potential[v] = potential[0] + lb;
            g.set_edge(v, -lb, 0);
        }
    }

    // int_cast_operators_api

    void apply(int_conv_operation_t /*op*/, variable_t dst, variable_t src) {
        // since reasoning about infinite precision we simply assign and
        // ignore the widths.
        assign(dst, src);
    }

    // bitwise_operators_api
    void apply(bitwise_operation_t op, variable_t x, variable_t y, variable_t z) {
        crab::CrabStats::count(getDomainName() + ".count.apply");
        crab::ScopedCrabStats __st__(getDomainName() + ".apply");

        // Convert to intervals and perform the operation
        normalize();
        this->operator-=(x);

        interval_t yi = operator[](y);
        interval_t zi = operator[](z);
        interval_t xi = interval_t::bottom();
        switch (op) {
        case OP_AND: {
            xi = yi.And(zi);
            break;
        }
        case OP_OR: {
            xi = yi.Or(zi);
            break;
        }
        case OP_XOR: {
            xi = yi.Xor(zi);
            break;
        }
        case OP_SHL: {
            xi = yi.Shl(zi);
            break;
        }
        case OP_LSHR: {
            xi = yi.LShr(zi);
            break;
        }
        case OP_ASHR: {
            xi = yi.AShr(zi);
            break;
        }
        default:
            CRAB_ERROR("DBM: unreachable");
        }
        set(x, xi);
    }

    void apply(bitwise_operation_t op, variable_t x, variable_t y, number_t k) {
        crab::CrabStats::count(getDomainName() + ".count.apply");
        crab::ScopedCrabStats __st__(getDomainName() + ".apply");

        // Convert to intervals and perform the operation
        normalize();
        interval_t yi = operator[](y);
        interval_t zi(k);
        interval_t xi = interval_t::bottom();

        switch (op) {
        case OP_AND: {
            xi = yi.And(zi);
            break;
        }
        case OP_OR: {
            xi = yi.Or(zi);
            break;
        }
        case OP_XOR: {
            xi = yi.Xor(zi);
            break;
        }
        case OP_SHL: {
            xi = yi.Shl(zi);
            break;
        }
        case OP_LSHR: {
            xi = yi.LShr(zi);
            break;
        }
        case OP_ASHR: {
            xi = yi.AShr(zi);
            break;
        }
        default:
            CRAB_ERROR("DBM: unreachable");
        }
        set(x, xi);
    }

    /*
       Begin unimplemented operations

       SplitDBM implements only standard abstract operations of a
       numerical domain.  The implementation of boolean, array, or
       pointer operations is empty because they should never be
       called.
    */
    // array operations
    void array_init(variable_t a, linear_expression_t elem_size, linear_expression_t lb_idx, linear_expression_t ub_idx,
                    linear_expression_t val) {}
    void array_load(variable_t lhs, variable_t a, linear_expression_t elem_size, linear_expression_t i) {}
    void array_store(variable_t a, linear_expression_t elem_size, linear_expression_t i, linear_expression_t v,
                     bool is_singleton) {}
    void array_store_range(variable_t a, linear_expression_t elem_size, linear_expression_t i, linear_expression_t j,
                           linear_expression_t v) {}
    void array_assign(variable_t lhs, variable_t rhs) {}
    // backward array operations
    void backward_array_init(variable_t a, linear_expression_t elem_size, linear_expression_t lb_idx,
                             linear_expression_t ub_idx, linear_expression_t val, SplitDBM invariant) {}
    void backward_array_load(variable_t lhs, variable_t a, linear_expression_t elem_size, linear_expression_t i,
                             SplitDBM invariant) {}
    void backward_array_store(variable_t a, linear_expression_t elem_size, linear_expression_t i, linear_expression_t v,
                              bool is_singleton, SplitDBM invariant) {}
    void backward_array_store_range(variable_t a, linear_expression_t elem_size, linear_expression_t i,
                                    linear_expression_t j, linear_expression_t v, SplitDBM invariant) {}
    void backward_array_assign(variable_t lhs, variable_t rhs, SplitDBM invariant) {}
    /* End unimplemented operations */

    void project(const variable_vector_t &variables) {
        crab::CrabStats::count(getDomainName() + ".count.project");
        crab::ScopedCrabStats __st__(getDomainName() + ".project");

        if (is_bottom() || is_top()) {
            return;
        }
        if (variables.empty()) {
            return;
        }

        normalize();

        std::vector<bool> save(rev_map.size(), false);
        for (auto x : variables) {
            auto it = vert_map.find(x);
            if (it != vert_map.end())
                save[(*it).second] = true;
        }

        for (vert_id v = 0; v < rev_map.size(); v++) {
            if (!save[v] && rev_map[v]) {
                operator-=((*rev_map[v]));
            }
        }
    }

    void forget(const variable_vector_t &variables) {
        crab::CrabStats::count(getDomainName() + ".count.forget");
        crab::ScopedCrabStats __st__(getDomainName() + ".forget");

        if (is_bottom() || is_top()) {
            return;
        }

        for (auto v : variables) {
            auto it = vert_map.find(v);
            if (it != vert_map.end()) {
                operator-=(v);
            }
        }
    }

    void expand(variable_t x, variable_t y) {
        crab::CrabStats::count(getDomainName() + ".count.expand");
        crab::ScopedCrabStats __st__(getDomainName() + ".expand");

        if (is_bottom() || is_top()) {
            return;
        }

        CRAB_LOG("zones-split", crab::outs() << "Before expand " << x << " into " << y << ":\n" << *this << "\n");

        auto it = vert_map.find(y);
        if (it != vert_map.end()) {
            CRAB_ERROR("split_dbm expand operation failed because y already exists");
        }

        vert_id ii = get_vert(x);
        vert_id jj = get_vert(y);

        for (auto edge : g.e_preds(ii)) {
            g.add_edge(edge.vert, edge.val, jj);
        }

        for (auto edge : g.e_succs(ii)) {
            g.add_edge(jj, edge.val, edge.vert);
        }

        potential[jj] = potential[ii];

        CRAB_LOG("zones-split", crab::outs() << "After expand " << x << " into " << y << ":\n" << *this << "\n");
    }

    void rename(const variable_vector_t &from, const variable_vector_t &to);

    void extract(const variable_t &x, linear_constraint_system_t &csts, bool only_equalities);

    // -- begin array_sgraph_domain_helper_traits

    // return true iff cst is unsatisfiable without modifying the DBM
    bool is_unsat(linear_constraint_t cst);

    void active_variables(std::vector<variable_t> &out) const {
        out.reserve(g.size());
        for (auto v : g.verts()) {
            if (rev_map[v]) {
                out.push_back((*(rev_map[v])));
            }
        }
    }
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
