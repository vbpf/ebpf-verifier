// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
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

#include <optional>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include <boost/container/flat_map.hpp>

#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/thresholds.hpp"
#include "crab/variable.hpp"
#include "crab_utils/adapt_sgraph.hpp"
#include "crab_utils/bignums.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/graph_ops.hpp"
#include "crab_utils/safeint.hpp"
#include "crab_utils/stats.hpp"

#include "string_constraints.hpp"

// These constants are mostly used in ebpf_domain.cpp, but some uses
// in split_dbm.cpp and array_domain.cpp require them to be declared here.
// The exact numbers are taken advantage of in ebpf_domain_t
enum type_encoding_t {
    T_UNINIT = -7,
    T_MAP_PROGRAMS = -6,
    T_MAP = -5,
    T_NUM = -4,
    T_CTX = -3,
    T_PACKET = -2,
    T_STACK = -1,
    T_SHARED = 0
};

namespace crab {

enum class arith_binop_t { ADD, SUB, MUL, SDIV, UDIV, SREM, UREM };
enum class bitwise_binop_t { AND, OR, XOR, SHL, LSHR, ASHR };
using binop_t = std::variant<arith_binop_t, bitwise_binop_t>;


namespace domains {

/** DBM weights (Weight) can be represented using one of the following
 * types:
 *
 * 1) basic integer type: e.g., long
 * 2) safei64
 * 3) z_number
 *
 * 1) is the fastest but things can go wrong if some DBM
 * operation overflows. 2) is slower than 1) but it checks for
 * overflow before any DBM operation. 3) is the slowest and it
 * represents weights using unbounded mathematical integers so
 * overflow is not a concern but it might not be what you need
 * when reasoning about programs with wraparound semantics.
 **/

struct SafeInt64DefaultParams {
    using Weight = safe_i64;
    using graph_t = AdaptGraph;
};

/**
 * Helper to translate from Number to DBM Weight (graph weights).  Number
 * used to be the template parameter of the DBM-based abstract domain to
 * represent a number. Number might not fit into Weight type.
 **/
inline SafeInt64DefaultParams::Weight convert_NtoW(const z_number& n, bool& overflow) {
    overflow = false;
    if (!n.fits_sint64()) {
        overflow = true;
        return 0;
    }
    return SafeInt64DefaultParams::Weight(n);
}

class SplitDBM final {
  private:
    using variable_vector_t = std::vector<variable_t>;

    using Params = SafeInt64DefaultParams;
    using Weight = typename Params::Weight;
    using graph_t = typename Params::graph_t;
    using vert_id = typename graph_t::vert_id;
    using vert_map_t = boost::container::flat_map<variable_t, vert_id>;
    using vmap_elt_t = typename vert_map_t::value_type;
    using rev_map_t = std::vector<std::optional<variable_t>>;
    using GrOps = GraphOps<graph_t>;
    using GrPerm = GraphPerm<graph_t>;
    using edge_vector = typename GrOps::edge_vector;
    // < <x, y>, k> == x - y <= k.
    using diffcst_t = std::pair<std::pair<variable_t, variable_t>, Weight>;
    using vert_set_t = std::unordered_set<vert_id>;

  private:
    //================
    // Domain data
    //================
    // GKG: ranges are now maintained in the graph
    vert_map_t vert_map; // Mapping from variables to vertices
    rev_map_t rev_map;
    graph_t g;                 // The underlying relation graph
    std::vector<Weight> potential; // Stored potential for the vertex
    vert_set_t unstable;
    bool _is_bottom;

    vert_id get_vert(variable_t v);

    class vert_set_wrap_t {
      public:
        explicit vert_set_wrap_t(const vert_set_t& _vs) : vs(_vs) {}

        bool operator[](vert_id v) const { return vs.find(v) != vs.end(); }
        const vert_set_t& vs;
    };

    // Evaluate the potential value of a variable.
    Weight pot_value(variable_t v) const {
        auto it = vert_map.find(v);
        if (it != vert_map.end())
            return potential[(*it).second];
        return ((Weight)0);
    }

    // Evaluate an expression under the chosen potentials
    Weight eval_expression(const linear_expression_t& e, bool overflow) const {
        Weight res(convert_NtoW(e.constant_term(), overflow));
        if (overflow) {
            return Weight(0);
        }

        for (const auto& [variable, coefficient] : e.variable_terms()) {
            Weight coef = convert_NtoW(coefficient, overflow);
            if (overflow) {
                return Weight(0);
            }
            res += (pot_value(variable) - potential[0]) * coef;
        }
        return res;
    }

    interval_t compute_residual(const linear_expression_t& e, variable_t pivot) const {
        interval_t residual(-e.constant_term());
        for (const auto& [variable, coefficient] : e.variable_terms()) {
            if (variable != pivot) {
                residual = residual - (interval_t(coefficient) * this->operator[](variable));
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
    void diffcsts_of_assign(variable_t x, const linear_expression_t& exp,
                            /* if true then process the upper
                               bounds, else the lower bounds */
                            bool extract_upper_bounds,
                            /* foreach {v, k} \in diff_csts we have
                               the difference constraint v - k <= k */
                            std::vector<std::pair<variable_t, Weight>>& diff_csts) const;

    // Turn an assignment into a set of difference constraints.
    void diffcsts_of_assign(variable_t x, const linear_expression_t& exp, std::vector<std::pair<variable_t, Weight>>& lb,
                            std::vector<std::pair<variable_t, Weight>>& ub) {
        diffcsts_of_assign(x, exp, true, ub);
        diffcsts_of_assign(x, exp, false, lb);
    }

    /**
     * Turn a linear inequality into a set of difference
     * constraints.
     **/
    void diffcsts_of_lin_leq(const linear_expression_t& exp,
                             /* difference contraints */
                             std::vector<diffcst_t>& csts,
                             /* x >= lb for each {x,lb} in lbs */
                             std::vector<std::pair<variable_t, Weight>>& lbs,
                             /* x <= ub for each {x,ub} in ubs */
                             std::vector<std::pair<variable_t, Weight>>& ubs) const;

    bool add_linear_leq(const linear_expression_t& exp);

    // x != n
    void add_univar_disequation(variable_t x, const number_t& n);

    void add_disequation(const linear_expression_t& e) {
        // XXX: similar precision as the interval domain
        for (const auto& [variable, coefficient] : e.variable_terms()) {
            interval_t i = compute_residual(e, variable) / interval_t(coefficient);
            if (auto k = i.singleton()) {
                add_univar_disequation(variable, *k);
            }
        }
        normalize();
    }

    interval_t get_interval(variable_t x) const { return get_interval(vert_map, g, x); }

    static interval_t get_interval(const vert_map_t& m, const graph_t& r, variable_t x) {
        auto it = m.find(x);
        if (it == m.end()) {
            return interval_t::top();
        }
        vert_id v = (*it).second;
        interval_t x_out = interval_t(r.elem(v, 0) ? -number_t(r.edge_val(v, 0)) : bound_t::minus_infinity(),
                                      r.elem(0, v) ? number_t(r.edge_val(0, v)) : bound_t::plus_infinity());
        return x_out;
    }

    // Restore potential after an edge addition
    bool repair_potential(vert_id src, vert_id dest) { return GrOps::repair_potential(g, potential, src, dest); }

    // Restore closure after a single edge addition
    void close_over_edge(vert_id ii, vert_id jj);

  public:
    explicit SplitDBM(bool is_bottom = false) : _is_bottom(is_bottom) {
        g.growTo(1); // Allocate the zero vector
        potential.emplace_back(0);
        rev_map.push_back(std::nullopt);
    }

    // FIXME: Rewrite to avoid copying if o is _|_
    SplitDBM(vert_map_t&& _vert_map, rev_map_t&& _rev_map, graph_t&& _g, std::vector<Weight>&& _potential,
             vert_set_t&& _unstable)
        : vert_map(std::move(_vert_map)), rev_map(std::move(_rev_map)), g(std::move(_g)),
          potential(std::move(_potential)), unstable(std::move(_unstable)), _is_bottom(false) {

        CrabStats::count("SplitDBM.count.copy");
        ScopedCrabStats __st__("SplitDBM.copy");

        CRAB_LOG("zones-split-size", auto p = size();
                 std::cout << "#nodes = " << p.first << " #edges=" << p.second << "\n";);

        assert(g.size() > 0);
        normalize();
    }

    SplitDBM(const SplitDBM& o) = default;
    SplitDBM(SplitDBM&& o) = default;

    SplitDBM& operator=(const SplitDBM& o) = default;
    SplitDBM& operator=(SplitDBM&& o) = default;

    void set_to_top() {
        this->~SplitDBM();
        new (this) SplitDBM(false);
    }

    void set_to_bottom() {
        this->~SplitDBM();
        new (this) SplitDBM(true);
    }

    bool is_bottom() const { return _is_bottom; }

    static SplitDBM top() { return SplitDBM(false); }

    static SplitDBM bottom() { return SplitDBM(true); }

    bool is_top() const {
        if (_is_bottom)
            return false;
        return g.is_empty();
    }

    bool operator<=(const SplitDBM& o) const;

    // FIXME: can be done more efficient
    void operator|=(const SplitDBM& o) { *this = *this | o; }
    void operator|=(SplitDBM&& o) {
        if (is_bottom()) {
            std::swap(*this, o);
        } else {
            *this = *this | o;
        }
    }

    SplitDBM operator|(const SplitDBM& o) const&;

    SplitDBM operator|(SplitDBM&& o) && {
        if (is_bottom() || o.is_top())
            return std::move(o);
        if (is_top() || o.is_bottom())
            return std::move(*this);
        return ((const SplitDBM&)*this) | (const SplitDBM&)o;
    }

    SplitDBM operator|(const SplitDBM& o) && {
        if (is_top() || o.is_bottom())
            return std::move(*this);
        return ((const SplitDBM&)*this) | o;
    }

    SplitDBM operator|(SplitDBM&& o) const& {
        if (is_bottom() || o.is_top())
            return std::move(o);
        return (*this) | (const SplitDBM&)o;
    }

    SplitDBM widen(const SplitDBM& o) const;

    SplitDBM widening_thresholds(const SplitDBM& o, const iterators::thresholds_t& ts) const {
        // TODO: use thresholds
        return this->widen(o);
    }

    SplitDBM operator&(const SplitDBM& o) const;

    SplitDBM narrow(const SplitDBM& o) const;

    void normalize();

    void operator-=(variable_t v);

    void assign(variable_t x, const linear_expression_t& e);

    void assign(std::optional<variable_t> x, const linear_expression_t& e) {
        if (x) {
            assign(*x, e);
        }
    }
    void assign(variable_t x, signed long long int n) { assign(x, linear_expression_t(n)); }

    void assign(variable_t x, variable_t v) {
        assign(x, linear_expression_t{v});
    }
    void assign(variable_t x, const std::optional<linear_expression_t>& e) {
        if (e) {
            assign(x, *e);
        } else {
            *this -= x;
        }
    };

    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z);

    void apply(arith_binop_t op, variable_t x, variable_t y, const number_t& k);

    // bitwise_operators_api
    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z);

    void apply(bitwise_binop_t op, variable_t x, variable_t y, const number_t& k);

    void apply(binop_t op, variable_t x, variable_t y, const number_t& z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }

    void apply(binop_t op, variable_t x, variable_t y, variable_t z) {
        std::visit([&](auto top) { apply(top, x, y, z); }, op);
    }

    void operator+=(const linear_constraint_t& cst);

    SplitDBM when(const linear_constraint_t& cst) const {
        SplitDBM res(*this);
        res += cst;
        return res;
    }

    interval_t eval_interval(const linear_expression_t& e) const {
        interval_t r{e.constant_term()};
        for (const auto& [variable, coefficient] : e.variable_terms())
            r += coefficient * operator[](variable);
        return r;
    }

    interval_t operator[](variable_t x) const {
        if (is_bottom()) {
            return interval_t::bottom();
        } else {
            return get_interval(vert_map, g, x);
        }
    }

    void set(variable_t x, const interval_t& intv);

    void forget(const variable_vector_t& variables);

    // -- begin array_sgraph_domain_helper_traits

    // -- end array_sgraph_domain_helper_traits

    // return number of vertices and edges
    std::pair<std::size_t, std::size_t> size() const { return {g.size(), g.num_edges()}; }

  private:
    bool entail_aux(const linear_constraint_t& cst) const {
        SplitDBM dom(*this); // copy is necessary
        dom += cst.negate();
        return dom.is_bottom();
    }

    bool intersect_aux(const linear_constraint_t& cst) const {
        SplitDBM dom(*this); // copy is necessary
        dom += cst;
        return !dom.is_bottom();
    }

  public:
    /*
       Public API

       bool entail(const linear_constraint_t&);

       bool intersect(const linear_constraint_t&);
     */


    // Return true if inv intersects with cst.
    bool intersect(const linear_constraint_t& cst) const {
        if (is_bottom() || cst.is_contradiction())
            return false;
        if (is_top() || cst.is_tautology())
            return true;
        return intersect_aux(cst);
    }

    // Return true if entails rhs.
    bool entail(const linear_constraint_t& rhs) const {
        if (is_bottom())
            return true;
        if (rhs.is_tautology())
            return true;
        if (rhs.is_contradiction())
            return false;
        interval_t interval = eval_interval(rhs.expression());
        switch (rhs.kind()) {
        case constraint_kind_t::EQUALS_ZERO:
            if (interval.singleton() == std::optional<number_t>(number_t(0)))
                return true;
            break;
        case constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO:
            if (interval.ub() <= number_t(0))
                return true;
            break;
        case constraint_kind_t::LESS_THAN_ZERO:
            if (interval.ub() < number_t(0))
                return true;
            break;
        case constraint_kind_t::NOT_ZERO:
            if (interval.ub() < number_t(0) || interval.lb() > number_t(0))
                return true;
            break;
        }
        if (rhs.kind() == constraint_kind_t::EQUALS_ZERO) {
            // try to convert the equality into inequalities so when it's
            // negated we do not have disequalities.
            return entail_aux(linear_constraint_t(rhs.expression(), constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO)) &&
                   entail_aux(linear_constraint_t(rhs.expression() * number_t(-1),
                                                  constraint_kind_t::LESS_THAN_OR_EQUALS_ZERO));
        } else {
            return entail_aux(rhs);
        }

        // Note: we cannot convert rhs into SplitDBM and then use the <=
        //       operator. The problem is that we cannot know for sure
        //       whether SplitDBM can represent precisely rhs. It is not
        //       enough to do something like
        //
        //       SplitDBM dom = rhs;
        //       if (dom.is_top()) { ... }
    }

    friend std::ostream& operator<<(std::ostream& o, const SplitDBM& dom);
    string_invariant to_set() const;
}; // class SplitDBM

} // namespace domains
} // namespace crab
