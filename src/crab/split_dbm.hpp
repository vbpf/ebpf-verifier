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

class SplitDBM final {
  public:
    using Params = SafeInt64DefaultParams;
    using graph_t = typename Params::graph_t;
    using Weight = typename Params::Weight;
    using vert_id = typename graph_t::vert_id;
    using vert_map_t = boost::container::flat_map<variable_t, vert_id>;

  private:
    using variable_vector_t = std::vector<variable_t>;

    using rev_map_t = std::vector<std::optional<variable_t>>;
    using GrOps = GraphOps<graph_t>;
    using edge_vector = typename GrOps::edge_vector;
    // < <x, y>, k> == x - y <= k.
    using diffcst_t = std::pair<std::pair<variable_t, variable_t>, Weight>;
    using vert_set_t = std::unordered_set<vert_id>;
    friend class vert_set_wrap_t;

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
    bool _is_bottom{};

    vert_id get_vert(variable_t v);
    // Evaluate the potential value of a variable.
    [[nodiscard]] Weight pot_value(variable_t v) const;

    // Evaluate an expression under the chosen potentials
    [[nodiscard]] Weight eval_expression(const linear_expression_t& e, bool overflow) const;

    [[nodiscard]] interval_t compute_residual(const linear_expression_t& e, variable_t pivot) const;

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
                            std::vector<std::pair<variable_t, Weight>>& ub);

    /**
     * Turn a linear inequality into a set of difference
     * constraints.
     **/
    void diffcsts_of_lin_leq(const linear_expression_t& exp,
                             /* difference constraints */
                             std::vector<diffcst_t>& csts,
                             /* x >= lb for each {x,lb} in lbs */
                             std::vector<std::pair<variable_t, Weight>>& lbs,
                             /* x <= ub for each {x,ub} in ubs */
                             std::vector<std::pair<variable_t, Weight>>& ubs) const;

    bool add_linear_leq(const linear_expression_t& exp);

    // x != n
    void add_univar_disequation(variable_t x, const number_t& n);

    [[nodiscard]] interval_t get_interval(variable_t x, int finite_width) const;

    // Restore potential after an edge addition
    bool repair_potential(vert_id src, vert_id dest) { return GrOps::repair_potential(g, potential, src, dest); }

    void normalize();

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

  public:
    explicit SplitDBM(bool is_bottom = false) : _is_bottom(is_bottom) {
        g.growTo(1); // Allocate the zero vector
        potential.emplace_back(0);
        rev_map.push_back(std::nullopt);
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

    [[nodiscard]] bool is_bottom() const { return _is_bottom; }

    static SplitDBM top() { return SplitDBM(false); }

    static SplitDBM bottom() { return SplitDBM(true); }

    [[nodiscard]] bool is_top() const {
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

    [[nodiscard]] SplitDBM widen(const SplitDBM& o) const;

    [[nodiscard]] SplitDBM widening_thresholds(const SplitDBM& o, const iterators::thresholds_t& ts) const {
        // TODO: use thresholds
        return this->widen(o);
    }

    SplitDBM operator&(const SplitDBM& o) const;

    [[nodiscard]] SplitDBM narrow(const SplitDBM& o) const;

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

    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);

    void apply(arith_binop_t op, variable_t x, variable_t y, const number_t& k, int finite_width);

    // bitwise_operators_api
    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);

    void apply(bitwise_binop_t op, variable_t x, variable_t y, const number_t& k, int finite_width);

    void apply(binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width) {
        std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
    }

    void apply(binop_t op, variable_t x, variable_t y, variable_t z, int finite_width) {
        std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
    }

    void operator+=(const linear_constraint_t& cst);

    [[nodiscard]] SplitDBM when(const linear_constraint_t& cst) const {
        SplitDBM res(*this);
        res += cst;
        return res;
    }

    [[nodiscard]] interval_t eval_interval(const linear_expression_t& e) const;

    interval_t operator[](variable_t x) const;

    void set(variable_t x, const interval_t& intv);

    void forget(const variable_vector_t& variables);

    // return number of vertices and edges
    [[nodiscard]] std::pair<std::size_t, std::size_t> size() const { return {g.size(), g.num_edges()}; }

  private:
    [[nodiscard]] bool entail_aux(const linear_constraint_t& cst) const {
        // copy is necessary
        return this->when(cst.negate()).is_bottom();
    }

    [[nodiscard]] bool intersect_aux(const linear_constraint_t& cst) const {
        // copy is necessary
        return !this->when(cst).is_bottom();
    }

  public:
    // Return true if inv intersects with cst.
    [[nodiscard]] bool intersect(const linear_constraint_t& cst) const;

    // Return true if entails rhs.
    [[nodiscard]] bool entail(const linear_constraint_t& rhs) const;

    friend std::ostream& operator<<(std::ostream& o, const SplitDBM& dom);
    [[nodiscard]] string_invariant to_set() const;
}; // class SplitDBM

} // namespace domains
} // namespace crab
