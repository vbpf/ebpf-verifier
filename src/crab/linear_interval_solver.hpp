/*******************************************************************************
 *
 * Resolution of a system of linear constraints over the domain of intervals
 * is based on W. Harvey & P. J. Stuckey's paper: Improving linear constraint
 * propagation by changing constraint representation, in Constraints,
 * 8(2):173–207, 2003.
 *
 * Author: Arnaud J. Venet (arnaud.j.venet@nasa.gov)
 *
 * Contributors: Alexandre C. D. Wimmers (alexandre.c.wimmers@nasa.gov)
 *               Jorge Navas (jorge.navas@sri.com)
 * Notices:
 *
 * Copyright (c) 2011 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Disclaimers:
 *
 * No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF
 * ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED
 * TO, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS,
 * ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL BE
 * ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM TO
 * THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
 * ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS,
 * RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS
 * RESULTING FROM USE OF THE SUBJECT SOFTWARE.  FURTHER, GOVERNMENT AGENCY
 * DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY SOFTWARE,
 * IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
 *
 * Waiver and Indemnity:  RECIPIENT AGREES TO WAIVE ANY AND ALL CLAIMS AGAINST
 * THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL
 * AS ANY PRIOR RECIPIENT.  IF RECIPIENT'S USE OF THE SUBJECT SOFTWARE RESULTS
 * IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES OR LOSSES ARISING FROM SUCH
 * USE, INCLUDING ANY DAMAGES FROM PRODUCTS BASED ON, OR RESULTING FROM,
 * RECIPIENT'S USE OF THE SUBJECT SOFTWARE, RECIPIENT SHALL INDEMNIFY AND HOLD
 * HARMLESS THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS,
 * AS WELL AS ANY PRIOR RECIPIENT, TO THE EXTENT PERMITTED BY LAW.
 * RECIPIENT'S SOLE REMEDY FOR ANY SUCH MATTER SHALL BE THE IMMEDIATE,
 * UNILATERAL TERMINATION OF THIS AGREEMENT.
 *
 ******************************************************************************/

#pragma once

#include "crab/bignums.hpp"
#include "crab/debug.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"
#include "crab/wrapint.hpp"
#include <boost/optional.hpp>
#include <map>
#include <set>
#include <vector>

namespace ikos {

// Interval traits:
// The solver is parametric on the kind of Interval
namespace linear_interval_solver_impl {
// gamma(i) \ gamma(j)
template <typename Interval>
inline Interval trim_interval(Interval i, Interval j);

template <typename Interval, typename Number>
inline Interval mk_interval(Number n, typename crab::wrapint::bitwidth_t bitwidth) {
    // default implementation ignores bitwidth
    return Interval(n);
}

template <typename Interval>
Interval lower_half_line(Interval i, bool is_signed);

template <typename Interval>
Interval upper_half_line(Interval i, bool is_signed);
} // namespace linear_interval_solver_impl

template <typename Number, typename VariableName, typename IntervalCollection>
class linear_interval_solver {

  public:
    using Interval = typename IntervalCollection::value_type;
    using variable_t = variable<Number, VariableName>;
    using linear_expression_t = linear_expression<Number, VariableName>;
    using linear_constraint_t = linear_constraint<Number, VariableName>;
    using linear_constraint_system_t = linear_constraint_system<Number, VariableName>;
    using bitwidth_t = typename variable_t::bitwidth_t;

  private:
    using cst_table_t = std::vector<linear_constraint_t>;
    using uint_set_t = std::set<unsigned int>;
    using trigger_table_t = std::map<variable_t, uint_set_t>;
    using variable_set_t = typename linear_constraint_t::variable_set_t;

    std::size_t m_max_cycles;
    std::size_t m_max_op;
    bool m_is_contradiction;
    bool m_is_large_system;
    cst_table_t m_cst_table;
    trigger_table_t m_trigger_table;
    variable_set_t m_refined_variables;
    std::size_t m_op_count;

    static const std::size_t _large_system_cst_threshold = 3;
    // cost of one propagation cycle for a dense 3x3 system of constraints
    static const std::size_t _large_system_op_threshold = 27;

    // return true if bottom
    bool refine(variable_t v, Interval i, IntervalCollection &env) {
        crab::ScopedCrabStats __st__("Linear Interval Solver.Solving refinement");
        CRAB_LOG("integer-solver", crab::outs() << "\tRefine " << v << " with " << i << "\n";);
        Interval old_i = env[v];
        Interval new_i = old_i & i;
        CRAB_LOG("integer-solver", crab::outs() << "\tOld=" << old_i << " New=" << new_i << "\n";);
        if (new_i.is_bottom()) {
            return true;
        }
        if (!(old_i == new_i)) {
            env.set(v, new_i);
            m_refined_variables += v;
            ++(m_op_count);
        }
        return false;
    }

    Interval compute_residual(const linear_constraint_t &cst, variable_t pivot, IntervalCollection &env) {
        crab::ScopedCrabStats __st__("Linear Interval Solver.Solving computing residual");
        namespace interval_traits = linear_interval_solver_impl;
        bitwidth_t w = pivot.get_bitwidth();
        Interval residual = interval_traits::mk_interval<Interval>(cst.constant(), w);
        for (typename linear_constraint_t::const_iterator it = cst.begin(); it != cst.end(); ++it) {
            variable_t v = it->second;
            if (!(v == pivot)) {
                residual = residual - (interval_traits::mk_interval<Interval>(it->first, w) * env[v]);
                ++(m_op_count);
                if (residual.is_top())
                    break;
            }
        }
        return residual;
    }

    // return true if bottom found while propagation
    bool propagate(const linear_constraint_t &cst, IntervalCollection &env) {
        crab::ScopedCrabStats __st__("Linear Interval Solver.Solving propagation");
        namespace interval_traits = linear_interval_solver_impl;

        CRAB_LOG("integer-solver", linear_constraint_t tmp(cst);
                 crab::outs() << "Integer solver processing " << tmp << "\n";);

        for (typename linear_constraint_t::const_iterator it = cst.begin(), et = cst.end(); it != et; ++it) {
            Number c = it->first;
            variable_t pivot = it->second;
            Interval res = compute_residual(cst, pivot, env);
            Interval rhs = Interval::top();
            if (!res.is_top()) {
                Interval ic = interval_traits::mk_interval<Interval>(c, pivot.get_bitwidth());
                rhs = res / ic;
            }

            if (cst.is_equality()) {
                if (refine(pivot, rhs, env)) {
                    return true;
                }
            } else if (cst.is_inequality()) {
                if (c > 0) {
                    if (refine(pivot, interval_traits::lower_half_line(rhs, cst.is_signed()), env)) {
                        return true;
                    }
                } else {
                    if (refine(pivot, interval_traits::upper_half_line(rhs, cst.is_signed()), env)) {
                        return true;
                    }
                }
            } else if (cst.is_strict_inequality()) {
                // do nothing
            } else {
                // cst is a disequation
                Interval old_i = env[pivot];
                Interval new_i = interval_traits::trim_interval(old_i, rhs);
                if (new_i.is_bottom()) {
                    return true;
                }
                if (!(old_i == new_i)) {
                    env.set(pivot, new_i);
                    m_refined_variables += pivot;
                }
                ++(m_op_count);
            }
        }
        return false;
    }

    bool solve_large_system(IntervalCollection &env) {
        m_op_count = 0;
        m_refined_variables.clear();
        for (typename cst_table_t::iterator it = m_cst_table.begin(); it != m_cst_table.end(); ++it) {
            if (propagate(*it, env)) {
                return true;
            }
        }
        do {
            variable_set_t vars_to_process(m_refined_variables);
            m_refined_variables.clear();
            for (typename variable_set_t::iterator it = vars_to_process.begin(); it != vars_to_process.end(); ++it) {
                uint_set_t &csts = m_trigger_table[*it];
                for (typename uint_set_t::iterator cst_it = csts.begin(); cst_it != csts.end(); ++cst_it) {
                    if (propagate(m_cst_table.at(*cst_it), env)) {
                        return true;
                    }
                }
            }
        } while (!m_refined_variables.empty() && m_op_count <= m_max_op);
        return false;
    }

    bool solve_small_system(IntervalCollection &env) {
        std::size_t cycle = 0;
        do {
            ++cycle;
            m_refined_variables.clear();
            for (typename cst_table_t::iterator it = m_cst_table.begin(); it != m_cst_table.end(); ++it) {
                if (propagate(*it, env)) {
                    return true;
                }
            }
        } while (!m_refined_variables.empty() && cycle <= m_max_cycles);
        return false;
    }

  public:
    linear_interval_solver(const linear_constraint_system_t &csts, std::size_t max_cycles)
        : m_max_cycles(max_cycles), m_is_contradiction(false), m_is_large_system(false), m_op_count(0) {

        crab::ScopedCrabStats __st_a__("Linear Interval Solver");
        crab::ScopedCrabStats __st_b__("Linear Interval Solver.Preprocessing");
        std::size_t op_per_cycle = 0;
        for (typename linear_constraint_system_t::const_iterator it = csts.begin(); it != csts.end(); ++it) {
            const linear_constraint_t &cst = *it;
            if (cst.is_contradiction()) {
                m_is_contradiction = true;
                return;
            } else if (cst.is_tautology()) {
                continue;
            } else {
                std::size_t cst_size = cst.size();
                if (cst.is_strict_inequality()) {
                    // convert e < c into {e <= c, e != c}
                    linear_constraint_t c1(cst.expression(), linear_constraint_t::kind_t::INEQUALITY);
                    linear_constraint_t c2(cst.expression(), linear_constraint_t::kind_t::DISEQUATION);
                    m_cst_table.push_back(c1);
                    m_cst_table.push_back(c2);
                    cst_size = c1.size() + c2.size();
                } else {
                    m_cst_table.push_back(cst);
                }
                // cost of one reduction step on the constraint in terms
                // of accesses to the interval collection
                op_per_cycle += cst_size * cst_size;
            }
        }

        m_is_large_system =
            (m_cst_table.size() > _large_system_cst_threshold) || (op_per_cycle > _large_system_op_threshold);

        if (!m_is_contradiction && m_is_large_system) {
            m_max_op = op_per_cycle * max_cycles;
            for (unsigned int i = 0; i < m_cst_table.size(); ++i) {
                const linear_constraint_t &cst = m_cst_table.at(i);
                variable_set_t vars = cst.variables();
                for (typename variable_set_t::iterator it = vars.begin(); it != vars.end(); ++it) {
                    m_trigger_table[*it].insert(i);
                }
            }
        }
    }

    void run(IntervalCollection &env) {
        crab::ScopedCrabStats __st_a__("Linear Interval Solver");
        crab::ScopedCrabStats __st_b__("Linear Interval Solver.Solving");
        if (m_is_contradiction) {
            env.set_to_bottom();
        } else {
            bool is_bottom = false;
            if (m_is_large_system) {
                is_bottom = solve_large_system(env);
            } else {
                is_bottom = solve_small_system(env);
            }
            if (is_bottom) {
                env.set_to_bottom();
            }
        }
    }

}; // class linear_interval_solver

} // namespace ikos
