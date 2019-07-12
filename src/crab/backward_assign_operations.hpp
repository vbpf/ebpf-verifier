#pragma once

/**
 * Implement generic backward assignments.
 *
 * Be aware that unless the assignment is invertible the result is an
 * over-approximation so we need to adapt these operations in case we
 * need under-approximations.
 **/

#include "crab/abstract_domain_operators.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

namespace crab {
namespace domains {

template <class AbsDom>
class BackwardAssignOps {
  public:

    using variable_t = typename AbsDom::variable_t;
    using linear_constraint_t = typename AbsDom::linear_constraint_t;
    using linear_expression_t = typename AbsDom::linear_expression_t;

    /*
     * Backward x := e
     *
     *  General case:
     *   if x does not appear in e
     *      1) add constraint x = e
     *      2) forget x
     *   else
     *      1) add new variable x'
     *      2) add constraint x = e[x'/x]
     *      3) forget x
     *      4) rename x' as x
     *
     *  Invertible operation (y can be equal to x):
     *    x = y + k <--> y = x - k
     *    x = y - k <--> y = x + k
     *    x = y * k <--> y = x / k  if (k != 0)
     *    x = y / k <--> y = x * k  if (k != 0)
     *
     *  Fallback case:
     *   forget(x)
     **/

    // x := e
    static void assign(AbsDom &dom, variable_t x, linear_expression_t e, AbsDom inv) {
        crab::CrabStats::count(AbsDom::getDomainName() + ".count.backward_assign");
        crab::ScopedCrabStats __st__(AbsDom::getDomainName() + ".backward_assign");

        if (dom.is_bottom())
            return;

        if (e.variables() >= x) {
            auto &vfac = x.name().get_var_factory();
            variable_t old_x(vfac.get(), x.get_type());
            std::map<variable_t, variable_t> renaming_map;
            renaming_map.insert({x, old_x});
            linear_expression_t renamed_e = e.rename(renaming_map);
            dom += linear_constraint_t(renamed_e - x, linear_constraint_t::EQUALITY);
            dom -= x;
            dom.rename({old_x}, {x});
        } else {
            dom += linear_constraint_t(e - x, linear_constraint_t::EQUALITY);
            dom -= x;
        }
        dom = dom & inv;
    }

    // x := y op k
    static void apply(AbsDom &dom, operation_t op, variable_t x, variable_t y, number_t k, AbsDom inv) {
        crab::CrabStats::count(AbsDom::getDomainName() + ".count.backward_apply");
        crab::ScopedCrabStats __st__(AbsDom::getDomainName() + ".backward_apply");

        if (dom.is_bottom()) {
            return;
        }

        CRAB_LOG("backward", crab::outs() << x << ":=" << y << " " << op << " " << k << "\n"
                                          << "BEFORE " << dom << "\n";);

        switch (op) {
        case OP_ADDITION:
            dom.apply(OP_SUBTRACTION, y, x, k);
            if (!(x == y)) {
                dom -= x;
            }
            break;
        case OP_SUBTRACTION:
            dom.apply(OP_ADDITION, y, x, k);
            if (!(x == y)) {
                dom -= x;
            }
            break;
        case OP_MULTIPLICATION:
            if (k != 0) {
                dom.apply(OP_SDIV, y, x, k);
                if (!(x == y)) {
                    dom -= x;
                }
            } else {
                dom -= x;
            }
            break;
        case OP_SDIV:
            if (k != 0) {
                dom.apply(OP_MULTIPLICATION, y, x, k);
                if (!(x == y)) {
                    dom -= x;
                }
            } else {
                dom -= x;
            }
            break;
        case OP_UDIV:
        case OP_SREM:
        case OP_UREM:
        default:
            CRAB_WARN("backwards x:= y ", op, " k is not implemented");
            dom -= x;
        }

        dom = dom & inv;

        CRAB_LOG("backward", crab::outs() << "AFTER " << dom << "\n");
        return;
    }

    // x = y op z
    static void apply(AbsDom &dom, operation_t op, variable_t x, variable_t y, variable_t z, AbsDom inv) {
        crab::CrabStats::count(AbsDom::getDomainName() + ".count.backward_apply");
        crab::ScopedCrabStats __st__(AbsDom::getDomainName() + ".backward_apply");

        if (dom.is_bottom()) {
            return;
        }

        CRAB_LOG("backward", crab::outs() << x << ":=" << y << " " << op << " " << z << "\n"
                                          << "BEFORE " << dom << "\n";);

        switch (op) {
        case OP_ADDITION:
            assign(dom, x, linear_expression_t(y + z), inv);
            break;
        case OP_SUBTRACTION:
            assign(dom, x, linear_expression_t(y - z), inv);
            break;
        case OP_MULTIPLICATION:
        case OP_SDIV:
        case OP_UDIV:
        case OP_SREM:
        case OP_UREM:
            CRAB_WARN("backwards x = y ", op, " z not implemented");
            dom -= x;
            break;
        }
        dom = dom & inv;
        CRAB_LOG("backward", crab::outs() << "AFTER " << dom << "\n");
    }
};

} // end namespace domains
} // end namespace crab
