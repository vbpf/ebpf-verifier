/*******************************************************************************
 * Extend abstract domains with very specialized operations.
 ******************************************************************************/

#pragma once

#include "crab/debug.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/types.hpp"

namespace crab {

namespace domains {

// Special operations needed by the checker
template <typename Domain>
class checker_domain_traits {
  private:
    struct entailment {
        Domain _dom;
        entailment(Domain dom) : _dom(dom) {}
        bool operator()(const linear_constraint_t& cst) {
            Domain dom(_dom); // copy is necessary
            linear_constraint_t neg_cst = cst.negate();
            dom += neg_cst;
            return dom.is_bottom();
        }
    };

  public:
    /*
       Public API

       static bool entail(Domain&, const linear_constraint_t&);

       static bool intersect(Domain&, const linear_constraint_t&);
     */

    // Return true if lhs entails rhs.
    static bool entail(Domain& lhs, const linear_constraint_t& rhs) {
        if (lhs.is_bottom())
            return true;
        if (rhs.is_tautology())
            return true;
        if (rhs.is_contradiction())
            return false;

        CRAB_LOG("checker-entailment", linear_constraint_t tmp(rhs); outs() << "Checking whether\n"
                                                                            << lhs << "\nentails " << tmp << "\n";);

        bool res;
        entailment op(lhs);
        if (rhs.is_equality()) {
            // try to convert the equality into inequalities so when it's
            // negated we do not have disequalities.
            linear_constraint_system_t inequalities;
            inequalities += linear_constraint_t(rhs.expression(), linear_constraint_t::INEQUALITY);
            inequalities += linear_constraint_t(rhs.expression() * number_t(-1), linear_constraint_t::INEQUALITY);
            res = std::all_of(inequalities.begin(), inequalities.end(), op);
        } else {
            res = op(rhs);
        }

        CRAB_LOG("checker-entailment", if (res) { outs() << "\t**entailment holds.\n"; } else {
            outs() << "\t**entailment does not hold.\n";
        });

        // Note: we cannot convert rhs into Domain and then use the <=
        //       operator. The problem is that we cannot know for sure
        //       whether Domain can represent precisely rhs. It is not
        //       enough to do something like
        //
        //       Dom dom = rhs;
        //       if (dom.is_top()) { ... }

        return res;
    }

    // Return true if inv intersects with cst.
    static bool intersect(Domain& inv, const linear_constraint_t& cst) {
        if (inv.is_bottom() || cst.is_contradiction())
            return false;
        if (inv.is_top() || cst.is_tautology())
            return true;

        Domain dom(inv);
        dom += cst;
        return !dom.is_bottom();
    }
};

} // end namespace domains
} // end namespace crab
