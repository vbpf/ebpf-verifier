/*******************************************************************************
 * Extend abstract domains with very specialized operations.
 ******************************************************************************/

#pragma once

namespace crab {

namespace domains {

// Perform constraint simplifications depending on the abstract domain
template <typename Domain>
class constraint_simp_domain_traits {
  public:
    using number_t = typename Domain::number_t;
    using linear_constraint_t = typename Domain::linear_constraint_t;
    using linear_constraint_system_t = typename Domain::linear_constraint_system_t;

    // Convert an equality into two inequalities. This is not
    // possible for machine arithmetic domains.
    static void lower_equality(linear_constraint_t cst, linear_constraint_system_t &csts) {
        if (cst.is_equality()) {
            csts += linear_constraint_t(cst.expression(), linear_constraint_t::INEQUALITY);
            csts += linear_constraint_t(cst.expression() * number_t(-1), linear_constraint_t::INEQUALITY);
        } else {
            csts += cst;
        }
    }
};

// Special operations needed by the checker
template <typename Domain>
class checker_domain_traits {
  public:
    using varname_t = typename Domain::varname_t;
    using number_t = typename Domain::number_t;
    using linear_constraint_t = typename Domain::linear_constraint_t;
    using linear_constraint_system_t = typename Domain::linear_constraint_system_t;

  private:
    struct entailment {
        Domain _dom;
        entailment(Domain dom) : _dom(dom) {}
        bool operator()(const linear_constraint_t &cst) {
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
    static bool entail(Domain &lhs, const linear_constraint_t &rhs) {
        if (lhs.is_bottom())
            return true;
        if (rhs.is_tautology())
            return true;
        if (rhs.is_contradiction())
            return false;

        CRAB_LOG("checker-entailment", linear_constraint_t tmp(rhs); crab::outs()
                                                                     << "Checking whether\n"
                                                                     << lhs << "\nentails " << tmp << "\n";);

        bool res;
        entailment op(lhs);
        if (rhs.is_equality()) {
            // try to convert the equality into inequalities so when it's
            // negated we do not have disequalities.
            linear_constraint_system_t inequalities;
            constraint_simp_domain_traits<Domain>::lower_equality(rhs, inequalities);
            res = std::all_of(inequalities.begin(), inequalities.end(), op);
        } else {
            res = op(rhs);
        }

        CRAB_LOG("checker-entailment", if (res) { crab::outs() << "\t**entailment holds.\n"; } else {
            crab::outs() << "\t**entailment does not hold.\n";
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
    static bool intersect(Domain &inv, const linear_constraint_t &cst) {
        if (inv.is_bottom() || cst.is_contradiction())
            return false;
        if (inv.is_top() || cst.is_tautology())
            return true;

        Domain dom(inv);
        dom += cst;
        return !dom.is_bottom();
    }
};

// Special operations for applying reduction between domains.
template <typename Domain>
class reduced_domain_traits {
  public:
    using variable_t = typename Domain::variable_t;
    using linear_constraint_t = typename Domain::linear_constraint_t;
    using linear_constraint_system_t = typename Domain::linear_constraint_system_t;

    // extract linear constraints from dom involving x and store in
    // ctsts
    static void extract(Domain &dom, const variable_t &x, linear_constraint_system_t &csts, bool only_equalities) {
        auto all_csts = dom.to_linear_constraint_system();
        for (auto cst : all_csts) {
            if (only_equalities && (!cst.is_equality())) {
                continue;
            }
            auto vars = cst.variables();
            if (vars[x]) {
                csts += cst;
            }
        }
    }
};

// Experimental (TO BE REMOVED):
//
// Special operations needed by array_sparse_graph domain's
// clients.
template <typename Domain>
class array_sgraph_domain_traits {
  public:
    template <class CFG>
    static void do_initialization(CFG cfg) {}
};

// Operations needed by the array_sparse_graph domain.
template <typename Domain>
class array_sgraph_domain_helper_traits {
  public:
    using linear_constraint_t = typename Domain::linear_constraint_t;
    using variable_vector_t = typename Domain::variable_vector_t;

    // FIXME: this does similar thing to
    // checker_domain_traits<Domain>::entail
    static bool is_unsat(Domain &inv, linear_constraint_t cst) {
        Domain copy(inv);
        copy += cst;
        return copy.is_bottom();
    }

    static void active_variables(Domain &inv, variable_vector_t &out) {
        CRAB_ERROR("operation active_variables not implemented");
    }
};

} // end namespace domains
} // end namespace crab
