#pragma once

/*
   Implementation of the abstract transfer functions by reducing them
   to abstract domain operations.

   These are the main Crab statements for which we define their abstract
   transfer functions:

   ARITHMETIC and BOOLEAN
     x := y bin_op z;
     x := y;
     assume(cst)
     assert(cst);
     x := select(cond, y, z);

   ARRAYS
     a[l...u] := v (a,b are arrays and v can be bool/integer/pointer)
     a[i] := v;
     v := a[i];
     a := b

   POINTERS
     *p = q;
     p = *q;
     p := q+n
     p := &obj;
     p := &fun
     p := null;

   FUNCTIONS
     x := foo(arg1,...,argn);
     return r;

   havoc(x);

 */

#include "crab/abstract_domain_operators.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/stats.hpp"

namespace crab {
namespace analyzer {

/**
 * API abstract transformer
 **/
template <typename Number, typename VariableName>
class abs_transformer_api : public crab::cfg::statement_visitor {
  public:


    using var_t = ikos::variable<number_t, VariableName>;
    using lin_exp_t = ikos::linear_expression<number_t, VariableName>;
    using lin_cst_t = ikos::linear_constraint<number_t, VariableName>;
    using lin_cst_sys_t = ikos::linear_constraint_system<number_t, VariableName>;

    using havoc_t = crab::cfg::havoc_stmt<number_t, VariableName>;
    using unreach_t = crab::cfg::unreachable_stmt<number_t, VariableName>;

    using bin_op_t = crab::cfg::binary_op<number_t, VariableName>;
    using assign_t = crab::cfg::assignment<number_t, VariableName>;
    using assume_t = crab::cfg::assume_stmt<number_t, VariableName>;
    using select_t = crab::cfg::select_stmt<number_t, VariableName>;
    using assert_t = crab::cfg::assert_stmt<number_t, VariableName>;

    using int_cast_t = crab::cfg::int_cast_stmt<number_t, VariableName>;

    using arr_init_t = crab::cfg::array_init_stmt<number_t, VariableName>;
    using arr_store_t = crab::cfg::array_store_stmt<number_t, VariableName>;
    using arr_load_t = crab::cfg::array_load_stmt<number_t, VariableName>;
    using arr_assign_t = crab::cfg::array_assign_stmt<number_t, VariableName>;

  protected:
    virtual void exec(havoc_t &) {}
    virtual void exec(unreach_t &) {}
    virtual void exec(bin_op_t &) {}
    virtual void exec(assign_t &) {}
    virtual void exec(assume_t &) {}
    virtual void exec(select_t &) {}
    virtual void exec(assert_t &) {}
    virtual void exec(int_cast_t &) {}
    virtual void exec(arr_init_t &) {}
    virtual void exec(arr_store_t &) {}
    virtual void exec(arr_load_t &) {}
    virtual void exec(arr_assign_t &) {}

  public: /* visitor api */
    void visit(havoc_t &s) { exec(s); }
    void visit(unreach_t &s) { exec(s); }
    void visit(bin_op_t &s) { exec(s); }
    void visit(assign_t &s) { exec(s); }
    void visit(assume_t &s) { exec(s); }
    void visit(select_t &s) { exec(s); }
    void visit(assert_t &s) { exec(s); }
    void visit(int_cast_t &s) { exec(s); }
    void visit(arr_init_t &s) { exec(s); }
    void visit(arr_store_t &s) { exec(s); }
    void visit(arr_load_t &s) { exec(s); }
    void visit(arr_assign_t &s) { exec(s); }
};

/**
 * Abstract forward transformer for all statements. Function calls
 * can be redefined by derived classes. By default, all function
 * calls are ignored in a sound manner (by havoc'ing all outputs).
 **/
template <class AbsD>
class intra_abs_transformer : public abs_transformer_api<number_t, varname_t> {

  public:
    using abs_dom_t = AbsD;

    using variable_t = typename abs_dom_t::variable_t;

  public:
    using abs_transform_api_t = abs_transformer_api<number_t, varname_t>;
    using typename abs_transform_api_t::arr_assign_t;
    using typename abs_transform_api_t::arr_init_t;
    using typename abs_transform_api_t::arr_load_t;
    using typename abs_transform_api_t::arr_store_t;
    using typename abs_transform_api_t::assert_t;
    using typename abs_transform_api_t::assign_t;
    using typename abs_transform_api_t::assume_t;
    using typename abs_transform_api_t::bin_op_t;
    using typename abs_transform_api_t::havoc_t;
    using typename abs_transform_api_t::int_cast_t;
    using typename abs_transform_api_t::lin_cst_sys_t;
    using typename abs_transform_api_t::lin_cst_t;
    using typename abs_transform_api_t::lin_exp_t;
    using typename abs_transform_api_t::select_t;
    using typename abs_transform_api_t::unreach_t;
    using typename abs_transform_api_t::var_t;

  protected:
    /// XXX: the transformer does not own m_inv.
    /// We keep a pointer to avoid unnecessary copies. We don't use a
    /// reference because we might reassign m_inv multiple times.
    abs_dom_t *m_inv;

    bool m_ignore_assert;

  private:
    template <typename NumOrVar>
    void apply(abs_dom_t &inv, binary_operation_t op, variable_t x, variable_t y, NumOrVar z) {
        if (auto top = conv_op<ikos::operation_t>(op)) {
            inv.apply(*top, x, y, z);
        } else if (auto top = conv_op<ikos::bitwise_operation_t>(op)) {
            inv.apply(*top, x, y, z);
        } else {
            CRAB_ERROR("unsupported binary operator", op);
        }
    }

  public:
    intra_abs_transformer(abs_dom_t *inv, bool ignore_assert = false) : m_inv(inv), m_ignore_assert(ignore_assert) {}

    virtual ~intra_abs_transformer() {}

    void set(abs_dom_t *inv) { m_inv = inv; }

    abs_dom_t *get() {
        if (!m_inv) {
            CRAB_ERROR("Invariant passed to transformer cannot be null!");
        } else {
            return m_inv;
        }
    }

    void exec(bin_op_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        auto op1 = stmt.left();
        auto op2 = stmt.right();
        if (op1.get_variable() && op2.get_variable()) {
            apply(*get(), stmt.op(), stmt.lhs(), (*op1.get_variable()), (*op2.get_variable()));
        } else {
            assert(op1.get_variable() && op2.is_constant());
            apply(*get(), stmt.op(), stmt.lhs(), (*op1.get_variable()), op2.constant());
        }

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(select_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        abs_dom_t inv1(*get());
        abs_dom_t inv2(*get());

        inv1 += stmt.cond();
        inv2 += stmt.cond().negate();

        if (::crab::CrabSanityCheckFlag) {
            if (!pre_bot && (inv1.is_bottom() && inv2.is_bottom())) {
                CRAB_ERROR("select condition and its negation cannot be false simultaneously ", stmt);
            }
        }

        if (inv2.is_bottom()) {
            inv1.assign(stmt.lhs(), stmt.left());
            *get() = inv1;
        } else if (inv1.is_bottom()) {
            inv2.assign(stmt.lhs(), stmt.right());
            *get() = inv2;
        } else {
            inv1.assign(stmt.lhs(), stmt.left());
            inv2.assign(stmt.lhs(), stmt.right());
            *get() = inv1 | inv2;
        }

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(assign_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->assign(stmt.lhs(), stmt.rhs());

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(assume_t &stmt) { *get() += stmt.constraint(); }

    void exec(assert_t &stmt) {
        if (m_ignore_assert)
            return;

        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        *get() += stmt.constraint();

        if (::crab::CrabSanityCheckFlag) {
            if (!stmt.constraint().is_contradiction()) {
                bool post_bot = get()->is_bottom();
                if (!(pre_bot || !post_bot)) {
                    CRAB_WARN("Invariant became bottom after ", stmt, ".",
                              " This might indicate that the assertion is violated");
                }
            }
        }
    }

    void exec(int_cast_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        if (auto op = conv_op<crab::domains::int_conv_operation_t>(stmt.op())) {
            get()->apply(*op, stmt.dst(), stmt.src());
        } else {
            CRAB_ERROR("unsupported cast operator ", stmt.op());
        }

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(havoc_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        (*get()) -= stmt.variable();

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(unreach_t &stmt) { *get() = abs_dom_t::bottom(); }

    void exec(arr_init_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->array_init(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.val());

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(arr_store_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        if (stmt.lb_index().equal(stmt.ub_index())) {
            get()->array_store(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.value(), stmt.is_singleton());
        } else {
            get()->array_store_range(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.value());
        }

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(arr_load_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->array_load(stmt.lhs(), stmt.array(), stmt.elem_size(), stmt.index());

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(arr_assign_t &stmt) {
        bool pre_bot = false;
        if (::crab::CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->array_assign(stmt.lhs(), stmt.rhs());

        if (::crab::CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }
};

///////////////////////////////////////
/// For inter-procedural analysis
///////////////////////////////////////

template <typename AbsDom>
class inter_transformer_helpers {
  public:
    using linear_expression_t = typename AbsDom::linear_expression_t;
    using variable_t = typename AbsDom::variable_t;


    static void unify(AbsDom &inv, variable_t lhs, variable_t rhs) {
        assert(lhs.get_type() == rhs.get_type());
        switch (lhs.get_type()) {
        case INT_TYPE:
            inv.assign(lhs, rhs);
            break;
        case ARR_INT_TYPE:
            inv.array_assign(lhs, rhs);
            break;
        default:
            CRAB_ERROR("unsuported type");
        }
    }
};

/////////////////////////////////
/// For backward analysis
/////////////////////////////////

/**
 * Abstract transformer to compute necessary preconditions.
 **/
template <class AbsD, class InvT>
class intra_necessary_preconditions_abs_transformer
    : public abs_transformer_api<number_t, varname_t> {
  public:
    using abs_dom_t = AbsD;

    using variable_t = typename abs_dom_t::variable_t;
    using statement_t = crab::cfg::statement<number_t, varname_t>;
    using abs_transform_api_t = abs_transformer_api<number_t, varname_t>;
    using typename abs_transform_api_t::arr_assign_t;
    using typename abs_transform_api_t::arr_init_t;
    using typename abs_transform_api_t::arr_load_t;
    using typename abs_transform_api_t::arr_store_t;
    using typename abs_transform_api_t::assert_t;
    using typename abs_transform_api_t::assign_t;
    using typename abs_transform_api_t::assume_t;
    using typename abs_transform_api_t::bin_op_t;
    using typename abs_transform_api_t::havoc_t;
    using typename abs_transform_api_t::int_cast_t;
    using typename abs_transform_api_t::lin_cst_sys_t;
    using typename abs_transform_api_t::lin_cst_t;
    using typename abs_transform_api_t::lin_exp_t;
    using typename abs_transform_api_t::select_t;
    using typename abs_transform_api_t::unreach_t;
    using typename abs_transform_api_t::var_t;

  private:
    // used to compute the (necessary) preconditions
    abs_dom_t *m_pre;
    // used to refine the preconditions: map from statement_t to abs_dom_t.
    InvT *m_invariants;
    // ignore assertions
    bool m_ignore_assert;
    // if m_ignore_assert is false then enable compute preconditions
    // from good states, otherwise from bad states (by negating the
    // conditions of the assert statements).
    bool m_good_states;

  public:
    intra_necessary_preconditions_abs_transformer(abs_dom_t *post, InvT *invars, bool good_states,
                                                  bool ignore_assert = false)
        : m_pre(post), m_invariants(invars), m_ignore_assert(ignore_assert), m_good_states(good_states) {

        if (!m_invariants) {
            CRAB_ERROR("Invariant table cannot be null");
        }

        if (!m_pre) {
            CRAB_ERROR("Postcondition cannot be null");
        }
    }

    ~intra_necessary_preconditions_abs_transformer() = default;

    abs_dom_t &preconditions() { return *m_pre; }

    void exec(bin_op_t &stmt) {
        auto op = conv_op<ikos::operation_t>(stmt.op());
        if (!op || op >= ikos::OP_UDIV) {
            // ignore UDIV, SREM, UREM
            // CRAB_WARN("backward operation ", stmt.op(), " not implemented");
            (*m_pre) -= stmt.lhs();
            return;
        }

        auto op1 = stmt.left();
        auto op2 = stmt.right();
        abs_dom_t invariant = (*m_invariants)[&stmt];

        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt.lhs() << " := " << op1 << " " << *op << " " << op2 << "\n"
                                             << "\tFORWARD INV=" << invariant << "\n"
                                             << "\tPOST=" << *m_pre << "\n");

        if (op1.get_variable() && op2.get_variable()) {
            m_pre->backward_apply(*op, stmt.lhs(), (*op1.get_variable()), (*op2.get_variable()), invariant);
        } else {
            assert(op1.get_variable() && op2.is_constant());
            m_pre->backward_apply(*op, stmt.lhs(), (*op1.get_variable()), op2.constant(), invariant);
        }
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    // select(x := cond ? e1: e2, post) can be reduced to
    //   pre: goto b_then;
    //   pre: goto b_else;
    //   b_then:
    //     assume(cond);
    //     x := e1;
    //     goto post;
    //   b_else:
    //     assume(not(cond));
    //     x := e2;
    //     goto post;
    //   post: ....
    void exec(select_t &stmt) {
        abs_dom_t old_pre = (*m_invariants)[&stmt];

        // -- one of the two branches is false
        abs_dom_t then_inv(old_pre);
        then_inv += stmt.cond();
        if (then_inv.is_bottom()) {
            m_pre->backward_assign(stmt.lhs(), stmt.right(), old_pre);
            *m_pre += stmt.cond().negate();
            return;
        }

        abs_dom_t else_inv(old_pre);
        else_inv += stmt.cond().negate();
        if (else_inv.is_bottom()) {
            m_pre->backward_assign(stmt.lhs(), stmt.left(), old_pre);
            *m_pre += stmt.cond();
            return;
        }

        // -- both branches can be possible so we join them
        abs_dom_t pre_then(*m_pre);
        pre_then.backward_assign(stmt.lhs(), stmt.left(), old_pre);
        pre_then += stmt.cond();

        abs_dom_t pre_else(*m_pre);
        pre_else.backward_assign(stmt.lhs(), stmt.right(), old_pre);
        pre_else += stmt.cond().negate();

        *m_pre = pre_then | pre_else;
    }

    // x := e
    void exec(assign_t &stmt) {
        abs_dom_t invariant = (*m_invariants)[&stmt];

        CRAB_LOG("backward-tr", auto rhs = stmt.rhs(); crab::outs() << "** " << stmt.lhs() << " := " << rhs << "\n"
                                                                    << "\tFORWARD INV=" << invariant << "\n"
                                                                    << "\tPOST=" << *m_pre << "\n");

        m_pre->backward_assign(stmt.lhs(), stmt.rhs(), invariant);
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    // assume(c)
    // the precondition must contain c so forward and backward are the same.
    void exec(assume_t &stmt) {
        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                             << "\tPOST=" << *m_pre << "\n");
        *m_pre += stmt.constraint();
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    // assert(c)
    void exec(assert_t &stmt) {
        if (!m_ignore_assert) {
            CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                                 << "\tPOST=" << *m_pre << "\n");
            if (m_good_states) {
                // similar to assume(c)
                *m_pre += stmt.constraint();
            } else {
                // here we are interested in computing preconditions of the
                // error states. Thus, we propagate backwards "not c" which
                // represents the error states.
                abs_dom_t error;
                error += stmt.constraint().negate();
                // we need to join to consider all possible preconditions to
                // error. Otherwise, if we would have two assertions
                // "assert(x >= -2); assert(x <= 2);" we would have
                // incorrectly contradictory constraints.
                *m_pre |= error;
            }

            CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
        }
    }

    // similar to assume(false)
    void exec(unreach_t &stmt) { *m_pre = abs_dom_t::bottom(); }

    // x := *
    // x can be anything before the assignment
    void exec(havoc_t &stmt) { *m_pre -= stmt.variable(); }

    void exec(int_cast_t &stmt) {
        abs_dom_t invariant = (*m_invariants)[&stmt];
        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                             << "\tPOST=" << *m_pre << "\n");
        m_pre->backward_assign(stmt.dst(), stmt.src(), invariant);
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    void exec(arr_init_t &stmt) {
        abs_dom_t invariant = (*m_invariants)[&stmt];

        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                             << "\tFORWARD INV=" << invariant << "\n"
                                             << "\tPOST=" << *m_pre << "\n");
        m_pre->backward_array_init(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.val(),
                                   invariant);
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    void exec(arr_load_t &stmt) {
        abs_dom_t invariant = (*m_invariants)[&stmt];

        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                             << "\tFORWARD INV=" << invariant << "\n"
                                             << "\tPOST=" << *m_pre << "\n");
        m_pre->backward_array_load(stmt.lhs(), stmt.array(), stmt.elem_size(), stmt.index(), invariant);
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    void exec(arr_store_t &stmt) {
        abs_dom_t invariant = (*m_invariants)[&stmt];
        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                             << "\tFORWARD INV=" << invariant << "\n"
                                             << "\tPOST=" << *m_pre << "\n");
        if (stmt.lb_index().equal(stmt.ub_index())) {
            m_pre->backward_array_store(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.value(),
                                        stmt.is_singleton(), invariant);
        } else {
            m_pre->backward_array_store_range(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(),
                                              stmt.value(), invariant);
        }
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }

    void exec(arr_assign_t &stmt) {
        abs_dom_t invariant = (*m_invariants)[&stmt];
        CRAB_LOG("backward-tr", crab::outs() << "** " << stmt << "\n"
                                             << "\tFORWARD INV=" << invariant << "\n"
                                             << "\tPOST=" << *m_pre << "\n");
        m_pre->backward_array_assign(stmt.lhs(), stmt.rhs(), invariant);
        CRAB_LOG("backward-tr", crab::outs() << "\tPRE=" << *m_pre << "\n");
    }
};

} // namespace analyzer
} // namespace crab
