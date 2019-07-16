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
class abs_transformer_api : public statement_visitor {
  protected:
    virtual void exec(havoc_t&) {}
    virtual void exec(unreachable_t&) {}
    virtual void exec(binary_op_t&) {}
    virtual void exec(assign_t&) {}
    virtual void exec(assume_t&) {}
    virtual void exec(select_t&) {}
    virtual void exec(assert_t&) {}
    virtual void exec(int_cast_t&) {}
    virtual void exec(array_init_t&) {}
    virtual void exec(array_store_t&) {}
    virtual void exec(array_load_t&) {}
    virtual void exec(array_assign_t&) {}

  public: /* visitor api */
    void visit(havoc_t& s) { exec(s); }
    void visit(unreachable_t& s) { exec(s); }
    void visit(binary_op_t& s) { exec(s); }
    void visit(assign_t& s) { exec(s); }
    void visit(assume_t& s) { exec(s); }
    void visit(select_t& s) { exec(s); }
    void visit(assert_t& s) { exec(s); }
    void visit(int_cast_t& s) { exec(s); }
    void visit(array_init_t& s) { exec(s); }
    void visit(array_store_t& s) { exec(s); }
    void visit(array_load_t& s) { exec(s); }
    void visit(array_assign_t& s) { exec(s); }
};

/**
 * Abstract forward transformer for all statements. Function calls
 * can be redefined by derived classes. By default, all function
 * calls are ignored in a sound manner (by havoc'ing all outputs).
 **/
template <class AbsD>
class intra_abs_transformer : public abs_transformer_api {

  public:
    using abs_dom_t = AbsD;

  public:
    using abs_transform_api_t = abs_transformer_api;

  protected:
    /// XXX: the transformer does not own m_inv.
    /// We keep a pointer to avoid unnecessary copies. We don't use a
    /// reference because we might reassign m_inv multiple times.
    abs_dom_t* m_inv;

    bool m_ignore_assert;

  private:
    template <typename NumOrVar>
    void apply(abs_dom_t& inv, binary_operation_t op, variable_t x, variable_t y, NumOrVar z) {
        if (auto top = conv_op<operation_t>(op)) {
            inv.apply(*top, x, y, z);
        } else if (auto top = conv_op<bitwise_operation_t>(op)) {
            inv.apply(*top, x, y, z);
        } else {
            CRAB_ERROR("unsupported binary operator", op);
        }
    }

  public:
    intra_abs_transformer(abs_dom_t* inv, bool ignore_assert = false) : m_inv(inv), m_ignore_assert(ignore_assert) {}

    virtual ~intra_abs_transformer() {}

    void set(abs_dom_t* inv) { m_inv = inv; }

    abs_dom_t* get() {
        if (!m_inv) {
            CRAB_ERROR("Invariant passed to transformer cannot be null!");
        } else {
            return m_inv;
        }
    }

    void exec(binary_op_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
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

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(select_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        abs_dom_t inv1(*get());
        abs_dom_t inv2(*get());

        inv1 += stmt.cond();
        inv2 += stmt.cond().negate();

        if (CrabSanityCheckFlag) {
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

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(assign_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->assign(stmt.lhs(), stmt.rhs());

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(assume_t& stmt) { *get() += stmt.constraint(); }

    void exec(assert_t& stmt) {
        if (m_ignore_assert)
            return;

        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        *get() += stmt.constraint();

        if (CrabSanityCheckFlag) {
            if (!stmt.constraint().is_contradiction()) {
                bool post_bot = get()->is_bottom();
                if (!(pre_bot || !post_bot)) {
                    CRAB_WARN("Invariant became bottom after ", stmt, ".",
                              " This might indicate that the assertion is violated");
                }
            }
        }
    }

    void exec(int_cast_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        if (auto op = conv_op<domains::int_conv_operation_t>(stmt.op())) {
            get()->apply(*op, stmt.dst(), stmt.src());
        } else {
            CRAB_ERROR("unsupported cast operator ", stmt.op());
        }

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(havoc_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        (*get()) -= stmt.variable();

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(unreachable_t& stmt) { *get() = abs_dom_t::bottom(); }

    void exec(array_init_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->array_init(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.val());

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(array_store_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        if (stmt.lb_index().equal(stmt.ub_index())) {
            get()->array_store(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.value(), stmt.is_singleton());
        } else {
            get()->array_store_range(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.value());
        }

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(array_load_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->array_load(stmt.lhs(), stmt.array(), stmt.elem_size(), stmt.index());

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(array_assign_t& stmt) {
        bool pre_bot = false;
        if (CrabSanityCheckFlag) {
            pre_bot = get()->is_bottom();
        }

        get()->array_assign(stmt.lhs(), stmt.rhs());

        if (CrabSanityCheckFlag) {
            bool post_bot = get()->is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }
};

} // namespace analyzer
} // namespace crab
