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

   havoc(x);

 */

#include "crab/abstract_domain_operators.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

namespace crab {

/**
 * Abstract forward transformer for all statements. Function calls
 * can be redefined by derived classes. By default, all function
 * calls are ignored in a sound manner (by havoc'ing all outputs).
 **/
template <class AbsDomain>
class intra_abs_transformer {
    using abs_dom_t = AbsDomain;

  public:
    abs_dom_t m_inv;

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
    intra_abs_transformer(const abs_dom_t& inv) : m_inv(inv) {}

    void operator()(const binary_op_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        auto op1 = stmt.left;
        auto op2 = stmt.right;
        if (op1.get_variable() && op2.get_variable()) {
            apply(m_inv, stmt.op, stmt.lhs, (*op1.get_variable()), (*op2.get_variable()));
        } else {
            assert(op1.get_variable() && op2.is_constant());
            apply(m_inv, stmt.op, stmt.lhs, (*op1.get_variable()), op2.constant());
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const select_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        abs_dom_t inv1(m_inv);
        abs_dom_t inv2(m_inv);

        inv1 += stmt.cond;
        inv2 += stmt.cond.negate();

        if constexpr (CrabSanityCheckFlag) {
            if (!pre_bot && (inv1.is_bottom() && inv2.is_bottom())) {
                CRAB_ERROR("select condition and its negation cannot be false simultaneously ", stmt);
            }
        }

        if (inv2.is_bottom()) {
            inv1.assign(stmt.lhs, stmt.left);
            m_inv = inv1;
        } else if (inv1.is_bottom()) {
            inv2.assign(stmt.lhs, stmt.right);
            m_inv = inv2;
        } else {
            inv1.assign(stmt.lhs, stmt.left);
            inv2.assign(stmt.lhs, stmt.right);
            m_inv = inv1 | inv2;
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const assign_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.assign(stmt.lhs, stmt.rhs);

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const assume_t& stmt) { m_inv += stmt.constraint; }

    void operator()(const assert_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv += stmt.constraint;

        if constexpr (CrabSanityCheckFlag) {
            if (!stmt.constraint.is_contradiction()) {
                bool post_bot = m_inv.is_bottom();
                if (!(pre_bot || !post_bot)) {
                    CRAB_WARN("Invariant became bottom after ", stmt, ".",
                              " This might indicate that the assertion is violated");
                }
            }
        }
    }

    void operator()(const havoc_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv -= stmt.variable();

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const array_init_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.array_init(stmt.array, stmt.elem_size, stmt.lb_index, stmt.ub_index, stmt.val);

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const array_store_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        if (stmt.lb_index.equal(stmt.ub_index)) {
            m_inv.array_store(stmt.array, stmt.elem_size, stmt.lb_index, stmt.value, stmt.is_singleton);
        } else {
            m_inv.array_store_range(stmt.array, stmt.elem_size, stmt.lb_index, stmt.ub_index, stmt.value);
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const array_load_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.array_load(stmt.lhs, stmt.array, stmt.elem_size, stmt.index);

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void operator()(const std::monostate& stmt) { }
};

enum class check_kind_t { Safe, Error, Warning, Unreachable };

// Toy database to store invariants.
class checks_db {
    using check_t = std::pair<debug_info, check_kind_t>;

  public:
    std::set<check_t> m_db{};
    std::map<check_kind_t, int> total{
        {check_kind_t::Safe, {}},
        {check_kind_t::Error, {}},
        {check_kind_t::Warning, {}},
        {check_kind_t::Unreachable, {}},
    };

    void merge_db(checks_db&& other) {
        m_db.insert(other.m_db.begin(), other.m_db.end());
        for (auto [k, v] : other.total)
            total[k] += v;
        other.m_db.clear();
        other.total.clear();
    }

    int total_safe() const { return total.at(check_kind_t::Safe); }
    int total_error() const { return total.at(check_kind_t::Error); }
    int total_warning() const { return total.at(check_kind_t::Warning); }
    int total_unreachable() const { return total.at(check_kind_t::Unreachable); }

  public:
    checks_db() = default;

    void add_warning(const assert_t& s) {
        add(check_kind_t::Warning, s);
    }

    void add_redundant(const assert_t& s) {
        add(check_kind_t::Safe, s);
    }

    void add_unreachable(const assert_t& s) {
        add(check_kind_t::Unreachable, s);
    }

    void add(check_kind_t status, const assert_t& s) {
        total[status]++;
        debug_info dbg = s.get_debug_info();
        if (dbg.has_debug())
            m_db.insert(check_t(dbg, status));
    }

    void write(crab_os& o) const {
        std::vector<int> cnts = {total_safe(), total_error(), total_warning(), total_unreachable()};
        int maxvlen = 0;
        for (auto c : cnts) {
            maxvlen = std::max(maxvlen, (int)std::to_string(c).size());
        }

        o << std::string((int)maxvlen - std::to_string(total_safe()).size(), ' ') << total_safe()
          << std::string(2, ' ') << "Number of total safe checks\n";
        o << std::string((int)maxvlen - std::to_string(total_error()).size(), ' ') << total_error()
          << std::string(2, ' ') << "Number of total error checks\n";
        o << std::string((int)maxvlen - std::to_string(total_warning()).size(), ' ') << total_warning()
          << std::string(2, ' ') << "Number of total warning checks\n";
        o << std::string((int)maxvlen - std::to_string(total_unreachable()).size(), ' ') << total_unreachable()
          << std::string(2, ' ') << "Number of total unreachable checks\n";
    }
};

template <typename AbsDomain>
class assert_property_checker : public intra_abs_transformer<AbsDomain> {

  public:
    checks_db m_db;
    using abs_dom_t = AbsDomain;
    using parent = intra_abs_transformer<AbsDomain>;

    using parent::parent;

    void operator()(const assert_t& s) {
        linear_constraint_t cst = s.constraint;
        if (cst.is_contradiction()) {
            if (this->m_inv.is_bottom()) {
                m_db.add_redundant(s);
            } else {
                m_db.add_warning(s);
            }
            return;
        }

        if (this->m_inv.is_bottom()) {
            m_db.add_unreachable(s);
            return;
        }

        if (domains::checker_domain_traits<abs_dom_t>::entail(this->m_inv, cst)) {
            m_db.add_redundant(s);
        } else if (domains::checker_domain_traits<abs_dom_t>::intersect(this->m_inv, cst)) {
            // TODO: add_error() if imply negation
            m_db.add_warning(s);
        } else {
            /* Instead this program:
                x:=0;
                y:=1;
                if (x=34) {
                    assert(y==2);
                }
            Suppose due to some abstraction we have:
                havoc(x);
                y:=1;
                if (x=34) {
                    assert(y==2);
                }
            As a result, we have inv={y=1,x=34}  and cst={y=2}
            Note that inv does not either entail or intersect with cst.
            However, the original program does not violate the assertion.
            */
            m_db.add_warning(s);
        }
        parent::operator()(s); // propagate invariants to the next stmt
    }

    template <typename T>
    void operator()(const T& s) { parent::operator()(s); }
};

template <typename AbsDomain>
inline AbsDomain transform(const basic_block_t& bb, const AbsDomain& from_inv) {
    intra_abs_transformer<AbsDomain> transformer(from_inv);
    for (const new_statement_t& statement : bb) {
        std::visit(transformer, statement);
    }
    return std::move(transformer.m_inv);
}

template <typename AbsDomain>
inline void check_block(const basic_block_t& bb, const AbsDomain& from_inv, checks_db& db) {
    if (std::none_of(bb.begin(), bb.end(), [](const auto& s) { return std::holds_alternative<assert_t>(s); }))
        return;
    assert_property_checker<AbsDomain> checker(from_inv);
    for (const new_statement_t& statement : bb) {
        std::visit(checker, statement);
    }
    db.merge_db(std::move(checker.m_db));
}

} // namespace crab
