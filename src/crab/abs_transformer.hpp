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

#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/abstract_domain_operators.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"

namespace crab {

/**
 * API abstract transformer
 **/
class abs_transformer_api : public statement_visitor {
  protected:
    virtual ~abs_transformer_api() { }

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
template <class AbsDomain>
class intra_abs_transformer : public abs_transformer_api {
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
    intra_abs_transformer(const abs_dom_t& inv) : m_inv(inv) { }

    virtual ~intra_abs_transformer() { }

    void exec(binary_op_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        auto op1 = stmt.left();
        auto op2 = stmt.right();
        if (op1.get_variable() && op2.get_variable()) {
            apply(m_inv, stmt.op(), stmt.lhs(), (*op1.get_variable()), (*op2.get_variable()));
        } else {
            assert(op1.get_variable() && op2.is_constant());
            apply(m_inv, stmt.op(), stmt.lhs(), (*op1.get_variable()), op2.constant());
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(select_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        abs_dom_t inv1(m_inv);
        abs_dom_t inv2(m_inv);

        inv1 += stmt.cond();
        inv2 += stmt.cond().negate();

        if constexpr (CrabSanityCheckFlag) {
            if (!pre_bot && (inv1.is_bottom() && inv2.is_bottom())) {
                CRAB_ERROR("select condition and its negation cannot be false simultaneously ", stmt);
            }
        }

        if (inv2.is_bottom()) {
            inv1.assign(stmt.lhs(), stmt.left());
            m_inv = inv1;
        } else if (inv1.is_bottom()) {
            inv2.assign(stmt.lhs(), stmt.right());
            m_inv = inv2;
        } else {
            inv1.assign(stmt.lhs(), stmt.left());
            inv2.assign(stmt.lhs(), stmt.right());
            m_inv = inv1 | inv2;
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(assign_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.assign(stmt.lhs(), stmt.rhs());

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(assume_t& stmt) { m_inv += stmt.constraint(); }

    void exec(assert_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv += stmt.constraint();

        if constexpr (CrabSanityCheckFlag) {
            if (!stmt.constraint().is_contradiction()) {
                bool post_bot = m_inv.is_bottom();
                if (!(pre_bot || !post_bot)) {
                    CRAB_WARN("Invariant became bottom after ", stmt, ".",
                              " This might indicate that the assertion is violated");
                }
            }
        }
    }

    void exec(int_cast_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        if (auto op = conv_op<domains::int_conv_operation_t>(stmt.op())) {
            m_inv.apply(*op, stmt.dst(), stmt.src());
        } else {
            CRAB_ERROR("unsupported cast operator ", stmt.op());
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(havoc_t& stmt) {
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

    void exec(unreachable_t& stmt) { m_inv = abs_dom_t::bottom(); }

    void exec(array_init_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.array_init(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.val());

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(array_store_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        if (stmt.lb_index().equal(stmt.ub_index())) {
            m_inv.array_store(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.value(), stmt.is_singleton());
        } else {
            m_inv.array_store_range(stmt.array(), stmt.elem_size(), stmt.lb_index(), stmt.ub_index(), stmt.value());
        }

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(array_load_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.array_load(stmt.lhs(), stmt.array(), stmt.elem_size(), stmt.index());

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }

    void exec(array_assign_t& stmt) {
        bool pre_bot = false;
        if constexpr (CrabSanityCheckFlag) {
            pre_bot = m_inv.is_bottom();
        }

        m_inv.array_assign(stmt.lhs(), stmt.rhs());

        if constexpr (CrabSanityCheckFlag) {
            bool post_bot = m_inv.is_bottom();
            if (!(pre_bot || !post_bot)) {
                CRAB_ERROR("Invariant became bottom after ", stmt);
            }
        }
    }
};

enum check_kind_t { _SAFE, _ERR, _WARN, _UNREACH };

// Toy database to store invariants. We may want to replace it with
// a permanent external database.
class checks_db {
    using check_t = std::pair<debug_info, check_kind_t>;

  public:
    std::set<check_t> m_db{};
    unsigned m_total_safe{};
    unsigned m_total_err{};
    unsigned m_total_unreach{};
    unsigned m_total_warn{};

    // Verbosity to print user messages
    int m_verbose{};

    // Statements where checks occur
    std::vector<const assert_t*> m_safe_checks{};
    std::vector<const assert_t*> m_warning_checks{};
    std::vector<const assert_t*> m_error_checks{};

  public:
    void add_safe(std::string msg, const assert_t* s) {
        add(_SAFE);
        m_safe_checks.push_back(s);
    }

    void add_warning(std::string msg, const assert_t* s) {
        add(_WARN, s->get_debug_info());
        m_warning_checks.push_back(s);
    }

    void add_error(std::string msg, const assert_t* s) {
        add(_ERR, s->get_debug_info());
        m_error_checks.push_back(s);
    }


    template <typename AbsDomain>
    void add_warning(const assert_t& s, const AbsDomain& invariant) {
        if (m_verbose >= 2) {
            crab_string_os os;
            os << "Property : " << s.constraint() << "\n";
            // os << "Invariant: " << invariant;
            add_warning(os.str(), &s);
        } else {
            add_warning("", &s);
        }
    }

    template <typename AbsDomain>
    void add_redundant(const assert_t& s, const AbsDomain& invariant) {
        if (m_verbose >= 3) {
            crab_string_os os;
            os << "Property : " << s.constraint() << "\n";
            // os << "Invariant: " << invariant;
            add_safe(os.str(), &s);
        } else {
            add_safe("", &s);
        }
    }
    checks_db() = default;

    unsigned get_total_safe() const { return m_total_safe + m_total_unreach; }

    unsigned get_total_warning() const { return m_total_warn; }

    unsigned get_total_error() const { return m_total_err; }

    // add an entry in the database
    void add(check_kind_t status, debug_info dbg = debug_info()) {
        switch (status) {
        case _SAFE: m_total_safe++; break;
        case _ERR: m_total_err++; break;
        case _UNREACH: m_total_unreach++; break;
        default: m_total_warn++;
        }
        if (dbg.has_debug())
            m_db.insert(check_t(dbg, status));
    }

    // merge two databases
    void operator+=(const checks_db& other) {
        m_db.insert(other.m_db.begin(), other.m_db.end());
        m_total_safe += other.m_total_safe;
        m_total_err += other.m_total_err;
        m_total_warn += other.m_total_warn;
        m_total_unreach += other.m_total_unreach;
    }

    void write(crab_os& o) const {
        std::vector<unsigned> cnts = {m_total_safe, m_total_err, m_total_warn, m_total_unreach};
        unsigned MaxValLen = 0;
        for (auto c : cnts) {
            MaxValLen = std::max(MaxValLen, (unsigned)std::to_string(c).size());
        }

        o << std::string((int)MaxValLen - std::to_string(m_total_safe).size(), ' ') << m_total_safe
          << std::string(2, ' ') << "Number of total safe checks\n";
        o << std::string((int)MaxValLen - std::to_string(m_total_err).size(), ' ') << m_total_err << std::string(2, ' ')
          << "Number of total error checks\n";
        o << std::string((int)MaxValLen - std::to_string(m_total_warn).size(), ' ') << m_total_warn
          << std::string(2, ' ') << "Number of total warning checks\n";
        o << std::string((int)MaxValLen - std::to_string(m_total_unreach).size(), ' ') << m_total_unreach
          << std::string(2, ' ') << "Number of total unreachable checks\n";

        unsigned MaxFileLen = 0;
        for (auto const& p : m_db) {
            MaxFileLen = std::max(MaxFileLen, (unsigned)p.first.m_file.size());
        }

        for (auto const& p : m_db) {
            switch (p.second) {
            case _SAFE: o << "safe: "; break;
            case _ERR: o << "error: "; break;
            case _UNREACH: o << "unreachable: "; break;
            default: o << "warning: "; break;
            }
            // print all checks here
            // o << p.first.m_file << std::string((int) MaxFileLen - p.first.m_file.size(), ' ')
            //   << std::string(2, ' ')
            //   << " line " << p.first.m_line
            //   << " col " << p.first.m_col << "\n";
        }
    }
};

template <typename AbsDomain>
class assert_property_checker : public intra_abs_transformer<AbsDomain> {
    // FIX: no need for refernce; simply merge dbs.
    checks_db& m_db;

  public:
    using abs_dom_t = AbsDomain;
    using intra_abs_transformer<AbsDomain>::intra_abs_transformer;

    assert_property_checker(const AbsDomain& from_inv, checks_db& db) : intra_abs_transformer<AbsDomain>(from_inv), m_db(db)  { }

protected:
    virtual void visit(assert_t& s) override {
        linear_constraint_t cst = s.constraint();
        if (cst.is_contradiction()) {
            if (this->m_inv.is_bottom()) {
                m_db.add_redundant(s, this->m_inv);
            } else {
                m_db.add_warning(s, this->m_inv);
            }
            return;
        }

        if (this->m_inv.is_bottom()) {
            m_db.add(_UNREACH);
            return;
        }

        if (domains::checker_domain_traits<abs_dom_t>::entail(this->m_inv, cst)) {
            m_db.add_redundant(s, this->m_inv);
        } else if (domains::checker_domain_traits<abs_dom_t>::intersect(this->m_inv, cst)) {
            m_db.add_warning(s, this->m_inv);
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
            m_db.add_warning(s, this->m_inv);
        }
        intra_abs_transformer<AbsDomain>::visit(s); // propagate invariants to the next stmt
    }
};

template <typename AbsDomain>
inline AbsDomain transform(const basic_block_t& bb, const AbsDomain& from_inv) {
    intra_abs_transformer<AbsDomain> transformer(from_inv);
    for (statement_t& statement : bb) {
        statement.accept(&transformer);
    }
    return std::move(transformer.m_inv);
}

template <typename AbsDomain>
inline void check_block(const basic_block_t& bb, const AbsDomain& from_inv, checks_db& db) {
    if (std::none_of(bb.begin(), bb.end(), [](const auto& s) { return s.is_assert(); }))
        return;
    assert_property_checker<AbsDomain> checker(from_inv, db);
    for (statement_t& statement : bb) {
            statement.accept(&checker);
    }
}


} // namespace crab
