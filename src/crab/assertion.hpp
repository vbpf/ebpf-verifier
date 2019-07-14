#pragma once

/*
   User-definable assertion checker
 */

#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"

#include "crab/types.hpp"

namespace crab {

namespace checker {

enum check_kind_t { _SAFE, _ERR, _WARN, _UNREACH };

// Toy database to store invariants. We may want to replace it with
// a permanent external database.
class checks_db {
    using check_t = std::pair<crab::debug_info, check_kind_t>;
    using checks_db_t = std::set<check_t>;

    checks_db_t m_db;
    unsigned m_total_safe;
    unsigned m_total_err;
    unsigned m_total_unreach;
    unsigned m_total_warn;

  public:
    checks_db() : m_total_safe(0), m_total_err(0), m_total_unreach(0), m_total_warn(0) {}

    void clear() {
        m_db.clear();
        m_total_safe = 0;
        m_total_err = 0;
        m_total_unreach = 0;
        m_total_warn = 0;
    }

    unsigned get_total_safe() const { return m_total_safe + m_total_unreach; }

    unsigned get_total_warning() const { return m_total_warn; }

    unsigned get_total_error() const { return m_total_err; }

    // add an entry in the database
    void add(check_kind_t status, crab::debug_info dbg = crab::debug_info()) {
        switch (status) {
        case _SAFE:
            m_total_safe++;
            break;
        case _ERR:
            m_total_err++;
            break;
        case _UNREACH:
            m_total_unreach++;
            break;
        default:
            m_total_warn++;
        }
        if (dbg.has_debug())
            m_db.insert(check_t(dbg, status));
    }

    // merge two databases
    void operator+=(const checks_db &other) {
        m_db.insert(other.m_db.begin(), other.m_db.end());
        m_total_safe += other.m_total_safe;
        m_total_err += other.m_total_err;
        m_total_warn += other.m_total_warn;
        m_total_unreach += other.m_total_unreach;
    }

    void write(crab_os &o) const {
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
        for (auto const &p : m_db) {
            MaxFileLen = std::max(MaxFileLen, (unsigned)p.first.m_file.size());
        }

        for (auto const &p : m_db) {
            switch (p.second) {
            case _SAFE:
                o << "safe: ";
                break;
            case _ERR:
                o << "error: ";
                break;
            case _UNREACH:
                o << "unreachable: ";
                break;
            default:
                o << "warning: ";
                break;
            }
            // print all checks here
            // o << p.first.m_file << std::string((int) MaxFileLen - p.first.m_file.size(), ' ')
            //   << std::string(2, ' ')
            //   << " line " << p.first.m_line
            //   << " col " << p.first.m_col << "\n";
        }
    }
};

template <typename Analyzer>
class assert_property_checker
    : public crab::statement_visitor {
  public:


    using interval_t = ikos::interval<number_t>;
    using abs_dom_t = typename Analyzer::abs_dom_t;

    using abs_tr_t = typename Analyzer::abs_tr_t;

    using lin_exp_t = typename abs_dom_t::linear_expression_t;
    using lin_cst_t = typename abs_dom_t::linear_constraint_t;
    using lin_cst_sys_t = typename abs_dom_t::linear_constraint_system_t;

  public:
    // set internal state for the checker
    void set(abs_tr_t *abs_tr, const std::set<const statement_t *> &safe_assertions) {
        m_abs_tr = abs_tr;
        m_safe_assertions.insert(safe_assertions.begin(), safe_assertions.end());
    }

    const checks_db &get_db() const { return m_db; }

    checks_db &get_db() { return m_db; }

    const std::vector<const statement_t *> &get_safe_checks() const { return m_safe_checks; }

    const std::vector<const statement_t *> &get_warning_checks() const { return m_warning_checks; }

    const std::vector<const statement_t *> &get_error_checks() const { return m_error_checks; }

    void write(crab_os &o) const { m_db.write(o); }

    bool is_interesting(const basic_block_t &bb) const {
        for (auto &s : bb) {
            if (s.is_assert()) {
                return true;
            }
        }
        return false;
    }

    // The abstract transformer
    abs_tr_t *m_abs_tr{};
    // Known safe assertions before start forward propagation (it can be empty)
    std::set<const statement_t *> m_safe_assertions;
    // Verbosity to print user messages
    int m_verbose;
    // Store debug information about the checks
    checks_db m_db;
    // Statements where checks occur
    std::vector<const statement_t *> m_safe_checks;
    std::vector<const statement_t *> m_warning_checks;
    std::vector<const statement_t *> m_error_checks;

    void add_safe(std::string msg, const statement_t *s) {
        m_db.add(_SAFE);
        m_safe_checks.push_back(s);
    }

    void add_warning(std::string msg, const statement_t *s) {
        m_db.add(_WARN, s->get_debug_info());
        m_warning_checks.push_back(s);
    }

    void add_error(std::string msg, const statement_t *s) {
        m_db.add(_ERR, s->get_debug_info());
        m_error_checks.push_back(s);
    }

    /* Visitor API */
    void visit(binary_op_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(assign_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(assume_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(select_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(int_cast_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(havoc_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(unreachable_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(array_init_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(array_store_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }
    void visit(array_load_t &s) {
        if (this->m_abs_tr)
            s.accept(&*this->m_abs_tr);
    }

    void visit(assert_t &s) { check(s); }

    void check(assert_t &s) {
        if (!this->m_abs_tr)
            return;

        lin_cst_t cst = s.constraint();

        if (this->m_safe_assertions.count(&s) > 0) {
            crab::crab_string_os os;
            if (this->m_verbose >= 3) {
                os << "Property : " << cst << "\n";
                os << "Invariant: " << *(this->m_abs_tr->get()) << "\n";
                os << "Note: it was proven by the forward+backward analysis";
            }
            this->add_safe(os.str(), &s);
        } else {
            if (cst.is_contradiction()) {
                if (this->m_abs_tr->get()->is_bottom()) {
                    crab::crab_string_os os;
                    if (this->m_verbose >= 3) {
                        os << "Property : " << cst << "\n";
                        os << "Invariant: " << *(this->m_abs_tr->get());
                    }
                    this->add_safe(os.str(), &s);
                } else {
                    crab::crab_string_os os;
                    if (this->m_verbose >= 2) {
                        os << "Property : " << cst << "\n";
                        os << "Invariant: " << *(this->m_abs_tr->get());
                    }
                    this->add_warning(os.str(), &s);
                }
                return;
            }

            if (this->m_abs_tr->get()->is_bottom()) {
                this->m_db.add(_UNREACH);
                return;
            }

            abs_dom_t inv(*(this->m_abs_tr->get()));
            if (crab::domains::checker_domain_traits<abs_dom_t>::entail(inv, cst)) {
                crab::crab_string_os os;
                if (this->m_verbose >= 3) {
                    os << "Property : " << cst << "\n";
                    os << "Invariant: " << inv;
                }
                this->add_safe(os.str(), &s);
            } else if (crab::domains::checker_domain_traits<abs_dom_t>::intersect(inv, cst)) {
                crab::crab_string_os os;
                if (this->m_verbose >= 2) {
                    os << "Property : " << cst << "\n";
                    os << "Invariant: " << inv;
                }
                this->add_warning(os.str(), &s);
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
                crab::crab_string_os os;
                if (this->m_verbose >= 2) {
                    os << "Property : " << cst << "\n";
                    os << "Invariant: " << inv;
                }
                this->add_warning(os.str(), &s);
            }
        }
        s.accept(&*this->m_abs_tr); // propagate invariants to the next stmt
    }
};
} // namespace checker
} // namespace crab
