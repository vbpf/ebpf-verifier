#pragma once

/*
   Base class for a property checker
 */

#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/types.hpp"

#include <set>
#include <vector>

namespace crab {

namespace checker {
typedef enum { _SAFE, _ERR, _WARN, _UNREACH } check_kind_t;

// Toy database to store invariants. We may want to replace it with
// a permanent external database.
class checks_db {
    typedef std::pair<crab::cfg::debug_info, check_kind_t> check_t;
    typedef std::set<check_t> checks_db_t;

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
    void add(check_kind_t status, crab::cfg::debug_info dbg = crab::cfg::debug_info()) {
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
class property_checker
    : public crab::cfg::statement_visitor<typename Analyzer::number_t, typename Analyzer::varname_t> {
  public:
    typedef typename Analyzer::abs_tr_t abs_tr_t;
    typedef typename Analyzer::varname_t varname_t;
    typedef typename Analyzer::number_t number_t;
    typedef typename Analyzer::abs_dom_t abs_dom_t;

    typedef typename abs_dom_t::variable_t var_t;
    typedef typename abs_dom_t::linear_expression_t lin_exp_t;
    typedef typename abs_dom_t::linear_constraint_t lin_cst_t;
    typedef typename abs_dom_t::linear_constraint_system_t lin_cst_sys_t;

    typedef typename Analyzer::cfg_t cfg_t;
    typedef typename cfg_t::basic_block_t basic_block_t;
    typedef crab::cfg::statement<number_t, varname_t> statement_t;
    typedef crab::cfg::binary_op<number_t, varname_t> bin_op_t;
    typedef crab::cfg::assignment<number_t, varname_t> assign_t;
    typedef crab::cfg::assume_stmt<number_t, varname_t> assume_t;
    typedef crab::cfg::assert_stmt<number_t, varname_t> assert_t;
    typedef crab::cfg::int_cast_stmt<number_t, varname_t> int_cast_t;
    typedef crab::cfg::select_stmt<number_t, varname_t> select_t;
    typedef crab::cfg::havoc_stmt<number_t, varname_t> havoc_t;
    typedef crab::cfg::unreachable_stmt<number_t, varname_t> unreach_t;
    typedef crab::cfg::array_init_stmt<number_t, varname_t> arr_init_t;
    typedef crab::cfg::array_store_stmt<number_t, varname_t> arr_store_t;
    typedef crab::cfg::array_load_stmt<number_t, varname_t> arr_load_t;

  protected:
    // The abstract transformer
    abs_tr_t *m_abs_tr;
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

        if (m_verbose >= 3) {
            crab::outs() << " --- SAFE --------------------\n";
            if (s->get_debug_info().has_debug()) {
                crab::outs() << s->get_debug_info() << "\n";
            }
            crab::outs() << msg << "\n";
            crab::outs() << " -----------------------------\n";
        }
    }

    void add_warning(std::string msg, const statement_t *s) {
        m_db.add(_WARN, s->get_debug_info());
        m_warning_checks.push_back(s);

        if (m_verbose >= 2) {
            crab::outs() << " --- WARNING -----------------\n";
            if (s->get_debug_info().has_debug()) {
                crab::outs() << s->get_debug_info() << "\n";
            }
            crab::outs() << msg << "\n";
            crab::outs() << " -----------------------------\n";
        }
    }

    void add_error(std::string msg, const statement_t *s) {
        m_db.add(_ERR, s->get_debug_info());
        m_error_checks.push_back(s);

        if (m_verbose >= 1) {
            crab::outs() << " --- ERROR -------------------\n";
            if (s->get_debug_info().has_debug()) {
                crab::outs() << s->get_debug_info() << "\n";
            }
            crab::outs() << msg << "\n";
            crab::outs() << " -----------------------------\n";
        }
    }

    virtual void check(assert_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(bin_op_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(assign_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(assume_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(select_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(int_cast_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(havoc_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(unreach_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(arr_init_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(arr_store_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

    virtual void check(arr_load_t &s) {
        if (!this->m_abs_tr)
            return;
        s.accept(&*this->m_abs_tr); // propagate m_inv to the next stmt
    }

  public:
    /* Visitor API */
    void visit(bin_op_t &s) { check(s); }
    void visit(assign_t &s) { check(s); }
    void visit(assume_t &s) { check(s); }
    void visit(select_t &s) { check(s); }
    void visit(assert_t &s) { check(s); }
    void visit(int_cast_t &s) { check(s); }
    void visit(havoc_t &s) { check(s); }
    void visit(unreach_t &s) { check(s); }
    void visit(arr_init_t &s) { check(s); }
    void visit(arr_store_t &s) { check(s); }
    void visit(arr_load_t &s) { check(s); }

    property_checker(int verbose) : m_abs_tr(nullptr), m_verbose(verbose) {}

    // whether the basic block is of interest for the checker
    virtual bool is_interesting(const basic_block_t &b) const { return true; }

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

    virtual std::string get_property_name() const { return "dummy property"; }

    void write(crab_os &o) const {
        o << get_property_name() << "\n";
        m_db.write(o);
    }
};
} // namespace checker
} // namespace crab
