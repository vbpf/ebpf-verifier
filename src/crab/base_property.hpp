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
enum check_kind_t { _SAFE, _ERR, _WARN, _UNREACH };

// Toy database to store invariants. We may want to replace it with
// a permanent external database.
class checks_db {
    using check_t = std::pair<crab::cfg::debug_info, check_kind_t>;
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
    using abs_tr_t = typename Analyzer::abs_tr_t;
    using varname_t = typename Analyzer::varname_t;
    using number_t = typename Analyzer::number_t;
    using abs_dom_t = typename Analyzer::abs_dom_t;

    using var_t = typename abs_dom_t::variable_t;
    using lin_exp_t = typename abs_dom_t::linear_expression_t;
    using lin_cst_t = typename abs_dom_t::linear_constraint_t;
    using lin_cst_sys_t = typename abs_dom_t::linear_constraint_system_t;

    using cfg_t = typename Analyzer::cfg_t;
    using basic_block_t = typename cfg_t::basic_block_t;
    using statement_t = crab::cfg::statement<number_t, varname_t>;
    using bin_op_t = crab::cfg::binary_op<number_t, varname_t>;
    using assign_t = crab::cfg::assignment<number_t, varname_t>;
    using assume_t = crab::cfg::assume_stmt<number_t, varname_t>;
    using assert_t = crab::cfg::assert_stmt<number_t, varname_t>;
    using int_cast_t = crab::cfg::int_cast_stmt<number_t, varname_t>;
    using select_t = crab::cfg::select_stmt<number_t, varname_t>;
    using havoc_t = crab::cfg::havoc_stmt<number_t, varname_t>;
    using unreach_t = crab::cfg::unreachable_stmt<number_t, varname_t>;
    using arr_init_t = crab::cfg::array_init_stmt<number_t, varname_t>;
    using arr_store_t = crab::cfg::array_store_stmt<number_t, varname_t>;
    using arr_load_t = crab::cfg::array_load_stmt<number_t, varname_t>;

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
    }

    void add_warning(std::string msg, const statement_t *s) {
        m_db.add(_WARN, s->get_debug_info());
        m_warning_checks.push_back(s);
    }

    void add_error(std::string msg, const statement_t *s) {
        m_db.add(_ERR, s->get_debug_info());
        m_error_checks.push_back(s);
    }

  public:
    /* Visitor API */
    void visit(bin_op_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(assign_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(assume_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(select_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(assert_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(int_cast_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(havoc_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(unreach_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(arr_init_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(arr_store_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }
    void visit(arr_load_t &s) { if (this->m_abs_tr) s.accept(&*this->m_abs_tr); }

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
