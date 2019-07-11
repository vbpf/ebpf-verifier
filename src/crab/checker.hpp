#pragma once

/*
   A generic forward checker for properties
 */

#include "crab/base_property.hpp"
#include "crab/fwd_analyzer.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

namespace crab {

namespace checker {

template <typename Analyzer>
class intra_checker {
  public:
    using prop_checker_ptr = std::shared_ptr<property_checker<Analyzer>>;
    using prop_checker_vector = std::vector<prop_checker_ptr>;

  private:
    using cfg_t = typename Analyzer::cfg_t;
    using statement_t = typename cfg_t::statement_t;
    using abs_dom_t = typename Analyzer::abs_dom_t;
    using abs_tr_t = typename Analyzer::abs_tr_t;

    Analyzer &m_analyzer;
    prop_checker_vector m_checkers;

  public:
    intra_checker(Analyzer &analyzer, prop_checker_vector checkers) : m_analyzer(analyzer), m_checkers(checkers) {}

    void run() {
        cfg_t cfg = m_analyzer.get_cfg();

        for (auto &bb : cfg) {
            for (auto checker : this->m_checkers) {
                if (checker->is_interesting(bb)) {
                    abs_dom_t inv = m_analyzer[bb.label()];
                    // Note: this has side effect:
                    std::shared_ptr<abs_tr_t> abs_tr = m_analyzer.get_abs_transformer(&inv);
                    // propagate forward the invariants from the block entry
                    // while checking the property
                    checker->set(abs_tr.get(), {});
                    for (auto &stmt : bb) {
                        stmt.accept(checker.get());
                    }
                }
            }
        }
    }

    void show(crab_os &o) {
        for (auto prop_checker : m_checkers) {
            prop_checker->write(o);
        }
    }

    // merge all the databases in one: useful for crab clients
    checks_db get_all_checks() const {
        checks_db res;
        for (auto prop_checker : m_checkers) {
            res += prop_checker->get_db();
        }
        return res;
    }
};

} // namespace checker
} // namespace crab
