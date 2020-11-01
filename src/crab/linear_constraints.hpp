/*******************************************************************************
 *
 * Data structures for the symbolic manipulation of linear constraints.
 *
 * Author: Arnaud J. Venet (arnaud.j.venet@nasa.gov)
 * Contributor: Jorge A. Navas (jorge.navas@sri.com)
 *
 * Notices:
 *
 * Copyright (c) 2011 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Disclaimers:
 *
 * No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF
 * ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED
 * TO, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS,
 * ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL BE
 * ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM TO
 * THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
 * ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS,
 * RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS
 * RESULTING FROM USE OF THE SUBJECT SOFTWARE.  FURTHER, GOVERNMENT AGENCY
 * DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY SOFTWARE,
 * IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
 *
 * Waiver and Indemnity:  RECIPIENT AGREES TO WAIVE ANY AND ALL CLAIMS AGAINST
 * THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS, AS WELL
 * AS ANY PRIOR RECIPIENT.  IF RECIPIENT'S USE OF THE SUBJECT SOFTWARE RESULTS
 * IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES OR LOSSES ARISING FROM SUCH
 * USE, INCLUDING ANY DAMAGES FROM PRODUCTS BASED ON, OR RESULTING FROM,
 * RECIPIENT'S USE OF THE SUBJECT SOFTWARE, RECIPIENT SHALL INDEMNIFY AND HOLD
 * HARMLESS THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND SUBCONTRACTORS,
 * AS WELL AS ANY PRIOR RECIPIENT, TO THE EXTENT PERMITTED BY LAW.
 * RECIPIENT'S SOLE REMEDY FOR ANY SUCH MATTER SHALL BE THE IMMEDIATE,
 * UNILATERAL TERMINATION OF THIS AGREEMENT.
 *
 ******************************************************************************/

#pragma once

#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/container/flat_map.hpp>
#include <boost/functional/hash.hpp>

#include "crab/variable.hpp"
#include "crab_types/patricia_trees.hpp"

namespace crab {

class linear_expression_t final {
  private:
    using map_t = boost::container::flat_map<variable_t, number_t>;
    using pair_t = typename map_t::value_type;

    const map_t _map;
    const number_t _cst = 0;

    linear_expression_t(map_t map, number_t cst) : _map(std::move(map)), _cst(std::move(cst)) {}

    static void add(map_t& map, variable_t x, const number_t& n) {
        typename map_t::iterator it = map.find(x);
        if (it != map.end()) {
            number_t r = it->second + n;
            if (r == 0) {
                map.erase(it);
            } else {
                it->second = r;
            }
        } else {
            if (n != 0) {
                map.insert(pair_t(x, n));
            }
        }
    }

  public:
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;

    linear_expression_t() = default;

    linear_expression_t(linear_expression_t&& other) = default;
    linear_expression_t(const linear_expression_t& other) = default;

    explicit linear_expression_t(number_t n) : _cst(std::move(n)) {}

    linear_expression_t(signed long long int n) : _cst(number_t(n)) {}

    linear_expression_t(variable_t x) : _map{ {x, number_t(1)} } {
    }

    linear_expression_t(const number_t& n, variable_t x) : _map{ {x, n} } {
    }

    const_iterator begin() const { return this->_map.begin(); }

    const_iterator end() const { return this->_map.end(); }

    size_t hash() const {
        size_t res = 0;
        for (const auto& p : *this) {
            boost::hash_combine(res, p);
        }
        boost::hash_combine(res, _cst);
        return res;
    }

    // syntactic equality
    bool equal(const linear_expression_t& o) const {
        if (is_constant()) {
            return o.is_constant() && constant() == o.constant();
        }
        if (constant() != o.constant() || size() != o.size()) {
            return false;
        }
        for (const_iterator it = begin(), jt = o.begin(), et = end(); it != et; ++it, ++jt) {
            if (it->first != jt->first || it->second != jt->second) {
                return false;
            }
        }
        return true;
    }

    bool is_constant() const { return (this->_map.empty()); }

    number_t constant() const { return this->_cst; }

    std::size_t size() const { return this->_map.size(); }

    number_t operator[](variable_t x) const {
        typename map_t::const_iterator it = this->_map.find(x);
        if (it != this->_map.end()) {
            return it->second;
        } else {
            return 0;
        }
    }

    linear_expression_t operator+(number_t n) const {
        linear_expression_t r(this->_map, this->_cst + std::move(n));
        return r;
    }

    linear_expression_t operator+(int n) const { return this->operator+(number_t(n)); }

    linear_expression_t operator+(variable_t x) const {
        map_t map = this->_map;
        add(map, x, number_t(1));
        return linear_expression_t(map, this->_cst);
    }

    linear_expression_t operator+(const linear_expression_t& e) const {
        map_t map = this->_map;
        for (typename map_t::const_iterator it = e._map.begin(); it != e._map.end(); ++it) {
            add(map, it->first, it->second);
        }
        return linear_expression_t(map, this->_cst + e._cst);
    }

    linear_expression_t operator-(const number_t& n) const { return this->operator+(-n); }

    linear_expression_t operator-(int n) const { return this->operator+(-number_t(n)); }

    linear_expression_t operator-(variable_t x) const {
        map_t map = this->_map;
        add(map, x, number_t(-1));
        return linear_expression_t(map, this->_cst);
    }

    linear_expression_t operator-() const { return this->operator*(number_t(-1)); }

    linear_expression_t operator-(const linear_expression_t& e) const {
        map_t map = this->_map;
        for (typename map_t::const_iterator it = e._map.begin(); it != e._map.end(); ++it) {
            add(map, it->first, -it->second);
        }
        return linear_expression_t(map, this->_cst - e._cst);
    }

    linear_expression_t operator*(const number_t& n) const {
        if (n == 0) {
            return linear_expression_t();
        } else {
            map_t map;
            for (auto [k, v] : _map) {
                number_t c = n * v;
                if (c != 0) {
                    map.insert(pair_t(k, c));
                }
            }
            return linear_expression_t(map, n * this->_cst);
        }
    }

    linear_expression_t operator*(int n) const { return operator*(number_t(n)); }

    friend std::ostream& operator<<(std::ostream& o, const linear_expression_t& e) {
        bool start = true;
        for (auto [v, n] : e) {
            if (n > 0 && !start) {
                o << "+";
            }
            if (n == -1) {
                o << "-";
            } else if (n != 1) {
                o << n << "*";
            }
            o << v;
            start = false;
        }
        if (e._cst > 0 && !e._map.empty()) {
            o << "+";
        }
        if (e._cst != 0 || e._map.empty()) {
            o << e._cst;
        }
        return o;
    }
}; // class linear_expression_t

inline std::size_t hash_value(const linear_expression_t& e) { return e.hash(); }

enum class cst_kind { EQUALITY, DISEQUATION, INEQUALITY, STRICT_INEQUALITY };

class linear_constraint_t final {

  public:
    using iterator = typename linear_expression_t::iterator;
    using const_iterator = typename linear_expression_t::const_iterator;

  private:
    const cst_kind _kind;
    const linear_expression_t _expr;
    // This flag has meaning only if _kind == INEQUALITY or STRICT_INEQUALITY.
    // If true the inequality is signed otherwise unsigned.
    // By default all constraints are signed.
    const bool _signedness;

  public:
    // linear_constraint_t() : _kind(EQUALITY), _signedness(true) {}
    linear_constraint_t(linear_constraint_t&& other) = default;
    linear_constraint_t(const linear_constraint_t& other) = default;

    linear_constraint_t(linear_expression_t expr, cst_kind kind)
        : _kind(kind), _expr(std::move(expr)), _signedness(true) {}

    linear_constraint_t(linear_expression_t expr, cst_kind kind, bool signedness)
        : _kind(kind), _expr(std::move(expr)), _signedness(signedness) {
        if (_kind != cst_kind::INEQUALITY && _kind != cst_kind::STRICT_INEQUALITY) {
            CRAB_ERROR("Only inequalities can have signedness information");
        }
    }

    static linear_constraint_t get_true() {
        linear_constraint_t res(linear_expression_t(number_t(0)), cst_kind::EQUALITY);
        return res;
    }

    static linear_constraint_t get_false() {
        linear_constraint_t res(linear_expression_t(number_t(0)), cst_kind::DISEQUATION);
        return res;
    }

    bool is_tautology() const {
        if (!this->_expr.is_constant())
            return false;
        const number_t c = this->_expr.constant();
        switch (this->_kind) {
        case cst_kind::DISEQUATION: return c != 0;
        case cst_kind::EQUALITY: return c == 0;
        case cst_kind::INEQUALITY: return c <= 0;
        case cst_kind::STRICT_INEQUALITY: return c < 0;
        default: CRAB_ERROR("Unreachable");
        }
    }

    bool is_contradiction() const {
        if (!this->_expr.is_constant())
            return false;
        const number_t c = this->_expr.constant();
        switch (this->_kind) {
        case cst_kind::DISEQUATION: return c == 0;
        case cst_kind::EQUALITY: return c != 0;
        case cst_kind::INEQUALITY: return c > 0;
        case cst_kind::STRICT_INEQUALITY: return c >= 0;
        default: CRAB_ERROR("Unreachable");
        }
    }

    bool is_inequality() const { return (this->_kind == cst_kind::INEQUALITY); }

    bool is_strict_inequality() const { return (this->_kind == cst_kind::STRICT_INEQUALITY); }

    bool is_equality() const { return (this->_kind == cst_kind::EQUALITY); }

    bool is_disequation() const { return (this->_kind == cst_kind::DISEQUATION); }

    const linear_expression_t& expression() const { return this->_expr; }

    cst_kind kind() const { return this->_kind; }

    bool is_signed() const {
        if (_kind != cst_kind::INEQUALITY && _kind != cst_kind::STRICT_INEQUALITY) {
            CRAB_WARN("Only inequalities have signedness");
        }
        return _signedness;
    }

    bool is_unsigned() const { return (!is_signed()); }

    const_iterator begin() const { return this->_expr.begin(); }

    const_iterator end() const { return this->_expr.end(); }

    std::size_t size() const { return this->_expr.size(); }

    // syntactic equality
    bool equal(const linear_constraint_t& o) const {
        return (_kind == o._kind && _signedness == o._signedness && _expr.equal(o._expr));
    }

    size_t hash() const {
        size_t res = 0;
        boost::hash_combine(res, _expr);
        boost::hash_combine(res, _kind);
        if (_kind == cst_kind::INEQUALITY || _kind == cst_kind::STRICT_INEQUALITY) {
            boost::hash_combine(res, _signedness);
        }
        return res;
    }

    index_t index() const {
        // XXX: to store linear constraints in patricia trees
        return (index_t)hash();
    }

    number_t operator[](variable_t x) const { return this->_expr.operator[](x); }

    linear_constraint_t negate() const {
        if (is_tautology()) {
            return get_false();
        } else if (is_contradiction()) {
            return get_true();
        } else {
            switch (kind()) {
            case cst_kind::INEQUALITY: {
                // try to take advantage if we use z_number_t.
                // negate(e <= 0) = e >= 1
                return linear_constraint_t(-(expression() - 1), cst_kind::INEQUALITY, is_signed());
            }
            case cst_kind::STRICT_INEQUALITY: {
                // negate(x + y < 0)  <-->  x + y >= 0 <--> -x -y <= 0
                linear_expression_t e = -this->_expr;
                return linear_constraint_t(e, cst_kind::INEQUALITY, is_signed());
            }
            case cst_kind::EQUALITY: return linear_constraint_t(this->_expr, cst_kind::DISEQUATION);
            case cst_kind::DISEQUATION: return linear_constraint_t(this->_expr, cst_kind::EQUALITY);
            default: CRAB_ERROR("Cannot negate linear constraint");
            }
        }
    }

    friend std::ostream& operator<<(std::ostream& o, const linear_constraint_t& cst) {
        if (cst.is_contradiction()) {
            o << "false";
        } else if (cst.is_tautology()) {
            o << "true";
        } else {
            linear_expression_t e = cst._expr - cst._expr.constant();
            o << e;
            switch (cst._kind) {
            case cst_kind::INEQUALITY: {
                if (cst.is_signed()) {
                    o << " <= ";
                } else {
                    o << " <=_u ";
                }
                break;
            }
            case cst_kind::STRICT_INEQUALITY: {
                if (cst.is_signed()) {
                    o << " < ";
                } else {
                    o << " <_u ";
                }
                break;
            }
            case cst_kind::EQUALITY: {
                o << " = ";
                break;
            }
            case cst_kind::DISEQUATION: {
                o << " != ";
                break;
            }
            }
            number_t c = -cst._expr.constant();
            o << c;
        }
        return o;
    }
}; // class linear_constraint_t

inline std::size_t hash_value(const linear_constraint_t& e) { return e.hash(); }

inline linear_expression_t var_sub(variable_t x, const number_t& n) { return linear_expression_t(x).operator-(n); }
inline linear_expression_t var_sub(variable_t x, variable_t y) { return linear_expression_t(x).operator-(y); }
inline linear_expression_t var_add(variable_t x, number_t n) { return linear_expression_t(x).operator+(std::move(n)); }
inline linear_expression_t var_add(variable_t x, variable_t y) { return linear_expression_t(x).operator+(y); }
inline linear_expression_t var_mul(const number_t& n, variable_t x) { return linear_expression_t(n, x); }
} // namespace crab
