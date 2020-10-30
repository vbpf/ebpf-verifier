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

#include "crab/patricia_trees.hpp"
#include "crab/types.hpp"

namespace crab {

class linear_expression_t final {

  public:
    using component_t = std::pair<number_t, variable_t>;
    using variable_set_t = patricia_tree_set<variable_t>;

  private:
    using map_t = boost::container::flat_map<variable_t, number_t>;
    using map_ptr = std::shared_ptr<map_t>;
    using pair_t = typename map_t::value_type;

    map_ptr _map;
    number_t _cst;

    linear_expression_t(map_ptr map, number_t cst) : _map(std::move(map)), _cst(std::move(cst)) {}

    linear_expression_t(const map_t& map, number_t cst) : _map(std::make_shared<map_t>()), _cst(std::move(cst)) {
        *this->_map = map;
    }

    void add(variable_t x, const number_t& n) {
        typename map_t::iterator it = this->_map->find(x);
        if (it != this->_map->end()) {
            number_t r = it->second + n;
            if (r == 0) {
                this->_map->erase(it);
            } else {
                it->second = r;
            }
        } else {
            if (n != 0) {
                this->_map->insert(pair_t(x, n));
            }
        }
    }

  public:
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;

    linear_expression_t() : _map(std::make_shared<map_t>()), _cst(0) {}

    linear_expression_t(linear_expression_t&& other) = default;
    linear_expression_t(const linear_expression_t& other) = default;

    explicit linear_expression_t(number_t n) : _map(std::make_shared<map_t>()), _cst(std::move(n)) {}

    linear_expression_t(signed long long int n) : _map(std::make_shared<map_t>()), _cst(number_t(n)) {}

    linear_expression_t(variable_t x) : _map(std::make_shared<map_t>()), _cst(0) {
        this->_map->insert(pair_t(x, number_t(1)));
    }

    linear_expression_t(const number_t& n, variable_t x) : _map(std::make_shared<map_t>()), _cst(0) {
        this->_map->insert(pair_t(x, n));
    }

    linear_expression_t& operator=(const linear_expression_t& e) {
        if (this != &e) {
            this->_map = e._map;
            this->_cst = e._cst;
        }
        return *this;
    }

    const_iterator begin() const { return this->_map->begin(); }

    const_iterator end() const { return this->_map->end(); }

    iterator begin() { return this->_map->begin(); }

    iterator end() { return this->_map->end(); }

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
            if (!o.is_constant()) {
                return false;
            } else {
                return (constant() == o.constant());
            }
        } else {
            if (constant() != o.constant()) {
                return false;
            }

            if (size() != o.size()) {
                return false;
            } else {
                for (const_iterator it = begin(), jt = o.begin(), et = end(); it != et; ++it, ++jt) {
                    if (((*it).first != (*jt).first) || ((*it).second != (*jt).second)) {
                        return false;
                    }
                }
                return true;
            }
        }
    }

    bool is_constant() const { return (this->_map->empty()); }

    number_t constant() const { return this->_cst; }

    std::size_t size() const { return this->_map->size(); }

    number_t operator[](variable_t x) const {
        typename map_t::const_iterator it = this->_map->find(x);
        if (it != this->_map->end()) {
            return it->second;
        } else {
            return 0;
        }
    }

    template <typename RenamingMap>
    linear_expression_t rename(const RenamingMap& map) const {
        number_t cst(this->_cst);
        linear_expression_t new_exp(cst);
        for (auto v : this->variables()) {
            auto const it = map.find(v);
            if (it != map.end()) {
                variable_t v_out((*it).second);
                new_exp = new_exp + linear_expression_t(this->operator[](v), v_out);
            } else {
                new_exp = new_exp + linear_expression_t(this->operator[](v), v);
            }
        }
        return new_exp;
    }

    linear_expression_t operator+(number_t n) const {
        linear_expression_t r(this->_map, this->_cst + std::move(n));
        return r;
    }

    linear_expression_t operator+(int n) const { return this->operator+(number_t(n)); }

    linear_expression_t operator+(variable_t x) const {
        linear_expression_t r(*this->_map, this->_cst);
        r.add(x, number_t(1));
        return r;
    }

    linear_expression_t operator+(const linear_expression_t& e) const {
        linear_expression_t r(*this->_map, this->_cst + e._cst);
        for (typename map_t::const_iterator it = e._map->begin(); it != e._map->end(); ++it) {
            r.add(it->first, it->second);
        }
        return r;
    }

    linear_expression_t operator-(const number_t& n) const { return this->operator+(-n); }

    linear_expression_t operator-(int n) const { return this->operator+(-number_t(n)); }

    linear_expression_t operator-(variable_t x) const {
        linear_expression_t r(*this->_map, this->_cst);
        r.add(x, number_t(-1));
        return r;
    }

    linear_expression_t operator-() const { return this->operator*(number_t(-1)); }

    linear_expression_t operator-(const linear_expression_t& e) const {
        linear_expression_t r(*this->_map, this->_cst - e._cst);
        for (typename map_t::const_iterator it = e._map->begin(); it != e._map->end(); ++it) {
            r.add(it->first, -it->second);
        }
        return r;
    }

    linear_expression_t operator*(const number_t& n) const {
        if (n == 0) {
            return linear_expression_t();
        } else {
            map_ptr map = std::make_shared<map_t>();
            for (typename map_t::const_iterator it = this->_map->begin(); it != this->_map->end(); ++it) {
                number_t c = n * it->second;
                if (c != 0) {
                    map->insert(pair_t(it->first, c));
                }
            }
            return linear_expression_t(map, n * this->_cst);
        }
    }

    linear_expression_t operator*(int n) const { return operator*(number_t(n)); }

    variable_set_t variables() const {
        variable_set_t variables;
        for (const auto& v_c : *this) {
            variables += v_c.first;
        }
        return variables;
    }

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
        if (e._cst > 0 && !e._map->empty()) {
            o << "+";
        }
        if (e._cst != 0 || e._map->empty()) {
            o << e._cst;
        }
        return o;
    }
}; // class linear_expression_t

inline std::size_t hash_value(const linear_expression_t& e) { return e.hash(); }

struct linear_expression_hasher_t {
    size_t operator()(const linear_expression_t& e) const { return e.hash(); }
};

struct linear_expression_equal_t {
    bool operator()(const linear_expression_t& e1, const linear_expression_t& e2) const { return e1.equal(e2); }
};

using linear_expression_unordered_set =
    std::unordered_set<linear_expression_t, linear_expression_hasher_t, linear_expression_equal_t>;

template <typename Value>
using linear_expression_unordered_map =
    std::unordered_map<linear_expression_t, Value, linear_expression_hasher_t, linear_expression_equal_t>;

class linear_constraint_t final {

  public:
    using variable_set_t = patricia_tree_set<variable_t>;
    using constraint_kind_t = enum { EQUALITY, DISEQUATION, INEQUALITY, STRICT_INEQUALITY };
    using iterator = typename linear_expression_t::iterator;
    using const_iterator = typename linear_expression_t::const_iterator;

  private:
    constraint_kind_t _kind;
    linear_expression_t _expr;
    // This flag has meaning only if _kind == INEQUALITY or STRICT_INEQUALITY.
    // If true the inequality is signed otherwise unsigned.
    // By default all constraints are signed.
    bool _signedness;

  public:
    linear_constraint_t() : _kind(EQUALITY), _signedness(true) {}
    linear_constraint_t(linear_constraint_t&& other) = default;
    linear_constraint_t(const linear_constraint_t& other) = default;

    linear_constraint_t(linear_expression_t expr, constraint_kind_t kind)
        : _kind(kind), _expr(std::move(expr)), _signedness(true) {}

    linear_constraint_t(linear_expression_t expr, constraint_kind_t kind, bool signedness)
        : _kind(kind), _expr(std::move(expr)), _signedness(signedness) {
        if (_kind != INEQUALITY && _kind != STRICT_INEQUALITY) {
            CRAB_ERROR("Only inequalities can have signedness information");
        }
    }

    static linear_constraint_t get_true() {
        linear_constraint_t res(linear_expression_t(number_t(0)), EQUALITY);
        return res;
    }

    static linear_constraint_t get_false() {
        linear_constraint_t res(linear_expression_t(number_t(0)), DISEQUATION);
        return res;
    }

    bool is_tautology() const {
        switch (this->_kind) {
        case DISEQUATION: return (this->_expr.is_constant() && this->_expr.constant() != 0);
        case EQUALITY: return (this->_expr.is_constant() && this->_expr.constant() == 0);
        case INEQUALITY: return (this->_expr.is_constant() && this->_expr.constant() <= 0);
        case STRICT_INEQUALITY: return (this->_expr.is_constant() && this->_expr.constant() < 0);
        default: CRAB_ERROR("Unreachable");
        }
    }

    bool is_contradiction() const {
        switch (this->_kind) {
        case DISEQUATION: return (this->_expr.is_constant() && this->_expr.constant() == 0);
        case EQUALITY: return (this->_expr.is_constant() && this->_expr.constant() != 0);
        case INEQUALITY: return (this->_expr.is_constant() && this->_expr.constant() > 0);
        case STRICT_INEQUALITY: return (this->_expr.is_constant() && this->_expr.constant() >= 0);
        default: CRAB_ERROR("Unreachable");
        }
    }

    bool is_inequality() const { return (this->_kind == INEQUALITY); }

    bool is_strict_inequality() const { return (this->_kind == STRICT_INEQUALITY); }

    bool is_equality() const { return (this->_kind == EQUALITY); }

    bool is_disequation() const { return (this->_kind == DISEQUATION); }

    const linear_expression_t& expression() const { return this->_expr; }

    constraint_kind_t kind() const { return this->_kind; }

    bool is_signed() const {
        if (_kind != INEQUALITY && _kind != STRICT_INEQUALITY) {
            CRAB_WARN("Only inequalities have signedness");
        }
        return _signedness;
    }

    bool is_unsigned() const { return (!is_signed()); }

    const_iterator begin() const { return this->_expr.begin(); }

    const_iterator end() const { return this->_expr.end(); }

    iterator begin() { return this->_expr.begin(); }

    iterator end() { return this->_expr.end(); }

    std::size_t size() const { return this->_expr.size(); }

    // syntactic equality
    bool equal(const linear_constraint_t& o) const {
        return (_kind == o._kind && _signedness == o._signedness && _expr.equal(o._expr));
    }

    size_t hash() const {
        size_t res = 0;
        boost::hash_combine(res, _expr);
        boost::hash_combine(res, _kind);
        if (_kind == INEQUALITY || _kind == STRICT_INEQUALITY) {
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
            case INEQUALITY: {
                // try to take advantage if we use z_number_t.
                // negate(e <= 0) = e >= 1
                return linear_constraint_t(-(expression() - 1), INEQUALITY, is_signed());
            }
            case STRICT_INEQUALITY: {
                // negate(x + y < 0)  <-->  x + y >= 0 <--> -x -y <= 0
                linear_expression_t e = -this->_expr;
                return linear_constraint_t(e, INEQUALITY, is_signed());
            }
            case EQUALITY: return linear_constraint_t(this->_expr, DISEQUATION);
            case DISEQUATION: return linear_constraint_t(this->_expr, EQUALITY);
            default: CRAB_ERROR("Cannot negate linear constraint");
            }
        }
    }

    template <typename RenamingMap>
    linear_constraint_t rename(const RenamingMap& map) const {
        linear_expression_t e = this->_expr.rename(map);
        return linear_constraint_t(e, this->_kind, is_signed());
    }

    friend std::ostream& operator<<(std::ostream& o, const linear_constraint_t& c) {
        if (c.is_contradiction()) {
            o << "false";
        } else if (c.is_tautology()) {
            o << "true";
        } else {
            linear_expression_t e = c._expr - c._expr.constant();
            o << e;
            switch (c._kind) {
            case INEQUALITY: {
                if (c.is_signed()) {
                    o << " <= ";
                } else {
                    o << " <=_u ";
                }
                break;
            }
            case STRICT_INEQUALITY: {
                if (c.is_signed()) {
                    o << " < ";
                } else {
                    o << " <_u ";
                }
                break;
            }
            case EQUALITY: {
                o << " = ";
                break;
            }
            case DISEQUATION: {
                o << " != ";
                break;
            }
            }
            number_t n = -c._expr.constant();
            o << n;
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
