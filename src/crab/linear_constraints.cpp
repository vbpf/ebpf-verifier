#include "crab/linear_constraints.hpp"

#include <boost/iterator/transform_iterator.hpp>

namespace ikos {

linear_expression_t::const_iterator linear_expression_t::begin() const {
    return boost::make_transform_iterator(this->_map->begin(), tr_value_ty());
}

linear_expression_t::const_iterator linear_expression_t::end() const {
    return boost::make_transform_iterator(this->_map->end(), tr_value_ty());
}

linear_expression_t::iterator linear_expression_t::begin() {
    return boost::make_transform_iterator(this->_map->begin(), tr_value_ty());
}

linear_expression_t::iterator linear_expression_t::end() {
    return boost::make_transform_iterator(this->_map->end(), tr_value_ty());
}

linear_constraint_t linear_constraint_t::negate() const {

    if (is_tautology()) {
        return get_false();
    } else if (is_contradiction()) {
        return get_true();
    } else {
        switch (kind()) {
        case INEQUALITY: {
            // negate_inequality tries to take advantage if we use z_number_t.
            return negate_inequality(*this);
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

void linear_constraint_t::write(crab::crab_os& o) const {
    if (this->is_contradiction()) {
        o << "false";
    } else if (this->is_tautology()) {
        o << "true";
    } else {
        linear_expression_t e = this->_expr - this->_expr.constant();
        o << e;
        switch (this->_kind) {
        case INEQUALITY: {
            if (is_signed()) {
                o << " <= ";
            } else {
                o << " <=_u ";
            }
            break;
        }
        case STRICT_INEQUALITY: {
            if (is_signed()) {
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
        number_t c = -this->_expr.constant();
        o << c;
    }
}

linear_constraint_system_t linear_constraint_system_t::normalize() const {
    linear_expression_unordered_set expr_set;
    linear_expression_unordered_map<unsigned> index_map;
    std::vector<bool> toremove(_csts.size(), false); // indexes to be removed
    linear_constraint_system_t out;

    for (unsigned i = 0, e = _csts.size(); i < e; ++i) {
        if (_csts[i].is_inequality()) {
            linear_expression_t exp = _csts[i].expression();
            if (expr_set.find(-exp) == expr_set.end()) {
                // remember the index and the expression
                index_map.insert({exp, i});
                expr_set.insert(exp);
            } else {
                // we found exp<=0 and -exp<= 0
                unsigned j = index_map[-exp];
                if (_csts[i].is_signed() == _csts[j].is_signed()) {
                    toremove[i] = true;
                    toremove[j] = true;
                    bool insert_pos = true;
                    if (exp.size() == 1 && (*(exp.begin())).first < 0) {
                        // unary equality: we choose the one with the positive position.
                        insert_pos = false;
                    }
                    if (!insert_pos) {
                        out += linear_constraint_t(-exp, linear_constraint_t::EQUALITY);
                    } else {
                        out += linear_constraint_t(exp, linear_constraint_t::EQUALITY);
                    }
                }
            }
        }
    }

    for (unsigned i = 0, e = _csts.size(); i < e; ++i) {
        if (!toremove[i]) {
            out += _csts[i];
        }
    }

    return out;
}
} // namespace ikos