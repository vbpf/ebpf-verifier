#include "crab/linear_constraints.hpp"

#include <boost/iterator/transform_iterator.hpp>

namespace crab {

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

void linear_constraint_t::write(std::ostream& o) const {
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

} // namespace crab