#include "crab/cfg.hpp"
#include "crab/crab_syntax.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/os.hpp"

namespace crab {

struct type_checker_visitor {

    void error(std::string msg, new_statement_t s) {
        crab_string_os os;
        os << "(type checking) " << msg << " in " << s;
        CRAB_ERROR(os.str());
    }

    void error(variable_t v, std::string msg, new_statement_t s) {
        crab_string_os os;
        os << "(type checking) " << v << msg << " in " << s;
        CRAB_ERROR(os.str());
    }

    void error(variable_t v1, variable_t v2, std::string msg, new_statement_t s) {
        crab_string_os os;
        os << "(type checking) " << v1 << " and " << msg << " in " << s;
        CRAB_ERROR(os.str());
    }

    bool same_type(variable_t v1, variable_t v2) { return v1.get_type() == v2.get_type(); }

    bool same_bitwidth(variable_t v1, variable_t v2) {
        // assume v1 and v2 have same type
        return v1.get_type() != TYPE::INT || v1.get_bitwidth() == v2.get_bitwidth();
    }

    bool num_or_var(linear_expression_t e) { return e.is_constant() || e.get_variable(); }

    // v1 is array type and v2 is a scalar type consistent with v1
    void check_array_and_scalar_type(variable_t v1, variable_t v2, new_statement_t s) {
        if (v1.get_type() != TYPE::ARR) {
            error(v1, "must be an array variable", s);
        } else if (v2.get_type() != TYPE::INT) {
            error(v1, v2, "do not have consistent types", s);
        }
    }

    void operator()(const binary_op_t& s) {
        variable_t lhs = s.lhs;
        linear_expression_t op1 = s.left;
        linear_expression_t op2 = s.right;

        if (lhs.get_type() != TYPE::INT)
            error("lhs must be integer", s);
        if (lhs.get_bitwidth() <= 1)
            error(lhs, "lhs must be have bitwidth > 1", s);

        if (std::optional<variable_t> v1 = op1.get_variable()) {
            if (!same_type(lhs, *v1))
                error("first operand cannot have different type from lhs", s);
            if (!same_bitwidth(lhs, *v1))
                error("first operand cannot have different bitwidth from lhs", s);
        } else {
            CRAB_ERROR("(type checking) first binary operand must be a variable in ", s);
        }
        if (std::optional<variable_t> v2 = op2.get_variable()) {
            if (!same_type(lhs, *v2))
                error("second operand cannot have different type from lhs", s);
            if (!same_bitwidth(lhs, *v2))
                error("second operand cannot have different bitwidth from lhs", s);
        } else {
            // TODO: we can still check that we use z_number of TYPE::INT
        }
    }

    void operator()(const assign_t& s) {
        variable_t lhs = s.lhs;
        linear_expression_t rhs = s.rhs;

        if (lhs.get_type() != TYPE::INT)
            error("lhs must be integer", s);
        if (lhs.get_bitwidth() <= 1)
            error("lhs must be have bitwidth > 1", s);

        for (auto const& v : rhs.variables()) {
            if (!same_type(lhs, v))
                error("variable cannot have different type from lhs", s);
            if (!same_bitwidth(lhs, v))
                error("variable cannot have different bitwidth from lhs", s);
        }
    }

    void operator()(const assume_t& s) {
        const variable_t* first_var = nullptr;
        for (auto const& v : s.constraint.variables()) {
            if (v.get_type() != TYPE::INT)
                error("assume variables must be integers", s);
            if (first_var) {
                if (!same_type(*first_var, v))
                    error("inconsistent types in assume variables", s);
                if (!same_bitwidth(*first_var, v))
                    error("inconsistent bitwidths in assume variables", s);
            } else {
                first_var = &v;
            }
        }
    }

    void operator()(const assert_t& s) {
        const variable_t* first_var = nullptr;
        for (auto const& v : s.constraint.variables()) {
            if (v.get_type() != TYPE::INT)
                error("assert variables must be integers", s);
            if (first_var) {
                if (!same_type(*first_var, v))
                    error("inconsistent types in assert variables", s);
                if (!same_bitwidth(*first_var, v))
                    error("inconsistent bitwidths in assert variables", s);
            } else {
                first_var = &v;
            }
        }
    }

    void operator()(const select_t& s) {
        if (s.lhs.get_type() != TYPE::INT)
            error("lhs must be integer", s);
        if (s.lhs.get_bitwidth() <= 1)
            error("lhs must be have bitwidth > 1", s);

        for (const variable_t& v : s.left.variables()) {
            if (!same_type(s.lhs, v))
                error("inconsistent types in select variables", s);
            if (!same_bitwidth(s.lhs, v))
                error("inconsistent bitwidths in select variables", s);
        }
        for (const variable_t& v : s.right.variables()) {
            if (!same_type(s.lhs, v))
                error("inconsistent types in select variables", s);
            if (!same_bitwidth(s.lhs, v))
                error("inconsistent bitwidths in select variables", s);
        }

        // -- The condition can have different bitwidth from
        //    lhs/left/right operands but must have same type.
        const variable_t* first_var = nullptr;
        for (const variable_t& v : s.cond.variables()) {
            if (v.get_type() != TYPE::INT)
                error("condition variables must be integers", s);
            if (!same_type(s.lhs, v))
                error("inconsistent types in select condition variables", s);
            if (first_var) {
                if (!same_type(*first_var, v))
                    error("inconsistent types in select condition variables", s);
                if (!same_bitwidth(*first_var, v))
                    error("inconsistent bitwidths in select condition variables", s);
            } else {
                first_var = &v;
            }
        }
    }

    void operator()(const havoc_t&) {}
    void operator()(const array_havoc_t& s) {

    }

    void operator()(const array_store_t& s) {
        // TODO: check that e_sz is the same number that v's bitwidth
        /// XXX: we allow linear expressions as indexes
        variable_t a = s.array;
        linear_expression_t v = s.value;
        if (a.get_type() != TYPE::ARR)
            error(a, "must be an array variable", s);
        if (!num_or_var(s.elem_size))
            error("element size must be number or variable", s);
        if (!num_or_var(v))
            error("array value must be number or variable", s);
        if (std::optional<variable_t> vv = v.get_variable()) {
            check_array_and_scalar_type(a, *vv, s);
        }
    }

    void operator()(const array_load_t& s) {
        // TODO: check that e_sz is the same number that lhs's bitwidth
        /// XXX: we allow linear expressions as indexes
        variable_t a = s.array;
        variable_t lhs = s.lhs;
        if (a.get_type() != TYPE::ARR)
            error(a, "must be an array variable", s);
        if (!num_or_var(s.elem_size))
            error("element size must be number or variable", s);
        check_array_and_scalar_type(a, lhs, s);
    }
}; // end class type_checker_visitor

void type_check(const cfg_ref_t& cfg) {
    type_checker_visitor vis;
    for (auto& [label, bb] : cfg) {
        for (const new_statement_t& statement : bb)
            std::visit(vis, statement);
    }
}

} // namespace crab