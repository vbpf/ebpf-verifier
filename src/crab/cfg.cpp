#include "crab/cfg.hpp"
#include "crab/types.hpp"

namespace crab {


void cfg_t::remove_useless_blocks() {
    if (!has_exit())
        return;

    cfg_rev_t rev_cfg(*this);

    visited_t useful, useless;
    mark_alive_blocks(rev_cfg.entry(), rev_cfg, useful);

    for (auto const& [label, bb] : *this) {
        if (!(useful.count(label) > 0)) {
            useless.insert(label);
        }
    }

    for (auto bb_id : useless) {
        remove(bb_id);
    }
}

struct type_checker_visitor {

    type_checker_visitor() {}

    void check_num(variable_t v, std::string msg, new_statement_t s) {
        if (v.get_type() != TYPE::INT) {
            crab_string_os os;
            os << "(type checking) " << msg << " in " << s;
            CRAB_ERROR(os.str());
        }
    }

    void check_int(variable_t v, std::string msg, new_statement_t s) {
        if ((v.get_type() != TYPE::INT) || (v.get_bitwidth() <= 1)) {
            crab_string_os os;
            os << "(type checking) " << msg << " in " << s;
            CRAB_ERROR(os.str());
        }
    }

    void check_bitwidth_if_int(variable_t v, std::string msg, const new_statement_t s) {
        if (v.get_type() == TYPE::INT) {
            if (v.get_bitwidth() <= 1) {
                crab_string_os os;
                os << "(type checking) " << msg << " in " << s;
                CRAB_ERROR(os.str());
            }
        }
    }

    void check_same_type(variable_t v1, variable_t v2, std::string msg, new_statement_t s) {
        if (v1.get_type() != v2.get_type()) {
            crab_string_os os;
            os << "(type checking) " << msg << " in " << s;
            CRAB_ERROR(os.str());
        }
    }

    void check_same_bitwidth(variable_t v1, variable_t v2, std::string msg, new_statement_t s) {
        // assume v1 and v2 have same type
        if (v1.get_type() == TYPE::INT) {
            if (v1.get_bitwidth() != v2.get_bitwidth()) {
                crab_string_os os;
                os << "(type checking) " << msg << " in " << s;
                CRAB_ERROR(os.str());
            }
        }
    }

    void check_num_or_var(linear_expression_t e, std::string msg, new_statement_t s) {
        if (!(e.is_constant() || e.get_variable())) {
            crab_string_os os;
            os << "(type checking) " << msg << " in " << s;
            CRAB_ERROR(os.str());
        }
    }

    void check_array(variable_t v, new_statement_t s) {
        switch (v.get_type()) {
        case TYPE::ARR: break;
        default: {
            crab_string_os os;
            os << "(type checking) " << v << " must be an array variable in " << s;
            CRAB_ERROR(os.str());
        }
        }
    }

    // v1 is array type and v2 is a scalar type consistent with v1
    void check_array_and_scalar_type(variable_t v1, variable_t v2, new_statement_t s) {
        switch (v1.get_type()) {
        case TYPE::ARR:
            if (v2.get_type() == TYPE::INT)
                return;
            break;
        default: {
            crab_string_os os;
            os << "(type checking) " << v1 << " must be an array variable in " << s;
            CRAB_ERROR(os.str());
        }
        }
        crab_string_os os;
        os << "(type checking) " << v1 << " and " << v2 << " do not have consistent types in " << s;
        CRAB_ERROR(os.str());
    }

    void operator()(const binary_op_t& s) {
        variable_t lhs = s.lhs;
        linear_expression_t op1 = s.left;
        linear_expression_t op2 = s.right;

        check_num(lhs, "lhs must be integer", s);
        check_bitwidth_if_int(lhs, "lhs must be have bitwidth > 1", s);

        if (std::optional<variable_t> v1 = op1.get_variable()) {
            check_same_type(lhs, *v1, "first operand cannot have different type from lhs", s);
            check_same_bitwidth(lhs, *v1, "first operand cannot have different bitwidth from lhs", s);
        } else {
            CRAB_ERROR("(type checking) first binary operand must be a variable in ", s);
        }
        if (std::optional<variable_t> v2 = op2.get_variable()) {
            check_same_type(lhs, *v2, "second operand cannot have different type from lhs", s);
            check_same_bitwidth(lhs, *v2, "second operand cannot have different bitwidth from lhs", s);
        } else {
            // TODO: we can still check that we use z_number of TYPE::INT
        }
    }

    void operator()(const assign_t& s) {
        variable_t lhs = s.lhs;
        linear_expression_t rhs = s.rhs;

        check_num(lhs, "lhs must be integer", s);
        check_bitwidth_if_int(lhs, "lhs must be have bitwidth > 1", s);

        for (auto const& v : rhs.variables()) {
            check_same_type(lhs, v, "variable cannot have different type from lhs", s);
            check_same_bitwidth(lhs, v, "variable cannot have different bitwidth from lhs", s);
        }
    }

    void operator()(const assume_t& s) {
        const variable_t* first_var = nullptr;
        for (auto const& v : s.constraint.variables()) {
            check_num(v, "assume variables must be integers", s);
            if (first_var) {
                check_same_type(*first_var, v, "inconsistent types in assume variables", s);
                check_same_bitwidth(*first_var, v, "inconsistent bitwidths in assume variables", s);
            } else {
                first_var = &v;
            }
        }
    }

    void operator()(const assert_t& s) {
        const variable_t* first_var = nullptr;
        for (auto const& v : s.constraint.variables()) {
            check_num(v, "assert variables must be integers", s);
            if (first_var) {
                check_same_type(*first_var, v, "inconsistent types in assert variables", s);
                check_same_bitwidth(*first_var, v, "inconsistent bitwidths in assert variables", s);
            } else {
                first_var = &v;
            }
        }
    }

    void operator()(const select_t& s) {
        check_num(s.lhs, "lhs must be integer", s);
        check_bitwidth_if_int(s.lhs, "lhs must be have bitwidth > 1", s);

        for (const variable_t& v : s.left.variables()) {
            check_same_type(s.lhs, v, "inconsistent types in select variables", s);
            check_same_bitwidth(s.lhs, v, "inconsistent bitwidths in select variables", s);
        }
        for (const variable_t& v : s.right.variables()) {
            check_same_type(s.lhs, v, "inconsistent types in select variables", s);
            check_same_bitwidth(s.lhs, v, "inconsistent bitwidths in select variables", s);
        }

        // -- The condition can have different bitwidth from
        //    lhs/left/right operands but must have same type.
        const variable_t* first_var = nullptr;
        for (const variable_t& v : s.cond.variables()) {
            check_num(v, "assume variables must be integer", s);
            check_same_type(s.lhs, v, "inconsistent types in select condition variables", s);
            if (first_var) {
                check_same_type(*first_var, v, "inconsistent types in select condition variables", s);
                check_same_bitwidth(*first_var, v, "inconsistent bitwidths in select condition variables", s);
            } else {
                first_var = &v;
            }
        }
    }

    void operator()(const havoc_t&) {}

    void operator()(const array_store_t& s) {
        // TODO: check that e_sz is the same number that v's bitwidth
        /// XXX: we allow linear expressions as indexes
        variable_t a = s.array;
        linear_expression_t e_sz = s.elem_size;
        linear_expression_t v = s.value;
        check_array(a, s);
        check_num_or_var(e_sz, "element size must be number or variable", s);
        check_num_or_var(v, "array value must be number or variable", s);
        if (std::optional<variable_t> vv = v.get_variable()) {
            check_array_and_scalar_type(a, *vv, s);
        }
    }

    void operator()(const array_load_t& s) {
        // TODO: check that e_sz is the same number that lhs's bitwidth
        /// XXX: we allow linear expressions as indexes
        variable_t a = s.array;
        linear_expression_t e_sz = s.elem_size;
        variable_t lhs = s.lhs;
        check_array(a, s);
        check_num_or_var(e_sz, "element size must be number or variable", s);
        check_array_and_scalar_type(a, lhs, s);
    }

    void operator()(const std::monostate& s) {}
}; // end class type_checker_visitor

basic_block_t& cfg_t::insert(basic_block_label_t bb_id) {
    auto it = m_blocks.find(bb_id);
    if (it != m_blocks.end())
        return it->second;

    m_blocks.emplace(bb_id, bb_id);
    return get_node(bb_id);
}

void cfg_t::remove(basic_block_label_t bb_id) {
    if (bb_id == m_entry) {
        CRAB_ERROR("Cannot remove entry block");
    }

    if (m_exit && *m_exit == bb_id) {
        CRAB_ERROR("Cannot remove exit block");
    }

    std::vector<std::pair<basic_block_t*, basic_block_t*>> dead_edges;
    auto& bb = get_node(bb_id);

    for (auto id : boost::make_iterator_range(bb.prev_blocks())) {
        if (bb_id != id) {
            dead_edges.push_back({&get_node(id), &bb});
        }
    }

    for (auto id : boost::make_iterator_range(bb.next_blocks())) {
        if (bb_id != id) {
            dead_edges.push_back({&bb, &get_node(id)});
        }
    }

    for (auto p : dead_edges) {
        (*p.first) -= (*p.second);
    }

    m_blocks.erase(bb_id);
}

void cfg_t::remove_unreachable_blocks() {
    visited_t alive, dead;
    mark_alive_blocks(entry(), *this, alive);

    for (auto const& [label, bb] : *this) {
        if (!(alive.count(label) > 0)) {
            dead.insert(label);
        }
    }

    for (auto bb_id : dead) {
        remove(bb_id);
    }
}

void type_check(const cfg_ref_t& cfg) {
    type_checker_visitor vis;
    for (auto& [label, bb] : cfg) {
        for (const new_statement_t& statement : bb)
            std::visit(vis, statement);
    }
}

} // namespace crab