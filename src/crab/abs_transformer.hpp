#pragma once

/*
   Implementation of the abstract transfer functions by reducing them
   to abstract domain operations.
*/
#include <limits>
#include <variant>
#include <iostream>

#include "crab/abstract_domain_operators.hpp"
#include "crab/abstract_domain_specialized_traits.hpp"
#include "crab/cfg.hpp"
#include "crab/debug.hpp"
#include "crab/linear_constraints.hpp"
#include "crab/stats.hpp"
#include "crab/types.hpp"

#include "config.hpp"
#include "dsl_syntax.hpp"
#include "spec_prototypes.hpp"
#include "spec_type_descriptors.hpp"

namespace crab {
/**
 * Abstract forward transformer for all statements.
 **/
variable_t reg_value(int i) { return variable_t::reg(data_kind_t::values, i); }
variable_t reg_offset(int i) { return variable_t::reg(data_kind_t::offsets, i); }
variable_t reg_type(int i) { return variable_t::reg(data_kind_t::types, i); }

variable_t reg_value(Reg i) { return reg_value(i.v); }
variable_t reg_offset(Reg i) { return reg_offset(i.v); }
variable_t reg_type(Reg i) { return reg_type(i.v); }

inline linear_constraint_t eq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, linear_constraint_t::EQUALITY};
}

inline linear_constraint_t neq(variable_t a, variable_t b) {
    using namespace dsl_syntax;
    return {a - b, linear_constraint_t::DISEQUATION};
};

constexpr int MAX_PACKET_OFF = 0xffff;
constexpr int64_t MY_INT_MAX = INT_MAX;
constexpr int64_t PTR_MAX = MY_INT_MAX - MAX_PACKET_OFF;

/** Linear constraint for a pointer comparison.
 */
inline linear_constraint_t jmp_to_cst_offsets_reg(Condition::Op op, variable_t dst_offset, variable_t src_offset) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return eq(dst_offset, src_offset);
    case Op::NE: return neq(dst_offset, src_offset);
    case Op::GE: return dst_offset >= src_offset;
    case Op::SGE: return dst_offset >= src_offset; // pointer comparison is unsigned
    case Op::LE: return dst_offset <= src_offset;
    case Op::SLE: return dst_offset <= src_offset; // pointer comparison is unsigned
    case Op::GT: return dst_offset >= src_offset + 1;
    case Op::SGT: return dst_offset >= src_offset + 1; // pointer comparison is unsigned
    case Op::SLT: return src_offset >= dst_offset + 1;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset >= dst_offset + 1; // FIX unsigned
    default: return dst_offset - dst_offset == 0;
    }
}

/** Linear constraints for a comparison with a constant.
 */
inline std::vector<linear_constraint_t> jmp_to_cst_imm(Condition::Op op, variable_t dst_value, int imm) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {dst_value == imm};
    case Op::NE: return {dst_value != imm};
    case Op::GE: return {dst_value >= (unsigned)imm}; // FIX unsigned
    case Op::SGE: return {dst_value >= imm};
    case Op::LE: return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= imm};
    case Op::GT: return {dst_value >= (unsigned)imm + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= imm + 1};
    case Op::LT: return {dst_value <= (unsigned)imm - 1}; // FIX unsigned
    case Op::SLT: return {dst_value <= imm - 1};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

/** Linear constraint for a numerical comparison between registers.
 */
inline std::vector<linear_constraint_t> jmp_to_cst_reg(Condition::Op op, variable_t dst_value, variable_t src_value) {
    using namespace dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {eq(dst_value, src_value)};
    case Op::NE: return {neq(dst_value, src_value)};
    case Op::GE: return {dst_value >= src_value}; // FIX unsigned
    case Op::SGE: return {dst_value >= src_value};
    case Op::LE: return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= src_value};
    case Op::GT: return {dst_value >= src_value + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= src_value + 1};
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return {src_value >= dst_value + 1}; // FIX unsigned
    case Op::SLT: return {src_value >= dst_value + 1};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

inline bool is_unsigned_cmp(Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT: return true;
    default: return false;
    }
    return {};
}

template <typename AbsDomain>
class intra_abs_transformer {
  public:
    AbsDomain m_inv;

  private:

    void scratch_caller_saved_registers() {
        for (int i = 1; i <= 5; i++) {
            havoc(reg_value(i));
            havoc(reg_offset(i));
            havoc(reg_type(i));
        }
    }

    template <typename NumOrVar>
    void apply(AbsDomain& inv, binop_t op, variable_t x, variable_t y, NumOrVar z, bool finite_width = false) {
        inv.apply(op, x, y, z);
        if (finite_width)
            overflow(x);
    }

    void add(variable_t lhs, variable_t op2) {                   apply(m_inv, crab::arith_binop_t::ADD,    lhs, lhs, op2); }
    void add(variable_t lhs, number_t op2) {                     apply(m_inv, crab::arith_binop_t::ADD,    lhs, lhs, op2); }
    void sub(variable_t lhs, variable_t op2) {                   apply(m_inv, crab::arith_binop_t::SUB,    lhs, lhs, op2); }
    void sub(variable_t lhs, number_t op2) {                     apply(m_inv, crab::arith_binop_t::SUB,    lhs, lhs, op2); }
    void add_overflow(variable_t lhs, variable_t op2) {          apply(m_inv, crab::arith_binop_t::ADD,    lhs, lhs, op2, true); }
    void add_overflow(variable_t lhs, number_t op2) {            apply(m_inv, crab::arith_binop_t::ADD,    lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, variable_t op2) {          apply(m_inv, crab::arith_binop_t::SUB,    lhs, lhs, op2, true); }
    void sub_overflow(variable_t lhs, number_t op2) {            apply(m_inv, crab::arith_binop_t::SUB,    lhs, lhs, op2, true); }
    void neg(variable_t lhs) {                                   apply(m_inv, crab::arith_binop_t::MUL,    lhs, lhs, (number_t)-1,  true); }
    void mul(variable_t lhs, variable_t op2) {                   apply(m_inv, crab::arith_binop_t::MUL,    lhs, lhs, op2, true); }
    void mul(variable_t lhs, number_t op2) {                     apply(m_inv, crab::arith_binop_t::MUL,    lhs, lhs, op2, true); }
    void div(variable_t lhs, variable_t op2) {                   apply(m_inv, crab::arith_binop_t::SDIV,   lhs, lhs, op2, true); }
    void div(variable_t lhs, number_t op2) {                     apply(m_inv, crab::arith_binop_t::SDIV,   lhs, lhs, op2, true); }
    void udiv(variable_t lhs, variable_t op2) {                  apply(m_inv, crab::arith_binop_t::UDIV,   lhs, lhs, op2, true); }
    void udiv(variable_t lhs, number_t op2) {                    apply(m_inv, crab::arith_binop_t::UDIV,   lhs, lhs, op2, true); }
    void rem(variable_t lhs, variable_t op2) {                   apply(m_inv, crab::arith_binop_t::SREM,   lhs, lhs, op2, true); }
    void rem(variable_t lhs, number_t op2, bool mod = true) {    apply(m_inv, crab::arith_binop_t::SREM,   lhs, lhs, op2, mod); }
    void urem(variable_t lhs, variable_t op2) {                  apply(m_inv, crab::arith_binop_t::UREM,   lhs, lhs, op2, true); }
    void urem(variable_t lhs, number_t op2) {                    apply(m_inv, crab::arith_binop_t::UREM,   lhs, lhs, op2, true); }

    void bitwise_and(variable_t lhs, variable_t op2) {           apply(m_inv, crab::bitwise_binop_t::AND,  lhs, lhs, op2); }
    void bitwise_and(variable_t lhs, number_t op2) {             apply(m_inv, crab::bitwise_binop_t::AND,  lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, variable_t op2) {            apply(m_inv, crab::bitwise_binop_t::OR,   lhs, lhs, op2); }
    void bitwise_or(variable_t lhs, number_t op2) {              apply(m_inv, crab::bitwise_binop_t::OR,   lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, variable_t op2) {           apply(m_inv, crab::bitwise_binop_t::XOR,  lhs, lhs, op2); }
    void bitwise_xor(variable_t lhs, number_t op2) {             apply(m_inv, crab::bitwise_binop_t::XOR,  lhs, lhs, op2); }
    void shl(variable_t lhs, variable_t op2) {                   apply(m_inv, crab::bitwise_binop_t::SHL,  lhs, lhs, op2, true); }
    void shl(variable_t lhs, number_t op2) {                     apply(m_inv, crab::bitwise_binop_t::SHL,  lhs, lhs, op2, true); }
    void lshr(variable_t lhs, variable_t op2) {                  apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void lshr(variable_t lhs, number_t op2) {                    apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, variable_t op2) {                  apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }
    void ashr(variable_t lhs, number_t op2) {                    apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }
    void assume(const linear_constraint_t& cst) { m_inv += cst; }
    void havoc(variable_t v) { m_inv -= v; }
    void assign(variable_t lhs, variable_t rhs) { m_inv.assign(lhs, rhs); }
    void assign(variable_t lhs, number_t rhs) { m_inv.assign(lhs, rhs); }

    void no_pointer(int i) {
        assign(reg_type(i), T_NUM);
        havoc(reg_offset(i));
    };
    void no_pointer(Reg r) {
        no_pointer(r.v);
    }

    static linear_constraint_t is_pointer(Reg v) { using namespace dsl_syntax; return reg_type(v) >= T_CTX; }
    static linear_constraint_t is_init(Reg v) { using namespace dsl_syntax; return reg_type(v) > T_UNINIT; }
    static linear_constraint_t is_shared(Reg v) { using namespace dsl_syntax; return reg_type(v) > T_SHARED; }
    static linear_constraint_t is_not_num(Reg v) { using namespace dsl_syntax; return reg_type(v) > T_NUM; }

    void overflow(variable_t lhs) {
        // handle overflow, assuming 64 bit
        number_t max(std::numeric_limits<int64_t>::max());
        number_t min(std::numeric_limits<int64_t>::min());
        AbsDomain over(m_inv);
        over += linear_constraint_t(linear_expression_t(number_t(-1), lhs).operator+(max),
                                    linear_constraint_t::STRICT_INEQUALITY);
        AbsDomain under(m_inv);
        under += linear_constraint_t(var_sub(lhs, min), linear_constraint_t::STRICT_INEQUALITY);
        if (over.is_bottom() || under.is_bottom())
            havoc(lhs);
    }

  public:
    intra_abs_transformer(const AbsDomain& inv) : m_inv(inv) {}

    void operator()(const binary_op_t& stmt) {
        assert(stmt.left.get_variable());
        variable_t var1 = *stmt.left.get_variable();
        linear_expression_t op2 = stmt.right;
        if (op2.get_variable()) {
            apply(m_inv, stmt.op, stmt.lhs, var1, *op2.get_variable());
        } else {
            assert(op2.is_constant());
            apply(m_inv, stmt.op, stmt.lhs, var1, op2.constant());
        }
        if (stmt.finite_width) {
            // overflow()
        }
    }

    void operator()(const select_t& stmt) {
        AbsDomain inv1(m_inv);
        AbsDomain inv2(m_inv);

        inv1 += stmt.cond;
        inv2 += stmt.cond.negate();

        if (inv2.is_bottom()) {
            inv1.assign(stmt.lhs, stmt.left);
            m_inv = inv1;
        } else if (inv1.is_bottom()) {
            inv2.assign(stmt.lhs, stmt.right);
            m_inv = inv2;
        } else {
            inv1.assign(stmt.lhs, stmt.left);
            inv2.assign(stmt.lhs, stmt.right);
            m_inv = inv1 | inv2;
        }
    }

    void operator()(const assign_t& stmt) { assign(stmt.lhs, stmt.rhs); }

    void operator()(const assume_t& stmt) { m_inv += stmt.constraint; }

    void operator()(const assert_t& stmt) { m_inv += stmt.constraint; }

    void operator()(const havoc_t& stmt) { havoc(stmt.lhs); }

    void operator()(const array_store_range_t& stmt) {
        m_inv.array_store_range(stmt.array, stmt.index, stmt.width, stmt.value);
    }

    void operator()(const array_store_t& stmt) {
        m_inv.array_store(stmt.array, stmt.elem_size, stmt.index, stmt.value);
    }

    void operator()(const array_havoc_t& stmt) { m_inv.array_havoc(stmt.array, stmt.index, stmt.elem_size); }

    void operator()(const array_load_t& stmt) { m_inv.array_load(stmt.lhs, stmt.array, stmt.elem_size, stmt.index); }

    void operator()(Assume const& b) {
        using namespace dsl_syntax;
        Condition cond = b.cond;
        Reg dst = cond.left;
        variable_t dst_value  = reg_value (dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type   = reg_type  (dst);
        if (std::holds_alternative<Reg>(cond.right)) {
            Reg src = std::get<Reg>(cond.right);
            variable_t src_value  = reg_value (src);
            variable_t src_offset = reg_offset(src);
            variable_t src_type   = reg_type  (src);
            AbsDomain different{m_inv};
            different += neq(dst_type, src_type);

            AbsDomain null_src{different}; null_src += is_pointer(dst);
            AbsDomain null_dst{different}; null_dst += is_pointer(src);

            m_inv += eq(dst_type, src_type);

            AbsDomain numbers{m_inv};
            numbers += dst_type == T_NUM;
            if (!is_unsigned_cmp(cond.op))
                for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst_value, src_value))
                    numbers += cst;

            m_inv += is_pointer(dst);
            m_inv += jmp_to_cst_offsets_reg(cond.op, dst_offset, src_offset);

            m_inv |= numbers;

            m_inv |= null_src;
            m_inv |= null_dst;
        } else {
            int imm = static_cast<int>(std::get<Imm>(cond.right).v);
            for (const linear_constraint_t& cst : jmp_to_cst_imm(cond.op, dst_value, imm))
                assume(cst);
        }
    }

    void operator()(Undefined const& a) {}
    void operator()(Un const& stmt) {
        switch (stmt.op) {
        case Un::Op::LE16:
        case Un::Op::LE32:
        case Un::Op::LE64:
            havoc(reg_value(stmt.dst));
            no_pointer(stmt.dst);
            break;
        case Un::Op::NEG:
            neg(reg_value(stmt.dst));
            no_pointer(stmt.dst);
            break;
        }
    }
    void operator()(Exit const& a) {}
    void operator()(Jmp const& a) {}

    void operator()(const Comparable& s) {
        m_inv += eq(reg_type(s.r1), reg_type(s.r2));
    }

    void operator()(const Addable& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_type(s.ptr) > T_NUM;
        AbsDomain is_ptr{m_inv};
        is_ptr += cond;
        is_ptr += reg_type(s.num) == T_NUM; // TODO: assert

        m_inv += cond.negate();
        m_inv |= is_ptr;
    }

    void operator()(const ValidSize& s) {
        using namespace dsl_syntax;
        variable_t r = reg_value(s.reg);
        m_inv += s.can_be_zero ? r >= 0 : r > 0;
    }

    void operator()(const ValidMapKeyValue& s) {
    }

    void operator()(const ValidAccess& s) {
    }

    void operator()(const ValidStore& s) {
        using namespace dsl_syntax;
        linear_constraint_t cond = reg_type(s.mem) != T_STACK;

        AbsDomain non_stack{m_inv};
        non_stack += cond;
        non_stack += reg_type(s.val) == T_NUM; // TODO: assert

        m_inv += cond.negate();
        m_inv |= non_stack;
    }

    void operator()(const TypeConstraint& s) {
        using namespace dsl_syntax;
        variable_t t = reg_type(s.reg);
        switch (s.types) {
            case TypeGroup::num: assume(t == T_NUM); break;
            case TypeGroup::map_fd: assume(t == T_MAP); break;
            case TypeGroup::ctx: assume(t == T_CTX); break;
            case TypeGroup::packet: assume(t == T_PACKET); break;
            case TypeGroup::stack: assume(t == T_STACK); break;
            case TypeGroup::shared: assume(t > T_SHARED); break;
            case TypeGroup::non_map_fd: assume(t >= T_NUM); break;
            case TypeGroup::mem: assume(t >= T_STACK); break;
            case TypeGroup::mem_or_num: assume(t >= T_NUM); assume(t != T_CTX); break;
            case TypeGroup::ptr: assume(t >= T_CTX); break;
            case TypeGroup::ptr_or_num: assume(t >= T_NUM); break;
            case TypeGroup::stack_or_packet: assume(t >= T_STACK); assume(t <= T_PACKET); break;
        }
    }

    void operator()(Assert const& stmt) {
        std::visit(*this, stmt.cst);
    };

    void operator()(Packet const& a) {
        assign(reg_type(0), T_NUM);
        havoc(reg_offset(0));
        havoc(reg_value(0));
        scratch_caller_saved_registers();
    }

    void exec_ctx_access(AbsDomain& assume_ctx, bool is_load, Reg mem_reg, Reg data_reg, int offset, int width) {
        using namespace dsl_syntax;
        if (!is_load) return;
        variable_t mem_reg_offset = reg_offset(mem_reg);
        variable_t mem_reg_type = reg_type(mem_reg);

        variable_t data_reg_value = reg_value(data_reg);
        variable_t data_reg_offset = reg_offset(data_reg);
        variable_t data_reg_type = reg_type(data_reg);

        linear_expression_t addr = mem_reg_offset + (number_t)offset;

        assume_ctx += mem_reg_type == T_CTX;

        if (assume_ctx.is_bottom()) return;

        ptype_descr desc = global_program_info.descriptor;

        AbsDomain assume_normal{assume_ctx}; 
        assume(addr != desc.data);
        assume(addr != desc.end);
            assume_normal += mem_reg_offset != desc.data;
            assume_normal += mem_reg_offset != desc.end;
        if (desc.meta >= 0) {
            assume_normal += mem_reg_offset != desc.meta;
        }
        assume_normal -= data_reg_value;
        assume_normal -= data_reg_offset;
        assume_normal.assign(data_reg_type, T_NUM);

        if (desc.data < 0) {
            std::swap(assume_ctx, assume_normal);
            return;
        }
        if (!assume_normal.is_bottom()) {
            assume_ctx -= data_reg_value;
            assume_ctx -= data_reg_offset;
            assume_ctx -= data_reg_type;
            return;
        }
        std::cerr << "Looking for packet registers\n";
        auto load_datap = [&](int start) -> bool {
            AbsDomain ret{assume_ctx};
            ret += addr == start;
            if (!ret.is_bottom()) {
                std::cerr << "Found!\n";
                return true;
            }
            return false;
        };
        assume_ctx.assign(data_reg_type, T_PACKET);
        assume_ctx -= data_reg_value;
        assume_ctx += 4098 <= data_reg_value;
        assume_ctx += data_reg_value <= PTR_MAX;
        if (load_datap(desc.data))
            assume_ctx.assign(data_reg_offset, offset);
        else if (load_datap(desc.end))
            assume_ctx.assign(data_reg_offset, variable_t::packet_size());
        else if (load_datap(desc.meta))
            assume_ctx.assign(data_reg_offset, variable_t::meta_offset());
        else assert(false);
    }

    template <typename A, typename X, typename Y, typename Z>
    void do_store_stack(AbsDomain& m_inv, int width, A addr, X val_type, Y val_value, std::optional<Z> opt_val_offset) {
        m_inv.array_store_range(data_kind_t::types, addr, width, val_type);
        if (width == 8) {
            m_inv.array_store(data_kind_t::values, addr, width, val_value);
            if (opt_val_offset)
                m_inv.array_store(data_kind_t::offsets, addr, width, *opt_val_offset);
            else 
                m_inv.array_havoc(data_kind_t::offsets, addr, width);
        } else {
            m_inv.array_havoc(data_kind_t::values, addr, width);
            m_inv.array_havoc(data_kind_t::offsets, addr, width);
        }
    }

    template <typename A>
    void do_load_stack(AbsDomain& m_inv, int width, A addr, Reg target) {
        if (width == 8) {
            m_inv.array_load(reg_offset(target), data_kind_t::offsets, width, addr);
            m_inv.array_load(reg_value(target), data_kind_t::values, width, addr);
            m_inv.array_load(reg_type(target), data_kind_t::types, width, addr);
        } else {
            m_inv -= reg_offset(target);
            m_inv -= reg_value(target);
            m_inv -= reg_type(target);
        }
    }

    void operator()(Mem const& b) {
        if (std::holds_alternative<Reg>(b.value)) {
            Reg data_reg = std::get<Reg>(b.value);
            if (b.is_load) {
                do_mem_load(b, data_reg);
            } else {
                do_mem_store(b, reg_type(data_reg), reg_value(data_reg), reg_offset(data_reg));
            }
        } else {
            do_mem_store(b, T_NUM, std::get<Imm>(b.value).v, std::optional<variable_t>{});
        }
    }

    void do_mem_load(Mem const& b, Reg target) {
        using namespace dsl_syntax;
        Reg mem_reg = b.access.basereg;
        int width = (int)b.access.width;
        int offset = (int)b.access.offset;
        if (mem_reg.v == 10) {
            number_t addr = STACK_SIZE + offset;
            do_load_stack(m_inv, width, addr, target);
            return;
        }
        variable_t mem_reg_type = reg_type(mem_reg);
        linear_expression_t addr = reg_offset(mem_reg) + (number_t)offset;

        AbsDomain assume_not_stack(m_inv);
        assume_not_stack += mem_reg_type != T_STACK;
        if (!assume_not_stack.is_bottom()) {
            AbsDomain assume_ctx{assume_not_stack};
            exec_ctx_access(assume_ctx, true, mem_reg, target, offset, width);

            assume_not_stack += mem_reg_type != T_CTX;
            if (assume_not_stack.is_bottom()) {
                std::swap(assume_not_stack, assume_ctx);
            } else {
                assume_not_stack.assign(reg_type(target), T_NUM);
                assume_not_stack -= reg_offset(target);
                assume_not_stack -= reg_value(target);
                assume_not_stack |= assume_ctx;
            }
        }
        m_inv += mem_reg_type == T_STACK;
        if (!m_inv.is_bottom()) {
            do_load_stack(m_inv, width, addr, target);
        }
        m_inv |= assume_not_stack;
    }

    template <typename Type, typename Value>
    void do_mem_store(Mem const& b, Type val_type, Value val_value, std::optional<variable_t> opt_val_offset) {
        using namespace dsl_syntax;
        Reg mem_reg = b.access.basereg;
        int width = (int)b.access.width;
        int offset = (int)b.access.offset;
        if (mem_reg.v == 10) {
            int addr = STACK_SIZE + offset;
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
            return;
        }
        variable_t mem_reg_type = reg_type(mem_reg);
        linear_expression_t addr = reg_offset(mem_reg) + (number_t)offset;

        AbsDomain assume_not_stack(m_inv);
        assume_not_stack += mem_reg_type != T_STACK;
        m_inv += mem_reg_type == T_STACK;
        if (!m_inv.is_bottom()) {
            do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset);
        }
        m_inv |= assume_not_stack;
        // TODO: rest of regions
        // assume_stack += mem_reg_type == T_STACK;
        // do_store_stack(assume_stack, b.access.width, addr, reg_type(data_reg), reg_value(data_reg), reg_offset(data_reg));

        // variable_t data_reg = std::get<Reg>(b.value);
        
        // AbsDomain assume_stack{m_inv}; assume_stack += mem_reg_type == T_STACK;
        // AbsDomain assume_shared{m_inv}; assume_shared += is_shared(mem_reg_type);
        // AbsDomain assume_ctx{m_inv}; assume_ctx += mem_reg_type == T_CTX;
        // if (machine.ctx_desc.data >= 0) {
        //     AbsDomain assume_packet{m_inv}; assume_packet += mem_reg_type == T_PACKET;
        // }
        // return m_inv;
    }

    void operator()(LockAdd const& a) {
        // nothing to do here
    }

    void operator()(Call const& call) {
        using namespace dsl_syntax;
        for (ArgSingle param : call.singles) {
            switch (param.kind) {
            case ArgSingle::Kind::ANYTHING:
                break;
            case ArgSingle::Kind::MAP_FD: {
                variable_t v = reg_value(param.reg.v);
                apply(m_inv, crab::bitwise_binop_t::LSHR, variable_t::map_value_size(), v, (number_t)14);
                variable_t mk = variable_t::map_key_size();
                apply(m_inv, crab::arith_binop_t::UREM, mk, v, (number_t)(1 << 14));
                lshr(mk, 6);
                break;
            }
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
                break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                break;
            }
        }
        for (ArgPair param : call.pairs) {
            switch (param.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL: break;
            case ArgPair::Kind::PTR_TO_MEM: break;
            case ArgPair::Kind::PTR_TO_UNINIT_MEM:
                // assume it's always the stack. The following fails to work for some reason
                // fork("assume_stack_uninit", arg.region == T_STACK)
                //    havoc_num_region(arg.offset, sizereg.value));
                // havoc_num_region(arg.offset, sizereg.value);
                break;
            }
        }
        scratch_caller_saved_registers();
        variable_t r0 = reg_value(0);
        havoc(r0);
        if (call.returns_map) {
            // no support for map-in-map yet:
            //   if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
            //    || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
            // This is the only way to get a null pointer - note the `<=`:
            m_inv += 0 <= r0;
            m_inv += r0 <= PTR_MAX;
            assign(reg_offset(0), 0);
            assign(reg_type(0), variable_t::map_value_size());
        } else {
            havoc(reg_offset(0));
            assign(reg_type(0), T_NUM);
            // assume(r0 < 0); for VOID, which is actually "no return if succeed".
        }
    }

    void operator()(LoadMapFd const& ins) {
        Reg dst = ins.dst;
        assign(reg_type(dst), T_MAP);
        assign(reg_value(dst), ins.mapfd);
        havoc(reg_offset(dst));
    }

    void operator()(Bin const& bin) {
        using namespace dsl_syntax;

        Reg dst = bin.dst;
        variable_t dst_value = reg_value(dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type = reg_type(dst);

        if (std::holds_alternative<Imm>(bin.v)) {
            // dst += K
            int imm = static_cast<int>(std::get<Imm>(bin.v).v);
            switch (bin.op) {
            case Bin::Op::MOV:
                assign(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::ADD:
                if (imm == 0)
                    return;
                add_overflow(dst_value, imm);
                add(dst_offset, imm);
                break;
            case Bin::Op::SUB:
                if (imm == 0)
                    return;
                sub_overflow(dst_value, imm);
                sub(dst_offset, imm);
                break;
            case Bin::Op::MUL:
                mul(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::DIV:
                div(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::MOD:
                rem(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::AND:
                // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
                bitwise_and(dst_value, imm);
                if ((int32_t)imm > 0) {
                    assume(dst_value <= imm);
                    assume(0 <= dst_value);
                }
                no_pointer(dst);
                break;
            case Bin::Op::RSH:
                ashr(dst_value, imm);
                assume(dst_value <= (1 << (64 - imm)));
                assume(dst_value >= 0);
                no_pointer(dst);
                break;
            case Bin::Op::LSH:
                lshr(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst_value, imm);
                no_pointer(dst);
                break;
            case Bin::Op::ARSH:
                ashr(dst_value, imm); // = (int64_t)dst >> imm;
                assume(dst_value <= (1 << (64 - imm)));
                assume(dst_value >= -(1 << (64 - imm)));
                no_pointer(dst);
                break;
            }
        } else {
            // dst op= src
            Reg src = std::get<Reg>(bin.v);
            variable_t src_value = reg_value(src);
            variable_t src_offset = reg_offset(src);
            variable_t src_type = reg_type(src);
            switch (bin.op) {
            case Bin::Op::ADD: {
                AbsDomain ptr_dst{m_inv};
                ptr_dst += is_pointer(dst);
                apply(ptr_dst, crab::arith_binop_t::ADD, dst_value , dst_value , src_value, true);
                apply(ptr_dst, crab::arith_binop_t::ADD, dst_offset, dst_offset, src_value, false);

                AbsDomain ptr_src{m_inv};
                ptr_src += is_pointer(src);
                apply(ptr_src, crab::arith_binop_t::ADD, dst_value , src_value , dst_value, true);
                apply(ptr_src, crab::arith_binop_t::ADD, dst_offset, src_offset, dst_value, false);
                ptr_src.assign(dst_type, src_type);

                m_inv += dst_type == T_NUM;
                m_inv += src_type == T_NUM;
                add_overflow(dst_value, src_value);

                m_inv |= ptr_dst;
                m_inv |= ptr_src;
                break;
            }
            case Bin::Op::SUB: {
                linear_constraint_t cond = src_type == T_NUM;
                AbsDomain num_src{m_inv};
                num_src += cond;

                AbsDomain ptr_dst{num_src};
                ptr_dst += is_pointer(dst);
                apply(ptr_dst, crab::arith_binop_t::SUB, dst_value , dst_value , src_value, true);
                apply(ptr_dst, crab::arith_binop_t::SUB, dst_offset, dst_offset, src_value, false);

                AbsDomain both_num{num_src};
                both_num += dst_type == T_NUM;
                apply(both_num, crab::arith_binop_t::SUB, dst_value , dst_value , src_value, true);

                m_inv += is_pointer(src);
                apply(m_inv, crab::arith_binop_t::SUB, dst_value , dst_offset , dst_offset);
                assign(dst_type, T_NUM);
                havoc(dst_offset);

                m_inv += cond.negate();
                m_inv |= both_num;
                m_inv |= ptr_dst;
                break;
            }
            case Bin::Op::MUL:
                mul(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::DIV:
                // For some reason, DIV is not checked for zerodiv
                div(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::MOD:
                // See DIV comment
                rem(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::OR:
                bitwise_or(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::AND:
                bitwise_and(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::LSH:
                lshr(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::RSH:
                ashr(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::XOR:
                bitwise_xor(dst_value, src_value);
                no_pointer(dst);
                break;
            case Bin::Op::MOV:
                assign(dst_value, src_value);
                assign(dst_offset, src_offset);
                assign(dst_type, src_type);
                break;
            case Bin::Op::ARSH:
                ashr(dst_value, src_value); // = (int64_t)dst >> src;
                no_pointer(dst);
                break;
            }
        }
        if (!bin.is64) {
            bitwise_and(dst_value, UINT32_MAX);
        }
    }
};

enum class check_kind_t { Safe, Error, Warning, Unreachable };

// Toy database to store invariants.
class checks_db final {
    using check_t = std::pair<debug_info, check_kind_t>;

  public:
    std::set<check_t> m_db{};
    std::map<check_kind_t, int> total{
        {check_kind_t::Safe, {}},
        {check_kind_t::Error, {}},
        {check_kind_t::Warning, {}},
        {check_kind_t::Unreachable, {}},
    };

    void merge_db(checks_db&& other) {
        m_db.insert(other.m_db.begin(), other.m_db.end());
        for (auto [k, v] : other.total)
            total[k] += v;
        other.m_db.clear();
        other.total.clear();
    }

    int total_safe() const { return total.at(check_kind_t::Safe); }
    int total_error() const { return total.at(check_kind_t::Error); }
    int total_warning() const { return total.at(check_kind_t::Warning); }
    int total_unreachable() const { return total.at(check_kind_t::Unreachable); }

  public:
    checks_db() = default;

    void add_warning(const assert_t& s) {
        if (global_options.print_failures)
            std::cout << s << "\n";
        add(check_kind_t::Warning, s);
    }

    void add_redundant(const assert_t& s) { add(check_kind_t::Safe, s); }

    void add_unreachable(const assert_t& s) { add(check_kind_t::Unreachable, s); }

    void add(check_kind_t status, const assert_t& s) {
        total[status]++;
        debug_info dbg = s.debug;
        if (dbg.has_debug()) {
            m_db.insert(check_t(dbg, status));
        }
    }

    void write(std::ostream& o) const {
        std::vector<int> cnts = {total_safe(), total_error(), total_warning(), total_unreachable()};
        int maxvlen = 0;
        for (auto c : cnts) {
            maxvlen = std::max(maxvlen, (int)std::to_string(c).size());
        }

        o << std::string((int)maxvlen - std::to_string(total_safe()).size(), ' ') << total_safe() << std::string(2, ' ')
          << "Number of total safe checks\n";
        o << std::string((int)maxvlen - std::to_string(total_error()).size(), ' ') << total_error()
          << std::string(2, ' ') << "Number of total error checks\n";
        o << std::string((int)maxvlen - std::to_string(total_warning()).size(), ' ') << total_warning()
          << std::string(2, ' ') << "Number of total warning checks\n";
        o << std::string((int)maxvlen - std::to_string(total_unreachable()).size(), ' ') << total_unreachable()
          << std::string(2, ' ') << "Number of total unreachable checks\n";
    }
};

template <typename AbsDomain>
class assert_property_checker final : public intra_abs_transformer<AbsDomain> {

  public:
    checks_db m_db;
    using parent = intra_abs_transformer<AbsDomain>;

    using parent::parent;

    void operator()(const assert_t& s) {
        linear_constraint_t cst = s.constraint;
        if (cst.is_contradiction()) {
            if (this->m_inv.is_bottom()) {
                m_db.add_redundant(s);
            } else {
                m_db.add_warning(s);
            }
            return;
        }

        if (this->m_inv.is_bottom()) {
            m_db.add_unreachable(s);
            return;
        }

        if (domains::checker_domain_traits<AbsDomain>::entail(this->m_inv, cst)) {
            m_db.add_redundant(s);
        } else if (domains::checker_domain_traits<AbsDomain>::intersect(this->m_inv, cst)) {
            // TODO: add_error() if imply negation
            m_db.add_warning(s);
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
            m_db.add_warning(s);
        }
        parent::operator()(s); // propagate invariants to the next stmt
    }

    template <typename T>
    void operator()(const T& s) {
        parent::operator()(s);
    }
};


template <typename AbsDomain>
inline AbsDomain setup_entry() {
    using namespace dsl_syntax;

    // intra_abs_transformer<AbsDomain>(inv);
    AbsDomain inv;
    inv += STACK_SIZE <= reg_value(10);
    inv.assign(reg_offset(10), STACK_SIZE);
    inv.assign(reg_type(10), T_STACK);

    inv += 1 <= reg_value(1);
    inv += reg_value(1) <= PTR_MAX;
    inv.assign(reg_offset(1), 0);
    inv.assign(reg_type(1), T_CTX);

    inv += 0 <= variable_t::packet_size();
    inv += variable_t::packet_size() < MAX_PACKET_OFF;
    if (global_program_info.descriptor.meta >= 0) {
        inv += variable_t::meta_offset() <= 0;
        inv += variable_t::meta_offset() >= -4098;
    } else {
        inv.assign(variable_t::meta_offset(), 0);
    }
    return inv;
}

template <typename AbsDomain>
inline AbsDomain transform(const basic_block_t& bb, const AbsDomain& from_inv) {
    intra_abs_transformer<AbsDomain> transformer(from_inv);
    for (const auto& statement : bb) {
        std::visit(transformer, statement);
    }
    return std::move(transformer.m_inv);
}

template <typename AbsDomain>
inline void check_block(const basic_block_t& bb, const AbsDomain& from_inv, checks_db& db) {
    if (std::none_of(bb.begin(), bb.end(), [](const auto& s) { return std::holds_alternative<Assert>(s); }))
        return;
    assert_property_checker<AbsDomain> checker(from_inv);
    for (const auto& statement : bb) {
        std::visit(checker, statement);
    }
    db.merge_db(std::move(checker.m_db));
}
} // namespace crab
