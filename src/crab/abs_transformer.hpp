#pragma once

/*
   Implementation of the abstract transfer functions by reducing them
   to abstract domain operations.

   These are the main Crab statements for which we define their abstract
   transfer functions:

   ARITHMETIC and BOOLEAN
     x := y bin_op z;
     x := y;
     assume(cst)
     assert(cst);
     x := select(cond, y, z);

   ARRAYS
     a[l...u] := v (a,b are arrays and v can be bool/integer/pointer)
     a[i] := v;
     v := a[i];

   havoc(x);

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
variable_t reg_type(int i) { return variable_t::reg(data_kind_t::regions, i); }

constexpr int MAX_PACKET_OFF = 0xffff;
constexpr int64_t MY_INT_MAX = INT_MAX;
constexpr int64_t PTR_MAX = MY_INT_MAX - MAX_PACKET_OFF;

template <typename AbsDomain>
class intra_abs_transformer {
  public:
    AbsDomain m_inv;

  private:
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
    void neg(variable_t lhs) {                                   apply(m_inv, crab::arith_binop_t::MUL,    lhs, lhs, -1,  true); }
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
    void assume(linear_constraint_t cst) { m_inv += cst; }

    void no_pointer(int i) {
        m_inv.assign(reg_type(i), T_NUM);
        m_inv -= reg_offset(i);
    };

    static linear_constraint_t is_pointer(int v) { using namespace dsl_syntax; return reg_type(v) >= T_CTX; }
    static linear_constraint_t is_init(int v) { using namespace dsl_syntax; return reg_type(v) > T_UNINIT; }
    static linear_constraint_t is_shared(int v) { using namespace dsl_syntax; return reg_type(v) > T_SHARED; }
    static linear_constraint_t is_not_num(int v) { using namespace dsl_syntax; return reg_type(v) > T_NUM; }

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
            m_inv -= lhs;
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

    void operator()(const assign_t& stmt) { m_inv.assign(stmt.lhs, stmt.rhs); }

    void operator()(const assume_t& stmt) { m_inv += stmt.constraint; }

    void operator()(const assert_t& stmt) { m_inv += stmt.constraint; }

    void operator()(const havoc_t& stmt) { m_inv -= stmt.lhs; }

    void operator()(const array_store_range_t& stmt) {
        m_inv.array_store_range(stmt.array, stmt.index, stmt.width, stmt.value);
    }

    void operator()(const array_store_t& stmt) {
        m_inv.array_store(stmt.array, stmt.elem_size, stmt.index, stmt.value);
    }

    void operator()(const array_havoc_t& stmt) { m_inv.array_havoc(stmt.array, stmt.elem_size, stmt.index); }

    void operator()(const array_load_t& stmt) { m_inv.array_load(stmt.lhs, stmt.array, stmt.elem_size, stmt.index); }

    void operator()(Undefined const& a) {}
    void operator()(Un const& a) {}
    void operator()(Exit const& a) {}
    void operator()(Jmp const& a) {}
    void operator()(Assume const& a) {}
    void operator()(Assert const& a) {}
    void operator()(Packet const& a) {}
    void operator()(Mem const& a) {}
    void operator()(LockAdd const& a) {}

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
        for (int i = 1; i <= 5; i++) {
            m_inv -= reg_value(i);
            m_inv -= reg_offset(i);
            m_inv -= reg_type(i);
        }
        variable_t r0 = reg_value(0);
        m_inv -= r0;
        if (call.returns_map) {
            // no support for map-in-map yet:
            //   if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
            //    || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
            // This is the only way to get a null pointer - note the `<=`:
            m_inv += 0 <= r0;
            m_inv += r0 <= PTR_MAX;
            m_inv.assign(reg_offset(0), 0);
            m_inv.assign(reg_type(0), variable_t::map_value_size());
        } else {
            m_inv -= reg_offset(0);
            m_inv.assign(reg_type(0), T_NUM);
            // assume(r0 < 0); for VOID, which is actually "no return if succeed".
        }
    }

    void operator()(LoadMapFd const& ins) {
        int dst = ins.dst.v;
        m_inv.assign(reg_type(dst), T_MAP);
        m_inv.assign(reg_value(dst), ins.mapfd);
        m_inv -= reg_offset(dst);
    }

    void operator()(Bin const& bin) {
        using namespace dsl_syntax;

        int dst = bin.dst.v;
        variable_t dst_value = reg_value(dst);
        variable_t dst_offset = reg_offset(dst);
        variable_t dst_type = reg_type(dst);

        if (std::holds_alternative<Imm>(bin.v)) {
            // dst += K
            int imm = static_cast<int>(std::get<Imm>(bin.v).v);
            switch (bin.op) {
            case Bin::Op::MOV:
                m_inv.assign(dst_value, imm);
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
            int src = static_cast<int>(std::get<Reg>(bin.v).v);
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

                m_inv = m_inv | ptr_dst;
                m_inv = m_inv | ptr_src;
                break;
            }
            case Bin::Op::SUB: {
                AbsDomain num_src{m_inv};
                num_src += src_type == T_NUM;

                AbsDomain ptr_dst{num_src};
                ptr_dst += is_pointer(dst);
                apply(ptr_dst, crab::arith_binop_t::SUB, dst_value , dst_value , src_value, true);
                apply(ptr_dst, crab::arith_binop_t::SUB, dst_offset, dst_offset, src_value, false);

                AbsDomain both_num{num_src};
                both_num += dst_type == T_NUM;
                apply(both_num, crab::arith_binop_t::SUB, dst_value , dst_value , src_value, true);

                m_inv += is_pointer(src);
                apply(m_inv, crab::arith_binop_t::SUB, dst_value , dst_offset , dst_offset);
                m_inv.assign(dst_type, T_NUM);
                m_inv -= dst_offset;

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
                m_inv.assign(dst_value, src_value);
                m_inv.assign(dst_offset, src_offset);
                m_inv.assign(dst_type, src_type);
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
    inv.assign(reg_offset(1), T_CTX);

    inv += 0 <= variable_t::packet_size();
    inv += variable_t::packet_size() < MAX_PACKET_OFF;
    //  .where(machine.ctx_desc.meta >= 0).assume(machine.meta_offset <= 0).assume(machine.meta_offset >= -4098)
    //                        .otherwise().assign(machine.meta_offset, 0)
    //  .done();
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
