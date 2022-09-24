// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <algorithm>
#include <bitset>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include "boost/range/algorithm/set_algorithm.hpp"

#include "crab_utils/stats.hpp"

#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"

#include "asm_ostream.hpp"
#include "config.hpp"
#include "crab_verifier.hpp"
#include "dsl_syntax.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"

using crab::domains::NumAbsDomain;
using crab::data_kind_t;

struct reg_pack_t {
    variable_t value, ctx_offset, map_fd, packet_offset, shared_offset, stack_offset, type, shared_region_size, stack_numeric_size;
};

reg_pack_t reg_pack(int i) {
    return {
        variable_t::reg(data_kind_t::values, i),
        variable_t::reg(data_kind_t::ctx_offsets, i),
        variable_t::reg(data_kind_t::map_fds, i),
        variable_t::reg(data_kind_t::packet_offsets, i),
        variable_t::reg(data_kind_t::shared_offsets, i),
        variable_t::reg(data_kind_t::stack_offsets, i),
        variable_t::reg(data_kind_t::types, i),
        variable_t::reg(data_kind_t::shared_region_sizes, i),
        variable_t::reg(data_kind_t::stack_numeric_sizes, i),
    };
}
reg_pack_t reg_pack(Reg r) { return reg_pack(r.v); }

static linear_constraint_t eq(variable_t a, variable_t b) {
    using namespace crab::dsl_syntax;
    return {a - b, constraint_kind_t::EQUALS_ZERO};
}

static linear_constraint_t eq_types(const Reg& a, const Reg& b) {
    return eq(reg_pack(a).type, reg_pack(b).type);
}

static linear_constraint_t neq(variable_t a, variable_t b) {
    using namespace crab::dsl_syntax;
    return {a - b, constraint_kind_t::NOT_ZERO};
}

constexpr int MAX_PACKET_SIZE = 0xffff;
constexpr int64_t MY_INT_MAX = INT_MAX;
constexpr int64_t PTR_MAX = MY_INT_MAX - MAX_PACKET_SIZE;

/** Linear constraint for a pointer comparison.
 */
static linear_constraint_t jmp_to_cst_offsets_reg(Condition::Op op, variable_t dst_offset, variable_t src_offset) {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return eq(dst_offset, src_offset);
    case Op::NE: return neq(dst_offset, src_offset);
    case Op::GE: return dst_offset >= src_offset;
    case Op::SGE: return dst_offset >= src_offset; // pointer comparison is unsigned
    case Op::LE: return dst_offset <= src_offset;
    case Op::SLE: return dst_offset <= src_offset; // pointer comparison is unsigned
    case Op::GT: return dst_offset > src_offset;
    case Op::SGT: return dst_offset > src_offset; // pointer comparison is unsigned
    case Op::SLT: return src_offset > dst_offset;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset > dst_offset; // FIX unsigned
    default: return dst_offset - dst_offset == 0;
    }
}

/** Linear constraints for a comparison with a constant.
 */
static std::vector<linear_constraint_t> jmp_to_cst_imm(Condition::Op op, variable_t dst_value, int imm) {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {dst_value == imm};
    case Op::NE: return {dst_value != imm};
    case Op::GE: return {dst_value >= (unsigned)imm}; // FIX unsigned
    case Op::SGE: return {dst_value >= imm};
    case Op::LE: return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= imm};
    case Op::GT: return {dst_value > (unsigned)imm}; // FIX unsigned
    case Op::SGT: return {dst_value > imm};
    case Op::LT: return {dst_value < (unsigned)imm}; // FIX unsigned
    case Op::SLT: return {dst_value < imm};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

/** Linear constraint for a numerical comparison between registers.
 */
static std::vector<linear_constraint_t> jmp_to_cst_reg(Condition::Op op, variable_t dst_value, variable_t src_value) {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {eq(dst_value, src_value)};
    case Op::NE: return {neq(dst_value, src_value)};
    case Op::GE: return {dst_value >= src_value}; // FIX unsigned
    case Op::SGE: return {dst_value >= src_value};
    case Op::LE: return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= src_value};
    case Op::GT: return {dst_value > src_value}; // FIX unsigned
    case Op::SGT: return {dst_value > src_value};
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return {src_value > dst_value}; // FIX unsigned
    case Op::SLT: return {src_value > dst_value};
    case Op::SET: throw std::exception();
    case Op::NSET: return {};
    }
    return {};
}

static bool is_unsigned_cmp(Condition::Op op) {
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

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg, int type) {
    reg_pack_t r = reg_pack(reg);
    switch (type) {
    case T_CTX: return r.ctx_offset;
    case T_MAP:
    case T_MAP_PROGRAMS: return r.map_fd;
    case T_PACKET: return r.packet_offset;
    case T_SHARED: return r.shared_offset;
    case T_STACK: return r.stack_offset;
    default: return {};
    }
}

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg, const NumAbsDomain& inv) const {
    return get_type_offset_variable(reg, type_inv.get_type(inv, reg_pack(reg).type));
}

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg) const {
    return get_type_offset_variable(reg, m_inv);
}

void ebpf_domain_t::set_require_check(std::function<check_require_func_t> f) { check_require = std::move(f); }

ebpf_domain_t ebpf_domain_t::top() {
    ebpf_domain_t abs;
    abs.set_to_top();
    return abs;
}

ebpf_domain_t ebpf_domain_t::bottom() {
    ebpf_domain_t abs;
    abs.set_to_bottom();
    return abs;
}

ebpf_domain_t::ebpf_domain_t() : m_inv(NumAbsDomain::top()) {}

ebpf_domain_t::ebpf_domain_t(NumAbsDomain inv, crab::domains::array_domain_t stack) : m_inv(std::move(inv)), stack(stack) {}

void ebpf_domain_t::set_to_top() {
    m_inv.set_to_top();
    stack.set_to_top();
}

void ebpf_domain_t::set_to_bottom() { m_inv.set_to_bottom(); }

bool ebpf_domain_t::is_bottom() const { return m_inv.is_bottom(); }

bool ebpf_domain_t::is_top() const { return m_inv.is_top() && stack.is_top(); }

bool ebpf_domain_t::operator<=(const ebpf_domain_t& other) {
    return m_inv <= other.m_inv && stack <= other.stack;
}

bool ebpf_domain_t::operator==(const ebpf_domain_t& other) const {
    return stack == other.stack && m_inv <= other.m_inv && other.m_inv <= m_inv;
}

void ebpf_domain_t::TypeDomain::add_extra_invariant(NumAbsDomain& dst,
                                                    std::map<crab::variable_t,
                                                    crab::interval_t>& extra_invariants,
                                                    variable_t type_variable,
                                                    type_encoding_t type,
                                                    data_kind_t kind,
                                                    const NumAbsDomain& src) const {
    bool dst_has_type = has_type(dst, type_variable, type);
    bool src_has_type = has_type(src, type_variable, type);
    variable_t v = variable_t::kind_var(kind, type_variable);

    // If type is contained in exactly one of dst or src,
    // we need to remember the value.
    if (dst_has_type && !src_has_type)
        extra_invariants.emplace(v, dst.eval_interval(v));
    else if (!dst_has_type && src_has_type)
        extra_invariants.emplace(v, src.eval_interval(v));
}

void ebpf_domain_t::TypeDomain::selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain& src) const {
    // Some variables are type-specific.  Type-specific variables
    // for a register can exist in the domain whenever the associated
    // type value is present in the register's types interval (and the
    // value is not Top), and are absent otherwise.  That is, we want
    // to keep track of implications of the form
    // "if register R has type=T then R.T_offset has value ...".
    //
    // If a type value is legal in exactly one of the two domains, a
    // normal join operation would remove any type-specific variables
    // from the resulting merged domain since absence from the other
    // would be interpreted to mean Top.
    //
    // However, when the type value is not present in one domain, any
    // any type-specific variables for that type are instead to be
    // interpreted as Bottom, so we want to preserve the values of any
    // type-specific variables from the other domain where the type
    // value is legal.
    //
    // Example input:
    //   r1.type=stack, r1.stack_offset=100
    //   r1.type=packet, r1.packet_offset=4
    // Output:
    //   r1.type={stack,packet}, r1.stack_offset=100, r1.packet_offset=4

    std::map<crab::variable_t, crab::interval_t> extra_invariants;
    if (!dst.is_bottom()) {
        for (variable_t v : variable_t::get_type_variables()) {
            add_extra_invariant(dst, extra_invariants, v, T_CTX, data_kind_t::ctx_offsets, src);
            add_extra_invariant(dst, extra_invariants, v, T_MAP, data_kind_t::map_fds, src);
            add_extra_invariant(dst, extra_invariants, v, T_MAP_PROGRAMS, data_kind_t::map_fds, src);
            add_extra_invariant(dst, extra_invariants, v, T_PACKET, data_kind_t::packet_offsets, src);
            add_extra_invariant(dst, extra_invariants, v, T_SHARED, data_kind_t::shared_offsets, src);
            add_extra_invariant(dst, extra_invariants, v, T_STACK, data_kind_t::stack_offsets, src);
            add_extra_invariant(dst, extra_invariants, v, T_SHARED, data_kind_t::shared_region_sizes, src);
            add_extra_invariant(dst, extra_invariants, v, T_STACK, data_kind_t::stack_numeric_sizes, src);
        }
    }

    // Do a normal join operation on the domain.
    dst |= std::move(src);

    // Now add in the extra invariants saved above.
    for (auto& [variable, interval] : extra_invariants) {
        dst.set(variable, interval);
    }
}

void ebpf_domain_t::operator|=(ebpf_domain_t&& other) {
    if (is_bottom()) {
        *this = other;
        return;
    }
    if (other.is_bottom()) {
        return;
    }

    type_inv.selectively_join_based_on_type(m_inv, other.m_inv);

    stack |= other.stack;
}

void ebpf_domain_t::operator|=(const ebpf_domain_t& other) {
    ebpf_domain_t tmp{other};
    operator|=(std::move(tmp));
}

ebpf_domain_t ebpf_domain_t::operator|(ebpf_domain_t&& other) const {
    return ebpf_domain_t(m_inv | std::move(other.m_inv), stack | other.stack);
}

ebpf_domain_t ebpf_domain_t::operator|(const ebpf_domain_t& other) const& {
    return ebpf_domain_t(m_inv | other.m_inv, stack | other.stack);
}

ebpf_domain_t ebpf_domain_t::operator|(const ebpf_domain_t& other) && {
    return ebpf_domain_t(other.m_inv | std::move(m_inv), other.stack | std::move(stack));
}

ebpf_domain_t ebpf_domain_t::operator&(const ebpf_domain_t& other) const {
    return ebpf_domain_t(m_inv & other.m_inv, stack & other.stack);
}

ebpf_domain_t ebpf_domain_t::widen(const ebpf_domain_t& other) {
    return ebpf_domain_t(m_inv.widen(other.m_inv), stack | other.stack);
}

ebpf_domain_t ebpf_domain_t::widening_thresholds(const ebpf_domain_t& other, const crab::iterators::thresholds_t& ts) {
    return ebpf_domain_t(m_inv.widening_thresholds(other.m_inv, ts), stack | other.stack);
}

ebpf_domain_t ebpf_domain_t::narrow(const ebpf_domain_t& other) {
    return ebpf_domain_t(m_inv.narrow(other.m_inv), stack & other.stack);
}

void ebpf_domain_t::operator+=(const linear_constraint_t& cst) { m_inv += cst; }

void ebpf_domain_t::operator-=(variable_t var) { m_inv -= var; }

void ebpf_domain_t::assign(variable_t x, const linear_expression_t& e) { m_inv.assign(x, e); }
void ebpf_domain_t::assign(variable_t x, long e) { m_inv.set(x, crab::interval_t(number_t(e))); }

void ebpf_domain_t::apply(crab::arith_binop_t op, variable_t x, variable_t y, const number_t& z) { m_inv.apply(op, x, y, z); }

void ebpf_domain_t::apply(crab::arith_binop_t op, variable_t x, variable_t y, variable_t z) { m_inv.apply(op, x, y, z); }

void ebpf_domain_t::apply(crab::bitwise_binop_t op, variable_t x, variable_t y, variable_t z) { m_inv.apply(op, x, y, z); }

void ebpf_domain_t::apply(crab::bitwise_binop_t op, variable_t x, variable_t y, const number_t& k) { m_inv.apply(op, x, y, k); }

void ebpf_domain_t::apply(crab::binop_t op, variable_t x, variable_t y, const number_t& z) {
    std::visit([&](auto top) { apply(top, x, y, z); }, op);
}

void ebpf_domain_t::apply(crab::binop_t op, variable_t x, variable_t y, variable_t z) {
    std::visit([&](auto top) { apply(top, x, y, z); }, op);
}

void ebpf_domain_t::scratch_caller_saved_registers() {
    for (int i = R1_ARG; i <= R5_ARG; i++) {
        Reg r{(uint8_t)i};
        havoc_register(m_inv, r);
        type_inv.havoc_type(m_inv, r);
    }
}

void ebpf_domain_t::forget_packet_pointers() {
    using namespace crab::dsl_syntax;

    for (variable_t type_variable : variable_t::get_type_variables()) {
        if (type_inv.has_type(m_inv, type_variable, T_PACKET)) {
            havoc(variable_t::kind_var(data_kind_t::types, type_variable));
            havoc(variable_t::kind_var(data_kind_t::packet_offsets, type_variable));
            havoc(variable_t::kind_var(data_kind_t::values, type_variable));
        }
    }

    initialize_packet(*this);
}

void ebpf_domain_t::apply(NumAbsDomain& inv, crab::binop_t op, variable_t x, variable_t y, const number_t& z, bool finite_width) {
    inv.apply(op, x, y, z);
    if (finite_width)
        overflow(x);
}

void ebpf_domain_t::apply(NumAbsDomain& inv, crab::binop_t op, variable_t x, variable_t y, variable_t z, bool finite_width) {
    inv.apply(op, x, y, z);
    if (finite_width)
        overflow(x);
}

void ebpf_domain_t::add(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
void ebpf_domain_t::add(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2); }
void ebpf_domain_t::sub(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
void ebpf_domain_t::sub(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2); }
void ebpf_domain_t::add_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
void ebpf_domain_t::add_overflow(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::ADD, lhs, lhs, op2, true); }
void ebpf_domain_t::sub_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
void ebpf_domain_t::sub_overflow(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::SUB, lhs, lhs, op2, true); }
void ebpf_domain_t::neg(variable_t lhs) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, (number_t)-1, true); }
void ebpf_domain_t::mul(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
void ebpf_domain_t::mul(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::MUL, lhs, lhs, op2, true); }
void ebpf_domain_t::div(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
void ebpf_domain_t::div(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::SDIV, lhs, lhs, op2, true); }
void ebpf_domain_t::udiv(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
void ebpf_domain_t::udiv(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::UDIV, lhs, lhs, op2, true); }
void ebpf_domain_t::rem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, true); }
void ebpf_domain_t::rem(variable_t lhs, const number_t& op2, bool mod) {
    apply(m_inv, crab::arith_binop_t::SREM, lhs, lhs, op2, mod);
}
void ebpf_domain_t::urem(variable_t lhs, variable_t op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }
void ebpf_domain_t::urem(variable_t lhs, const number_t& op2) { apply(m_inv, crab::arith_binop_t::UREM, lhs, lhs, op2, true); }

void ebpf_domain_t::bitwise_and(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
void ebpf_domain_t::bitwise_and(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::AND, lhs, lhs, op2); }
void ebpf_domain_t::bitwise_or(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
void ebpf_domain_t::bitwise_or(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::OR, lhs, lhs, op2); }
void ebpf_domain_t::bitwise_xor(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
void ebpf_domain_t::bitwise_xor(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::XOR, lhs, lhs, op2); }
void ebpf_domain_t::shl_overflow(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
void ebpf_domain_t::shl_overflow(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::SHL, lhs, lhs, op2, true); }
void ebpf_domain_t::lshr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
void ebpf_domain_t::lshr(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::LSHR, lhs, lhs, op2); }
void ebpf_domain_t::ashr(variable_t lhs, variable_t op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }
void ebpf_domain_t::ashr(variable_t lhs, const number_t& op2) { apply(m_inv, crab::bitwise_binop_t::ASHR, lhs, lhs, op2); }


static void assume(NumAbsDomain& inv, const linear_constraint_t& cst) { inv += cst; }
void ebpf_domain_t::assume(const linear_constraint_t& cst) { ::assume(m_inv, cst); }

void ebpf_domain_t::require(NumAbsDomain& inv, const linear_constraint_t& cst, const std::string& s) {
    if (check_require)
        check_require(inv, cst, s + " (" + this->current_assertion + ")");
    if (thread_local_options.assume_assertions) {
        // avoid redundant errors
        ::assume(inv, cst);
    }
}

/// Forget everything we know about the value of a variable.
void ebpf_domain_t::havoc(variable_t v) { m_inv -= v; }
void ebpf_domain_t::havoc_offsets(NumAbsDomain& inv, const Reg& reg) {
    reg_pack_t r = reg_pack(reg);
    inv -= r.ctx_offset;
    inv -= r.map_fd;
    inv -= r.packet_offset;
    inv -= r.shared_offset;
    inv -= r.shared_region_size;
    inv -= r.stack_offset;
    inv -= r.stack_numeric_size;
}
void ebpf_domain_t::havoc_offsets(const Reg& reg) { havoc_offsets(m_inv, reg); }
void ebpf_domain_t::havoc_register(NumAbsDomain& inv, const Reg& reg) {
    reg_pack_t r = reg_pack(reg);
    havoc_offsets(inv, reg);
    inv -= r.value;
}

void ebpf_domain_t::assign(variable_t lhs, variable_t rhs) { m_inv.assign(lhs, rhs); }

static linear_constraint_t type_is_pointer(const reg_pack_t& r) {
    using namespace crab::dsl_syntax;
    return r.type >= T_CTX;
}

static linear_constraint_t type_is_number(const Reg& r) {
    using namespace crab::dsl_syntax;
    return reg_pack(r).type == T_NUM;
}

static linear_constraint_t type_is_not_stack(const reg_pack_t& r) {
    using namespace crab::dsl_syntax;
    return r.type != T_STACK;
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, type_encoding_t t) {
    inv.assign(reg_pack(lhs).type, t);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs) {
    inv.assign(reg_pack(lhs).type, reg_pack(rhs).type);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const Reg& rhs) {
    inv.assign(lhs, reg_pack(rhs).type);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, int rhs) {
    inv.assign(lhs, rhs);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs) {
    inv.assign(reg_pack(lhs).type, rhs);
}

void ebpf_domain_t::TypeDomain::havoc_type(NumAbsDomain& inv, const Reg& r) {
    inv -= reg_pack(r).type;
}

int ebpf_domain_t::TypeDomain::get_type(const NumAbsDomain& inv, const Reg& r) const {
    auto res = inv[reg_pack(r).type].singleton();
    if (!res)
        return T_UNINIT;
    return (int)*res;
}

int ebpf_domain_t::TypeDomain::get_type(const NumAbsDomain& inv, variable_t v) const {
    auto res = inv[v].singleton();
    if (!res)
        return T_UNINIT;
    return (int)*res;
}

int ebpf_domain_t::TypeDomain::get_type(const NumAbsDomain& inv, int t) const { return t; }

// Check whether a given type value is within the range of a given type variable's value.
bool ebpf_domain_t::TypeDomain::has_type(const NumAbsDomain& inv, const Reg& r, type_encoding_t type) const {
    crab::interval_t interval = inv[reg_pack(r).type];
    if (interval.is_top())
        return true;
    return (interval.lb().number().value_or(INT_MIN) <= type) && (interval.ub().number().value_or(INT_MAX) >= type);
}

bool ebpf_domain_t::TypeDomain::has_type(const NumAbsDomain& inv, variable_t v, type_encoding_t type) const {
    crab::interval_t interval = inv[v];
    if (interval.is_top())
        return true;
    return (interval.lb().number().value_or(INT_MIN) <= type) && (interval.ub().number().value_or(INT_MAX) >= type);
}

bool ebpf_domain_t::TypeDomain::has_type(const NumAbsDomain& inv, int t, type_encoding_t type) const { return t == type; }

NumAbsDomain ebpf_domain_t::TypeDomain::join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                                        const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const {
    crab::interval_t types = inv.eval_interval(reg_pack(reg).type);
    if (types.is_bottom())
        return NumAbsDomain(true);
    if (types.is_top()) {
        NumAbsDomain res(inv);
        transition(res, static_cast<type_encoding_t>(T_UNINIT));
        return res;
    }
    NumAbsDomain res(true);
    auto lb = types.lb().is_finite() ? (type_encoding_t)(int)(types.lb().number().value()) : T_MAP_PROGRAMS;
    auto ub = types.ub().is_finite() ? (type_encoding_t)(int)(types.ub().number().value()) : T_SHARED;
    for (type_encoding_t type = lb; type <= ub; type = (type_encoding_t)((int)type + 1)) {
        NumAbsDomain tmp(inv);
        transition(tmp, type);
        selectively_join_based_on_type(res, tmp); // res |= tmp;
    }
    return res;
}

NumAbsDomain ebpf_domain_t::TypeDomain::join_by_if_else(const NumAbsDomain& inv, const linear_constraint_t& condition,
                                                        const std::function<void(NumAbsDomain&)>& if_true,
                                                        const std::function<void(NumAbsDomain&)>& if_false) const {
    NumAbsDomain true_case(inv.when(condition));
    if_true(true_case);

    NumAbsDomain false_case(inv.when(condition.negate()));
    if_false(false_case);

    return true_case | false_case;
}

bool ebpf_domain_t::TypeDomain::same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const {
    return inv.entail(eq_types(a, b));
}

bool ebpf_domain_t::TypeDomain::implies_type(const NumAbsDomain& inv, const linear_constraint_t& a, const linear_constraint_t& b) const {
    return inv.when(a).entail(b);
}

bool ebpf_domain_t::TypeDomain::is_in_group(const NumAbsDomain& m_inv, const Reg& r, TypeGroup group) const {
    using namespace crab::dsl_syntax;
    variable_t t = reg_pack(r).type;
    switch (group) {
    case TypeGroup::number: return m_inv.entail(t == T_NUM);
    case TypeGroup::map_fd: return m_inv.entail(t == T_MAP);
    case TypeGroup::map_fd_programs: return m_inv.entail(t == T_MAP_PROGRAMS);
    case TypeGroup::ctx: return m_inv.entail(t == T_CTX);
    case TypeGroup::packet: return m_inv.entail(t == T_PACKET);
    case TypeGroup::stack: return m_inv.entail(t == T_STACK);
    case TypeGroup::shared: return m_inv.entail(t == T_SHARED);
    case TypeGroup::non_map_fd: return m_inv.entail(t >= T_NUM);
    case TypeGroup::mem: return m_inv.entail(t >= T_PACKET);
    case TypeGroup::mem_or_num:
        return m_inv.entail(t >= T_NUM) && m_inv.entail(t != T_CTX);
    case TypeGroup::pointer: return m_inv.entail(t >= T_CTX);
    case TypeGroup::ptr_or_num: return m_inv.entail(t >= T_NUM);
    case TypeGroup::stack_or_packet:
        return m_inv.entail(t >= T_PACKET) && m_inv.entail(t <= T_STACK);
    case TypeGroup::singleton_ptr:
        return m_inv.entail(t >= T_CTX) && m_inv.entail(t <= T_STACK);
    }
    assert(false);
    return false;
}

void ebpf_domain_t::overflow(variable_t lhs) {
    using namespace crab::dsl_syntax;
    auto interval = m_inv[lhs];
    // handle overflow, assuming 64 bit
    number_t max(std::numeric_limits<int64_t>::max() / 2);
    number_t min(std::numeric_limits<int64_t>::min() / 2);
    if (interval.lb() <= min || interval.ub() >= max)
        havoc(lhs);
}

void ebpf_domain_t::operator()(const basic_block_t& bb, bool check_termination) {
    for (const Instruction& statement : bb) {
        std::visit(*this, statement);
    }
    if (check_termination) {
        // +1 to avoid being tricked by empty loops
        add(variable_t::instruction_count(), crab::number_t((unsigned)bb.size() + 1));
    }
}

int ebpf_domain_t::get_instruction_count_upper_bound() {
    const auto& ub = m_inv[variable_t::instruction_count()].ub();
    return (ub.is_finite() && ub.number().value().fits_sint()) ? (int)ub.number().value() : INT_MAX;
}

void ebpf_domain_t::check_access_stack(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= EBPF_STACK_SIZE, "Upper bound must be at most EBPF_STACK_SIZE");
}

void ebpf_domain_t::check_access_context(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= global_program_info.type.context_descriptor->size,
            std::string("Upper bound must be at most ") + std::to_string(global_program_info.type.context_descriptor->size));
}

void ebpf_domain_t::check_access_packet(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                                        std::optional<variable_t> packet_size) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= variable_t::meta_offset(), "Lower bound must be at least meta_offset");
    if (packet_size)
        require(inv, ub <= *packet_size, "Upper bound must be at most packet_size");
    else
        require(inv, ub <= MAX_PACKET_SIZE, std::string{"Upper bound must be at most "} + std::to_string(MAX_PACKET_SIZE));
}

void ebpf_domain_t::check_access_shared(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                                        variable_t region_size) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= region_size, std::string("Upper bound must be at most ") + region_size.name());
}

void ebpf_domain_t::operator()(const Assume& s) {
    Condition cond = s.cond;
    auto dst = reg_pack(cond.left);
    if (std::holds_alternative<Reg>(cond.right)) {
        auto src_reg = std::get<Reg>(cond.right);
        auto src = reg_pack(src_reg);
        if (type_inv.same_type(m_inv, cond.left, std::get<Reg>(cond.right))) {
            m_inv = type_inv.join_over_types(m_inv, cond.left, [&](NumAbsDomain& inv, type_encoding_t type) {
                if (type == T_NUM) {
                    if (!is_unsigned_cmp(cond.op))
                        for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst.value, src.value))
                            inv += cst;
                } else {
                    // Either pointers to a singleton region,
                    // or an equality comparison on map descriptors/pointers to non-singleton locations
                    if (auto dst_offset = get_type_offset_variable(cond.left, type))
                        if (auto src_offset = get_type_offset_variable(src_reg, type))
                            inv += jmp_to_cst_offsets_reg(cond.op, dst_offset.value(), src_offset.value());
                }
            });
        } else {
            // We should only reach here if `--assume-assert` is off
            assert(!thread_local_options.assume_assertions || is_bottom());
            // be sound in any case, it happens to flush out bugs:
            m_inv.set_to_top();
        }
    } else {
        int imm = static_cast<int>(std::get<Imm>(cond.right).v);
        for (const linear_constraint_t& cst : jmp_to_cst_imm(cond.op, dst.value, imm))
            assume(cst);
    }
}

void ebpf_domain_t::operator()(const Undefined& a) {}

void ebpf_domain_t::operator()(const Un& stmt) {
    auto dst = reg_pack(stmt.dst);
    switch (stmt.op) {
    case Un::Op::BE16:
    case Un::Op::BE32:
    case Un::Op::BE64:
    case Un::Op::LE16:
    case Un::Op::LE32:
    case Un::Op::LE64:
        havoc(dst.value);
        havoc_offsets(stmt.dst);
        break;
    case Un::Op::NEG:
        neg(dst.value);
        havoc_offsets(stmt.dst);
        break;
    }
}

void ebpf_domain_t::operator()(const Exit& a) {}

void ebpf_domain_t::operator()(const Jmp& a) {}

void ebpf_domain_t::operator()(const Comparable& s) {
    using namespace crab::dsl_syntax;
    if (type_inv.same_type(m_inv, s.r1, s.r2)) {
        // Same type. If both are numbers, that's okay. Otherwise:
        auto inv = m_inv.when(reg_pack(s.r2).type != T_NUM);
        // We must check that they belong to a singleton region:
        if (!type_inv.is_in_group(inv, s.r1, TypeGroup::singleton_ptr)) {
            require(inv, linear_constraint_t::FALSE(), "Cannot subtract pointers to non-singleton regions");
            return;
        }
        // And, to avoid wraparound errors, they must be within bounds.
        this->operator()(ValidAccess{s.r1, 0, Imm{0}, false});
        this->operator()(ValidAccess{s.r2, 0, Imm{0}, false});
    } else {
        // _Maybe_ different types, so r2 must be a number.
        // We checked in a previous assertion that r1 is a pointer or a number.
        require(m_inv, reg_pack(s.r2).type == T_NUM, "Cannot subtract pointers to different regions");
    };
}

void ebpf_domain_t::operator()(const Addable& s) {
    if (!type_inv.implies_type(m_inv, type_is_pointer(reg_pack(s.ptr)),type_is_number(s.num)))
        require(m_inv, linear_constraint_t::FALSE(), "Only numbers can be added to pointers");
}

void ebpf_domain_t::operator()(const ValidStore& s) {
    if (!type_inv.implies_type(m_inv, type_is_not_stack(reg_pack(s.mem)), type_is_number(s.val)))
        require(m_inv, linear_constraint_t::FALSE(), "Only numbers can be stored to externally-visible regions");
}

void ebpf_domain_t::operator()(const TypeConstraint& s) {
    if (!type_inv.is_in_group(m_inv, s.reg, s.types))
        require(m_inv, linear_constraint_t::FALSE(), "");
}

void ebpf_domain_t::operator()(const ValidSize& s) {
    using namespace crab::dsl_syntax;
    auto r = reg_pack(s.reg);
    require(m_inv, s.can_be_zero ? r.value >= 0 : r.value > 0, "");
}

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool ebpf_domain_t::get_map_fd_range(const Reg& map_fd_reg, int* start_fd, int* end_fd) const {
    const crab::interval_t& map_fd_interval = m_inv[reg_pack(map_fd_reg).map_fd];
    auto lb = map_fd_interval.lb().number();
    auto ub = map_fd_interval.ub().number();
    if (!lb || !lb->fits_sint() || !ub || !ub->fits_sint())
        return false;
    *start_fd = (int)lb.value();
    *end_fd = (int)ub.value();

    // Cap the maximum range we'll check.
    const int max_range = 32;
    return (*map_fd_interval.finite_size() < max_range);
}

// All maps in the range must have the same type for us to use it.
std::optional<uint32_t> ebpf_domain_t::get_map_type(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return std::optional<uint32_t>();

    std::optional<uint32_t> type;
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &global_program_info.platform->get_map_descriptor(map_fd);
        if (map == nullptr)
            return std::optional<uint32_t>();
        if (!type.has_value())
            type = map->type;
        else if (map->type != *type)
            return std::optional<uint32_t>();
    }
    return type;
}

// All maps in the range must have the same inner map fd for us to use it.
std::optional<uint32_t> ebpf_domain_t::get_map_inner_map_fd(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return {};

    std::optional<uint32_t> inner_map_fd;
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &global_program_info.platform->get_map_descriptor(map_fd);
        if (map == nullptr)
            return {};
        if (!inner_map_fd.has_value())
            inner_map_fd = map->inner_map_fd;
        else if (map->type != *inner_map_fd)
            return {};
    }
    return inner_map_fd;
}

// We can deal with a range of key sizes.
crab::interval_t ebpf_domain_t::get_map_key_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return crab::interval_t::top();

    crab::interval_t result = crab::interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (EbpfMapDescriptor* map = &global_program_info.platform->get_map_descriptor(map_fd))
            result = result | crab::interval_t(number_t(map->key_size));
        else
            return crab::interval_t::top();
    }
    return result;
}

// We can deal with a range of value sizes.
crab::interval_t ebpf_domain_t::get_map_value_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return crab::interval_t::top();

    crab::interval_t result = crab::interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (EbpfMapDescriptor* map = &global_program_info.platform->get_map_descriptor(map_fd))
            result = result | crab::interval_t(number_t(map->value_size));
        else
            return crab::interval_t::top();
    }
    return result;
}

// We can deal with a range of max_entries values.
crab::interval_t ebpf_domain_t::get_map_max_entries(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd))
        return crab::interval_t::top();

    crab::interval_t result = crab::interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (EbpfMapDescriptor* map = &global_program_info.platform->get_map_descriptor(map_fd))
            result = result | crab::interval_t(number_t(map->max_entries));
        else
            return crab::interval_t::top();
    }
    return result;
}

void ebpf_domain_t::operator()(const ValidMapKeyValue& s) {
    using namespace crab::dsl_syntax;

    auto fd_type = get_map_type(s.map_fd_reg);

    auto access_reg = reg_pack(s.access_reg);
    int width;
    if (s.key) {
        auto key_size = get_map_key_size(s.map_fd_reg).singleton();
        if (!key_size.has_value()) {
            require(m_inv, linear_constraint_t::FALSE(), "Map key size is not singleton");
            return;
        }
        width = (int)key_size.value();
    } else {
        auto value_size = get_map_value_size(s.map_fd_reg).singleton();
        if (!value_size.has_value()) {
            require(m_inv, linear_constraint_t::FALSE(), "Map value size is not singleton");
            return;
        }
        width = (int)value_size.value();
    }

    m_inv = type_inv.join_over_types(m_inv, s.access_reg, [&](NumAbsDomain& inv, type_encoding_t access_reg_type) {
        if (access_reg_type == T_STACK) {
            variable_t lb = access_reg.stack_offset;
            linear_expression_t ub = lb + width;
            if (!stack.all_num(inv, lb, ub)) {
                auto lb_is = inv[lb].lb().number();
                std::string lb_s = lb_is && lb_is->fits_sint() ? std::to_string((int)*lb_is) : "-oo";
                auto ub_is = inv.eval_interval(ub).ub().number();
                std::string ub_s = ub_is && ub_is->fits_sint() ? std::to_string((int)*ub_is) : "oo";
                require(inv, linear_constraint_t::FALSE(), "Illegal map update with a non-numerical value [" + lb_s + "-" + ub_s + ")");
            } else if (thread_local_options.strict && fd_type.has_value()) {
                EbpfMapType map_type = global_program_info.platform->get_map_type(*fd_type);
                if (map_type.is_array) {
                    // Get offset value.
                    variable_t key_ptr = access_reg.stack_offset;
                    std::optional<number_t> offset = inv[key_ptr].singleton();
                    if (!offset.has_value()) {
                        require(inv, linear_constraint_t::FALSE(), "Pointer must be a singleton");
                    } else if (s.key) {
                        // Look up the value pointed to by the key pointer.
                        variable_t key_value =
                            variable_t::cell_var(data_kind_t::values, (uint64_t)offset.value(), sizeof(uint32_t));

                        if (auto max_entries = get_map_max_entries(s.map_fd_reg).lb().number())
                            require(inv, key_value < *max_entries, "Array index overflow");
                        else
                            require(inv, linear_constraint_t::FALSE(), "Max entries is not finite");
                        require(inv, key_value >= 0, "Array index underflow");
                    }
                }
            }
        } else if (access_reg_type == T_PACKET) {
            variable_t lb = access_reg.packet_offset;
            linear_expression_t ub = lb + width;
            check_access_packet(inv, lb, ub, {});
            // Packet memory is both readable and writable.
        } else {
            require(inv, linear_constraint_t::FALSE(), "Only stack or packet can be used as a parameter");
        }
    });
}

void ebpf_domain_t::operator()(const ValidAccess& s) {
    using namespace crab::dsl_syntax;

    bool is_comparison_check = s.width == (Value)Imm{0};

    auto reg = reg_pack(s.reg);
    // join_over_types instead of simple iteration is only needed for assume-assert
    m_inv = type_inv.join_over_types(m_inv, s.reg, [&](NumAbsDomain& inv, type_encoding_t type) {
        switch (type) {
        case T_PACKET: {
            linear_expression_t lb = reg.packet_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width) ? lb + std::get<Imm>(s.width).v
                                                                          : lb + reg_pack(std::get<Reg>(s.width)).value;
            check_access_packet(inv, lb, ub,
                                is_comparison_check ? std::optional<variable_t>{} : variable_t::packet_size());
            // if within bounds, it can never be null
            // Context memory is both readable and writable.
            break;
        }
        case T_STACK: {
            linear_expression_t lb = reg.stack_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width) ? lb + std::get<Imm>(s.width).v
                                                                          : lb + reg_pack(std::get<Reg>(s.width)).value;
            check_access_stack(inv, lb, ub);
            // if within bounds, it can never be null
            if (s.access_type == AccessType::read) {
                // Require that the stack range contains numbers.
                if (!stack.all_num(inv, lb, ub)) {
                    if (s.offset < 0) {
                        require(inv, linear_constraint_t::FALSE(), "Stack content is not numeric");
                    } else if (std::holds_alternative<Imm>(s.width)) {
                        if (!inv.entail(std::get<Imm>(s.width).v <= reg.stack_numeric_size - s.offset)) {
                            require(inv, linear_constraint_t::FALSE(), "Stack content is not numeric");
                        }
                    } else {
                        if (!inv.entail(reg_pack(std::get<Reg>(s.width)).value <= reg.stack_numeric_size - s.offset)) {
                            require(inv, linear_constraint_t::FALSE(), "Stack content is not numeric");
                        }
                    }
                }
            }
            break;
        }
        case T_CTX: {
            linear_expression_t lb = reg.ctx_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width) ? lb + std::get<Imm>(s.width).v
                                                                          : lb + reg_pack(std::get<Reg>(s.width)).value;
            check_access_context(inv, lb, ub);
            // if within bounds, it can never be null
            // The context is both readable and writable.
            break;
        }
        case T_NUM:
            if (!is_comparison_check) {
                if (s.or_null) {
                    require(inv, reg.value == 0, "Non-null number");
                } else {
                    require(inv, linear_constraint_t::FALSE(), "Only pointers can be dereferenced");
                }
            }
            break;
        case T_MAP:
        case T_MAP_PROGRAMS:
            if (!is_comparison_check) {
                require(inv, linear_constraint_t::FALSE(), "FDs cannot be dereferenced directly");
            }
            break;
        case T_SHARED: {
            linear_expression_t lb = reg.shared_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width) ? lb + std::get<Imm>(s.width).v
                                                                             : lb + reg_pack(std::get<Reg>(s.width)).value;
            check_access_shared(inv, lb, ub, reg.shared_region_size);
            if (!is_comparison_check && !s.or_null)
                require(inv, reg.value > 0, "Possible null access");
            // Shared memory is zero-initialized when created so is safe to read and write.
            break;
        }
        default:
            require(inv, linear_constraint_t::FALSE(), "Invalid type");
            break;
        }
    });
}

void ebpf_domain_t::operator()(const ZeroCtxOffset& s) {
    using namespace crab::dsl_syntax;
    auto reg = reg_pack(s.reg);
    require(m_inv, reg.ctx_offset == 0, "");
}

void ebpf_domain_t::operator()(const Assert& stmt) {
    if (check_require || thread_local_options.assume_assertions) {
        this->current_assertion = to_string(stmt.cst);
        std::visit(*this, stmt.cst);
        this->current_assertion.clear();
    }
}

void ebpf_domain_t::operator()(const Packet& a) {
    auto reg = reg_pack(R0_RETURN_VALUE);
    Reg r0_reg{(uint8_t)R0_RETURN_VALUE};
    type_inv.assign_type(m_inv, r0_reg, T_NUM);
    havoc_offsets(r0_reg);
    havoc(reg.value);
    scratch_caller_saved_registers();
}

void ebpf_domain_t::do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width, const Reg& src_reg) {
    type_inv.assign_type(inv, target_reg, stack.load(inv, data_kind_t::types, addr, width));
    using namespace crab::dsl_syntax;
    if (inv.entail(width <= reg_pack(src_reg).stack_numeric_size))
        type_inv.assign_type(inv, target_reg, T_NUM);

    const reg_pack_t& target = reg_pack(target_reg);
    havoc_register(inv, target_reg);
    if (width == 1 || width == 2 || width == 4 || width == 8) {
        inv.assign(target.value, stack.load(inv,  data_kind_t::values, addr, width));

        if (type_inv.has_type(m_inv, target.type, T_CTX))
            inv.assign(target.ctx_offset, stack.load(inv, data_kind_t::ctx_offsets, addr, width));
        if (type_inv.has_type(m_inv, target.type, T_MAP) || type_inv.has_type(m_inv, target.type, T_MAP_PROGRAMS))
            inv.assign(target.map_fd, stack.load(inv, data_kind_t::map_fds, addr, width));
        if (type_inv.has_type(m_inv, target.type, T_PACKET))
            inv.assign(target.packet_offset, stack.load(inv, data_kind_t::packet_offsets, addr, width));
        if (type_inv.has_type(m_inv, target.type, T_SHARED)) {
            inv.assign(target.shared_offset, stack.load(inv, data_kind_t::shared_offsets, addr, width));
            inv.assign(target.shared_region_size, stack.load(inv, data_kind_t::shared_region_sizes, addr, width));
        }
        if (type_inv.has_type(m_inv, target.type, T_STACK)) {
            inv.assign(target.stack_offset, stack.load(inv, data_kind_t::stack_offsets, addr, width));
            inv.assign(target.stack_numeric_size, stack.load(inv, data_kind_t::stack_numeric_sizes, addr, width));
        }
    }
}

void ebpf_domain_t::do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague, int width) {
    using namespace crab::dsl_syntax;
    if (inv.is_bottom())
        return;

    const ebpf_context_descriptor_t* desc = global_program_info.type.context_descriptor;

    const reg_pack_t& target = reg_pack(target_reg);

    if (desc->end < 0) {
        havoc_register(inv, target_reg);
        type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }

    crab::interval_t interval = inv.eval_interval(addr_vague);
    std::optional<number_t> maybe_addr = interval.singleton();
    havoc_register(inv, target_reg);

    bool may_touch_ptr = interval[desc->data] || interval[desc->meta] || interval[desc->end];

    if (!maybe_addr) {
        if (may_touch_ptr)
            type_inv.havoc_type(inv, target_reg);
        else
            type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }

    number_t addr = *maybe_addr;

    if (addr == desc->data) {
        inv.assign(target.packet_offset, 0);
    } else if (addr == desc->end) {
        inv.assign(target.packet_offset, variable_t::packet_size());
    } else if (addr == desc->meta) {
        inv.assign(target.packet_offset, variable_t::meta_offset());
    } else {
        if (may_touch_ptr)
            type_inv.havoc_type(inv, target_reg);
        else
            type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }
    type_inv.assign_type(inv, target_reg, T_PACKET);
    inv += 4098 <= target.value;
    inv += target.value <= PTR_MAX;
}

void ebpf_domain_t::do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width) {
    if (inv.is_bottom())
        return;
    const reg_pack_t& target = reg_pack(target_reg);

    type_inv.assign_type(inv, target_reg, T_NUM);
    havoc_register(inv, target_reg);

    // A 1 or 2 byte copy results in a limited range of values that may be used as array indices.
    if (width == 1) {
        inv.set(target.value, crab::interval_t(0, UINT8_MAX));
    } else if (width == 2) {
        inv.set(target.value, crab::interval_t(0, UINT16_MAX));
    }
}

void ebpf_domain_t::do_load(const Mem& b, const Reg& target_reg) {
    using namespace crab::dsl_syntax;

    auto mem_reg = reg_pack(b.access.basereg);
    int width = b.access.width;
    int offset = b.access.offset;

    if (b.access.basereg.v == R10_STACK_POINTER) {
        linear_expression_t addr = mem_reg.stack_offset + (number_t)offset;
        do_load_stack(m_inv, target_reg, addr, width, b.access.basereg);
        return;
    }

    m_inv = type_inv.join_over_types(m_inv, b.access.basereg, [&](NumAbsDomain& inv, type_encoding_t type) {
        switch (type) {
            case T_UNINIT: return;
            case T_MAP: return;
            case T_MAP_PROGRAMS: return;
            case T_NUM: return;
            case T_CTX: {
                linear_expression_t addr = mem_reg.ctx_offset + (number_t)offset;
                do_load_ctx(inv, target_reg, addr, width);
                break;
            }
            case T_STACK: {
                linear_expression_t addr = mem_reg.stack_offset + (number_t)offset;
                do_load_stack(inv, target_reg, addr, width, b.access.basereg);
                break;
            }
            case T_PACKET: {
                linear_expression_t addr = mem_reg.packet_offset + (number_t)offset;
                do_load_packet_or_shared(inv, target_reg, addr, width);
                break;
            }
            default: {
                linear_expression_t addr = mem_reg.shared_offset + (number_t)offset;
                do_load_packet_or_shared(inv, target_reg, addr, width);
                break;
            }
        }
    });
}

template <typename A, typename X, typename Y>
void ebpf_domain_t::do_store_stack(NumAbsDomain& inv, int width, const A& addr, X val_type, Y val_value,
                                   const std::optional<reg_pack_t>& opt_val_reg) {
    std::optional<variable_t> var = stack.store_type(inv, addr, width, val_type);
    type_inv.assign_type(inv, var, val_type);
    if (width == 8) {
        inv.assign(stack.store(inv, data_kind_t::values, addr, width, val_value), val_value);

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_CTX)) {
            inv.assign(stack.store(inv, data_kind_t::ctx_offsets, addr, width, opt_val_reg->ctx_offset), opt_val_reg->ctx_offset);
        } else {
            stack.havoc(inv, data_kind_t::ctx_offsets, addr, width);
        }

        if (opt_val_reg && (type_inv.has_type(m_inv, val_type, T_MAP) ||
                                   type_inv.has_type(m_inv, val_type, T_MAP_PROGRAMS))) {
            inv.assign(stack.store(inv, data_kind_t::map_fds, addr, width, opt_val_reg->map_fd), opt_val_reg->map_fd);
        } else {
            stack.havoc(inv, data_kind_t::map_fds, addr, width);
        }

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_PACKET)) {
            inv.assign(stack.store(inv, data_kind_t::packet_offsets, addr, width, opt_val_reg->packet_offset), opt_val_reg->packet_offset);
        } else {
            stack.havoc(inv, data_kind_t::packet_offsets, addr, width);
        }

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_SHARED)) {
            inv.assign(stack.store(inv, data_kind_t::shared_offsets, addr, width, opt_val_reg->shared_offset), opt_val_reg->shared_offset);
            inv.assign(stack.store(inv, data_kind_t::shared_region_sizes, addr, width, opt_val_reg->shared_region_size),
                       opt_val_reg->shared_region_size);
        } else {
            stack.havoc(inv, data_kind_t::shared_region_sizes, addr, width);
            stack.havoc(inv, data_kind_t::shared_offsets, addr, width);
        }

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_STACK)) {
            inv.assign(stack.store(inv, data_kind_t::stack_offsets, addr, width, opt_val_reg->stack_offset), opt_val_reg->stack_offset);
            inv.assign(stack.store(inv, data_kind_t::stack_numeric_sizes, addr, width, opt_val_reg->stack_numeric_size),
                       opt_val_reg->stack_numeric_size);
        } else {
            stack.havoc(inv, data_kind_t::stack_offsets, addr, width);
            stack.havoc(inv, data_kind_t::stack_numeric_sizes, addr, width);
        }
    } else {
        if ((width == 1 || width == 2 || width == 4) && type_inv.get_type(m_inv, val_type) == T_NUM) {
            // Keep track of numbers on the stack that might be used as array indices.
            inv.assign(stack.store(inv, data_kind_t::values, addr, width, val_value), val_value);
        } else {
            stack.havoc(inv, data_kind_t::values, addr, width);
        }
        stack.havoc(inv, data_kind_t::ctx_offsets, addr, width);
        stack.havoc(inv, data_kind_t::map_fds, addr, width);
        stack.havoc(inv, data_kind_t::packet_offsets, addr, width);
        stack.havoc(inv, data_kind_t::shared_offsets, addr, width);
        stack.havoc(inv, data_kind_t::stack_offsets, addr, width);
        stack.havoc(inv, data_kind_t::shared_region_sizes, addr, width);
        stack.havoc(inv, data_kind_t::stack_numeric_sizes, addr, width);
    }

    // Update stack_numeric_size for any stack type variables.
    // stack_numeric_size holds the number of continuous bytes
    // starting from stack_offset that are known to be numeric.
    auto updated_lb = m_inv.eval_interval(addr).lb();
    auto updated_ub = m_inv.eval_interval(addr).ub() + width;
    for (variable_t type_variable : variable_t::get_type_variables()) {
        if (!type_inv.has_type(inv, type_variable, T_STACK))
            continue;
        variable_t stack_offset_variable = variable_t::kind_var(data_kind_t::stack_offsets, type_variable);
        variable_t stack_numeric_size_variable = variable_t::kind_var(data_kind_t::stack_numeric_sizes, type_variable);

        using namespace crab::dsl_syntax;
        // See if the variable's numeric interval overlaps with changed bytes.
        if (m_inv.intersect(addr <= stack_offset_variable + stack_numeric_size_variable) &&
            m_inv.intersect(addr + width >= stack_offset_variable)) {
            havoc(stack_numeric_size_variable);
            recompute_stack_numeric_size(m_inv, type_variable);
        }
    }
}

void ebpf_domain_t::operator()(const Mem& b) {
    if (m_inv.is_bottom())
        return;
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value));
        } else {
            auto data = std::get<Reg>(b.value);
            auto data_reg = reg_pack(data);
            do_mem_store(b, data, data_reg.value, data_reg);
        }
    } else {
        do_mem_store(b, T_NUM, std::get<Imm>(b.value).v, {});
    }
}

template <typename Type, typename Value>
void ebpf_domain_t::do_mem_store(const Mem& b, Type val_type, Value val_value, const std::optional<reg_pack_t>& val_reg) {
    if (m_inv.is_bottom())
        return;
    using namespace crab::dsl_syntax;
    int width = b.access.width;
    int offset = b.access.offset;
    if (b.access.basereg.v == R10_STACK_POINTER) {
        int addr = EBPF_STACK_SIZE + offset;
        do_store_stack(m_inv, width, addr, val_type, val_value, val_reg);
        return;
    }
    m_inv = type_inv.join_over_types(m_inv, b.access.basereg, [&](NumAbsDomain& inv, type_encoding_t type) {
        if (type == T_STACK) {
            linear_expression_t addr = linear_expression_t(get_type_offset_variable(b.access.basereg, type).value()) + offset;
            do_store_stack(inv, width, addr, val_type, val_value, val_reg);
        }
        // do nothing for any other type
    });
}

void ebpf_domain_t::operator()(const LockAdd& a) {
    // nothing to do here
}

void ebpf_domain_t::operator()(const Call& call) {
    using namespace crab::dsl_syntax;
    if (m_inv.is_bottom())
        return;
    std::optional<Reg> maybe_fd_reg{};
    for (ArgSingle param : call.singles) {
        switch (param.kind) {
        case ArgSingle::Kind::MAP_FD:
            maybe_fd_reg = param.reg;
            break;
        case ArgSingle::Kind::ANYTHING:
        case ArgSingle::Kind::MAP_FD_PROGRAMS:
        case ArgSingle::Kind::PTR_TO_MAP_KEY:
        case ArgSingle::Kind::PTR_TO_MAP_VALUE:
        case ArgSingle::Kind::PTR_TO_CTX:
            // Do nothing. We don't track the content of relevant memory regions
            break;
        }
    }
    for (ArgPair param : call.pairs) {
        switch (param.kind) {
        case ArgPair::Kind::PTR_TO_READABLE_MEM_OR_NULL:
        case ArgPair::Kind::PTR_TO_READABLE_MEM:
            // Do nothing. No side effect allowed.
            break;

        case ArgPair::Kind::PTR_TO_WRITABLE_MEM: {
            bool store_numbers = true;
            variable_t addr = get_type_offset_variable(param.mem).value();
            variable_t width = reg_pack(param.size).value;

            m_inv = type_inv.join_over_types(m_inv, param.mem, [&](NumAbsDomain& inv, type_encoding_t type) {
                if (type == T_STACK) {
                    // Pointer to a memory region that the called function may change,
                    // so we must havoc.
                    stack.havoc(inv, data_kind_t::types, addr, width);
                    stack.havoc(inv, data_kind_t::values, addr, width);
                    stack.havoc(inv, data_kind_t::ctx_offsets, addr, width);
                    stack.havoc(inv, data_kind_t::map_fds, addr, width);
                    stack.havoc(inv, data_kind_t::packet_offsets, addr, width);
                    stack.havoc(inv, data_kind_t::shared_offsets, addr, width);
                    stack.havoc(inv, data_kind_t::stack_offsets, addr, width);
                    stack.havoc(inv, data_kind_t::shared_region_sizes, addr, width);
                } else {
                    store_numbers = false;
                }
            });
            if (store_numbers) {
                // Functions are not allowed to write sensitive data,
                // and initialization is guaranteed
                stack.store_numbers(m_inv, addr, width);
            }
        }
        }
    }

    Reg r0_reg{(uint8_t)R0_RETURN_VALUE};
    auto r0_pack = reg_pack(r0_reg);
    havoc(r0_pack.stack_numeric_size);
    if (call.is_map_lookup) {
        // This is the only way to get a null pointer
        if (maybe_fd_reg) {
            if (auto map_type = get_map_type(*maybe_fd_reg)) {
                if (global_program_info.platform->get_map_type(*map_type).value_type == EbpfMapValueType::MAP) {
                    if (auto inner_map_fd = get_map_inner_map_fd(*maybe_fd_reg)) {
                        do_load_mapfd(r0_reg, (int)*inner_map_fd, true);
                        goto out;
                    }
                } else {
                    assign_valid_ptr(r0_reg, true);
                    assign(r0_pack.shared_offset, 0);
                    m_inv.set(r0_pack.shared_region_size, get_map_value_size(*maybe_fd_reg));
                    type_inv.assign_type(m_inv, r0_reg, T_SHARED);
                }
            }
        }
        assign_valid_ptr(r0_reg, true);
        assign(r0_pack.shared_offset, 0);
        type_inv.assign_type(m_inv, r0_reg, T_SHARED);
    } else {
        havoc(r0_pack.value);
        havoc_offsets(r0_reg);
        type_inv.assign_type(m_inv, r0_reg, T_NUM);
        // assume(r0_pack.value < 0); for INTEGER_OR_NO_RETURN_IF_SUCCEED.
    }
out:
    scratch_caller_saved_registers();
    if (call.reallocate_packet) {
        forget_packet_pointers();
    }
}

void ebpf_domain_t::do_load_mapfd(const Reg& dst_reg, int mapfd, bool maybe_null) {
    const EbpfMapDescriptor& desc = global_program_info.platform->get_map_descriptor(mapfd);
    const EbpfMapType& type = global_program_info.platform->get_map_type(desc.type);
    if (type.value_type == EbpfMapValueType::PROGRAM) {
        type_inv.assign_type(m_inv, dst_reg, T_MAP_PROGRAMS);
    } else {
        type_inv.assign_type(m_inv, dst_reg, T_MAP);
    }
    const reg_pack_t& dst = reg_pack(dst_reg);
    assign(dst.map_fd, mapfd);
    assign_valid_ptr(dst_reg, maybe_null);
}

void ebpf_domain_t::operator()(const LoadMapFd& ins) {
    do_load_mapfd(ins.dst, ins.mapfd, false);
}

void ebpf_domain_t::assign_valid_ptr(const Reg& dst_reg, bool maybe_null) {
    using namespace crab::dsl_syntax;
    const reg_pack_t& reg = reg_pack(dst_reg);
    havoc(reg.value);
    if (maybe_null) {
        m_inv += 0 <= reg.value;
    } else {
        m_inv += 0 < reg.value;
    }
    m_inv += reg.value <= PTR_MAX;
}

// If nothing is known of the stack_numeric_size,
// try to recompute the stack_numeric_size.
void ebpf_domain_t::recompute_stack_numeric_size(NumAbsDomain& inv, variable_t type_variable) {
    variable_t stack_numeric_size_variable = variable_t::kind_var(data_kind_t::stack_numeric_sizes, type_variable);

    if (!inv.eval_interval(stack_numeric_size_variable).is_top())
        return;

    if (type_inv.has_type(inv, type_variable, T_STACK)) {
        int numeric_size =
            stack.min_all_num_size(inv, variable_t::kind_var(data_kind_t::stack_offsets, type_variable));
        if (numeric_size > 0)
            inv.assign(stack_numeric_size_variable, numeric_size);
    }
}

void ebpf_domain_t::recompute_stack_numeric_size(NumAbsDomain& inv, const Reg& reg) {
    recompute_stack_numeric_size(inv, reg_pack(reg).type);
}

void ebpf_domain_t::add(const Reg& reg, int imm) {
    auto dst = reg_pack(reg);
    auto offset = get_type_offset_variable(reg);
    add_overflow(dst.value, imm);
    if (offset.has_value()) {
        add(offset.value(), imm);
        if (imm > 0)
            // Since the start offset is increasing but
            // the end offset is not, the numeric size decreases.
            sub(dst.stack_numeric_size, imm);
        else if (imm < 0)
            havoc(dst.stack_numeric_size);
        recompute_stack_numeric_size(m_inv, reg);
    }
}

void ebpf_domain_t::operator()(const Bin& bin) {
    using namespace crab::dsl_syntax;

    auto dst = reg_pack(bin.dst);

    if (std::holds_alternative<Imm>(bin.v)) {
        // dst += K
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        switch (bin.op) {
        case Bin::Op::MOV:
            assign(dst.value, imm);
            type_inv.assign_type(m_inv, bin.dst, T_NUM);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::ADD:
            if (imm == 0)
                return;
            add(bin.dst, imm);
            break;
        case Bin::Op::SUB:
            if (imm == 0)
                return;
            add(bin.dst, -imm);
            break;
        case Bin::Op::MUL:
            mul(dst.value, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::DIV:
            div(dst.value, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOD:
            rem(dst.value, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            bitwise_or(dst.value, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            bitwise_and(dst.value, imm);
            if ((int32_t)imm > 0) {
                assume(dst.value <= imm);
                assume(0 <= dst.value);
            }
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH:
            // avoid signedness and overflow issues in shl_overflow(dst.value, imm);
            shl_overflow(dst.value, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::RSH:
            // avoid signedness and overflow issues in lshr(dst.value, imm);
            havoc(dst.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::ARSH:
            // avoid signedness and overflow issues in ashr(dst.value, imm);
            // = (int64_t)dst >> imm;
            havoc(dst.value);
            // assume(dst.value <= (1 << (64 - imm)));
            // assume(dst.value >= -(1 << (64 - imm)));
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::XOR:
            bitwise_xor(dst.value, imm);
            havoc_offsets(bin.dst);
            break;
        }
    } else {
        // dst op= src
        auto src_reg = std::get<Reg>(bin.v);
        auto src = reg_pack(src_reg);
        switch (bin.op) {
        case Bin::Op::ADD: {
            if (type_inv.same_type(m_inv, bin.dst, std::get<Reg>(bin.v))) {
                // both must be numbers
                add_overflow(dst.value, src.value);
            } else {
                // Here we're not sure that lhs and rhs are the same type; they might be.
                // But previous assertions should fail unless we know that exactly one of lhs or rhs is a pointer.
                m_inv = type_inv.join_over_types(m_inv, bin.dst, [&](NumAbsDomain& inv, type_encoding_t dst_type) {
                    inv = type_inv.join_over_types(inv, src_reg, [&](NumAbsDomain& inv, type_encoding_t src_type) {
                        if (dst_type == T_NUM && src_type != T_NUM) {
                            // num += ptr
                            type_inv.assign_type(inv, bin.dst, src_type);
                            if (auto dst_offset = get_type_offset_variable(bin.dst, src_type))
                                apply(inv, crab::arith_binop_t::ADD, dst_offset.value(), dst.value,
                                      get_type_offset_variable(src_reg, src_type).value(), false);
                            if (src_type == T_SHARED)
                                inv.assign(dst.shared_region_size, src.shared_region_size);
                        } else if (dst_type != T_NUM && src_type == T_NUM) {
                            // ptr += num
                            type_inv.assign_type(inv, bin.dst, dst_type);
                            if (auto dst_offset = get_type_offset_variable(bin.dst, dst_type)) {
                                apply(inv, crab::arith_binop_t::ADD, dst_offset.value(), dst_offset.value(), src.value,
                                      false);
                                if (dst_type == T_STACK) {
                                    // Reduce the numeric size.
                                    using namespace crab::dsl_syntax;
                                    if (m_inv.intersect(src.value < 0)) {
                                        inv -= dst.stack_numeric_size;
                                        recompute_stack_numeric_size(inv, dst.type);
                                    } else
                                        apply(inv, crab::arith_binop_t::SUB, dst.stack_numeric_size,
                                              dst.stack_numeric_size, src.value, false);
                                }
                            }
                        } else if (dst_type == T_NUM && src_type == T_NUM) {
                            // dst and src don't necessarily have the same type, but among the possibilities
                            // enumerated is the case where they are both numbers.
                            apply(inv, crab::arith_binop_t::ADD, dst.value, dst.value, src.value, true);
                        } else {
                            // We ignore the cases here that do not match the assumption described
                            // above.  Joining bottom with another results will leave the other
                            // results unchanged.
                            inv.set_to_bottom();
                        }
                    });
                });
                // careful: change dst.value only after dealing with offset
                apply(m_inv, crab::arith_binop_t::ADD, dst.value, dst.value, src.value, true);
            }
            break;
        }
        case Bin::Op::SUB: {
            if (type_inv.same_type(m_inv, bin.dst, std::get<Reg>(bin.v))) {
                // src and dest have the same type.
                m_inv = type_inv.join_over_types(m_inv, bin.dst, [&](NumAbsDomain& inv, type_encoding_t type) {
                    switch (type) {
                    case T_NUM:
                        // This is: sub_overflow(inv, dst.value, src.value);
                        apply(inv, crab::arith_binop_t::SUB, dst.value, dst.value, src.value, true);
                        type_inv.assign_type(inv, bin.dst, T_NUM);
                        havoc_offsets(inv, bin.dst);
                        break;
                    default:
                        // ptr -= ptr
                        // Assertions should make sure we only perform this on non-shared pointers.
                        if (auto dst_offset = get_type_offset_variable(bin.dst, type)) {
                            apply(inv, crab::arith_binop_t::SUB, dst.value, dst_offset.value(),
                                  get_type_offset_variable(src_reg, type).value(), true);
                            inv -= dst_offset.value();
                        }
                        havoc_offsets(inv, bin.dst);
                        type_inv.assign_type(inv, bin.dst, T_NUM);
                        break;
                    }
                });
            } else {
                // We're not sure that lhs and rhs are the same type.
                // Either they're different, or at least one is not a singleton.
                if (type_inv.get_type(m_inv, std::get<Reg>(bin.v)) != T_NUM) {
                    type_inv.havoc_type(m_inv, bin.dst);
                    havoc(dst.value);
                    havoc_offsets(bin.dst);
                } else {
                    sub_overflow(dst.value, src.value);
                    if (auto dst_offset = get_type_offset_variable(bin.dst)) {
                        sub(dst_offset.value(), src.value);
                        if (type_inv.has_type(m_inv, dst.type, T_STACK)) {
                            // Reduce the numeric size.
                            using namespace crab::dsl_syntax;
                            if (m_inv.intersect(src.value > 0)) {
                                m_inv -= dst.stack_numeric_size;
                                recompute_stack_numeric_size(m_inv, dst.type);
                            } else
                                apply(m_inv, crab::arith_binop_t::ADD, dst.stack_numeric_size,
                                      dst.stack_numeric_size, src.value, false);
                        }
                    }
                }
            }
            break;
        }
        case Bin::Op::MUL:
            mul(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::DIV:
            // DIV is not checked for zerodiv
            div(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOD:
            // See DIV comment
            rem(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            bitwise_or(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            bitwise_and(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH:
            shl_overflow(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::RSH:
            havoc(dst.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::ARSH:
            havoc(dst.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::XOR:
            bitwise_xor(dst.value, src.value);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOV:
            assign(dst.value, src.value);
            havoc_offsets(bin.dst);
            m_inv = type_inv.join_over_types(m_inv, src_reg, [&](NumAbsDomain& inv, type_encoding_t type) {
                inv.assign(dst.type, type);

                switch (type) {
                case T_CTX: inv.assign(dst.ctx_offset, src.ctx_offset); break;
                case T_MAP:
                case T_MAP_PROGRAMS: inv.assign(dst.map_fd, src.map_fd); break;
                case T_PACKET:
                    inv.assign(dst.packet_offset, src.packet_offset);
                    break;
                case T_SHARED:
                    inv.assign(dst.shared_region_size, src.shared_region_size);
                    inv.assign(dst.shared_offset, src.shared_offset);
                    break;
                case T_STACK:
                    inv.assign(dst.stack_offset, src.stack_offset);
                    inv.assign(dst.stack_numeric_size, src.stack_numeric_size);
                    break;
                default: break;
                }
            });
            havoc(dst.type);
            type_inv.assign_type(m_inv, bin.dst, std::get<Reg>(bin.v));
            break;
        }
    }
    if (!bin.is64) {
        bitwise_and(dst.value, UINT32_MAX);
    }
}

string_invariant ebpf_domain_t::to_set() {
    return this->m_inv.to_set() + this->stack.to_set();
}

std::ostream& operator<<(std::ostream& o, const ebpf_domain_t& dom) {
    if (dom.is_bottom()) {
        o << "_|_";
    } else {
        o << dom.m_inv << "\nStack: " << dom.stack;
    }
    return o;
}

void ebpf_domain_t::initialize_packet(ebpf_domain_t& inv) {
    using namespace crab::dsl_syntax;

    inv -= variable_t::packet_size();
    inv -= variable_t::meta_offset();

    inv += 0 <= variable_t::packet_size();
    inv += variable_t::packet_size() < MAX_PACKET_SIZE;
    auto info = global_program_info;
    if (info.type.context_descriptor->meta >= 0) {
        inv += variable_t::meta_offset() <= 0;
        inv += variable_t::meta_offset() >= -4098;
    } else {
        inv.assign(variable_t::meta_offset(), 0);
    }
}

ebpf_domain_t ebpf_domain_t::from_constraints(const std::set<std::string>& constraints) {
    ebpf_domain_t inv;
    auto numeric_ranges = std::vector<crab::interval_t>();
    for (const auto& cst : parse_linear_constraints(constraints, numeric_ranges)) {
        inv += cst;
    }
    for (const crab::interval_t& range : numeric_ranges) {
        int start = (int)range.lb().number().value();
        int width = 1 + (int)(range.ub() - range.lb()).number().value();
        inv.stack.initialize_numbers(start, width);
    }
    // TODO: handle other stack type constraints
    return inv;
}

ebpf_domain_t ebpf_domain_t::setup_entry(bool check_termination) {
    using namespace crab::dsl_syntax;

    ebpf_domain_t inv;
    auto r10 = reg_pack(R10_STACK_POINTER);
    Reg r10_reg{(uint8_t)R10_STACK_POINTER};
    inv += EBPF_STACK_SIZE <= r10.value;
    inv += r10.value <= PTR_MAX;
    inv.assign(r10.stack_offset, EBPF_STACK_SIZE);
    // stack_numeric_size would be 0, but TOP has the same result
    // so no need to assign it.
    inv.type_inv.assign_type(inv.m_inv, r10_reg, T_STACK);

    auto r1 = reg_pack(R1_ARG);
    Reg r1_reg{(uint8_t)R1_ARG};
    inv += 1 <= r1.value;
    inv += r1.value <= PTR_MAX;
    inv.assign(r1.ctx_offset, 0);
    inv.type_inv.assign_type(inv.m_inv, r1_reg, T_CTX);

    initialize_packet(inv);

    if (check_termination) {
        inv.assign(variable_t::instruction_count(), 0);
    }
    return inv;
}
