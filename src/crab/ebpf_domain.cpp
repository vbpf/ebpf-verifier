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
    variable_t value, offset, type, region_size;
};

reg_pack_t reg_pack(int i) {
    return {
        variable_t::reg(data_kind_t::values, i),
        variable_t::reg(data_kind_t::offsets, i),
        variable_t::reg(data_kind_t::types, i),
        variable_t::reg(data_kind_t::region_size, i),
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

void ebpf_domain_t::operator|=(ebpf_domain_t&& other) {
    if (is_bottom()) {
        *this = other;
        return;
    }
    m_inv |= std::move(other.m_inv);
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
        auto reg = reg_pack(i);
        havoc(reg.value);
        havoc(reg.offset);
        type_inv.havoc_type(m_inv, Reg{(uint8_t)i});
    }
}

void ebpf_domain_t::forget_packet_pointers() {
    using namespace crab::dsl_syntax;

    initialize_packet(*this);

    for (variable_t v : variable_t::get_type_variables()) {
        // TODO: this is sufficient, but for clarity it may be useful to forget the offset and value too.
        if (m_inv.intersect(v == T_PACKET))
            m_inv -= v;
    }
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
        check_require(inv, cst, s);
    if (thread_local_options.assume_assertions) {
        // avoid redundant errors
        ::assume(inv, cst);
    }
}

/// Forget everything we know about the value of a variable.
void ebpf_domain_t::havoc(variable_t v) { m_inv -= v; }

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

NumAbsDomain ebpf_domain_t::TypeDomain::join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                                        const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const {
    crab::interval_t types = inv.eval_interval(reg_pack(reg).type);
    if (types.is_bottom())
        return NumAbsDomain(true);
    if (auto lb = types.lb().number()) {
        if (auto ub = types.ub().number()) {
            NumAbsDomain res(true);
            for (int type = (int)*lb; type <= (int)*ub; type++) {
                NumAbsDomain tmp(inv);
                transition(tmp, static_cast<type_encoding_t>(type));
                res |= tmp;
            }
            return res;
        }
    }
    NumAbsDomain res(inv);
    transition(res, static_cast<type_encoding_t>(T_UNINIT));
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

void ebpf_domain_t::check_access_stack(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, std::string("Lower bound must be at least 0") + s);
    require(inv, ub <= EBPF_STACK_SIZE, std::string("Upper bound must be at most EBPF_STACK_SIZE") + s + std::string(", make sure to bounds check any pointer access"));
}

void ebpf_domain_t::check_access_context(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, std::string("Lower bound must be at least 0") + s);
    require(inv, ub <= global_program_info.type.context_descriptor->size,
            std::string("Upper bound must be at most ") + std::to_string(global_program_info.type.context_descriptor->size) +
                s);
}

void ebpf_domain_t::check_access_packet(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s,
                                        std::optional<variable_t> region_size) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= variable_t::meta_offset(), std::string("Lower bound must be at least meta_offset") + s);
    if (region_size)
        require(inv, ub <= *region_size,
                std::string("Upper bound must be at most packet_size") + s);
    else
        require(inv, ub <= MAX_PACKET_SIZE,
                std::string("Upper bound must be at most ") + std::to_string(MAX_PACKET_SIZE) + s);
}

void ebpf_domain_t::check_access_shared(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub, const std::string& s,
                                        variable_t region_size) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, std::string("Lower bound must be at least 0") + s);
    require(inv, ub <= region_size, std::string("Upper bound must be at most ") + region_size.name() + s);
}

void ebpf_domain_t::operator()(const Assume& s) {
    Condition cond = s.cond;
    auto dst = reg_pack(cond.left);
    if (std::holds_alternative<Reg>(cond.right)) {
        auto src = reg_pack(std::get<Reg>(cond.right));
        if (type_inv.same_type(m_inv, cond.left, std::get<Reg>(cond.right))) {
            m_inv = type_inv.join_by_if_else(m_inv,
                type_is_number(cond.left),
                [&](NumAbsDomain& inv) {
                    if (!is_unsigned_cmp(cond.op))
                        for (const linear_constraint_t& cst : jmp_to_cst_reg(cond.op, dst.value, src.value))
                            inv += cst;
                },
                [&](NumAbsDomain& inv) {
                    // Either pointers to a singleton region,
                    // or an equality comparison on map descriptors/pointers to non-singleton locations
                    inv += jmp_to_cst_offsets_reg(cond.op, dst.offset, src.offset);
                }
            );
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
        havoc(dst.offset);
        break;
    case Un::Op::NEG:
        neg(dst.value);
        havoc(dst.offset);
        break;
    }
}

void ebpf_domain_t::operator()(const Exit& a) {}

void ebpf_domain_t::operator()(const Jmp& a) {}

void ebpf_domain_t::operator()(const Comparable& s) {
    if (!type_inv.same_type(m_inv, s.r1, s.r2))
        require(m_inv, linear_constraint_t::FALSE(), to_string(s));
}

void ebpf_domain_t::operator()(const Addable& s) {
    if (!type_inv.implies_type(m_inv, type_is_pointer(reg_pack(s.ptr)),type_is_number(s.num)))
        require(m_inv, linear_constraint_t::FALSE(), "only numbers can be added to pointers (" + to_string(s) + ")");
}

void ebpf_domain_t::operator()(const ValidStore& s) {
    if (!type_inv.implies_type(m_inv, type_is_not_stack(reg_pack(s.mem)), type_is_number(s.val)))
        require(m_inv, linear_constraint_t::FALSE(), "Only numbers can be stored to externally-visible regions");
}

void ebpf_domain_t::operator()(const TypeConstraint& s) {
    if (!type_inv.is_in_group(m_inv, s.reg, s.types))
        require(m_inv, linear_constraint_t::FALSE(), to_string(s));
}

void ebpf_domain_t::operator()(const ValidSize& s) {
    using namespace crab::dsl_syntax;
    auto r = reg_pack(s.reg);
    require(m_inv, s.can_be_zero ? r.value >= 0 : r.value > 0, to_string(s));
}

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool ebpf_domain_t::get_map_fd_range(const Reg& map_fd_reg, int* start_fd, int* end_fd) const {
    const crab::interval_t& map_fd_interval = m_inv[reg_pack(map_fd_reg).offset];
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
    std::string m = std::string(" (") + to_string(s) + ")";
    variable_t lb = access_reg.offset;
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
    linear_expression_t ub = lb + width;

    m_inv = type_inv.join_over_types(m_inv, s.access_reg, [&](NumAbsDomain& inv, type_encoding_t access_reg_type) {
        if (access_reg_type == T_STACK) {
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
                    variable_t key_ptr = access_reg.offset;
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
            check_access_packet(inv, lb, ub, m, {});
        } else {
            require(inv, linear_constraint_t::FALSE(), "Only stack or packet can be used as a parameter" + m);
        }
    });
}

void ebpf_domain_t::operator()(const ValidAccess& s) {
    using namespace crab::dsl_syntax;

    bool is_comparison_check = s.width == (Value)Imm{0};

    auto reg = reg_pack(s.reg);
    linear_expression_t lb = reg.offset + s.offset;
    linear_expression_t ub = std::holds_alternative<Imm>(s.width)
        ? lb + std::get<Imm>(s.width).v
        : lb + reg_pack(std::get<Reg>(s.width)).value;
    std::string m = std::string(" (") + to_string(s) + ")";
    // join_over_types instead of simple iteration is only needed for assume-assert
    m_inv = type_inv.join_over_types(m_inv, s.reg, [&](NumAbsDomain& inv, type_encoding_t type) {
        switch (type) {
        case T_PACKET:
            check_access_packet(inv, lb, ub, m, is_comparison_check ? std::optional<variable_t>{} : reg.region_size);
            // if within bounds, it can never be null
            break;
        case T_STACK:
            check_access_stack(inv, lb, ub, m);
            // if within bounds, it can never be null
            break;
        case T_CTX:
            check_access_context(inv, lb, ub, m);
            // if within bounds, it can never be null
            break;
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
        case T_SHARED:
            check_access_shared(inv, lb, ub, m, reg.region_size);
            if (!is_comparison_check && !s.or_null)
                require(inv, reg.value > 0, "Possible null access");
            break;
        default:
            require(inv, linear_constraint_t::FALSE(), "Invalid type");
            break;
        }
    });
}

void ebpf_domain_t::operator()(const ZeroOffset& s) {
    using namespace crab::dsl_syntax;
    auto reg = reg_pack(s.reg);
    require(m_inv, reg.offset == 0, to_string(s));
}

void ebpf_domain_t::operator()(const Assert& stmt) {
    if (check_require || thread_local_options.assume_assertions)
        std::visit(*this, stmt.cst);
}

void ebpf_domain_t::operator()(const Packet& a) {
    auto reg = reg_pack(R0_RETURN_VALUE);
    type_inv.assign_type(m_inv, Reg{(uint8_t)R0_RETURN_VALUE}, T_NUM);
    havoc(reg.offset);
    havoc(reg.value);
    scratch_caller_saved_registers();
}

void ebpf_domain_t::do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width) {
    type_inv.assign_type(inv, target_reg, stack.load(inv, data_kind_t::types, addr, width));

    const reg_pack_t& target = reg_pack(target_reg);
    if (width == 1 || width == 2 || width == 4 || width == 8) {
        inv.assign(target.value, stack.load(inv,  data_kind_t::values, addr, width));
        inv.assign(target.offset, stack.load(inv, data_kind_t::offsets, addr, width));
        inv.assign(target.region_size, stack.load(inv, data_kind_t::region_size, addr, width));
    } else {
        inv -= target.value;
        inv -= target.offset;
        inv -= target.region_size;
    }
}

void ebpf_domain_t::do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague, int width) {
    using namespace crab::dsl_syntax;
    if (inv.is_bottom())
        return;

    const ebpf_context_descriptor_t* desc = global_program_info.type.context_descriptor;

    const reg_pack_t& target = reg_pack(target_reg);
    inv -= target.value;

    if (desc->end < 0) {
        inv -= target.offset;
        type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }

    crab::interval_t interval = inv.eval_interval(addr_vague);
    std::optional<number_t> maybe_addr = interval.singleton();

    bool may_touch_ptr = interval[desc->data] || interval[desc->meta] || interval[desc->end];

    if (!maybe_addr) {
        inv -= target.offset;
        if (may_touch_ptr)
            type_inv.havoc_type(inv, target_reg);
        else
            type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }

    number_t addr = *maybe_addr;

    if (addr == desc->data) {
        inv.assign(target.offset, 0);
    } else if (addr == desc->end) {
        inv.assign(target.offset, variable_t::packet_size());
    } else if (addr == desc->meta) {
        inv.assign(target.offset, variable_t::meta_offset());
    } else {
        inv -= target.offset;
        if (may_touch_ptr)
            type_inv.havoc_type(inv, target_reg);
        else
            type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }
    type_inv.assign_type(inv, target_reg, T_PACKET);
    inv.assign(target.region_size, variable_t::packet_size());
    inv += 4098 <= target.value;
    inv += target.value <= PTR_MAX;
}

void ebpf_domain_t::do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width) {
    if (inv.is_bottom())
        return;
    const reg_pack_t& target = reg_pack(target_reg);

    type_inv.assign_type(inv, target_reg, T_NUM);
    inv -= target.offset;

    // A 1 or 2 byte copy results in a limited range of values that may be used as array indices.
    if (width == 1) {
        inv.set(target.value, crab::interval_t(0, UINT8_MAX));
    } else if (width == 2) {
        inv.set(target.value, crab::interval_t(0, UINT16_MAX));
    } else {
        inv -= target.value;
    }
}

void ebpf_domain_t::do_load(const Mem& b, const Reg& target_reg) {
    using namespace crab::dsl_syntax;

    auto mem_reg = reg_pack(b.access.basereg);
    int width = b.access.width;
    int offset = b.access.offset;
    linear_expression_t addr = mem_reg.offset + (number_t)offset;

    if (b.access.basereg.v == R10_STACK_POINTER) {
        do_load_stack(m_inv, target_reg, addr, width);
        return;
    }

    m_inv = type_inv.join_over_types(m_inv, b.access.basereg, [&](NumAbsDomain& inv, type_encoding_t type) {
        switch (type) {
            case T_UNINIT: return;
            case T_MAP: return;
            case T_MAP_PROGRAMS: return;
            case T_NUM: return;
            case T_CTX: do_load_ctx(inv, target_reg, addr, width); break;
            case T_STACK: do_load_stack(inv, target_reg, addr, width); break;
            case T_PACKET: do_load_packet_or_shared(inv, target_reg, addr, width); break;
            default: do_load_packet_or_shared(inv, target_reg, addr, width); break;
        }
    });
}

template <typename A, typename X, typename Y>
void ebpf_domain_t::do_store_stack(NumAbsDomain& inv, int width, const A& addr, X val_type, Y val_value,
                    std::optional<variable_t> opt_val_offset, std::optional<variable_t> opt_val_region_size) {
    type_inv.assign_type(inv, stack.store_type(inv, addr, width, val_type), val_type);
    if (width == 8) {
        inv.assign(stack.store(inv, data_kind_t::values, addr, width, val_value), val_value);
        if (opt_val_offset && type_inv.get_type(m_inv, val_type) != T_NUM) {
            inv.assign(stack.store(inv, data_kind_t::offsets, addr, width, *opt_val_offset), *opt_val_offset);
            inv.assign(stack.store(inv, data_kind_t::region_size, addr, width, *opt_val_region_size), *opt_val_region_size);
        } else {
            stack.havoc(inv, data_kind_t::offsets, addr, width);
            stack.havoc(inv, data_kind_t::region_size, addr, width);
        }
    } else if ((width == 1 || width == 2 || width == 4) && type_inv.get_type(m_inv, val_type) == T_NUM) {
        // Keep track of numbers on the stack that might be used as array indices.
        inv.assign(stack.store(inv, data_kind_t::values, addr, width, val_value), val_value);
        stack.havoc(inv, data_kind_t::offsets, addr, width);
        stack.havoc(inv, data_kind_t::region_size, addr, width);
    } else {
        stack.havoc(inv, data_kind_t::values, addr, width);
        stack.havoc(inv, data_kind_t::offsets, addr, width);
        stack.havoc(inv, data_kind_t::region_size, addr, width);
    }
}

void ebpf_domain_t::operator()(const Mem& b) {
    if (m_inv.is_bottom())
        return;
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value));
        } else {
            auto data_reg = reg_pack(std::get<Reg>(b.value));
            do_mem_store(b, std::get<Reg>(b.value), data_reg.value, data_reg.offset, data_reg.region_size);
        }
    } else {
        do_mem_store(b, T_NUM, std::get<Imm>(b.value).v, {}, {});
    }
}

template <typename Type, typename Value>
void ebpf_domain_t::do_mem_store(const Mem& b, Type val_type, Value val_value, std::optional<variable_t> opt_val_offset, std::optional<variable_t> opt_val_region_size) {
    if (m_inv.is_bottom())
        return;
    using namespace crab::dsl_syntax;
    auto mem_reg = reg_pack(b.access.basereg);
    int width = b.access.width;
    int offset = b.access.offset;
    if (b.access.basereg.v == R10_STACK_POINTER) {
        int addr = EBPF_STACK_SIZE + offset;
        do_store_stack(m_inv, width, addr, val_type, val_value, opt_val_offset, opt_val_region_size);
        return;
    }
    linear_expression_t addr = linear_expression_t(mem_reg.offset) + offset;
    m_inv = type_inv.join_over_types(m_inv, b.access.basereg, [&](NumAbsDomain& inv, type_encoding_t type) {
        if (type == T_STACK)
            do_store_stack(inv, width, addr, val_type, val_value, opt_val_offset, opt_val_region_size);
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
        case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
        case ArgPair::Kind::PTR_TO_MEM:
            // Do nothing. No side effect allowed.
            break;

        case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
            bool store_numbers = true;
            variable_t addr = reg_pack(param.mem).offset;
            variable_t width = reg_pack(param.size).value;

            m_inv = type_inv.join_over_types(m_inv, param.mem, [&](NumAbsDomain& inv, type_encoding_t type) {
                if (type == T_STACK) {
                    // Pointer to a memory region that the called function may change,
                    // so we must havoc.
                    stack.havoc(inv, data_kind_t::types, addr, width);
                    stack.havoc(inv, data_kind_t::values, addr, width);
                    stack.havoc(inv, data_kind_t::offsets, addr, width);
                    stack.havoc(inv, data_kind_t::region_size, addr, width);
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
                    assign(r0_pack.offset, 0);
                    m_inv.set(reg_pack(r0_reg).region_size, get_map_value_size(*maybe_fd_reg));
                    type_inv.assign_type(m_inv, r0_reg, T_SHARED);
                }
            }
        }
        assign_valid_ptr(r0_reg, true);
        assign(r0_pack.offset, 0);
        type_inv.assign_type(m_inv, r0_reg, T_SHARED);
    } else {
        havoc(r0_pack.value);
        havoc(r0_pack.offset);
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
    assign(dst.offset, mapfd);
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
            havoc(dst.offset);
            break;
        case Bin::Op::ADD:
            if (imm == 0)
                return;
            add_overflow(dst.value, imm);
            add(dst.offset, imm);
            break;
        case Bin::Op::SUB:
            if (imm == 0)
                return;
            sub_overflow(dst.value, imm);
            sub(dst.offset, imm);
            break;
        case Bin::Op::MUL:
            mul(dst.value, imm);
            havoc(dst.offset);
            break;
        case Bin::Op::DIV:
            div(dst.value, imm);
            havoc(dst.offset);
            break;
        case Bin::Op::MOD:
            rem(dst.value, imm);
            havoc(dst.offset);
            break;
        case Bin::Op::OR:
            bitwise_or(dst.value, imm);
            havoc(dst.offset);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            bitwise_and(dst.value, imm);
            if ((int32_t)imm > 0) {
                assume(dst.value <= imm);
                assume(0 <= dst.value);
            }
            havoc(dst.offset);
            break;
        case Bin::Op::LSH:
            // avoid signedness and overflow issues in shl_overflow(dst.value, imm);
            shl_overflow(dst.value, imm);
            havoc(dst.offset);
            break;
        case Bin::Op::RSH:
            // avoid signedness and overflow issues in lshr(dst.value, imm);
            havoc(dst.value);
            havoc(dst.offset);
            break;
        case Bin::Op::ARSH:
            // avoid signedness and overflow issues in ashr(dst.value, imm);
            // = (int64_t)dst >> imm;
            havoc(dst.value);
            // assume(dst.value <= (1 << (64 - imm)));
            // assume(dst.value >= -(1 << (64 - imm)));
            havoc(dst.offset);
            break;
        case Bin::Op::XOR:
            bitwise_xor(dst.value, imm);
            havoc(dst.offset);
            break;
        }
    } else {
        // dst op= src
        auto src = reg_pack(std::get<Reg>(bin.v));
        switch (bin.op) {
        case Bin::Op::ADD: {
            if (type_inv.same_type(m_inv, bin.dst, std::get<Reg>(bin.v))) {
                // both must be numbers
                add_overflow(dst.value, src.value);
            } else {
                // Here we're not sure that lhs and rhs are the same type; they might be.
                // But previous assertions should fail unless we know that exactly one of lhs or rhs to is a pointer
                m_inv = type_inv.join_by_if_else(m_inv,
                    type_is_number(bin.dst),
                    [&](NumAbsDomain& inv) {
                        // num + ptr
                        apply(inv, crab::arith_binop_t::ADD, dst.offset, dst.value, src.offset, false);
                        type_inv.assign_type(inv, bin.dst, std::get<Reg>(bin.v));
                        inv.assign(dst.region_size, src.region_size);
                    },
                    [&](NumAbsDomain& inv) {
                        // ptr + num
                        apply(inv, crab::arith_binop_t::ADD, dst.offset, dst.offset, src.value, false);
                    }
                );
                // careful: change dst.value only after dealing with offset
                apply(m_inv, crab::arith_binop_t::ADD, dst.value, dst.value, src.value, true);
            }
            break;
        }
        case Bin::Op::SUB: {
            if (type_inv.same_type(m_inv, bin.dst, std::get<Reg>(bin.v))) {
                m_inv = type_inv.join_by_if_else(m_inv,
                    type_is_number(bin.dst),
                    [&](NumAbsDomain& inv) {
                        // This is: sub_overflow(inv, dst.value, src.value);
                        apply(inv, crab::arith_binop_t::SUB, dst.value, dst.value, src.value, true);
                    },
                    [&](NumAbsDomain& inv) {
                        // Assertions should make sure we only perform this on non-shared pointers
                        apply(inv, crab::arith_binop_t::SUB, dst.value, dst.offset, src.offset, true);
                        inv -= dst.offset;
                        inv -= dst.region_size;
                        type_inv.assign_type(inv, bin.dst, T_NUM);
                    }
                );
            } else {
                // Here we're not sure that lhs and rhs are the same type; they might be, meaning lhs may be a number.
                // But previous assertions should fail unless we know that rhs is a number.
                if (type_inv.get_type(m_inv, std::get<Reg>(bin.v)) != T_NUM) {
                    type_inv.havoc_type(m_inv, bin.dst);
                    havoc(dst.value);
                    havoc(dst.offset);
                    havoc(dst.region_size);
                } else {
                    sub_overflow(dst.value, src.value);
                    // No harm comes from subtracting the value from an offset of a number, which is TOP.
                    sub(dst.offset, src.value);
                }
            }
            break;
        }
        case Bin::Op::MUL:
            mul(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::DIV:
            // DIV is not checked for zerodiv
            div(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::MOD:
            // See DIV comment
            rem(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::OR:
            bitwise_or(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::AND:
            bitwise_and(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::LSH:
            shl_overflow(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::RSH:
            havoc(dst.value);
            havoc(dst.offset);
            break;
        case Bin::Op::ARSH:
            havoc(dst.value);
            havoc(dst.offset);
            break;
        case Bin::Op::XOR:
            bitwise_xor(dst.value, src.value);
            havoc(dst.offset);
            break;
        case Bin::Op::MOV:
            assign(dst.value, src.value);
            assign(dst.offset, src.offset);
            assign(dst.region_size, src.region_size);
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

ebpf_domain_t ebpf_domain_t::from_constraints(const std::vector<linear_constraint_t>& csts) {
    // TODO: handle type constraints separately
    ebpf_domain_t inv;
    for (const auto& cst: csts) {
        inv += cst;
    }
    return inv;
}

ebpf_domain_t ebpf_domain_t::setup_entry(bool check_termination) {
    using namespace crab::dsl_syntax;

    ebpf_domain_t inv;
    auto r10 = reg_pack(R10_STACK_POINTER);
    Reg r10_reg{(uint8_t)R10_STACK_POINTER};
    inv += EBPF_STACK_SIZE <= r10.value;
    inv += r10.value <= PTR_MAX;
    inv.assign(r10.offset, EBPF_STACK_SIZE);
    inv.type_inv.assign_type(inv.m_inv, r10_reg, T_STACK);
    inv.assign(r10.region_size, EBPF_STACK_SIZE);

    auto r1 = reg_pack(R1_ARG);
    Reg r1_reg{(uint8_t)R1_ARG};
    inv += 1 <= r1.value;
    inv += r1.value <= PTR_MAX;
    inv.assign(r1.offset, 0);
    inv.type_inv.assign_type(inv.m_inv, r1_reg, T_CTX);

    initialize_packet(inv);

    if (check_termination) {
        inv.assign(variable_t::instruction_count(), 0);
    }
    return inv;
}
