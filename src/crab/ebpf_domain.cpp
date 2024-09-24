// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <optional>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"

#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab/finite_domain.hpp"

#include "asm_ostream.hpp"
#include "asm_unmarshal.hpp"
#include "config.hpp"
#include "dsl_syntax.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"

using crab::domains::NumAbsDomain;
namespace crab {
struct reg_pack_t {
    variable_t svalue; // int64_t value.
    variable_t uvalue; // uint64_t value.
    variable_t ctx_offset;
    variable_t map_fd;
    variable_t packet_offset;
    variable_t shared_offset;
    variable_t stack_offset;
    variable_t type;
    variable_t shared_region_size;
    variable_t stack_numeric_size;
};

reg_pack_t reg_pack(const int i) {
    return {
        variable_t::reg(data_kind_t::svalues, i),
        variable_t::reg(data_kind_t::uvalues, i),
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
reg_pack_t reg_pack(const Reg r) { return reg_pack(r.v); }

static linear_constraint_t eq_types(const Reg& a, const Reg& b) {
    using dsl_syntax::eq;
    return eq(reg_pack(a).type, reg_pack(b).type);
}

static linear_constraint_t neq(const variable_t a, const variable_t b) {
    using namespace crab::dsl_syntax;
    return {a - b, constraint_kind_t::NOT_ZERO};
}

constexpr int MAX_PACKET_SIZE = 0xffff;

// Pointers in the BPF VM are defined to be 64 bits.  Some contexts, like
// data, data_end, and meta in Linux's struct xdp_md are only 32 bit offsets
// from a base address not exposed to the program, but when a program is loaded,
// the offsets get replaced with 64-bit address pointers.  However, we currently
// need to do pointer arithmetic on 64-bit numbers so for now we cap the interval
// to 32 bits.
constexpr int64_t PTR_MAX = std::numeric_limits<int32_t>::max() - MAX_PACKET_SIZE;

/** Linear constraint for a pointer comparison.
 */
static linear_constraint_t assume_cst_offsets_reg(const Condition::Op op, bool is64, const variable_t dst_offset,
                                                  const variable_t src_offset) {
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
static std::vector<linear_constraint_t> assume_cst_imm(const NumAbsDomain& inv, const Condition::Op op, const bool is64,
                                                       const variable_t dst_svalue, const variable_t dst_uvalue,
                                                       const int64_t imm) {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ:
    case Op::SGE:
    case Op::SLE:
    case Op::SGT:
    case Op::SLT:
        return inv->assume_signed_cst_interval(op, is64, dst_svalue, dst_uvalue, number_t{imm},
                                               number_t{static_cast<uint64_t>(imm)});
    case Op::SET:
    case Op::NSET: return inv->assume_bit_cst_interval(op, is64, dst_uvalue, interval_t(imm));
    case Op::NE:
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT:
        return inv->assume_unsigned_cst_interval(op, is64, dst_svalue, dst_uvalue, number_t{imm},
                                                 number_t{static_cast<uint64_t>(imm)});
    }
    return {};
}

/** Linear constraint for a numerical comparison between registers.
 */
static std::vector<linear_constraint_t> assume_cst_reg(const NumAbsDomain& inv, const Condition::Op op, const bool is64,
                                                       const variable_t dst_svalue, const variable_t dst_uvalue,
                                                       const variable_t src_svalue, const variable_t src_uvalue) {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;
    if (is64) {
        switch (op) {
        case Op::EQ: {
            const interval_t src_interval = inv.eval_interval(src_svalue);
            if (!src_interval.is_singleton() && (src_interval <= interval_t::nonnegative_int(true))) {
                return {eq(dst_svalue, src_svalue), eq(dst_uvalue, src_uvalue), eq(dst_svalue, dst_uvalue)};
            } else {
                return {eq(dst_svalue, src_svalue), eq(dst_uvalue, src_uvalue)};
            }
        }
        case Op::NE: return {neq(dst_svalue, src_svalue)};
        case Op::SGE: return {dst_svalue >= src_svalue};
        case Op::SLE: return {dst_svalue <= src_svalue};
        case Op::SGT: return {dst_svalue > src_svalue};
        // Note: reverse the test as a workaround strange lookup:
        case Op::SLT: return {src_svalue > dst_svalue};
        case Op::SET:
        case Op::NSET: return inv->assume_bit_cst_interval(op, is64, dst_uvalue, inv.eval_interval(src_uvalue));
        case Op::GE:
        case Op::LE:
        case Op::GT:
        case Op::LT: return inv->assume_unsigned_cst_interval(op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        }
    } else {
        switch (op) {
        case Op::EQ:
        case Op::SGE:
        case Op::SLE:
        case Op::SGT:
        case Op::SLT: return inv->assume_signed_cst_interval(op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        case Op::SET:
        case Op::NSET: return inv->assume_bit_cst_interval(op, is64, dst_uvalue, inv.eval_interval(src_uvalue));
        case Op::NE:
        case Op::GE:
        case Op::LE:
        case Op::GT:
        case Op::LT: return inv->assume_unsigned_cst_interval(op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        }
    }
    assert(false);
    throw std::exception();
}

std::optional<variable_t> ebpf_domain_t::get_type_offset_variable(const Reg& reg, const int type) {
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

ebpf_domain_t::ebpf_domain_t(NumAbsDomain inv, const crab::domains::array_domain_t& stack)
    : m_inv(std::move(inv)), stack(stack) {}

void ebpf_domain_t::set_to_top() {
    m_inv.set_to_top();
    stack.set_to_top();
}

void ebpf_domain_t::set_to_bottom() { m_inv.set_to_bottom(); }

bool ebpf_domain_t::is_bottom() const { return m_inv.is_bottom(); }

bool ebpf_domain_t::is_top() const { return m_inv.is_top() && stack.is_top(); }

bool ebpf_domain_t::operator<=(const ebpf_domain_t& other) const {
    return m_inv <= other.m_inv && stack <= other.stack;
}

bool ebpf_domain_t::operator==(const ebpf_domain_t& other) const {
    return stack == other.stack && m_inv <= other.m_inv && other.m_inv <= m_inv;
}

void ebpf_domain_t::TypeDomain::add_extra_invariant(const NumAbsDomain& dst,
                                                    std::map<variable_t, interval_t>& extra_invariants,
                                                    const variable_t type_variable, const type_encoding_t type,
                                                    const data_kind_t kind, const NumAbsDomain& src) const {
    const bool dst_has_type = has_type(dst, type_variable, type);
    const bool src_has_type = has_type(src, type_variable, type);
    variable_t v = variable_t::kind_var(kind, type_variable);

    // If type is contained in exactly one of dst or src,
    // we need to remember the value.
    if (dst_has_type && !src_has_type) {
        extra_invariants.emplace(v, dst.eval_interval(v));
    } else if (!dst_has_type && src_has_type) {
        extra_invariants.emplace(v, src.eval_interval(v));
    }
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
    // However, when the type value is not present in one domain,
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

    std::map<crab::variable_t, interval_t> extra_invariants;
    if (!dst.is_bottom()) {
        for (const variable_t v : variable_t::get_type_variables()) {
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
    return ebpf_domain_t(other.m_inv | std::move(m_inv), other.stack | stack);
}

ebpf_domain_t ebpf_domain_t::operator&(const ebpf_domain_t& other) const {
    return ebpf_domain_t(m_inv & other.m_inv, stack & other.stack);
}

ebpf_domain_t ebpf_domain_t::calculate_constant_limits() {
    ebpf_domain_t inv;
    using namespace crab::dsl_syntax;
    for (const int i : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
        const auto r = reg_pack(i);
        inv.m_inv += r.svalue <= std::numeric_limits<int32_t>::max();
        inv.m_inv += r.svalue >= std::numeric_limits<int32_t>::min();
        inv.m_inv += r.uvalue <= std::numeric_limits<uint32_t>::max();
        inv.m_inv += r.uvalue >= 0;
        inv.m_inv += r.stack_offset <= EBPF_STACK_SIZE;
        inv.m_inv += r.stack_offset >= 0;
        inv.m_inv += r.shared_offset <= r.shared_region_size;
        inv.m_inv += r.shared_offset >= 0;
        inv.m_inv += r.packet_offset <= variable_t::packet_size();
        inv.m_inv += r.packet_offset >= 0;
        if (thread_local_options.check_termination) {
            for (const variable_t counter : variable_t::get_loop_counters()) {
                inv.m_inv += counter <= std::numeric_limits<int32_t>::max();
                inv.m_inv += counter >= 0;
                inv.m_inv += counter <= r.svalue;
            }
        }
    }
    return inv;
}

static const ebpf_domain_t constant_limits = ebpf_domain_t::calculate_constant_limits();

ebpf_domain_t ebpf_domain_t::widen(const ebpf_domain_t& other, const bool to_constants) const {
    ebpf_domain_t res{m_inv.widen(other.m_inv), stack | other.stack};
    if (to_constants) {
        return res & constant_limits;
    }
    return res;
}

ebpf_domain_t ebpf_domain_t::narrow(const ebpf_domain_t& other) const {
    return ebpf_domain_t(m_inv.narrow(other.m_inv), stack & other.stack);
}

/// Forget everything we know about the value of a variable.
void ebpf_domain_t::havoc(const variable_t v) { m_inv -= v; }
void havoc_offsets(NumAbsDomain& inv, const Reg& reg) {
    const reg_pack_t r = reg_pack(reg);
    inv -= r.ctx_offset;
    inv -= r.map_fd;
    inv -= r.packet_offset;
    inv -= r.shared_offset;
    inv -= r.shared_region_size;
    inv -= r.stack_offset;
    inv -= r.stack_numeric_size;
}
void ebpf_domain_t::havoc_offsets(const Reg& reg) { crab::havoc_offsets(m_inv, reg); }
void havoc_register(NumAbsDomain& inv, const Reg& reg) {
    const reg_pack_t r = reg_pack(reg);
    havoc_offsets(inv, reg);
    inv -= r.svalue;
    inv -= r.uvalue;
}

void ebpf_domain_t::scratch_caller_saved_registers() {
    for (int i = R1_ARG; i <= R5_ARG; i++) {
        Reg r{static_cast<uint8_t>(i)};
        crab::havoc_register(m_inv, r);
        type_inv.havoc_type(m_inv, r);
    }
}

void ebpf_domain_t::save_callee_saved_registers(const std::string& prefix) {
    // Create variables specific to the new call stack frame that store
    // copies of the states of r6 through r9.
    for (int r = R6; r <= R9; r++) {
        for (data_kind_t kind = data_kind_t::types; kind <= data_kind_t::stack_numeric_sizes;
             kind = static_cast<data_kind_t>(static_cast<int>(kind) + 1)) {
            const variable_t src_var = variable_t::reg(kind, r);
            if (!m_inv[src_var].is_top()) {
                m_inv->assign(variable_t::stack_frame_var(kind, r, prefix), src_var);
            }
        }
    }
}

void ebpf_domain_t::restore_callee_saved_registers(const std::string& prefix) {
    for (int r = R6; r <= R9; r++) {
        for (data_kind_t kind = data_kind_t::types; kind <= data_kind_t::stack_numeric_sizes;
             kind = static_cast<data_kind_t>(static_cast<int>(kind) + 1)) {
            const variable_t src_var = variable_t::stack_frame_var(kind, r, prefix);
            if (!m_inv[src_var].is_top()) {
                m_inv->assign(variable_t::reg(kind, r), src_var);
            } else {
                havoc(variable_t::reg(kind, r));
            }
            havoc(src_var);
        }
    }
}

void ebpf_domain_t::forget_packet_pointers() {
    using namespace crab::dsl_syntax;

    for (const variable_t type_variable : variable_t::get_type_variables()) {
        if (type_inv.has_type(m_inv, type_variable, T_PACKET)) {
            havoc(variable_t::kind_var(data_kind_t::types, type_variable));
            havoc(variable_t::kind_var(data_kind_t::packet_offsets, type_variable));
            havoc(variable_t::kind_var(data_kind_t::svalues, type_variable));
            havoc(variable_t::kind_var(data_kind_t::uvalues, type_variable));
        }
    }

    initialize_packet(*this);
}

static void assume(NumAbsDomain& inv, const linear_constraint_t& cst) { inv += cst; }
void ebpf_domain_t::assume(const linear_constraint_t& cst) { crab::assume(m_inv, cst); }

void ebpf_domain_t::require(NumAbsDomain& inv, const linear_constraint_t& cst, const std::string& s) {
    if (check_require) {
        check_require(inv, cst, s + " (" + this->current_assertion + ")");
    }
    if (thread_local_options.assume_assertions) {
        // avoid redundant errors
        crab::assume(inv, cst);
    }
}

static linear_constraint_t type_is_pointer(const reg_pack_t& r) {
    using namespace crab::dsl_syntax;
    return r.type >= T_CTX;
}

static linear_constraint_t type_is_number(const reg_pack_t& r) {
    using namespace crab::dsl_syntax;
    return r.type == T_NUM;
}

static linear_constraint_t type_is_number(const Reg& r) { return type_is_number(reg_pack(r)); }

static linear_constraint_t type_is_not_stack(const reg_pack_t& r) {
    using namespace crab::dsl_syntax;
    return r.type != T_STACK;
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const type_encoding_t t) {
    inv.assign(reg_pack(lhs).type, t);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs) {
    inv.assign(reg_pack(lhs).type, reg_pack(rhs).type);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const std::optional<variable_t> lhs, const Reg& rhs) {
    inv.assign(lhs, reg_pack(rhs).type);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const std::optional<variable_t> lhs,
                                            const number_t& rhs) {
    inv.assign(lhs, rhs);
}

void ebpf_domain_t::TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs,
                                            const std::optional<linear_expression_t>& rhs) {
    inv.assign(reg_pack(lhs).type, rhs);
}

void ebpf_domain_t::TypeDomain::havoc_type(NumAbsDomain& inv, const Reg& r) { inv -= reg_pack(r).type; }

int ebpf_domain_t::TypeDomain::get_type(const NumAbsDomain& inv, const Reg& r) const {
    const auto res = inv[reg_pack(r).type].singleton();
    if (!res) {
        return T_UNINIT;
    }
    return static_cast<int>(*res);
}

int ebpf_domain_t::TypeDomain::get_type(const NumAbsDomain& inv, const variable_t v) const {
    const auto res = inv[v].singleton();
    if (!res) {
        return T_UNINIT;
    }
    return static_cast<int>(*res);
}

int ebpf_domain_t::TypeDomain::get_type(const NumAbsDomain& inv, const number_t& t) const {
    return static_cast<int>(t);
}

// Check whether a given type value is within the range of a given type variable's value.
bool ebpf_domain_t::TypeDomain::has_type(const NumAbsDomain& inv, const Reg& r, const type_encoding_t type) const {
    const interval_t interval = inv[reg_pack(r).type];
    if (interval.is_top()) {
        return true;
    }
    return (interval.lb().number().value_or(INT_MIN) <= type) && (interval.ub().number().value_or(INT_MAX) >= type);
}

bool ebpf_domain_t::TypeDomain::has_type(const NumAbsDomain& inv, const variable_t v,
                                         const type_encoding_t type) const {
    const interval_t interval = inv[v];
    if (interval.is_top()) {
        return true;
    }
    return (interval.lb().number().value_or(INT_MIN) <= type) && (interval.ub().number().value_or(INT_MAX) >= type);
}

bool ebpf_domain_t::TypeDomain::has_type(const NumAbsDomain& inv, const number_t& t, const type_encoding_t type) const {
    return t == number_t{type};
}

NumAbsDomain ebpf_domain_t::TypeDomain::join_over_types(
    const NumAbsDomain& inv, const Reg& reg,
    const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const {
    interval_t types = inv.eval_interval(reg_pack(reg).type);
    if (types.is_bottom()) {
        return NumAbsDomain::bottom();
    }
    if (types.is_top()) {
        NumAbsDomain res(inv);
        transition(res, static_cast<type_encoding_t>(T_UNINIT));
        return res;
    }
    NumAbsDomain res = NumAbsDomain::bottom();
    auto lb = types.lb().is_finite() ? static_cast<type_encoding_t>(static_cast<int>(types.lb().number().value()))
                                     : T_MAP_PROGRAMS;
    auto ub =
        types.ub().is_finite() ? static_cast<type_encoding_t>(static_cast<int>(types.ub().number().value())) : T_SHARED;
    for (type_encoding_t type = lb; type <= ub; type = static_cast<type_encoding_t>(static_cast<int>(type) + 1)) {
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

bool ebpf_domain_t::TypeDomain::implies_type(const NumAbsDomain& inv, const linear_constraint_t& a,
                                             const linear_constraint_t& b) const {
    return inv.when(a).entail(b);
}

bool ebpf_domain_t::TypeDomain::is_in_group(const NumAbsDomain& inv, const Reg& r, const TypeGroup group) const {
    using namespace crab::dsl_syntax;
    const variable_t t = reg_pack(r).type;
    switch (group) {
    case TypeGroup::number: return inv.entail(t == T_NUM);
    case TypeGroup::map_fd: return inv.entail(t == T_MAP);
    case TypeGroup::map_fd_programs: return inv.entail(t == T_MAP_PROGRAMS);
    case TypeGroup::ctx: return inv.entail(t == T_CTX);
    case TypeGroup::packet: return inv.entail(t == T_PACKET);
    case TypeGroup::stack: return inv.entail(t == T_STACK);
    case TypeGroup::shared: return inv.entail(t == T_SHARED);
    case TypeGroup::non_map_fd: return inv.entail(t >= T_NUM);
    case TypeGroup::mem: return inv.entail(t >= T_PACKET);
    case TypeGroup::mem_or_num: return inv.entail(t >= T_NUM) && inv.entail(t != T_CTX);
    case TypeGroup::pointer: return inv.entail(t >= T_CTX);
    case TypeGroup::ptr_or_num: return inv.entail(t >= T_NUM);
    case TypeGroup::stack_or_packet: return inv.entail(t >= T_PACKET) && inv.entail(t <= T_STACK);
    case TypeGroup::singleton_ptr: return inv.entail(t >= T_CTX) && inv.entail(t <= T_STACK);
    }
    assert(false);
    return false;
}

void ebpf_domain_t::operator()(const basic_block_t& bb) {
    if (!m_inv) {
        return;
    }
    for (const Instruction& statement : bb) {
        std::visit(*this, statement);
    }
}

void ebpf_domain_t::check_access_stack(NumAbsDomain& inv, const linear_expression_t& lb,
                                       const linear_expression_t& ub) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= EBPF_STACK_SIZE, "Upper bound must be at most EBPF_STACK_SIZE");
}

void ebpf_domain_t::check_access_context(NumAbsDomain& inv, const linear_expression_t& lb,
                                         const linear_expression_t& ub) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= global_program_info->type.context_descriptor->size,
            std::string("Upper bound must be at most ") +
                std::to_string(global_program_info->type.context_descriptor->size));
}

void ebpf_domain_t::check_access_packet(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                                        const std::optional<variable_t> packet_size) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= variable_t::meta_offset(), "Lower bound must be at least meta_offset");
    if (packet_size) {
        require(inv, ub <= *packet_size, "Upper bound must be at most packet_size");
    } else {
        require(inv, ub <= MAX_PACKET_SIZE,
                std::string{"Upper bound must be at most "} + std::to_string(MAX_PACKET_SIZE));
    }
}

void ebpf_domain_t::check_access_shared(NumAbsDomain& inv, const linear_expression_t& lb, const linear_expression_t& ub,
                                        const variable_t region_size) {
    using namespace crab::dsl_syntax;
    require(inv, lb >= 0, "Lower bound must be at least 0");
    require(inv, ub <= region_size, std::string("Upper bound must be at most ") + region_size.name());
}

void ebpf_domain_t::operator()(const Assume& s) {
    if (!m_inv) {
        return;
    }
    const Condition cond = s.cond;
    const auto dst = reg_pack(cond.left);
    if (std::holds_alternative<Reg>(cond.right)) {
        const auto src_reg = std::get<Reg>(cond.right);
        const auto src = reg_pack(src_reg);
        if (type_inv.same_type(m_inv, cond.left, std::get<Reg>(cond.right))) {
            m_inv = type_inv.join_over_types(m_inv, cond.left, [&](NumAbsDomain& inv, const type_encoding_t type) {
                if (type == T_NUM) {
                    for (const linear_constraint_t& cst :
                         assume_cst_reg(m_inv, cond.op, cond.is64, dst.svalue, dst.uvalue, src.svalue, src.uvalue)) {
                        inv += cst;
                    }
                } else {
                    // Either pointers to a singleton region,
                    // or an equality comparison on map descriptors/pointers to non-singleton locations
                    if (const auto dst_offset = get_type_offset_variable(cond.left, type)) {
                        if (const auto src_offset = get_type_offset_variable(src_reg, type)) {
                            inv += assume_cst_offsets_reg(cond.op, cond.is64, dst_offset.value(), src_offset.value());
                        }
                    }
                }
            });
        } else {
            // We should only reach here if `--assume-assert` is off
            assert(!thread_local_options.assume_assertions || is_bottom());
            // be sound in any case, it happens to flush out bugs:
            m_inv.set_to_top();
        }
    } else {
        const int64_t imm = static_cast<int64_t>(std::get<Imm>(cond.right).v);
        for (const linear_constraint_t& cst : assume_cst_imm(m_inv, cond.op, cond.is64, dst.svalue, dst.uvalue, imm)) {
            assume(cst);
        }
    }
}

void ebpf_domain_t::operator()(const Undefined& a) {}

// Simple truncation function usable with swap_endianness().
template <class T>
BOOST_CONSTEXPR T truncate(T x) BOOST_NOEXCEPT {
    return x;
}

void ebpf_domain_t::operator()(const Un& stmt) {
    if (!m_inv) {
        return;
    }
    const auto dst = reg_pack(stmt.dst);
    auto swap_endianness = [&]<typename T>(const variable_t v, T input, const auto& be_or_le) {
        if (m_inv->entail(type_is_number(stmt.dst))) {
            const auto interval = m_inv->eval_interval(v);
            if (const std::optional<number_t> n = interval.singleton()) {
                if (n->fits_cast_to_int64()) {
                    input = static_cast<T>(n.value().cast_to_sint64());
                    T output = be_or_le(input);
                    m_inv.set(v, interval_t(number_t(output), number_t(output)));
                    return;
                }
            }
        }
        havoc(v);
        havoc_offsets(stmt.dst);
    };
    // Swap bytes if needed.  For 64-bit types we need the weights to fit in a
    // signed int64, but for smaller types we don't want sign extension,
    // so we use unsigned which still fits in a signed int64.
    switch (stmt.op) {
    case Un::Op::BE16:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, static_cast<uint16_t>(0), boost::endian::endian_reverse<uint16_t>);
            swap_endianness(dst.uvalue, static_cast<uint16_t>(0), boost::endian::endian_reverse<uint16_t>);
        } else {
            swap_endianness(dst.svalue, static_cast<uint16_t>(0), truncate<uint16_t>);
            swap_endianness(dst.uvalue, static_cast<uint16_t>(0), truncate<uint16_t>);
        }
        break;
    case Un::Op::BE32:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, static_cast<uint32_t>(0), boost::endian::endian_reverse<uint32_t>);
            swap_endianness(dst.uvalue, static_cast<uint32_t>(0), boost::endian::endian_reverse<uint32_t>);
        } else {
            swap_endianness(dst.svalue, static_cast<uint32_t>(0), truncate<uint32_t>);
            swap_endianness(dst.uvalue, static_cast<uint32_t>(0), truncate<uint32_t>);
        }
        break;
    case Un::Op::BE64:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, static_cast<int64_t>(0), boost::endian::endian_reverse<int64_t>);
            swap_endianness(dst.uvalue, static_cast<uint64_t>(0), boost::endian::endian_reverse<uint64_t>);
        }
        break;
    case Un::Op::LE16:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, static_cast<uint16_t>(0), boost::endian::endian_reverse<uint16_t>);
            swap_endianness(dst.uvalue, static_cast<uint16_t>(0), boost::endian::endian_reverse<uint16_t>);
        } else {
            swap_endianness(dst.svalue, static_cast<uint16_t>(0), truncate<uint16_t>);
            swap_endianness(dst.uvalue, static_cast<uint16_t>(0), truncate<uint16_t>);
        }
        break;
    case Un::Op::LE32:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, static_cast<uint32_t>(0), boost::endian::endian_reverse<uint32_t>);
            swap_endianness(dst.uvalue, static_cast<uint32_t>(0), boost::endian::endian_reverse<uint32_t>);
        } else {
            swap_endianness(dst.svalue, static_cast<uint32_t>(0), truncate<uint32_t>);
            swap_endianness(dst.uvalue, static_cast<uint32_t>(0), truncate<uint32_t>);
        }
        break;
    case Un::Op::LE64:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, static_cast<int64_t>(0), boost::endian::endian_reverse<int64_t>);
            swap_endianness(dst.uvalue, static_cast<uint64_t>(0), boost::endian::endian_reverse<uint64_t>);
        }
        break;
    case Un::Op::SWAP16:
        swap_endianness(dst.svalue, static_cast<uint16_t>(0), boost::endian::endian_reverse<uint16_t>);
        swap_endianness(dst.uvalue, static_cast<uint16_t>(0), boost::endian::endian_reverse<uint16_t>);
        break;
    case Un::Op::SWAP32:
        swap_endianness(dst.svalue, static_cast<uint32_t>(0), boost::endian::endian_reverse<uint32_t>);
        swap_endianness(dst.uvalue, static_cast<uint32_t>(0), boost::endian::endian_reverse<uint32_t>);
        break;
    case Un::Op::SWAP64:
        swap_endianness(dst.svalue, static_cast<int64_t>(0), boost::endian::endian_reverse<int64_t>);
        swap_endianness(dst.uvalue, static_cast<uint64_t>(0), boost::endian::endian_reverse<uint64_t>);
        break;
    case Un::Op::NEG:
        m_inv->neg(dst.svalue, dst.uvalue, stmt.is64 ? 64 : 32);
        havoc_offsets(stmt.dst);
        break;
    }
}

void ebpf_domain_t::operator()(const Exit& a) {
    // Clean up any state for the current stack frame.
    const std::string prefix = a.stack_frame_prefix;
    if (prefix.empty()) {
        return;
    }
    restore_callee_saved_registers(prefix);
}

void ebpf_domain_t::operator()(const Jmp& a) {}

void ebpf_domain_t::operator()(const Comparable& s) {
    using namespace crab::dsl_syntax;
    if (!m_inv) {
        return;
    }
    if (type_inv.same_type(m_inv, s.r1, s.r2)) {
        // Same type. If both are numbers, that's okay. Otherwise:
        auto inv = m_inv.when(reg_pack(s.r2).type != T_NUM);
        // We must check that they belong to a singleton region:
        if (!type_inv.is_in_group(inv, s.r1, TypeGroup::singleton_ptr) &&
            !type_inv.is_in_group(inv, s.r1, TypeGroup::map_fd)) {
            require(inv, linear_constraint_t::false_const(), "Cannot subtract pointers to non-singleton regions");
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
    if (!m_inv) {
        return;
    }
    if (!type_inv.implies_type(m_inv, type_is_pointer(reg_pack(s.ptr)), type_is_number(s.num))) {
        require(m_inv, linear_constraint_t::false_const(), "Only numbers can be added to pointers");
    }
}

void ebpf_domain_t::operator()(const ValidDivisor& s) {
    using namespace crab::dsl_syntax;
    if (!m_inv) {
        return;
    }
    const auto reg = reg_pack(s.reg);
    if (!type_inv.implies_type(m_inv, type_is_pointer(reg), type_is_number(s.reg))) {
        require(m_inv, linear_constraint_t::false_const(), "Only numbers can be used as divisors");
    }
    if (!thread_local_options.allow_division_by_zero) {
        const auto v = s.is_signed ? reg.svalue : reg.uvalue;
        require(m_inv, v != 0, "Possible division by zero");
    }
}

void ebpf_domain_t::operator()(const ValidStore& s) {
    if (!m_inv) {
        return;
    }
    if (!type_inv.implies_type(m_inv, type_is_not_stack(reg_pack(s.mem)), type_is_number(s.val))) {
        require(m_inv, linear_constraint_t::false_const(), "Only numbers can be stored to externally-visible regions");
    }
}

void ebpf_domain_t::operator()(const TypeConstraint& s) {
    if (!m_inv) {
        return;
    }
    if (!type_inv.is_in_group(m_inv, s.reg, s.types)) {
        require(m_inv, linear_constraint_t::false_const(), "Invalid type");
    }
}

void ebpf_domain_t::operator()(const FuncConstraint& s) {
    if (!m_inv) {
        return;
    }
    // Look up the helper function id.
    const reg_pack_t& reg = reg_pack(s.reg);
    auto src_interval = m_inv.eval_interval(reg.svalue);
    if (auto sn = src_interval.singleton()) {
        if (sn->fits_sint32()) {
            // We can now process it as if the id was immediate.
            int32_t imm = sn->cast_to_sint32();
            if (!global_program_info->platform->is_helper_usable(imm)) {
                require(m_inv, linear_constraint_t::false_const(), "invalid helper function id " + std::to_string(imm));
                return;
            }
            Call call = make_call(imm, *global_program_info->platform);
            for (Assert a : get_assertions(call, *global_program_info, {})) {
                (*this)(a);
            }
            return;
        }
    }
    require(m_inv, linear_constraint_t::false_const(), "callx helper function id is not a valid singleton");
}

void ebpf_domain_t::operator()(const ValidSize& s) {
    using namespace crab::dsl_syntax;
    if (!m_inv) {
        return;
    }
    const auto r = reg_pack(s.reg);
    require(m_inv, s.can_be_zero ? r.svalue >= 0 : r.svalue > 0, "Invalid size");
}

// Get the start and end of the range of possible map fd values.
// In the future, it would be cleaner to use a set rather than an interval
// for map fds.
bool ebpf_domain_t::get_map_fd_range(const Reg& map_fd_reg, int32_t* start_fd, int32_t* end_fd) const {
    const interval_t& map_fd_interval = m_inv[reg_pack(map_fd_reg).map_fd];
    const auto lb = map_fd_interval.lb().number();
    const auto ub = map_fd_interval.ub().number();
    if (!lb || !lb->fits_sint32() || !ub || !ub->fits_sint32()) {
        return false;
    }
    *start_fd = static_cast<int32_t>(lb.value());
    *end_fd = static_cast<int32_t>(ub.value());

    // Cap the maximum range we'll check.
    constexpr int max_range = 32;
    return (*map_fd_interval.finite_size() < max_range);
}

// All maps in the range must have the same type for us to use it.
std::optional<uint32_t> ebpf_domain_t::get_map_type(const Reg& map_fd_reg) const {
    int32_t start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return std::optional<uint32_t>();
    }

    std::optional<uint32_t> type;
    for (int32_t map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd);
        if (map == nullptr) {
            return std::optional<uint32_t>();
        }
        if (!type.has_value()) {
            type = map->type;
        } else if (map->type != *type) {
            return std::optional<uint32_t>();
        }
    }
    return type;
}

// All maps in the range must have the same inner map fd for us to use it.
std::optional<uint32_t> ebpf_domain_t::get_map_inner_map_fd(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return {};
    }

    std::optional<uint32_t> inner_map_fd;
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd);
        if (map == nullptr) {
            return {};
        }
        if (!inner_map_fd.has_value()) {
            inner_map_fd = map->inner_map_fd;
        } else if (map->type != *inner_map_fd) {
            return {};
        }
    }
    return inner_map_fd;
}

// We can deal with a range of key sizes.
interval_t ebpf_domain_t::get_map_key_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return interval_t::top();
    }

    interval_t result = interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | interval_t(number_t(map->key_size));
        } else {
            return interval_t::top();
        }
    }
    return result;
}

// We can deal with a range of value sizes.
interval_t ebpf_domain_t::get_map_value_size(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return interval_t::top();
    }

    interval_t result = interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | interval_t(number_t(map->value_size));
        } else {
            return interval_t::top();
        }
    }
    return result;
}

// We can deal with a range of max_entries values.
interval_t ebpf_domain_t::get_map_max_entries(const Reg& map_fd_reg) const {
    int start_fd, end_fd;
    if (!get_map_fd_range(map_fd_reg, &start_fd, &end_fd)) {
        return interval_t::top();
    }

    interval_t result = interval_t::bottom();
    for (int map_fd = start_fd; map_fd <= end_fd; map_fd++) {
        if (const EbpfMapDescriptor* map = &global_program_info->platform->get_map_descriptor(map_fd)) {
            result = result | interval_t(number_t(map->max_entries));
        } else {
            return interval_t::top();
        }
    }
    return result;
}

void ebpf_domain_t::operator()(const ValidCall& s) {
    if (!m_inv) {
        return;
    }
    if (!s.stack_frame_prefix.empty()) {
        const EbpfHelperPrototype proto = global_program_info->platform->get_helper_prototype(s.func);
        if (proto.return_type == EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED) {
            require(m_inv, linear_constraint_t::false_const(), "tail call not supported in subprogram");
            return;
        }
    }
}

void ebpf_domain_t::operator()(const ValidMapKeyValue& s) {
    using namespace crab::dsl_syntax;
    if (!m_inv) {
        return;
    }

    const auto fd_type = get_map_type(s.map_fd_reg);

    const auto access_reg = reg_pack(s.access_reg);
    int width;
    if (s.key) {
        const auto key_size = get_map_key_size(s.map_fd_reg).singleton();
        if (!key_size.has_value()) {
            require(m_inv, linear_constraint_t::false_const(), "Map key size is not singleton");
            return;
        }
        width = static_cast<int>(key_size.value());
    } else {
        const auto value_size = get_map_value_size(s.map_fd_reg).singleton();
        if (!value_size.has_value()) {
            require(m_inv, linear_constraint_t::false_const(), "Map value size is not singleton");
            return;
        }
        width = static_cast<int>(value_size.value());
    }

    m_inv = type_inv.join_over_types(m_inv, s.access_reg, [&](NumAbsDomain& inv, type_encoding_t access_reg_type) {
        if (access_reg_type == T_STACK) {
            variable_t lb = access_reg.stack_offset;
            linear_expression_t ub = lb + width;
            if (!stack.all_num(inv, lb, ub)) {
                auto lb_is = inv[lb].lb().number();
                std::string lb_s = lb_is && lb_is->fits_sint32() ? std::to_string(static_cast<int32_t>(*lb_is)) : "-oo";
                auto ub_is = inv.eval_interval(ub).ub().number();
                std::string ub_s = ub_is && ub_is->fits_sint32() ? std::to_string(static_cast<int32_t>(*ub_is)) : "oo";
                require(inv, linear_constraint_t::false_const(),
                        "Illegal map update with a non-numerical value [" + lb_s + "-" + ub_s + ")");
            } else if (thread_local_options.strict && fd_type.has_value()) {
                EbpfMapType map_type = global_program_info->platform->get_map_type(*fd_type);
                if (map_type.is_array) {
                    // Get offset value.
                    variable_t key_ptr = access_reg.stack_offset;
                    std::optional<number_t> offset = inv[key_ptr].singleton();
                    if (!offset.has_value()) {
                        require(inv, linear_constraint_t::false_const(), "Pointer must be a singleton");
                    } else if (s.key) {
                        // Look up the value pointed to by the key pointer.
                        variable_t key_value =
                            variable_t::cell_var(data_kind_t::svalues, (uint64_t)offset.value(), sizeof(uint32_t));

                        if (auto max_entries = get_map_max_entries(s.map_fd_reg).lb().number()) {
                            require(inv, key_value < *max_entries, "Array index overflow");
                        } else {
                            require(inv, linear_constraint_t::false_const(), "Max entries is not finite");
                        }
                        require(inv, key_value >= 0, "Array index underflow");
                    }
                }
            }
        } else if (access_reg_type == T_PACKET) {
            variable_t lb = access_reg.packet_offset;
            linear_expression_t ub = lb + width;
            check_access_packet(inv, lb, ub, {});
            // Packet memory is both readable and writable.
        } else if (access_reg_type == T_SHARED) {
            variable_t lb = access_reg.shared_offset;
            linear_expression_t ub = lb + width;
            check_access_shared(inv, lb, ub, access_reg.shared_region_size);
            require(inv, access_reg.svalue > 0, "Possible null access");
            // Shared memory is zero-initialized when created so is safe to read and write.
        } else {
            require(inv, linear_constraint_t::false_const(), "Only stack or packet can be used as a parameter");
        }
    });
}

void ebpf_domain_t::operator()(const ValidAccess& s) {
    using namespace crab::dsl_syntax;
    if (!m_inv) {
        return;
    }

    const bool is_comparison_check = s.width == static_cast<Value>(Imm{0});

    const auto reg = reg_pack(s.reg);
    // join_over_types instead of simple iteration is only needed for assume-assert
    m_inv = type_inv.join_over_types(m_inv, s.reg, [&](NumAbsDomain& inv, type_encoding_t type) {
        switch (type) {
        case T_PACKET: {
            linear_expression_t lb = reg.packet_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width)
                                         ? lb + std::get<Imm>(s.width).v
                                         : lb + reg_pack(std::get<Reg>(s.width)).svalue;
            check_access_packet(inv, lb, ub,
                                is_comparison_check ? std::optional<variable_t>{} : variable_t::packet_size());
            // if within bounds, it can never be null
            // Context memory is both readable and writable.
            break;
        }
        case T_STACK: {
            linear_expression_t lb = reg.stack_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width)
                                         ? lb + std::get<Imm>(s.width).v
                                         : lb + reg_pack(std::get<Reg>(s.width)).svalue;
            check_access_stack(inv, lb, ub);
            // if within bounds, it can never be null
            if (s.access_type == AccessType::read) {
                // Require that the stack range contains numbers.
                if (!stack.all_num(inv, lb, ub)) {
                    if (s.offset < 0) {
                        require(inv, linear_constraint_t::false_const(), "Stack content is not numeric");
                    } else if (std::holds_alternative<Imm>(s.width)) {
                        if (!inv.entail(static_cast<int>(std::get<Imm>(s.width).v) <=
                                        reg.stack_numeric_size - s.offset)) {
                            require(inv, linear_constraint_t::false_const(), "Stack content is not numeric");
                        }
                    } else {
                        if (!inv.entail(reg_pack(std::get<Reg>(s.width)).svalue <= reg.stack_numeric_size - s.offset)) {
                            require(inv, linear_constraint_t::false_const(), "Stack content is not numeric");
                        }
                    }
                }
            }
            break;
        }
        case T_CTX: {
            linear_expression_t lb = reg.ctx_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width)
                                         ? lb + std::get<Imm>(s.width).v
                                         : lb + reg_pack(std::get<Reg>(s.width)).svalue;
            check_access_context(inv, lb, ub);
            // if within bounds, it can never be null
            // The context is both readable and writable.
            break;
        }
        case T_NUM:
            if (!is_comparison_check) {
                if (s.or_null) {
                    require(inv, reg.svalue == 0, "Non-null number");
                } else {
                    require(inv, linear_constraint_t::false_const(), "Only pointers can be dereferenced");
                }
            }
            break;
        case T_MAP:
        case T_MAP_PROGRAMS:
            if (!is_comparison_check) {
                require(inv, linear_constraint_t::false_const(), "FDs cannot be dereferenced directly");
            }
            break;
        case T_SHARED: {
            linear_expression_t lb = reg.shared_offset + s.offset;
            linear_expression_t ub = std::holds_alternative<Imm>(s.width)
                                         ? lb + std::get<Imm>(s.width).v
                                         : lb + reg_pack(std::get<Reg>(s.width)).svalue;
            check_access_shared(inv, lb, ub, reg.shared_region_size);
            if (!is_comparison_check && !s.or_null) {
                require(inv, reg.svalue > 0, "Possible null access");
            }
            // Shared memory is zero-initialized when created so is safe to read and write.
            break;
        }
        default: require(inv, linear_constraint_t::false_const(), "Invalid type"); break;
        }
    });
}

void ebpf_domain_t::operator()(const ZeroCtxOffset& s) {
    if (!m_inv) {
        return;
    }
    using namespace crab::dsl_syntax;
    const auto reg = reg_pack(s.reg);
    require(m_inv, reg.ctx_offset == 0, "Nonzero context offset");
}

void ebpf_domain_t::operator()(const Assert& stmt) {
    if (!m_inv) {
        return;
    }
    if (check_require || thread_local_options.assume_assertions) {
        this->current_assertion = to_string(stmt.cst);
        std::visit(*this, stmt.cst);
        this->current_assertion.clear();
    }
}

void ebpf_domain_t::operator()(const Packet& a) {
    if (!m_inv) {
        return;
    }
    const auto reg = reg_pack(R0_RETURN_VALUE);
    constexpr Reg r0_reg{R0_RETURN_VALUE};
    type_inv.assign_type(m_inv, r0_reg, T_NUM);
    havoc_offsets(r0_reg);
    havoc(reg.svalue);
    havoc(reg.uvalue);
    scratch_caller_saved_registers();
}

void ebpf_domain_t::do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr,
                                  const int width, const Reg& src_reg) {
    type_inv.assign_type(inv, target_reg, stack.load(inv, data_kind_t::types, addr, width));
    using namespace crab::dsl_syntax;
    if (inv.entail(width <= reg_pack(src_reg).stack_numeric_size)) {
        type_inv.assign_type(inv, target_reg, T_NUM);
    }

    const reg_pack_t& target = reg_pack(target_reg);
    if (width == 1 || width == 2 || width == 4 || width == 8) {
        // Use the addr before we havoc the destination register since we might be getting the
        // addr from that same register.
        const std::optional<linear_expression_t> sresult = stack.load(inv, data_kind_t::svalues, addr, width);
        const std::optional<linear_expression_t> uresult = stack.load(inv, data_kind_t::uvalues, addr, width);
        havoc_register(inv, target_reg);
        inv.assign(target.svalue, sresult);
        inv.assign(target.uvalue, uresult);

        if (type_inv.has_type(inv, target.type, T_CTX)) {
            inv.assign(target.ctx_offset, stack.load(inv, data_kind_t::ctx_offsets, addr, width));
        }
        if (type_inv.has_type(inv, target.type, T_MAP) || type_inv.has_type(inv, target.type, T_MAP_PROGRAMS)) {
            inv.assign(target.map_fd, stack.load(inv, data_kind_t::map_fds, addr, width));
        }
        if (type_inv.has_type(inv, target.type, T_PACKET)) {
            inv.assign(target.packet_offset, stack.load(inv, data_kind_t::packet_offsets, addr, width));
        }
        if (type_inv.has_type(inv, target.type, T_SHARED)) {
            inv.assign(target.shared_offset, stack.load(inv, data_kind_t::shared_offsets, addr, width));
            inv.assign(target.shared_region_size, stack.load(inv, data_kind_t::shared_region_sizes, addr, width));
        }
        if (type_inv.has_type(inv, target.type, T_STACK)) {
            inv.assign(target.stack_offset, stack.load(inv, data_kind_t::stack_offsets, addr, width));
            inv.assign(target.stack_numeric_size, stack.load(inv, data_kind_t::stack_numeric_sizes, addr, width));
        }
    } else {
        havoc_register(inv, target_reg);
    }
}

void ebpf_domain_t::do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague,
                                const int width) {
    using namespace crab::dsl_syntax;
    if (inv.is_bottom()) {
        return;
    }

    const ebpf_context_descriptor_t* desc = global_program_info->type.context_descriptor;

    const reg_pack_t& target = reg_pack(target_reg);

    if (desc->end < 0) {
        havoc_register(inv, target_reg);
        type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }

    const interval_t interval = inv.eval_interval(addr_vague);
    const std::optional<number_t> maybe_addr = interval.singleton();
    havoc_register(inv, target_reg);

    const bool may_touch_ptr = interval[desc->data] || interval[desc->meta] || interval[desc->end];

    if (!maybe_addr) {
        if (may_touch_ptr) {
            type_inv.havoc_type(inv, target_reg);
        } else {
            type_inv.assign_type(inv, target_reg, T_NUM);
        }
        return;
    }

    const number_t addr = *maybe_addr;

    // We use offsets for packet data, data_end, and meta during verification,
    // but at runtime they will be 64-bit pointers.  We can use the offset values
    // for verification like we use map_fd's as a proxy for maps which
    // at runtime are actually 64-bit memory pointers.
    const int offset_width = desc->end - desc->data;
    if (addr == desc->data) {
        if (width == offset_width) {
            inv.assign(target.packet_offset, 0);
        }
    } else if (addr == desc->end) {
        if (width == offset_width) {
            inv.assign(target.packet_offset, variable_t::packet_size());
        }
    } else if (addr == desc->meta) {
        if (width == offset_width) {
            inv.assign(target.packet_offset, variable_t::meta_offset());
        }
    } else {
        if (may_touch_ptr) {
            type_inv.havoc_type(inv, target_reg);
        } else {
            type_inv.assign_type(inv, target_reg, T_NUM);
        }
        return;
    }
    if (width == offset_width) {
        type_inv.assign_type(inv, target_reg, T_PACKET);
        inv += 4098 <= target.svalue;
        inv += target.svalue <= PTR_MAX;
    }
}

void ebpf_domain_t::do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr,
                                             const int width) {
    if (inv.is_bottom()) {
        return;
    }
    const reg_pack_t& target = reg_pack(target_reg);

    type_inv.assign_type(inv, target_reg, T_NUM);
    havoc_register(inv, target_reg);

    // A 1 or 2 byte copy results in a limited range of values that may be used as array indices.
    if (width == 1) {
        inv.set(target.svalue, interval_t(number_t{0}, number_t{UINT8_MAX}));
        inv.set(target.uvalue, interval_t(number_t{0}, number_t{UINT8_MAX}));
    } else if (width == 2) {
        inv.set(target.svalue, interval_t(number_t{0}, number_t{UINT16_MAX}));
        inv.set(target.uvalue, interval_t(number_t{0}, number_t{UINT16_MAX}));
    }
}

void ebpf_domain_t::do_load(const Mem& b, const Reg& target_reg) {
    using namespace crab::dsl_syntax;

    const auto mem_reg = reg_pack(b.access.basereg);
    const int width = b.access.width;
    const int offset = b.access.offset;

    if (b.access.basereg.v == R10_STACK_POINTER) {
        const linear_expression_t addr = mem_reg.stack_offset + (number_t)offset;
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

template <typename X, typename Y, typename Z>
void ebpf_domain_t::do_store_stack(NumAbsDomain& inv, const number_t& width, const linear_expression_t& addr,
                                   X val_type, Y val_svalue, Z val_uvalue,
                                   const std::optional<reg_pack_t>& opt_val_reg) {
    std::optional<variable_t> var = stack.store_type(inv, addr, width, val_type);
    type_inv.assign_type(inv, var, val_type);
    if (width == 8) {
        inv.assign(stack.store(inv, data_kind_t::svalues, addr, width, val_svalue), val_svalue);
        inv.assign(stack.store(inv, data_kind_t::uvalues, addr, width, val_uvalue), val_uvalue);

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_CTX)) {
            inv.assign(stack.store(inv, data_kind_t::ctx_offsets, addr, width, opt_val_reg->ctx_offset),
                       opt_val_reg->ctx_offset);
        } else {
            stack.havoc(inv, data_kind_t::ctx_offsets, addr, width);
        }

        if (opt_val_reg &&
            (type_inv.has_type(m_inv, val_type, T_MAP) || type_inv.has_type(m_inv, val_type, T_MAP_PROGRAMS))) {
            inv.assign(stack.store(inv, data_kind_t::map_fds, addr, width, opt_val_reg->map_fd), opt_val_reg->map_fd);
        } else {
            stack.havoc(inv, data_kind_t::map_fds, addr, width);
        }

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_PACKET)) {
            inv.assign(stack.store(inv, data_kind_t::packet_offsets, addr, width, opt_val_reg->packet_offset),
                       opt_val_reg->packet_offset);
        } else {
            stack.havoc(inv, data_kind_t::packet_offsets, addr, width);
        }

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_SHARED)) {
            inv.assign(stack.store(inv, data_kind_t::shared_offsets, addr, width, opt_val_reg->shared_offset),
                       opt_val_reg->shared_offset);
            inv.assign(stack.store(inv, data_kind_t::shared_region_sizes, addr, width, opt_val_reg->shared_region_size),
                       opt_val_reg->shared_region_size);
        } else {
            stack.havoc(inv, data_kind_t::shared_region_sizes, addr, width);
            stack.havoc(inv, data_kind_t::shared_offsets, addr, width);
        }

        if (opt_val_reg && type_inv.has_type(m_inv, val_type, T_STACK)) {
            inv.assign(stack.store(inv, data_kind_t::stack_offsets, addr, width, opt_val_reg->stack_offset),
                       opt_val_reg->stack_offset);
            inv.assign(stack.store(inv, data_kind_t::stack_numeric_sizes, addr, width, opt_val_reg->stack_numeric_size),
                       opt_val_reg->stack_numeric_size);
        } else {
            stack.havoc(inv, data_kind_t::stack_offsets, addr, width);
            stack.havoc(inv, data_kind_t::stack_numeric_sizes, addr, width);
        }
    } else {
        if ((width == 1 || width == 2 || width == 4) && type_inv.get_type(m_inv, val_type) == T_NUM) {
            // Keep track of numbers on the stack that might be used as array indices.
            inv.assign(stack.store(inv, data_kind_t::svalues, addr, width, val_svalue), val_svalue);
            inv.assign(stack.store(inv, data_kind_t::uvalues, addr, width, val_uvalue), val_uvalue);
        } else {
            stack.havoc(inv, data_kind_t::svalues, addr, width);
            stack.havoc(inv, data_kind_t::uvalues, addr, width);
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
    // stack_numeric_size holds the number of continuous bytes starting from stack_offset that are known to be numeric.
    auto updated_lb = m_inv.eval_interval(addr).lb();
    auto updated_ub = m_inv.eval_interval(addr).ub() + width;
    for (const variable_t type_variable : variable_t::get_type_variables()) {
        if (!type_inv.has_type(inv, type_variable, T_STACK)) {
            continue;
        }
        const variable_t stack_offset_variable = variable_t::kind_var(data_kind_t::stack_offsets, type_variable);
        const variable_t stack_numeric_size_variable =
            variable_t::kind_var(data_kind_t::stack_numeric_sizes, type_variable);

        using namespace crab::dsl_syntax;
        // See if the variable's numeric interval overlaps with changed bytes.
        if (m_inv.intersect(crab::dsl_syntax::operator<=(addr, stack_offset_variable + stack_numeric_size_variable)) &&
            m_inv.intersect(crab::dsl_syntax::operator>=(addr + width, stack_offset_variable))) {
            havoc(stack_numeric_size_variable);
            recompute_stack_numeric_size(m_inv, type_variable);
        }
    }
}

void ebpf_domain_t::operator()(const Mem& b) {
    if (!m_inv) {
        return;
    }
    if (std::holds_alternative<Reg>(b.value)) {
        if (b.is_load) {
            do_load(b, std::get<Reg>(b.value));
        } else {
            const auto data = std::get<Reg>(b.value);
            auto data_reg = reg_pack(data);
            do_mem_store(b, data, data_reg.svalue, data_reg.uvalue, data_reg);
        }
    } else {
        do_mem_store(b, number_t{T_NUM}, number_t{static_cast<int64_t>(std::get<Imm>(b.value).v)},
                     number_t{static_cast<uint64_t>(std::get<Imm>(b.value).v)}, {});
    }
}

template <typename Type, typename SValue, typename UValue>
void ebpf_domain_t::do_mem_store(const Mem& b, Type val_type, SValue val_svalue, UValue val_uvalue,
                                 const std::optional<reg_pack_t>& val_reg) {
    if (m_inv.is_bottom()) {
        return;
    }
    int width = b.access.width;
    const number_t offset{b.access.offset};
    if (b.access.basereg.v == R10_STACK_POINTER) {
        const number_t base_addr{EBPF_STACK_SIZE};
        do_store_stack(m_inv, width, base_addr + offset, val_type, val_svalue, val_uvalue, val_reg);
        return;
    }
    m_inv = type_inv.join_over_types(m_inv, b.access.basereg, [&](NumAbsDomain& inv, const type_encoding_t type) {
        if (type == T_STACK) {
            const linear_expression_t base_addr =
                linear_expression_t(get_type_offset_variable(b.access.basereg, type).value());
            do_store_stack(inv, width, crab::dsl_syntax::operator+(base_addr, offset), val_type, val_svalue, val_uvalue,
                           val_reg);
        }
        // do nothing for any other type
    });
}

// Construct a Bin operation that does the main operation that a given Atomic operation does atomically.
static Bin atomic_to_bin(const Atomic& a) {
    Bin bin{.dst = Reg{R11_ATOMIC_SCRATCH}, .v = a.valreg, .is64 = (a.access.width == sizeof(uint64_t)), .lddw = false};
    switch (a.op) {
    case Atomic::Op::ADD: bin.op = Bin::Op::ADD; break;
    case Atomic::Op::OR: bin.op = Bin::Op::OR; break;
    case Atomic::Op::AND: bin.op = Bin::Op::AND; break;
    case Atomic::Op::XOR: bin.op = Bin::Op::XOR; break;
    case Atomic::Op::XCHG:
    case Atomic::Op::CMPXCHG: bin.op = Bin::Op::MOV; break;
    default: throw std::exception();
    }
    return bin;
}

void ebpf_domain_t::operator()(const Atomic& a) {
    if (m_inv.is_bottom()) {
        return;
    }
    if (!m_inv.entail(type_is_pointer(reg_pack(a.access.basereg))) ||
        !m_inv.entail(type_is_number(reg_pack(a.valreg)))) {
        return;
    }
    if (m_inv.entail(type_is_not_stack(reg_pack(a.access.basereg)))) {
        // Shared memory regions are volatile so we can just havoc
        // any register that will be updated.
        if (a.op == Atomic::Op::CMPXCHG) {
            havoc_register(m_inv, Reg{R0_RETURN_VALUE});
        } else if (a.fetch) {
            havoc_register(m_inv, a.valreg);
        }
        return;
    }

    // Fetch the current value into the R11 pseudo-register.
    constexpr Reg r11{R11_ATOMIC_SCRATCH};
    (*this)(Mem{.access = a.access, .value = r11, .is_load = true});

    // Compute the new value in R11.
    (*this)(atomic_to_bin(a));

    if (a.op == Atomic::Op::CMPXCHG) {
        // For CMPXCHG, store the original value in r0.
        (*this)(Mem{.access = a.access, .value = Reg{R0_RETURN_VALUE}, .is_load = true});

        // For the destination, there are 3 possibilities:
        // 1) dst.value == r0.value : set R11 to valreg
        // 2) dst.value != r0.value : don't modify R11
        // 3) dst.value may or may not == r0.value : set R11 to the union of R11 and valreg
        // For now we just havoc the value of R11.
        havoc_register(m_inv, r11);
    } else if (a.fetch) {
        // For other FETCH operations, store the original value in the src register.
        (*this)(Mem{.access = a.access, .value = a.valreg, .is_load = true});
    }

    // Store the new value back in the original shared memory location.
    // Note that do_mem_store() currently doesn't track shared memory values,
    // but stack memory values are tracked and are legal here.
    (*this)(Mem{.access = a.access, .value = r11, .is_load = false});

    // Clear the R11 pseudo-register.
    havoc_register(m_inv, r11);
    type_inv.havoc_type(m_inv, r11);
}

void ebpf_domain_t::operator()(const Call& call) {
    using namespace crab::dsl_syntax;
    if (m_inv.is_bottom()) {
        return;
    }
    std::optional<Reg> maybe_fd_reg{};
    for (ArgSingle param : call.singles) {
        switch (param.kind) {
        case ArgSingle::Kind::MAP_FD: maybe_fd_reg = param.reg; break;
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
            auto variable = get_type_offset_variable(param.mem);
            if (!variable.has_value()) {
                require(m_inv, linear_constraint_t::false_const(), "Argument must be a pointer to writable memory");
                return;
            }
            variable_t addr = variable.value();
            variable_t width = reg_pack(param.size).svalue;

            m_inv = type_inv.join_over_types(m_inv, param.mem, [&](NumAbsDomain& inv, const type_encoding_t type) {
                if (type == T_STACK) {
                    // Pointer to a memory region that the called function may change,
                    // so we must havoc.
                    stack.havoc(inv, data_kind_t::types, addr, width);
                    stack.havoc(inv, data_kind_t::svalues, addr, width);
                    stack.havoc(inv, data_kind_t::uvalues, addr, width);
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

    constexpr Reg r0_reg{(uint8_t)R0_RETURN_VALUE};
    const auto r0_pack = reg_pack(r0_reg);
    havoc(r0_pack.stack_numeric_size);
    if (call.is_map_lookup) {
        // This is the only way to get a null pointer
        if (maybe_fd_reg) {
            if (const auto map_type = get_map_type(*maybe_fd_reg)) {
                if (global_program_info->platform->get_map_type(*map_type).value_type == EbpfMapValueType::MAP) {
                    if (const auto inner_map_fd = get_map_inner_map_fd(*maybe_fd_reg)) {
                        do_load_mapfd(r0_reg, static_cast<int>(*inner_map_fd), true);
                        goto out;
                    }
                } else {
                    assign_valid_ptr(r0_reg, true);
                    m_inv.assign(r0_pack.shared_offset, 0);
                    m_inv.set(r0_pack.shared_region_size, get_map_value_size(*maybe_fd_reg));
                    type_inv.assign_type(m_inv, r0_reg, T_SHARED);
                }
            }
        }
        assign_valid_ptr(r0_reg, true);
        m_inv->assign(r0_pack.shared_offset, 0);
        type_inv.assign_type(m_inv, r0_reg, T_SHARED);
    } else {
        havoc(r0_pack.svalue);
        havoc(r0_pack.uvalue);
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

void ebpf_domain_t::operator()(const CallLocal& call) {
    using namespace crab::dsl_syntax;
    if (m_inv.is_bottom()) {
        return;
    }
    save_callee_saved_registers(call.stack_frame_prefix);
}

void ebpf_domain_t::operator()(const Callx& callx) {
    using namespace crab::dsl_syntax;
    if (m_inv.is_bottom()) {
        return;
    }

    // Look up the helper function id.
    const reg_pack_t& reg = reg_pack(callx.func);
    const auto src_interval = m_inv.eval_interval(reg.svalue);
    if (const auto sn = src_interval.singleton()) {
        if (sn->fits_sint32()) {
            // We can now process it as if the id was immediate.
            const int32_t imm = sn->cast_to_sint32();
            if (!global_program_info->platform->is_helper_usable(imm)) {
                return;
            }
            const Call call = make_call(imm, *global_program_info->platform);
            (*this)(call);
            return;
        }
    }
}

void ebpf_domain_t::do_load_mapfd(const Reg& dst_reg, const int mapfd, const bool maybe_null) {
    const EbpfMapDescriptor& desc = global_program_info->platform->get_map_descriptor(mapfd);
    const EbpfMapType& type = global_program_info->platform->get_map_type(desc.type);
    if (type.value_type == EbpfMapValueType::PROGRAM) {
        type_inv.assign_type(m_inv, dst_reg, T_MAP_PROGRAMS);
    } else {
        type_inv.assign_type(m_inv, dst_reg, T_MAP);
    }
    const reg_pack_t& dst = reg_pack(dst_reg);
    m_inv->assign(dst.map_fd, mapfd);
    assign_valid_ptr(dst_reg, maybe_null);
}

void ebpf_domain_t::operator()(const LoadMapFd& ins) {
    if (!m_inv) {
        return;
    }
    do_load_mapfd(ins.dst, ins.mapfd, false);
}

void ebpf_domain_t::assign_valid_ptr(const Reg& dst_reg, const bool maybe_null) {
    using namespace crab::dsl_syntax;
    const reg_pack_t& reg = reg_pack(dst_reg);
    havoc(reg.svalue);
    havoc(reg.uvalue);
    if (maybe_null) {
        m_inv += 0 <= reg.svalue;
    } else {
        m_inv += 0 < reg.svalue;
    }
    m_inv += reg.svalue <= PTR_MAX;
    m_inv->assign(reg.uvalue, reg.svalue);
}

// If nothing is known of the stack_numeric_size,
// try to recompute the stack_numeric_size.
void ebpf_domain_t::recompute_stack_numeric_size(NumAbsDomain& inv, const variable_t type_variable) const {
    const variable_t stack_numeric_size_variable =
        variable_t::kind_var(data_kind_t::stack_numeric_sizes, type_variable);

    if (!inv.eval_interval(stack_numeric_size_variable).is_top()) {
        return;
    }

    if (type_inv.has_type(inv, type_variable, T_STACK)) {
        const int numeric_size =
            stack.min_all_num_size(inv, variable_t::kind_var(data_kind_t::stack_offsets, type_variable));
        if (numeric_size > 0) {
            inv.assign(stack_numeric_size_variable, numeric_size);
        }
    }
}

void ebpf_domain_t::recompute_stack_numeric_size(NumAbsDomain& inv, const Reg& reg) const {
    recompute_stack_numeric_size(inv, reg_pack(reg).type);
}

void ebpf_domain_t::add(const Reg& reg, const int imm, const int finite_width) {
    const auto dst = reg_pack(reg);
    const auto offset = get_type_offset_variable(reg);
    m_inv->add_overflow(dst.svalue, dst.uvalue, imm, finite_width);
    if (offset.has_value()) {
        m_inv->add(offset.value(), imm);
        if (imm > 0) {
            // Since the start offset is increasing but
            // the end offset is not, the numeric size decreases.
            m_inv->sub(dst.stack_numeric_size, imm);
        } else if (imm < 0) {
            havoc(dst.stack_numeric_size);
        }
        recompute_stack_numeric_size(m_inv, reg);
    }
}

void ebpf_domain_t::shl(const Reg& dst_reg, int imm, const int finite_width) {
    const reg_pack_t dst = reg_pack(dst_reg);

    if (m_inv.entail(type_is_number(dst))) {
        m_inv->shl(dst.svalue, dst.uvalue, imm, finite_width);
    } else {
        // The BPF ISA requires masking the imm.
        imm &= finite_width - 1;
        m_inv->shl_overflow(dst.svalue, dst.uvalue, imm);
    }
    havoc_offsets(dst_reg);
}

void ebpf_domain_t::lshr(const Reg& dst_reg, const int imm, const int finite_width) {
    const reg_pack_t dst = reg_pack(dst_reg);
    if (m_inv.entail(type_is_number(dst))) {
        m_inv->lshr(dst.svalue, dst.uvalue, imm, finite_width);
    } else {
        havoc(dst.svalue);
        havoc(dst.uvalue);
        havoc_offsets(dst_reg);
    }
}

static int _movsx_bits(const Bin::Op op) {
    switch (op) {
    case Bin::Op::MOVSX8: return 8;
    case Bin::Op::MOVSX16: return 16;
    case Bin::Op::MOVSX32: return 32;
    default: throw std::exception();
    }
}

void ebpf_domain_t::ashr(const Reg& dst_reg, const linear_expression_t& right_svalue, const int finite_width) {
    using namespace crab;

    const reg_pack_t dst = reg_pack(dst_reg);
    if (m_inv->entail(type_is_number(dst))) {
        if (m_inv->ashr(dst.svalue, dst.uvalue, right_svalue, finite_width)) {
            return;
        }
    }
    havoc_offsets(dst_reg);
}

void ebpf_domain_t::operator()(const Bin& bin) {
    using namespace crab::dsl_syntax;
    if (!m_inv) {
        return;
    }

    auto dst = reg_pack(bin.dst);
    int finite_width = bin.is64 ? 64 : 32;
    if (std::holds_alternative<Imm>(bin.v)) {
        // dst += K
        int64_t imm;
        if (bin.is64) {
            // Use the full signed value.
            imm = static_cast<int64_t>(std::get<Imm>(bin.v).v);
        } else {
            // Use only the low 32 bits of the value.
            imm = static_cast<int>(std::get<Imm>(bin.v).v);
            m_inv->bitwise_and(dst.svalue, dst.uvalue, UINT32_MAX);
        }
        switch (bin.op) {
        case Bin::Op::MOV:
            m_inv->assign(dst.svalue, imm);
            m_inv->assign(dst.uvalue, imm);
            m_inv->overflow_unsigned(dst.uvalue, (bin.is64) ? 64 : 32);
            type_inv.assign_type(m_inv, bin.dst, T_NUM);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::ADD:
            if (imm == 0) {
                return;
            }
            add(bin.dst, static_cast<int>(imm), finite_width);
            break;
        case Bin::Op::SUB:
            if (imm == 0) {
                return;
            }
            add(bin.dst, static_cast<int>(-imm), finite_width);
            break;
        case Bin::Op::MUL:
            m_inv->mul(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            m_inv->udiv(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            m_inv->urem(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            m_inv->sdiv(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            m_inv->srem(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            m_inv->bitwise_or(dst.svalue, dst.uvalue, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            m_inv->bitwise_and(dst.svalue, dst.uvalue, imm);
            if (static_cast<int32_t>(imm) > 0) {
                // AND with immediate is only a 32-bit operation so svalue and uvalue are the same.
                assume(dst.svalue <= imm);
                assume(dst.uvalue <= imm);
                assume(0 <= dst.svalue);
                assume(0 <= dst.uvalue);
            }
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH: shl(bin.dst, static_cast<int32_t>(imm), finite_width); break;
        case Bin::Op::RSH: lshr(bin.dst, static_cast<int32_t>(imm), finite_width); break;
        case Bin::Op::ARSH: ashr(bin.dst, number_t{static_cast<int32_t>(imm)}, finite_width); break;
        case Bin::Op::XOR:
            m_inv->bitwise_xor(dst.svalue, dst.uvalue, imm);
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
                m_inv->add_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
            } else {
                // Here we're not sure that lhs and rhs are the same type; they might be.
                // But previous assertions should fail unless we know that exactly one of lhs or rhs is a pointer.
                m_inv =
                    type_inv.join_over_types(m_inv, bin.dst, [&](NumAbsDomain& inv, const type_encoding_t dst_type) {
                        inv = type_inv.join_over_types(
                            inv, src_reg, [&](NumAbsDomain& inv, const type_encoding_t src_type) {
                                if (dst_type == T_NUM && src_type != T_NUM) {
                                    // num += ptr
                                    type_inv.assign_type(inv, bin.dst, src_type);
                                    if (const auto dst_offset = get_type_offset_variable(bin.dst, src_type)) {
                                        inv->apply(arith_binop_t::ADD, dst_offset.value(), dst.svalue,
                                                   get_type_offset_variable(src_reg, src_type).value());
                                    }
                                    if (src_type == T_SHARED) {
                                        inv.assign(dst.shared_region_size, src.shared_region_size);
                                    }
                                } else if (dst_type != T_NUM && src_type == T_NUM) {
                                    // ptr += num
                                    type_inv.assign_type(inv, bin.dst, dst_type);
                                    if (const auto dst_offset = get_type_offset_variable(bin.dst, dst_type)) {
                                        inv->add(dst_offset.value(), src.svalue);
                                        if (dst_type == T_STACK) {
                                            // Reduce the numeric size.
                                            using namespace crab::dsl_syntax;
                                            if (m_inv.intersect(src.svalue < 0)) {
                                                inv -= dst.stack_numeric_size;
                                                recompute_stack_numeric_size(inv, dst.type);
                                            } else {
                                                inv->sub(dst.stack_numeric_size, src.svalue);
                                            }
                                        }
                                    }
                                } else if (dst_type == T_NUM && src_type == T_NUM) {
                                    // dst and src don't necessarily have the same type, but among the possibilities
                                    // enumerated is the case where they are both numbers.
                                    inv->add_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
                                } else {
                                    // We ignore the cases here that do not match the assumption described
                                    // above.  Joining bottom with another results will leave the other
                                    // results unchanged.
                                    inv.set_to_bottom();
                                }
                            });
                    });
                // careful: change dst.value only after dealing with offset
                m_inv->add_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
            }
            break;
        }
        case Bin::Op::SUB: {
            if (bin.dst == src_reg) {
                type_inv.assign_type(m_inv, bin.dst, T_NUM);
                m_inv->assign(dst.svalue, 0);
                m_inv->assign(dst.uvalue, 0);
                crab::havoc_offsets(m_inv, bin.dst);
                break;
            }
            if (type_inv.same_type(m_inv, bin.dst, src_reg)) {
                // src and dest have the same type.
                m_inv = type_inv.join_over_types(m_inv, bin.dst, [&](NumAbsDomain& inv, const type_encoding_t type) {
                    switch (type) {
                    case T_NUM:
                        inv->sub_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
                        type_inv.assign_type(inv, bin.dst, T_NUM);
                        crab::havoc_offsets(inv, bin.dst);
                        break;
                    default:
                        // ptr -= ptr
                        // Assertions should make sure we only perform this on non-shared pointers.
                        if (const auto dst_offset = get_type_offset_variable(bin.dst, type)) {
                            inv->apply_signed(arith_binop_t::SUB, dst.svalue, dst.uvalue, dst_offset.value(),
                                              get_type_offset_variable(src_reg, type).value(), finite_width);
                            inv -= dst_offset.value();
                        }
                        crab::havoc_offsets(inv, bin.dst);
                        type_inv.assign_type(inv, bin.dst, T_NUM);
                        break;
                    }
                });
            } else {
                // We're not sure that lhs and rhs are the same type.
                // Either they're different, or at least one is not a singleton.
                if (type_inv.get_type(m_inv, src_reg) != T_NUM) {
                    type_inv.havoc_type(m_inv, bin.dst);
                    havoc(dst.svalue);
                    havoc(dst.uvalue);
                    havoc_offsets(bin.dst);
                } else {
                    m_inv->sub_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
                    if (auto dst_offset = get_type_offset_variable(bin.dst)) {
                        m_inv->sub(dst_offset.value(), src.svalue);
                        if (type_inv.has_type(m_inv, dst.type, T_STACK)) {
                            // Reduce the numeric size.
                            using namespace crab::dsl_syntax;
                            if (m_inv.intersect(src.svalue > 0)) {
                                m_inv -= dst.stack_numeric_size;
                                recompute_stack_numeric_size(m_inv, dst.type);
                            } else {
                                m_inv->add(dst.stack_numeric_size, src.svalue);
                            }
                        }
                    }
                }
            }
            break;
        }
        case Bin::Op::MUL:
            m_inv->mul(dst.svalue, dst.uvalue, src.svalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            m_inv->udiv(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            m_inv->urem(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            m_inv->sdiv(dst.svalue, dst.uvalue, src.svalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            m_inv->srem(dst.svalue, dst.uvalue, src.svalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            m_inv->bitwise_or(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            m_inv->bitwise_and(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH:
            if (m_inv->entail(type_is_number(src_reg))) {
                auto src_interval = m_inv->eval_interval(src.uvalue);
                if (std::optional<number_t> sn = src_interval.singleton()) {
                    uint64_t imm = sn->cast_to_uint64() & (bin.is64 ? 63 : 31);
                    if (imm <= INT32_MAX) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            m_inv->bitwise_and(dst.svalue, dst.uvalue, UINT32_MAX);
                        }
                        shl(bin.dst, static_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            m_inv->shl_overflow(dst.svalue, dst.uvalue, src.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::RSH:
            if (m_inv->entail(type_is_number(src_reg))) {
                auto src_interval = m_inv->eval_interval(src.uvalue);
                if (std::optional<number_t> sn = src_interval.singleton()) {
                    uint64_t imm = sn->cast_to_uint64() & (bin.is64 ? 63 : 31);
                    if (imm <= INT32_MAX) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            m_inv->bitwise_and(dst.svalue, dst.uvalue, UINT32_MAX);
                        }
                        lshr(bin.dst, static_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            havoc(dst.svalue);
            havoc(dst.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::ARSH:
            if (m_inv->entail(type_is_number(src_reg))) {
                ashr(bin.dst, src.svalue, finite_width);
                break;
            }
            havoc(dst.svalue);
            havoc(dst.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::XOR:
            m_inv->bitwise_xor(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32:
            // Keep relational information if operation is a no-op.
            if ((dst.svalue == src.svalue) &&
                (m_inv->eval_interval(dst.svalue) <= interval_t::signed_int(_movsx_bits(bin.op)))) {
                return;
            }
            if (m_inv->entail(type_is_number(src_reg))) {
                type_inv.assign_type(m_inv, bin.dst, T_NUM);
                havoc_offsets(bin.dst);
                m_inv->sign_extend(dst.svalue, dst.uvalue, src.svalue, finite_width, _movsx_bits(bin.op));
                break;
            }
            havoc(dst.svalue);
            havoc(dst.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOV:
            // Keep relational information if operation is a no-op.
            if ((dst.svalue == src.svalue) &&
                (m_inv->eval_interval(dst.uvalue) <= interval_t::unsigned_int(bin.is64))) {
                return;
            }
            m_inv->assign(dst.svalue, src.svalue);
            m_inv->assign(dst.uvalue, src.uvalue);
            havoc_offsets(bin.dst);
            m_inv = type_inv.join_over_types(m_inv, src_reg, [&](NumAbsDomain& inv, const type_encoding_t type) {
                switch (type) {
                case T_CTX:
                    if (bin.is64) {
                        inv->assign(dst.type, type);
                        inv->assign(dst.ctx_offset, src.ctx_offset);
                    }
                    break;
                case T_MAP:
                case T_MAP_PROGRAMS:
                    if (bin.is64) {
                        inv->assign(dst.type, type);
                        inv->assign(dst.map_fd, src.map_fd);
                    }
                    break;
                case T_PACKET:
                    if (bin.is64) {
                        inv->assign(dst.type, type);
                        inv->assign(dst.packet_offset, src.packet_offset);
                    }
                    break;
                case T_SHARED:
                    if (bin.is64) {
                        inv->assign(dst.type, type);
                        inv->assign(dst.shared_region_size, src.shared_region_size);
                        inv->assign(dst.shared_offset, src.shared_offset);
                    }
                    break;
                case T_STACK:
                    if (bin.is64) {
                        inv->assign(dst.type, type);
                        inv->assign(dst.stack_offset, src.stack_offset);
                        inv->assign(dst.stack_numeric_size, src.stack_numeric_size);
                    }
                    break;
                default: inv->assign(dst.type, type); break;
                }
            });
            if (bin.is64) {
                // Add dst.type=src.type invariant.
                if ((bin.dst.v != std::get<Reg>(bin.v).v) || (type_inv.get_type(m_inv, dst.type) == T_UNINIT)) {
                    // Only forget the destination type if we're copying from a different register,
                    // or from the same uninitialized register.
                    havoc(dst.type);
                }
                type_inv.assign_type(m_inv, bin.dst, std::get<Reg>(bin.v));
            }
            break;
        }
    }
    if (!bin.is64) {
        m_inv->bitwise_and(dst.svalue, dst.uvalue, UINT32_MAX);
    }
}

string_invariant ebpf_domain_t::to_set() const { return this->m_inv.to_set() + this->stack.to_set(); }

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

    inv.m_inv -= variable_t::packet_size();
    inv.m_inv -= variable_t::meta_offset();

    inv.m_inv += 0 <= variable_t::packet_size();
    inv.m_inv += variable_t::packet_size() < MAX_PACKET_SIZE;
    const auto info = *global_program_info;
    if (info.type.context_descriptor->meta >= 0) {
        inv.m_inv += variable_t::meta_offset() <= 0;
        inv.m_inv += variable_t::meta_offset() >= -4098;
    } else {
        inv.m_inv->assign(variable_t::meta_offset(), 0);
    }
}

ebpf_domain_t ebpf_domain_t::from_constraints(const std::set<std::string>& constraints, const bool setup_constraints) {
    ebpf_domain_t inv;
    if (setup_constraints) {
        inv = setup_entry(false);
    }
    auto numeric_ranges = std::vector<interval_t>();
    for (const auto& cst : parse_linear_constraints(constraints, numeric_ranges)) {
        inv.m_inv += cst;
    }
    for (const interval_t& range : numeric_ranges) {
        const int start = static_cast<int>(range.lb().number().value());
        const int width = 1 + static_cast<int>(range.finite_size().value());
        inv.stack.initialize_numbers(start, width);
    }
    // TODO: handle other stack type constraints
    return inv;
}

ebpf_domain_t ebpf_domain_t::setup_entry(const bool init_r1) {
    using namespace crab::dsl_syntax;

    ebpf_domain_t inv;
    const auto r10 = reg_pack(R10_STACK_POINTER);
    constexpr Reg r10_reg{(uint8_t)R10_STACK_POINTER};
    inv.m_inv += EBPF_STACK_SIZE <= r10.svalue;
    inv.m_inv += r10.svalue <= PTR_MAX;
    inv.m_inv->assign(r10.stack_offset, EBPF_STACK_SIZE);
    // stack_numeric_size would be 0, but TOP has the same result
    // so no need to assign it.
    inv.type_inv.assign_type(inv.m_inv, r10_reg, T_STACK);

    if (init_r1) {
        const auto r1 = reg_pack(R1_ARG);
        constexpr Reg r1_reg{(uint8_t)R1_ARG};
        inv.m_inv += 1 <= r1.svalue;
        inv.m_inv += r1.svalue <= PTR_MAX;
        inv.m_inv->assign(r1.ctx_offset, 0);
        inv.type_inv.assign_type(inv.m_inv, r1_reg, T_CTX);
    }

    initialize_packet(inv);
    return inv;
}

void ebpf_domain_t::initialize_loop_counter(const label_t& label) {
    m_inv.assign(variable_t::loop_counter(to_string(label)), 0);
}

bound_t ebpf_domain_t::get_loop_count_upper_bound() const {
    bound_t ub{number_t{0}};
    for (const variable_t counter : variable_t::get_loop_counters()) {
        ub = std::max(ub, m_inv[counter].ub());
    }
    return ub;
}

void ebpf_domain_t::operator()(const IncrementLoopCounter& ins) {
    if (!m_inv) {
        return;
    }
    m_inv->add(variable_t::loop_counter(to_string(ins.name)), 1);
}
} // namespace crab
