// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <optional>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"

#include "asm_unmarshal.hpp"
#include "config.hpp"
#include "crab/array_domain.hpp"
#include "crab/ebpf_domain.hpp"
#include "crab_utils/num_safety.hpp"
#include "dsl_syntax.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"

using crab::domains::NumAbsDomain;
namespace crab {

class ebpf_transformer final {
    ebpf_domain_t& dom;
    // shorthands:
    NumAbsDomain& m_inv;
    domains::array_domain_t& stack;
    TypeDomain& type_inv;

  public:
    explicit ebpf_transformer(ebpf_domain_t& dom)
        : dom(dom), m_inv(dom.m_inv), stack(dom.stack), type_inv(dom.type_inv) {}

    // abstract transformers
    void operator()(const Assume&);
    void operator()(const Atomic&);
    void operator()(const Bin&);
    void operator()(const Call&);
    void operator()(const CallLocal&);
    void operator()(const Callx&);
    void operator()(const Exit&);
    void operator()(const IncrementLoopCounter&);
    void operator()(const Jmp&) const;
    void operator()(const LoadMapFd&);
    void operator()(const Mem&);
    void operator()(const Packet&);
    void operator()(const Un&);
    void operator()(const Undefined&);

    void initialize_loop_counter(const label_t& label);

    static ebpf_domain_t setup_entry(bool init_r1);

  private:
    void assign(variable_t lhs, variable_t rhs);
    void assign(variable_t x, const linear_expression_t& e);
    void assign(variable_t x, int64_t e);

    void apply(arith_binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width);
    void apply(arith_binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);
    void apply(bitwise_binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);
    void apply(bitwise_binop_t op, variable_t x, variable_t y, const number_t& k, int finite_width);
    void apply(binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width);
    void apply(binop_t op, variable_t x, variable_t y, variable_t z, int finite_width);

    void add(const Reg& reg, int imm, int finite_width);
    void add(variable_t lhs, variable_t op2);
    void add(variable_t lhs, const number_t& op2);
    void sub(variable_t lhs, variable_t op2);
    void sub(variable_t lhs, const number_t& op2);
    void add_overflow(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void add_overflow(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void sub_overflow(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void sub_overflow(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void neg(variable_t lhss, variable_t lhsu, int finite_width);
    void mul(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void mul(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void sdiv(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void sdiv(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void udiv(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void udiv(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void srem(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void srem(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);
    void urem(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void urem(variable_t lhss, variable_t lhsu, const number_t& op2, int finite_width);

    void bitwise_and(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void bitwise_and(variable_t lhss, variable_t lhsu, const number_t& op2);
    void bitwise_or(variable_t lhss, variable_t lhsu, variable_t op2, int finite_width);
    void bitwise_or(variable_t lhss, variable_t lhsu, const number_t& op2);
    void bitwise_xor(variable_t lhsss, variable_t lhsu, variable_t op2, int finite_width);
    void bitwise_xor(variable_t lhss, variable_t lhsu, const number_t& op2);
    void shl(const Reg& reg, int imm, int finite_width);
    void shl_overflow(variable_t lhss, variable_t lhsu, variable_t op2);
    void shl_overflow(variable_t lhss, variable_t lhsu, const number_t& op2);
    void lshr(const Reg& reg, int imm, int finite_width);
    void ashr(const Reg& dst_reg, const linear_expression_t& right_svalue, int finite_width);
    void sign_extend(const Reg& dst_reg, const linear_expression_t& right_svalue, int finite_width, Bin::Op op);

    void assume(const linear_constraint_t& cst);

    /// Forget everything we know about the value of a variable.
    void havoc(variable_t v);

    /// Forget everything about all offset variables for a given register.
    void havoc_offsets(const Reg& reg);

    void scratch_caller_saved_registers();
    void save_callee_saved_registers(const std::string& prefix);
    void restore_callee_saved_registers(const std::string& prefix);
    void havoc_subprogram_stack(const std::string& prefix);
    void forget_packet_pointers();
    void do_load_mapfd(const Reg& dst_reg, int mapfd, bool maybe_null);

    void assign_valid_ptr(const Reg& dst_reg, bool maybe_null);

    void recompute_stack_numeric_size(NumAbsDomain& inv, const Reg& reg) const;
    void recompute_stack_numeric_size(NumAbsDomain& inv, variable_t type_variable) const;
    void do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width,
                       const Reg& src_reg);
    void do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague, int width);
    void do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr, int width);
    void do_load(const Mem& b, const Reg& target_reg);

    void do_store_stack(NumAbsDomain& inv, const linear_expression_t& addr, int width,
                        const linear_expression_t& val_type, const linear_expression_t& val_svalue,
                        const linear_expression_t& val_uvalue, const std::optional<reg_pack_t>& opt_val_reg);

    void do_mem_store(const Mem& b, const linear_expression_t& val_type, const linear_expression_t& val_svalue,
                      const linear_expression_t& val_uvalue, const std::optional<reg_pack_t>& opt_val_reg);
}; // end ebpf_domain_t

void ebpf_domain_transform(ebpf_domain_t& inv, const Instruction& ins) {
    if (inv.is_bottom()) {
        return;
    }
    std::visit(ebpf_transformer{inv}, ins);
    if (inv.is_bottom() && !std::holds_alternative<Assume>(ins)) {
        // Fail. raise an exception to stop the analysis.
        std::stringstream msg;
        msg << "Bug! pre-invariant:\n"
            << inv << "\n followed by instruction: " << ins << "\n"
            << "leads to bottom";
        throw std::logic_error(msg.str());
    }
}

/** Linear constraint for a pointer comparison.
 */
static linear_constraint_t assume_cst_offsets_reg(const Condition::Op op, const variable_t dst_offset,
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

static std::vector<linear_constraint_t> assume_bit_cst_interval(const NumAbsDomain& inv, Condition::Op op, bool is64,
                                                                variable_t dst_uvalue, interval_t src_interval) {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;

    auto dst_interval = inv.eval_interval(dst_uvalue);
    std::optional<number_t> dst_n = dst_interval.singleton();
    if (!dst_n || !dst_n.value().fits_cast_to<int64_t>()) {
        return {};
    }

    std::optional<number_t> src_n = src_interval.singleton();
    if (!src_n || !src_n->fits_cast_to<int64_t>()) {
        return {};
    }
    uint64_t src_int_value = src_n.value().cast_to<uint64_t>();
    if (!is64) {
        src_int_value = gsl::narrow_cast<uint32_t>(src_int_value);
    }

    bool result;
    switch (op) {
    case Op::SET: result = (dst_n.value().cast_to<uint64_t>() & src_int_value) != 0; break;
    case Op::NSET: result = (dst_n.value().cast_to<uint64_t>() & src_int_value) == 0; break;
    default: throw std::exception();
    }

    return {result ? linear_constraint_t::true_const() : linear_constraint_t::false_const()};
}

static std::vector<linear_constraint_t> assume_signed_64bit_eq(const NumAbsDomain& inv, const variable_t left_svalue,
                                                               const variable_t left_uvalue,
                                                               const interval_t& right_interval,
                                                               const linear_expression_t& right_svalue,
                                                               const linear_expression_t& right_uvalue) {
    using namespace crab::dsl_syntax;
    if (right_interval <= interval_t::nonnegative(64) && !right_interval.is_singleton()) {
        return {(left_svalue == right_svalue), (left_uvalue == right_uvalue), eq(left_svalue, left_uvalue)};
    } else {
        return {(left_svalue == right_svalue), (left_uvalue == right_uvalue)};
    }
}

static std::vector<linear_constraint_t> assume_signed_32bit_eq(const NumAbsDomain& inv, const variable_t left_svalue,
                                                               const variable_t left_uvalue,
                                                               const interval_t& right_interval) {
    using namespace crab::dsl_syntax;

    if (const auto rn = right_interval.singleton()) {
        const auto left_svalue_interval = inv.eval_interval(left_svalue);
        if (auto size = left_svalue_interval.finite_size()) {
            // Find the lowest 64-bit svalue whose low 32 bits match the singleton.

            // Get lower bound as a 64-bit value.
            int64_t lb = left_svalue_interval.lb().number()->cast_to<int64_t>();

            // Use the high 32-bits from the left lower bound and the low 32-bits from the right singleton.
            // The result might be lower than the lower bound.
            const int64_t lb_match = (lb & 0xFFFFFFFF00000000) | (rn->cast_to<int64_t>() & 0xFFFFFFFF);
            if (lb_match < lb) {
                // The result is lower than the left interval, so try the next higher matching 64-bit value.
                // It's ok if this goes higher than the left upper bound.
                lb += 0x100000000;
            }

            // Find the highest 64-bit svalue whose low 32 bits match the singleton.

            // Get upper bound as a 64-bit value.
            const int64_t ub = left_svalue_interval.ub().number()->cast_to<int64_t>();

            // Use the high 32-bits from the left upper bound and the low 32-bits from the right singleton.
            // The result might be higher than the upper bound.
            const int64_t ub_match = (ub & 0xFFFFFFFF00000000) | (rn->cast_to<int64_t>() & 0xFFFFFFFF);
            if (ub_match > ub) {
                // The result is higher than the left interval, so try the next lower matching 64-bit value.
                // It's ok if this goes lower than the left lower bound.
                lb -= 0x100000000;
            }

            if (to_unsigned(lb_match) <= to_unsigned(ub_match)) {
                // The interval is also valid when cast to a uvalue, meaning
                // both bounds are positive or both are negative.
                return {left_svalue >= lb_match, left_svalue <= ub_match, left_uvalue >= to_unsigned(lb_match),
                        left_uvalue <= to_unsigned(ub_match)};
            } else {
                // The interval can only be represented as an svalue.
                return {left_svalue >= lb_match, left_svalue <= ub_match};
            }
        }
    }
    return {};
}

// Given left and right values, get the left and right intervals, and also split
// the left interval into separate negative and positive intervals.
static void get_signed_intervals(const NumAbsDomain& inv, bool is64, const variable_t left_svalue,
                                 const variable_t left_uvalue, const linear_expression_t& right_svalue,
                                 interval_t& left_interval, interval_t& right_interval,
                                 interval_t& left_interval_positive, interval_t& left_interval_negative) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    // Get intervals as 32-bit or 64-bit as appropriate.
    left_interval = inv.eval_interval(left_svalue);
    right_interval = inv.eval_interval(right_svalue);
    if (!is64) {
        if ((left_interval <= interval_t::nonnegative(32) && right_interval <= interval_t::nonnegative(32)) ||
            (left_interval <= interval_t::negative(32) && right_interval <= interval_t::negative(32))) {
            is64 = true;
            // fallthrough as 64bit, including deduction of relational information
        } else {
            left_interval = left_interval.truncate_to<int32_t>();
            right_interval = right_interval.truncate_to<int32_t>();
            // continue as 32bit
        }
    }

    if (!left_interval.is_top()) {
        left_interval_positive = left_interval & interval_t::nonnegative(64);
        left_interval_negative = left_interval & interval_t::negative(64);
    } else {
        left_interval = inv.eval_interval(left_uvalue);
        if (!left_interval.is_top()) {
            // The interval is TOP as a signed interval but is represented precisely as an unsigned interval,
            // so split into two signed intervals that can be treated separately.
            left_interval_positive = left_interval & interval_t::nonnegative(64);
            const number_t lih_ub =
                left_interval.ub().number() ? left_interval.ub().number()->truncate_to<int64_t>() : -1;
            left_interval_negative = interval_t{std::numeric_limits<int64_t>::min(), lih_ub};
        } else {
            left_interval_positive = interval_t::nonnegative(64);
            left_interval_negative = interval_t::negative(64);
        }
    }

    left_interval = left_interval.truncate_to<int64_t>();
    right_interval = right_interval.truncate_to<int64_t>();
}

// Given left and right values, get the left and right intervals, and also split
// the left interval into separate low and high intervals.
static void get_unsigned_intervals(const NumAbsDomain& inv, bool is64, const variable_t left_svalue,
                                   const variable_t left_uvalue, const linear_expression_t& right_uvalue,
                                   interval_t& left_interval, interval_t& right_interval, interval_t& left_interval_low,
                                   interval_t& left_interval_high) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    // Get intervals as 32-bit or 64-bit as appropriate.
    left_interval = inv.eval_interval(left_uvalue);
    right_interval = inv.eval_interval(right_uvalue);
    if (!is64) {
        if ((left_interval <= interval_t::nonnegative(32) && right_interval <= interval_t::nonnegative(32)) ||
            (left_interval <= interval_t::unsigned_high(32) && right_interval <= interval_t::unsigned_high(32))) {
            is64 = true;
            // fallthrough as 64bit, including deduction of relational information
        } else {
            left_interval = left_interval.truncate_to<uint32_t>();
            right_interval = right_interval.truncate_to<uint32_t>();
            // continue as 32bit
        }
    }

    if (!left_interval.is_top()) {
        left_interval_low = left_interval & interval_t::nonnegative(64);
        left_interval_high = left_interval & interval_t::unsigned_high(64);
    } else {
        left_interval = inv.eval_interval(left_svalue);
        if (!left_interval.is_top()) {
            // The interval is TOP as an unsigned interval but is represented precisely as a signed interval,
            // so split into two unsigned intervals that can be treated separately.
            left_interval_low = interval_t(0, left_interval.ub()).truncate_to<uint64_t>();
            left_interval_high = interval_t(left_interval.lb(), -1).truncate_to<uint64_t>();
        } else {
            left_interval_low = interval_t::nonnegative(64);
            left_interval_high = interval_t::unsigned_high(64);
        }
    }

    left_interval = left_interval.truncate_to<uint64_t>();
    right_interval = right_interval.truncate_to<uint64_t>();
}

static std::vector<linear_constraint_t>
assume_signed_64bit_lt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                       const interval_t& left_interval_positive, const interval_t& left_interval_negative,
                       const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                       const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::negative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1].
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue, 0 <= left_uvalue,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::nonnegative(64) &&
               right_interval <= interval_t::nonnegative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue, 0 <= left_uvalue,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    }
}

static std::vector<linear_constraint_t>
assume_signed_32bit_lt(const NumAbsDomain& inv, const bool strict, const variable_t left_svalue,
                       const variable_t left_uvalue, const interval_t& left_interval_positive,
                       const interval_t& left_interval_negative, const linear_expression_t& right_svalue,
                       const linear_expression_t& right_uvalue, const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::negative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {std::numeric_limits<int32_t>::max() < left_uvalue,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::nonnegative(32) &&
               right_interval <= interval_t::nonnegative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX]
        const auto lpub = left_interval_positive.truncate_to<int32_t>().ub();
        return {left_svalue >= 0,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if (inv.eval_interval(left_svalue) <= interval_t::signed_int(32) &&
               inv.eval_interval(right_svalue) <= interval_t::signed_int(32)) {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else {
        // We can't directly compare the svalues since they may differ in high order bits.
        return {};
    }
}

static std::vector<linear_constraint_t>
assume_signed_64bit_gt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                       const interval_t& left_interval_positive, const interval_t& left_interval_negative,
                       const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                       const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::nonnegative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        const auto lpub = left_interval_positive.truncate_to<int64_t>().ub();
        return {left_svalue >= 0,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::negative(64) &&
               right_interval <= interval_t::negative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {std::numeric_limits<int64_t>::max() < left_uvalue,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    }
}

static std::vector<linear_constraint_t>
assume_signed_32bit_gt(const NumAbsDomain& inv, const bool strict, const variable_t left_svalue,
                       const variable_t left_uvalue, const interval_t& left_interval_positive,
                       const interval_t& left_interval_negative, const linear_expression_t& right_svalue,
                       const linear_expression_t& right_uvalue, const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::nonnegative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        const auto lpub = left_interval_positive.truncate_to<int32_t>().ub();
        return {left_svalue >= 0,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::negative(32) &&
               right_interval <= interval_t::negative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {left_uvalue >= number_t{std::numeric_limits<int32_t>::max()} + 1,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else if (inv.eval_interval(left_svalue) <= interval_t::signed_int(32) &&
               inv.eval_interval(right_svalue) <= interval_t::signed_int(32)) {
        // Interval can only be represented as an svalue.
        return {strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else {
        // We can't directly compare the svalues since they may differ in high order bits.
        return {};
    }
}

static std::vector<linear_constraint_t> assume_signed_cst_interval(const NumAbsDomain& inv, Condition::Op op, bool is64,
                                                                   variable_t left_svalue, variable_t left_uvalue,
                                                                   const linear_expression_t& right_svalue,
                                                                   const linear_expression_t& right_uvalue) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    interval_t left_interval = interval_t::bottom();
    interval_t right_interval = interval_t::bottom();
    interval_t left_interval_positive = interval_t::bottom();
    interval_t left_interval_negative = interval_t::bottom();
    get_signed_intervals(inv, is64, left_svalue, left_uvalue, right_svalue, left_interval, right_interval,
                         left_interval_positive, left_interval_negative);

    if (op == Condition::Op::EQ) {
        // Handle svalue == right.
        if (is64) {
            return assume_signed_64bit_eq(inv, left_svalue, left_uvalue, right_interval, right_svalue, right_uvalue);
        } else {
            return assume_signed_32bit_eq(inv, left_svalue, left_uvalue, right_interval);
        }
    }

    const bool is_lt = op == Condition::Op::SLT || op == Condition::Op::SLE;
    bool strict = op == Condition::Op::SLT || op == Condition::Op::SGT;

    auto llb = left_interval.lb();
    auto lub = left_interval.ub();
    auto rlb = right_interval.lb();
    auto rub = right_interval.ub();
    if (!is_lt && (strict ? lub <= rlb : lub < rlb)) {
        // Left signed interval is lower than right signed interval.
        return {linear_constraint_t::false_const()};
    } else if (is_lt && (strict ? llb >= rub : llb > rub)) {
        // Left signed interval is higher than right signed interval.
        return {linear_constraint_t::false_const()};
    }
    if (is_lt && (strict ? lub < rlb : lub <= rlb)) {
        // Left signed interval is lower than right signed interval.
        return {linear_constraint_t::true_const()};
    } else if (!is_lt && (strict ? llb > rub : llb >= rub)) {
        // Left signed interval is higher than right signed interval.
        return {linear_constraint_t::true_const()};
    }

    if (is64) {
        if (is_lt) {
            return assume_signed_64bit_lt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        } else {
            return assume_signed_64bit_gt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        }
    } else {
        // 32-bit compare.
        if (is_lt) {
            return assume_signed_32bit_lt(inv, strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        } else {
            return assume_signed_32bit_gt(inv, strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        }
    }
    return {};
}

static std::vector<linear_constraint_t>
assume_unsigned_64bit_lt(const NumAbsDomain& inv, bool strict, variable_t left_svalue, variable_t left_uvalue,
                         const interval_t& left_interval_low, const interval_t& left_interval_high,
                         const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                         const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    auto rub = right_interval.ub();
    auto lllb = left_interval_low.truncate_to<uint64_t>().lb();
    if (right_interval <= interval_t::nonnegative(64) && (strict ? lllb >= rub : lllb > rub)) {
        // The high interval is out of range.
        if (auto lsubn = inv.eval_interval(left_svalue).ub().number()) {
            return {left_uvalue >= 0, (strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue),
                    left_uvalue <= *lsubn, left_svalue >= 0};
        } else {
            return {left_uvalue >= 0, (strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue),
                    left_svalue >= 0};
        }
    }
    auto lhlb = left_interval_high.truncate_to<uint64_t>().lb();
    if (right_interval <= interval_t::unsigned_high(64) && (strict ? lhlb >= rub : lhlb > rub)) {
        // The high interval is out of range.
        if (auto lsubn = inv.eval_interval(left_svalue).ub().number()) {
            return {left_uvalue >= 0, (strict ? left_uvalue < *rub.number() : left_uvalue <= *rub.number()),
                    left_uvalue <= *lsubn, left_svalue >= 0};
        } else {
            return {left_uvalue >= 0, (strict ? left_uvalue < *rub.number() : left_uvalue <= *rub.number()),
                    left_svalue >= 0};
        }
    }
    if (right_interval <= interval_t::signed_int(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        auto llub = left_interval_low.truncate_to<uint64_t>().ub();
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                left_uvalue <= *llub.number(), 0 <= left_svalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if (left_interval_low.is_bottom() && right_interval <= interval_t::unsigned_high(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if ((left_interval_low | left_interval_high) == interval_t::unsigned_int(64)) {
        // Interval can only be represented as a uvalue, and was TOP before.
        return {strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    }
}

static std::vector<linear_constraint_t> assume_unsigned_32bit_lt(const NumAbsDomain& inv, const bool strict,
                                                                 const variable_t left_svalue,
                                                                 const variable_t left_uvalue,
                                                                 const linear_expression_t& right_svalue,
                                                                 const linear_expression_t& right_uvalue) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    if (inv.eval_interval(left_uvalue) <= interval_t::nonnegative(32) &&
        inv.eval_interval(right_uvalue) <= interval_t::nonnegative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT32_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if (inv.eval_interval(left_svalue) <= interval_t::negative(32) &&
               inv.eval_interval(right_svalue) <= interval_t::negative(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT32_MIN, -1].
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue};
    } else if (inv.eval_interval(left_uvalue) <= interval_t::unsigned_int(32) &&
               inv.eval_interval(right_uvalue) <= interval_t::unsigned_int(32)) {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
    } else {
        // We can't directly compare the uvalues since they may differ in high order bits.
        return {};
    }
}

static std::vector<linear_constraint_t>
assume_unsigned_64bit_gt(const NumAbsDomain& inv, const bool strict, const variable_t left_svalue,
                         const variable_t left_uvalue, const interval_t& left_interval_low,
                         const interval_t& left_interval_high, const linear_expression_t& right_svalue,
                         const linear_expression_t& right_uvalue, const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    const auto rlb = right_interval.lb();
    const auto llub = left_interval_low.truncate_to<uint64_t>().ub();
    const auto lhlb = left_interval_high.truncate_to<uint64_t>().lb();

    if (right_interval <= interval_t::nonnegative(64) && (strict ? llub <= rlb : llub < rlb)) {
        // The low interval is out of range.
        return {strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                *lhlb.number() == std::numeric_limits<uint64_t>::max() ? left_uvalue == *lhlb.number()
                                                                       : left_uvalue >= *lhlb.number(),
                left_svalue < 0};
    } else if (right_interval <= interval_t::unsigned_high(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else if ((left_interval_low | left_interval_high) <= interval_t::nonnegative(64) &&
               right_interval <= interval_t::nonnegative(64)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
    }
}

static std::vector<linear_constraint_t>
assume_unsigned_32bit_gt(const NumAbsDomain& inv, const bool strict, const variable_t left_svalue,
                         const variable_t left_uvalue, const interval_t& left_interval_low,
                         const interval_t& left_interval_high, const linear_expression_t& right_svalue,
                         const linear_expression_t& right_uvalue, const interval_t& right_interval) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::unsigned_high(32)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue};
    } else if (inv.eval_interval(left_uvalue) <= interval_t::unsigned_int(32) &&
               inv.eval_interval(right_uvalue) <= interval_t::unsigned_int(32)) {
        // Interval can only be represented as a uvalue.
        return {0 <= left_uvalue, strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
    } else {
        // We can't directly compare the uvalues since they may differ in high order bits.
        return {};
    };
}

static std::vector<linear_constraint_t> assume_unsigned_cst_interval(const NumAbsDomain& inv, Condition::Op op,
                                                                     bool is64, variable_t left_svalue,
                                                                     variable_t left_uvalue,
                                                                     const linear_expression_t& right_svalue,
                                                                     const linear_expression_t& right_uvalue) {
    using crab::interval_t;
    using namespace crab::dsl_syntax;

    interval_t left_interval = interval_t::bottom();
    interval_t right_interval = interval_t::bottom();
    interval_t left_interval_low = interval_t::bottom();
    interval_t left_interval_high = interval_t::bottom();
    get_unsigned_intervals(inv, is64, left_svalue, left_uvalue, right_uvalue, left_interval, right_interval,
                           left_interval_low, left_interval_high);

    // Handle uvalue != right.
    if (op == Condition::Op::NE) {
        if (auto rn = right_interval.singleton()) {
            if (rn == left_interval.truncate_to_uint(is64 ? 64 : 32).lb().number()) {
                // "NE lower bound" is equivalent to "GT lower bound".
                op = Condition::Op::GT;
                right_interval = interval_t{left_interval.lb()};
            } else if (rn == left_interval.ub().number()) {
                // "NE upper bound" is equivalent to "LT upper bound".
                op = Condition::Op::LT;
                right_interval = interval_t{left_interval.ub()};
            } else {
                return {};
            }
        } else {
            return {};
        }
    }

    const bool is_lt = op == Condition::Op::LT || op == Condition::Op::LE;
    bool strict = op == Condition::Op::LT || op == Condition::Op::GT;

    auto [llb, lub] = left_interval.pair();
    auto [rlb, rub] = right_interval.pair();
    if (is_lt ? (strict ? llb >= rub : llb > rub) : (strict ? lub <= rlb : lub < rlb)) {
        // Left unsigned interval is lower than right unsigned interval.
        return {linear_constraint_t::false_const()};
    }
    if (is_lt && (strict ? lub < rlb : lub <= rlb)) {
        // Left unsigned interval is lower than right unsigned interval. We still add a
        // relationship for use when widening, such as is used in the prime conformance test.
        if (is64) {
            return {strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
        }
        return {};
    } else if (!is_lt && (strict ? llb > rub : llb >= rub)) {
        // Left unsigned interval is higher than right unsigned interval. We still add a
        // relationship for use when widening, such as is used in the prime conformance test.
        if (is64) {
            return {strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
        } else {
            return {};
        }
    }

    if (is64) {
        if (is_lt) {
            return assume_unsigned_64bit_lt(inv, strict, left_svalue, left_uvalue, left_interval_low,
                                            left_interval_high, right_svalue, right_uvalue, right_interval);
        } else {
            return assume_unsigned_64bit_gt(inv, strict, left_svalue, left_uvalue, left_interval_low,
                                            left_interval_high, right_svalue, right_uvalue, right_interval);
        }
    } else {
        if (is_lt) {
            return assume_unsigned_32bit_lt(inv, strict, left_svalue, left_uvalue, right_svalue, right_uvalue);
        } else {
            return assume_unsigned_32bit_gt(inv, strict, left_svalue, left_uvalue, left_interval_low,
                                            left_interval_high, right_svalue, right_uvalue, right_interval);
        }
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
        return assume_signed_cst_interval(inv, op, is64, dst_svalue, dst_uvalue, imm, gsl::narrow_cast<uint64_t>(imm));
    case Op::SET:
    case Op::NSET: return assume_bit_cst_interval(inv, op, is64, dst_uvalue, interval_t{imm});
    case Op::NE:
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT:
        return assume_unsigned_cst_interval(inv, op, is64, dst_svalue, dst_uvalue, imm,
                                            gsl::narrow_cast<uint64_t>(imm));
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
            if (!src_interval.is_singleton() && src_interval <= interval_t::nonnegative(64)) {
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
        case Op::NSET: return assume_bit_cst_interval(inv, op, is64, dst_uvalue, inv.eval_interval(src_uvalue));
        case Op::GE:
        case Op::LE:
        case Op::GT:
        case Op::LT: return assume_unsigned_cst_interval(inv, op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        }
    } else {
        switch (op) {
        case Op::EQ:
        case Op::SGE:
        case Op::SLE:
        case Op::SGT:
        case Op::SLT: return assume_signed_cst_interval(inv, op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        case Op::SET:
        case Op::NSET: return assume_bit_cst_interval(inv, op, is64, dst_uvalue, inv.eval_interval(src_uvalue));
        case Op::NE:
        case Op::GE:
        case Op::LE:
        case Op::GT:
        case Op::LT: return assume_unsigned_cst_interval(inv, op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue);
        }
    }
    assert(false);
    throw std::exception();
}

void ebpf_transformer::assign(const variable_t x, const linear_expression_t& e) { m_inv.assign(x, e); }
void ebpf_transformer::assign(const variable_t x, const int64_t e) { m_inv.set(x, interval_t(e)); }

void ebpf_transformer::apply(const arith_binop_t op, const variable_t x, const variable_t y, const number_t& z,
                             const int finite_width) {
    m_inv.apply(op, x, y, z, finite_width);
}

void ebpf_transformer::apply(const arith_binop_t op, const variable_t x, const variable_t y, const variable_t z,
                             const int finite_width) {
    m_inv.apply(op, x, y, z, finite_width);
}

void ebpf_transformer::apply(const bitwise_binop_t op, const variable_t x, const variable_t y, const variable_t z,
                             const int finite_width) {
    m_inv.apply(op, x, y, z, finite_width);
}

void ebpf_transformer::apply(const bitwise_binop_t op, const variable_t x, const variable_t y, const number_t& k,
                             const int finite_width) {
    m_inv.apply(op, x, y, k, finite_width);
}

void ebpf_transformer::apply(binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width) {
    std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
}

void ebpf_transformer::apply(binop_t op, variable_t x, variable_t y, variable_t z, int finite_width) {
    std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
}

static void havoc_offsets(NumAbsDomain& inv, const Reg& reg) {
    const reg_pack_t r = reg_pack(reg);
    inv -= r.ctx_offset;
    inv -= r.map_fd;
    inv -= r.packet_offset;
    inv -= r.shared_offset;
    inv -= r.shared_region_size;
    inv -= r.stack_offset;
    inv -= r.stack_numeric_size;
}
static void havoc_register(NumAbsDomain& inv, const Reg& reg) {
    const reg_pack_t r = reg_pack(reg);
    havoc_offsets(inv, reg);
    inv -= r.svalue;
    inv -= r.uvalue;
}

void ebpf_transformer::scratch_caller_saved_registers() {
    for (int i = R1_ARG; i <= R5_ARG; i++) {
        Reg r{gsl::narrow<uint8_t>(i)};
        havoc_register(m_inv, r);
        type_inv.havoc_type(m_inv, r);
    }
}

void ebpf_transformer::save_callee_saved_registers(const std::string& prefix) {
    // Create variables specific to the new call stack frame that store
    // copies of the states of r6 through r9.
    for (int r = R6; r <= R9; r++) {
        for (const data_kind_t kind : iterate_kinds()) {
            const variable_t src_var = variable_t::reg(kind, r);
            if (!m_inv[src_var].is_top()) {
                assign(variable_t::stack_frame_var(kind, r, prefix), src_var);
            }
        }
    }
}

void ebpf_transformer::restore_callee_saved_registers(const std::string& prefix) {
    for (int r = R6; r <= R9; r++) {
        for (const data_kind_t kind : iterate_kinds()) {
            const variable_t src_var = variable_t::stack_frame_var(kind, r, prefix);
            if (!m_inv[src_var].is_top()) {
                assign(variable_t::reg(kind, r), src_var);
            } else {
                havoc(variable_t::reg(kind, r));
            }
            havoc(src_var);
        }
    }
}

void ebpf_transformer::havoc_subprogram_stack(const std::string& prefix) {
    const variable_t r10_stack_offset = reg_pack(R10_STACK_POINTER).stack_offset;
    const auto intv = m_inv.eval_interval(r10_stack_offset);
    if (!intv.is_singleton()) {
        return;
    }
    const int64_t stack_start = intv.singleton()->cast_to<int64_t>() - EBPF_SUBPROGRAM_STACK_SIZE;
    for (const data_kind_t kind : iterate_kinds()) {
        stack.havoc(m_inv, kind, stack_start, EBPF_SUBPROGRAM_STACK_SIZE);
    }
}

void ebpf_transformer::forget_packet_pointers() {
    using namespace crab::dsl_syntax;

    for (const variable_t type_variable : variable_t::get_type_variables()) {
        if (type_inv.has_type(m_inv, type_variable, T_PACKET)) {
            havoc(variable_t::kind_var(data_kind_t::types, type_variable));
            havoc(variable_t::kind_var(data_kind_t::packet_offsets, type_variable));
            havoc(variable_t::kind_var(data_kind_t::svalues, type_variable));
            havoc(variable_t::kind_var(data_kind_t::uvalues, type_variable));
        }
    }

    dom.initialize_packet();
}

static void overflow_bounds(NumAbsDomain& inv, variable_t lhs, number_t span, int finite_width, bool issigned) {
    using namespace crab::dsl_syntax;
    auto interval = inv[lhs];
    if (interval.ub() - interval.lb() >= span) {
        // Interval covers the full space.
        inv -= lhs;
        return;
    }
    if (interval.is_bottom()) {
        inv -= lhs;
        return;
    }
    number_t lb_value = interval.lb().number().value();
    number_t ub_value = interval.ub().number().value();

    // Compute the interval, taking overflow into account.
    // For a signed result, we need to ensure the signed and unsigned results match
    // so for a 32-bit operation, 0x80000000 should be a positive 64-bit number not
    // a sign extended negative one.
    number_t lb = lb_value.truncate_to_uint(finite_width);
    number_t ub = ub_value.truncate_to_uint(finite_width);
    if (issigned) {
        lb = lb.truncate_to<int64_t>();
        ub = ub.truncate_to<int64_t>();
    }
    if (lb > ub) {
        // Range wraps in the middle, so we cannot represent as an unsigned interval.
        inv -= lhs;
        return;
    }
    auto new_interval = interval_t{lb, ub};
    if (new_interval != interval) {
        // Update the variable, which will lose any relationships to other variables.
        inv.set(lhs, new_interval);
    }
}

static void overflow_signed(NumAbsDomain& inv, const variable_t lhs, const int finite_width) {
    const auto span{finite_width == 64   ? number_t{std::numeric_limits<uint64_t>::max()}
                    : finite_width == 32 ? number_t{std::numeric_limits<uint32_t>::max()}
                                         : throw std::exception()};
    overflow_bounds(inv, lhs, span, finite_width, true);
}

static void overflow_unsigned(NumAbsDomain& inv, const variable_t lhs, const int finite_width) {
    const auto span{finite_width == 64   ? number_t{std::numeric_limits<uint64_t>::max()}
                    : finite_width == 32 ? number_t{std::numeric_limits<uint32_t>::max()}
                                         : throw std::exception()};
    overflow_bounds(inv, lhs, span, finite_width, false);
}
static void apply_signed(NumAbsDomain& inv, const binop_t& op, const variable_t xs, const variable_t xu,
                         const variable_t y, const number_t& z, const int finite_width) {
    inv.apply(op, xs, y, z, finite_width);
    if (finite_width) {
        inv.assign(xu, xs);
        overflow_signed(inv, xs, finite_width);
        overflow_unsigned(inv, xu, finite_width);
    }
}

static void apply_unsigned(NumAbsDomain& inv, const binop_t& op, const variable_t xs, const variable_t xu,
                           const variable_t y, const number_t& z, const int finite_width) {
    inv.apply(op, xu, y, z, finite_width);
    if (finite_width) {
        inv.assign(xs, xu);
        overflow_signed(inv, xs, finite_width);
        overflow_unsigned(inv, xu, finite_width);
    }
}

static void apply_signed(NumAbsDomain& inv, const binop_t& op, const variable_t xs, const variable_t xu,
                         const variable_t y, const variable_t z, const int finite_width) {
    inv.apply(op, xs, y, z, finite_width);
    if (finite_width) {
        inv.assign(xu, xs);
        overflow_signed(inv, xs, finite_width);
        overflow_unsigned(inv, xu, finite_width);
    }
}

static void apply_unsigned(NumAbsDomain& inv, const binop_t& op, const variable_t xs, const variable_t xu,
                           const variable_t y, const variable_t z, const int finite_width) {
    inv.apply(op, xu, y, z, finite_width);
    if (finite_width) {
        inv.assign(xs, xu);
        overflow_signed(inv, xs, finite_width);
        overflow_unsigned(inv, xu, finite_width);
    }
}

void ebpf_transformer::add(const variable_t lhs, const variable_t op2) {
    apply_signed(m_inv, arith_binop_t::ADD, lhs, lhs, lhs, op2, 0);
}
void ebpf_transformer::add(const variable_t lhs, const number_t& op2) {
    apply_signed(m_inv, arith_binop_t::ADD, lhs, lhs, lhs, op2, 0);
}
void ebpf_transformer::sub(const variable_t lhs, const variable_t op2) {
    apply_signed(m_inv, arith_binop_t::SUB, lhs, lhs, lhs, op2, 0);
}
void ebpf_transformer::sub(const variable_t lhs, const number_t& op2) {
    apply_signed(m_inv, arith_binop_t::SUB, lhs, lhs, lhs, op2, 0);
}

// Add/subtract with overflow are both signed and unsigned. We can use either one of the two to compute the
// result before adjusting for overflow, though if one is top we want to use the other to retain precision.
void ebpf_transformer::add_overflow(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                                    const int finite_width) {
    apply_signed(m_inv, arith_binop_t::ADD, lhss, lhsu, !m_inv.eval_interval(lhss).is_top() ? lhss : lhsu, op2,
                 finite_width);
}
void ebpf_transformer::add_overflow(const variable_t lhss, const variable_t lhsu, const number_t& op2,
                                    const int finite_width) {
    apply_signed(m_inv, arith_binop_t::ADD, lhss, lhsu, !m_inv.eval_interval(lhss).is_top() ? lhss : lhsu, op2,
                 finite_width);
}
void ebpf_transformer::sub_overflow(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                                    const int finite_width) {
    apply_signed(m_inv, arith_binop_t::SUB, lhss, lhsu, !m_inv.eval_interval(lhss).is_top() ? lhss : lhsu, op2,
                 finite_width);
}
void ebpf_transformer::sub_overflow(const variable_t lhss, const variable_t lhsu, const number_t& op2,
                                    const int finite_width) {
    apply_signed(m_inv, arith_binop_t::SUB, lhss, lhsu, !m_inv.eval_interval(lhss).is_top() ? lhss : lhsu, op2,
                 finite_width);
}

void ebpf_transformer::neg(const variable_t lhss, const variable_t lhsu, const int finite_width) {
    apply_signed(m_inv, arith_binop_t::MUL, lhss, lhsu, lhss, -1, finite_width);
}
void ebpf_transformer::mul(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
    apply_signed(m_inv, arith_binop_t::MUL, lhss, lhsu, lhss, op2, finite_width);
}
void ebpf_transformer::mul(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
    apply_signed(m_inv, arith_binop_t::MUL, lhss, lhsu, lhss, op2, finite_width);
}
void ebpf_transformer::sdiv(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                            const int finite_width) {
    apply_signed(m_inv, arith_binop_t::SDIV, lhss, lhsu, lhss, op2, finite_width);
}
void ebpf_transformer::sdiv(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
    apply_signed(m_inv, arith_binop_t::SDIV, lhss, lhsu, lhss, op2, finite_width);
}
void ebpf_transformer::udiv(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                            const int finite_width) {
    apply_unsigned(m_inv, arith_binop_t::UDIV, lhss, lhsu, lhsu, op2, finite_width);
}
void ebpf_transformer::udiv(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
    apply_unsigned(m_inv, arith_binop_t::UDIV, lhss, lhsu, lhsu, op2, finite_width);
}
void ebpf_transformer::srem(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                            const int finite_width) {
    apply_signed(m_inv, arith_binop_t::SREM, lhss, lhsu, lhss, op2, finite_width);
}
void ebpf_transformer::srem(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
    apply_signed(m_inv, arith_binop_t::SREM, lhss, lhsu, lhss, op2, finite_width);
}
void ebpf_transformer::urem(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                            const int finite_width) {
    apply_unsigned(m_inv, arith_binop_t::UREM, lhss, lhsu, lhsu, op2, finite_width);
}
void ebpf_transformer::urem(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
    apply_unsigned(m_inv, arith_binop_t::UREM, lhss, lhsu, lhsu, op2, finite_width);
}

void ebpf_transformer::bitwise_and(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                                   const int finite_width) {
    apply_unsigned(m_inv, bitwise_binop_t::AND, lhss, lhsu, lhsu, op2, finite_width);
}
void ebpf_transformer::bitwise_and(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
    // Use finite width 64 to make the svalue be set as well as the uvalue.
    apply_unsigned(m_inv, bitwise_binop_t::AND, lhss, lhsu, lhsu, op2, 64);
}
void ebpf_transformer::bitwise_or(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                                  const int finite_width) {
    apply_unsigned(m_inv, bitwise_binop_t::OR, lhss, lhsu, lhsu, op2, finite_width);
}
void ebpf_transformer::bitwise_or(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
    apply_unsigned(m_inv, bitwise_binop_t::OR, lhss, lhsu, lhsu, op2, 64);
}
void ebpf_transformer::bitwise_xor(const variable_t lhss, const variable_t lhsu, const variable_t op2,
                                   const int finite_width) {
    apply_unsigned(m_inv, bitwise_binop_t::XOR, lhss, lhsu, lhsu, op2, finite_width);
}
void ebpf_transformer::bitwise_xor(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
    apply_unsigned(m_inv, bitwise_binop_t::XOR, lhss, lhsu, lhsu, op2, 64);
}
void ebpf_transformer::shl_overflow(const variable_t lhss, const variable_t lhsu, const variable_t op2) {
    apply_unsigned(m_inv, bitwise_binop_t::SHL, lhss, lhsu, lhsu, op2, 64);
}
void ebpf_transformer::shl_overflow(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
    apply_unsigned(m_inv, bitwise_binop_t::SHL, lhss, lhsu, lhsu, op2, 64);
}

static void assume(NumAbsDomain& inv, const linear_constraint_t& cst) { inv += cst; }
void ebpf_transformer::assume(const linear_constraint_t& cst) { crab::assume(m_inv, cst); }

/// Forget everything we know about the value of a variable.
void ebpf_transformer::havoc(const variable_t v) { m_inv -= v; }
void ebpf_transformer::havoc_offsets(const Reg& reg) { crab::havoc_offsets(m_inv, reg); }

void ebpf_transformer::assign(const variable_t lhs, const variable_t rhs) { m_inv.assign(lhs, rhs); }

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

void ebpf_transformer::operator()(const Assume& s) {
    const Condition cond = s.cond;
    const auto dst = reg_pack(cond.left);
    if (const auto psrc_reg = std::get_if<Reg>(&cond.right)) {
        const auto src_reg = *psrc_reg;
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
                    if (const auto dst_offset = dom.get_type_offset_variable(cond.left, type)) {
                        if (const auto src_offset = dom.get_type_offset_variable(src_reg, type)) {
                            inv += assume_cst_offsets_reg(cond.op, dst_offset.value(), src_offset.value());
                        }
                    }
                }
            });
        } else {
            // We should only reach here if `--assume-assert` is off
            assert(!thread_local_options.assume_assertions || dom.is_bottom());
            // be sound in any case, it happens to flush out bugs:
            m_inv.set_to_top();
        }
    } else {
        const int64_t imm = gsl::narrow_cast<int64_t>(std::get<Imm>(cond.right).v);
        for (const linear_constraint_t& cst : assume_cst_imm(m_inv, cond.op, cond.is64, dst.svalue, dst.uvalue, imm)) {
            assume(cst);
        }
    }
}

void ebpf_transformer::operator()(const Undefined& a) {}

// Simple truncation function usable with swap_endianness().
template <class T>
constexpr T truncate(T x) noexcept {
    return x;
}

void ebpf_transformer::operator()(const Un& stmt) {
    const auto dst = reg_pack(stmt.dst);
    auto swap_endianness = [&](const variable_t v, auto be_or_le) {
        if (m_inv.entail(type_is_number(stmt.dst))) {
            if (const auto n = m_inv.eval_interval(v).singleton()) {
                if (n->fits_cast_to<int64_t>()) {
                    m_inv.set(v, interval_t{be_or_le(n->cast_to<int64_t>())});
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
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint16_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint16_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint16_t>);
            swap_endianness(dst.uvalue, truncate<uint16_t>);
        }
        break;
    case Un::Op::BE32:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint32_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint32_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint32_t>);
            swap_endianness(dst.uvalue, truncate<uint32_t>);
        }
        break;
    case Un::Op::BE64:
        if (!thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<int64_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint64_t>);
        }
        break;
    case Un::Op::LE16:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint16_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint16_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint16_t>);
            swap_endianness(dst.uvalue, truncate<uint16_t>);
        }
        break;
    case Un::Op::LE32:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<uint32_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint32_t>);
        } else {
            swap_endianness(dst.svalue, truncate<uint32_t>);
            swap_endianness(dst.uvalue, truncate<uint32_t>);
        }
        break;
    case Un::Op::LE64:
        if (thread_local_options.big_endian) {
            swap_endianness(dst.svalue, boost::endian::endian_reverse<int64_t>);
            swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint64_t>);
        }
        break;
    case Un::Op::SWAP16:
        swap_endianness(dst.svalue, boost::endian::endian_reverse<uint16_t>);
        swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint16_t>);
        break;
    case Un::Op::SWAP32:
        swap_endianness(dst.svalue, boost::endian::endian_reverse<uint32_t>);
        swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint32_t>);
        break;
    case Un::Op::SWAP64:
        swap_endianness(dst.svalue, boost::endian::endian_reverse<int64_t>);
        swap_endianness(dst.uvalue, boost::endian::endian_reverse<uint64_t>);
        break;
    case Un::Op::NEG:
        neg(dst.svalue, dst.uvalue, stmt.is64 ? 64 : 32);
        havoc_offsets(stmt.dst);
        break;
    }
}

void ebpf_transformer::operator()(const Exit& a) {
    // Clean up any state for the current stack frame.
    const std::string prefix = a.stack_frame_prefix;
    if (prefix.empty()) {
        return;
    }
    havoc_subprogram_stack(prefix);
    restore_callee_saved_registers(prefix);

    // Restore r10.
    constexpr Reg r10_reg{R10_STACK_POINTER};
    add(r10_reg, EBPF_SUBPROGRAM_STACK_SIZE, 64);
}

void ebpf_transformer::operator()(const Jmp&) const {
    // This is a NOP. It only exists to hold the jump preconditions.
}

void ebpf_transformer::operator()(const Packet& a) {
    const auto reg = reg_pack(R0_RETURN_VALUE);
    constexpr Reg r0_reg{R0_RETURN_VALUE};
    type_inv.assign_type(m_inv, r0_reg, T_NUM);
    havoc_offsets(r0_reg);
    havoc(reg.svalue);
    havoc(reg.uvalue);
    scratch_caller_saved_registers();
}

void ebpf_transformer::do_load_stack(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr,
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

void ebpf_transformer::do_load_ctx(NumAbsDomain& inv, const Reg& target_reg, const linear_expression_t& addr_vague,
                                   const int width) {
    using namespace crab::dsl_syntax;
    if (inv.is_bottom()) {
        return;
    }

    const ebpf_context_descriptor_t* desc = thread_local_program_info->type.context_descriptor;

    const reg_pack_t& target = reg_pack(target_reg);

    if (desc->end < 0) {
        havoc_register(inv, target_reg);
        type_inv.assign_type(inv, target_reg, T_NUM);
        return;
    }

    const interval_t interval = inv.eval_interval(addr_vague);
    const std::optional<number_t> maybe_addr = interval.singleton();
    havoc_register(inv, target_reg);

    const bool may_touch_ptr =
        interval.contains(desc->data) || interval.contains(desc->meta) || interval.contains(desc->end);

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

void ebpf_transformer::do_load_packet_or_shared(NumAbsDomain& inv, const Reg& target_reg,
                                                const linear_expression_t& addr, const int width) {
    if (inv.is_bottom()) {
        return;
    }
    const reg_pack_t& target = reg_pack(target_reg);

    type_inv.assign_type(inv, target_reg, T_NUM);
    havoc_register(inv, target_reg);

    // A 1 or 2 byte copy results in a limited range of values that may be used as array indices.
    if (width == 1) {
        const interval_t full = interval_t::full<uint8_t>();
        inv.set(target.svalue, full);
        inv.set(target.uvalue, full);
    } else if (width == 2) {
        const interval_t full = interval_t::full<uint16_t>();
        inv.set(target.svalue, full);
        inv.set(target.uvalue, full);
    }
}

void ebpf_transformer::do_load(const Mem& b, const Reg& target_reg) {
    using namespace crab::dsl_syntax;

    const auto mem_reg = reg_pack(b.access.basereg);
    const int width = b.access.width;
    const int offset = b.access.offset;

    if (b.access.basereg.v == R10_STACK_POINTER) {
        const linear_expression_t addr = mem_reg.stack_offset + offset;
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
            linear_expression_t addr = mem_reg.ctx_offset + offset;
            do_load_ctx(inv, target_reg, addr, width);
            break;
        }
        case T_STACK: {
            linear_expression_t addr = mem_reg.stack_offset + offset;
            do_load_stack(inv, target_reg, addr, width, b.access.basereg);
            break;
        }
        case T_PACKET: {
            linear_expression_t addr = mem_reg.packet_offset + offset;
            do_load_packet_or_shared(inv, target_reg, addr, width);
            break;
        }
        default: {
            linear_expression_t addr = mem_reg.shared_offset + offset;
            do_load_packet_or_shared(inv, target_reg, addr, width);
            break;
        }
        }
    });
}

void ebpf_transformer::do_store_stack(NumAbsDomain& inv, const linear_expression_t& addr, const int width,
                                      const linear_expression_t& val_type, const linear_expression_t& val_svalue,
                                      const linear_expression_t& val_uvalue,
                                      const std::optional<reg_pack_t>& opt_val_reg) {
    {
        const std::optional<variable_t> var = stack.store_type(inv, addr, width, val_type);
        type_inv.assign_type(inv, var, val_type);
    }
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
        if (m_inv.intersect(dsl_syntax::operator<=(addr, stack_offset_variable + stack_numeric_size_variable)) &&
            m_inv.intersect(operator>=(addr + width, stack_offset_variable))) {
            havoc(stack_numeric_size_variable);
            recompute_stack_numeric_size(m_inv, type_variable);
        }
    }
}

void ebpf_transformer::operator()(const Mem& b) {
    if (m_inv.is_bottom()) {
        return;
    }
    if (const auto preg = std::get_if<Reg>(&b.value)) {
        if (b.is_load) {
            do_load(b, *preg);
        } else {
            const auto data_reg = reg_pack(*preg);
            do_mem_store(b, data_reg.type, data_reg.svalue, data_reg.uvalue, data_reg);
        }
    } else {
        const uint64_t imm = std::get<Imm>(b.value).v;
        do_mem_store(b, T_NUM, to_signed(imm), imm, {});
    }
}

void ebpf_transformer::do_mem_store(const Mem& b, const linear_expression_t& val_type,
                                    const linear_expression_t& val_svalue, const linear_expression_t& val_uvalue,
                                    const std::optional<reg_pack_t>& opt_val_reg) {
    if (m_inv.is_bottom()) {
        return;
    }
    const int width = b.access.width;
    const number_t offset{b.access.offset};
    if (b.access.basereg.v == R10_STACK_POINTER) {
        const auto r10_stack_offset = reg_pack(b.access.basereg).stack_offset;
        const auto r10_interval = m_inv.eval_interval(r10_stack_offset);
        if (r10_interval.is_singleton()) {
            const int32_t stack_offset = r10_interval.singleton()->cast_to<int32_t>();
            const number_t base_addr{stack_offset};
            do_store_stack(m_inv, base_addr + offset, width, val_type, val_svalue, val_uvalue, opt_val_reg);
        }
        return;
    }
    m_inv = type_inv.join_over_types(m_inv, b.access.basereg, [&](NumAbsDomain& inv, const type_encoding_t type) {
        if (type == T_STACK) {
            const auto base_addr = linear_expression_t(dom.get_type_offset_variable(b.access.basereg, type).value());
            do_store_stack(inv, dsl_syntax::operator+(base_addr, offset), width, val_type, val_svalue, val_uvalue,
                           opt_val_reg);
        }
        // do nothing for any other type
    });
}

// Construct a Bin operation that does the main operation that a given Atomic operation does atomically.
static Bin atomic_to_bin(const Atomic& a) {
    Bin bin{.dst = Reg{R11_ATOMIC_SCRATCH}, .v = a.valreg, .is64 = a.access.width == sizeof(uint64_t), .lddw = false};
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

void ebpf_transformer::operator()(const Atomic& a) {
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

void ebpf_transformer::operator()(const Call& call) {
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
            auto variable = dom.get_type_offset_variable(param.mem);
            if (!variable.has_value()) {
                // checked by the checker
                break;
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

    constexpr Reg r0_reg{R0_RETURN_VALUE};
    const auto r0_pack = reg_pack(r0_reg);
    havoc(r0_pack.stack_numeric_size);
    if (call.is_map_lookup) {
        // This is the only way to get a null pointer
        if (maybe_fd_reg) {
            if (const auto map_type = dom.get_map_type(*maybe_fd_reg)) {
                if (thread_local_program_info->platform->get_map_type(*map_type).value_type == EbpfMapValueType::MAP) {
                    if (const auto inner_map_fd = dom.get_map_inner_map_fd(*maybe_fd_reg)) {
                        do_load_mapfd(r0_reg, to_signed(*inner_map_fd), true);
                        goto out;
                    }
                } else {
                    assign_valid_ptr(r0_reg, true);
                    assign(r0_pack.shared_offset, 0);
                    m_inv.set(r0_pack.shared_region_size, dom.get_map_value_size(*maybe_fd_reg));
                    type_inv.assign_type(m_inv, r0_reg, T_SHARED);
                }
            }
        }
        assign_valid_ptr(r0_reg, true);
        assign(r0_pack.shared_offset, 0);
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

void ebpf_transformer::operator()(const CallLocal& call) {
    using namespace crab::dsl_syntax;
    if (m_inv.is_bottom()) {
        return;
    }
    save_callee_saved_registers(call.stack_frame_prefix);

    // Update r10.
    constexpr Reg r10_reg{R10_STACK_POINTER};
    add(r10_reg, -EBPF_SUBPROGRAM_STACK_SIZE, 64);
}

void ebpf_transformer::operator()(const Callx& callx) {
    using namespace crab::dsl_syntax;
    if (m_inv.is_bottom()) {
        return;
    }

    // Look up the helper function id.
    const reg_pack_t& reg = reg_pack(callx.func);
    const auto src_interval = m_inv.eval_interval(reg.svalue);
    if (const auto sn = src_interval.singleton()) {
        if (sn->fits<int32_t>()) {
            // We can now process it as if the id was immediate.
            const int32_t imm = sn->cast_to<int32_t>();
            if (!thread_local_program_info->platform->is_helper_usable(imm)) {
                return;
            }
            const Call call = make_call(imm, *thread_local_program_info->platform);
            (*this)(call);
        }
    }
}

void ebpf_transformer::do_load_mapfd(const Reg& dst_reg, const int mapfd, const bool maybe_null) {
    const EbpfMapDescriptor& desc = thread_local_program_info->platform->get_map_descriptor(mapfd);
    const EbpfMapType& type = thread_local_program_info->platform->get_map_type(desc.type);
    if (type.value_type == EbpfMapValueType::PROGRAM) {
        type_inv.assign_type(m_inv, dst_reg, T_MAP_PROGRAMS);
    } else {
        type_inv.assign_type(m_inv, dst_reg, T_MAP);
    }
    const reg_pack_t& dst = reg_pack(dst_reg);
    assign(dst.map_fd, mapfd);
    assign_valid_ptr(dst_reg, maybe_null);
}

void ebpf_transformer::operator()(const LoadMapFd& ins) { do_load_mapfd(ins.dst, ins.mapfd, false); }

void ebpf_transformer::assign_valid_ptr(const Reg& dst_reg, const bool maybe_null) {
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
    assign(reg.uvalue, reg.svalue);
}

// If nothing is known of the stack_numeric_size,
// try to recompute the stack_numeric_size.
void ebpf_transformer::recompute_stack_numeric_size(NumAbsDomain& inv, const variable_t type_variable) const {
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

void ebpf_transformer::recompute_stack_numeric_size(NumAbsDomain& inv, const Reg& reg) const {
    recompute_stack_numeric_size(inv, reg_pack(reg).type);
}

void ebpf_transformer::add(const Reg& reg, const int imm, const int finite_width) {
    const auto dst = reg_pack(reg);
    const auto offset = dom.get_type_offset_variable(reg);
    add_overflow(dst.svalue, dst.uvalue, imm, finite_width);
    if (offset.has_value()) {
        add(offset.value(), imm);
        if (imm > 0) {
            // Since the start offset is increasing but
            // the end offset is not, the numeric size decreases.
            sub(dst.stack_numeric_size, imm);
        } else if (imm < 0) {
            havoc(dst.stack_numeric_size);
        }
        recompute_stack_numeric_size(m_inv, reg);
    }
}

void ebpf_transformer::shl(const Reg& dst_reg, int imm, const int finite_width) {
    const reg_pack_t dst = reg_pack(dst_reg);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;

    if (m_inv.entail(type_is_number(dst))) {
        const auto interval = m_inv.eval_interval(dst.uvalue);
        if (interval.finite_size()) {
            const number_t lb = interval.lb().number().value();
            const number_t ub = interval.ub().number().value();
            uint64_t lb_n = lb.cast_to<uint64_t>();
            uint64_t ub_n = ub.cast_to<uint64_t>();
            const uint64_t uint_max = finite_width == 64 ? uint64_t{std::numeric_limits<uint64_t>::max()}
                                                         : uint64_t{std::numeric_limits<uint32_t>::max()};
            if (lb_n >> (finite_width - imm) != ub_n >> (finite_width - imm)) {
                // The bits that will be shifted out to the left are different,
                // which means all combinations of remaining bits are possible.
                lb_n = 0;
                ub_n = uint_max << imm & uint_max;
            } else {
                // The bits that will be shifted out to the left are identical
                // for all values in the interval, so we can safely shift left
                // to get a new interval.
                lb_n = lb_n << imm & uint_max;
                ub_n = ub_n << imm & uint_max;
            }
            m_inv.set(dst.uvalue, interval_t{lb_n, ub_n});
            m_inv.assign(dst.svalue, dst.uvalue);
            overflow_signed(m_inv, dst.svalue, finite_width);
            overflow_unsigned(m_inv, dst.uvalue, finite_width);
            return;
        }
    }
    shl_overflow(dst.svalue, dst.uvalue, imm);
    havoc_offsets(dst_reg);
}

void ebpf_transformer::lshr(const Reg& dst_reg, int imm, int finite_width) {
    reg_pack_t dst = reg_pack(dst_reg);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;

    if (m_inv.entail(type_is_number(dst))) {
        auto interval = m_inv.eval_interval(dst.uvalue);
        number_t lb_n{0};
        number_t ub_n{std::numeric_limits<uint64_t>::max() >> imm};
        if (interval.finite_size()) {
            number_t lb = interval.lb().number().value();
            number_t ub = interval.ub().number().value();
            if (finite_width == 64) {
                lb_n = lb.cast_to<uint64_t>() >> imm;
                ub_n = ub.cast_to<uint64_t>() >> imm;
            } else {
                number_t lb_w = lb.cast_to_sint(finite_width);
                number_t ub_w = ub.cast_to_sint(finite_width);
                lb_n = lb_w.cast_to<uint32_t>() >> imm;
                ub_n = ub_w.cast_to<uint32_t>() >> imm;

                // The interval must be valid since a signed range crossing 0
                // was earlier converted to a full unsigned range.
                assert(lb_n <= ub_n);
            }
        }
        m_inv.set(dst.uvalue, interval_t{lb_n, ub_n});
        m_inv.assign(dst.svalue, dst.uvalue);
        overflow_signed(m_inv, dst.svalue, finite_width);
        overflow_unsigned(m_inv, dst.uvalue, finite_width);
        return;
    }
    havoc(dst.svalue);
    havoc(dst.uvalue);
    havoc_offsets(dst_reg);
}

static int _movsx_bits(const Bin::Op op) {
    switch (op) {
    case Bin::Op::MOVSX8: return 8;
    case Bin::Op::MOVSX16: return 16;
    case Bin::Op::MOVSX32: return 32;
    default: throw std::exception();
    }
}

void ebpf_transformer::sign_extend(const Reg& dst_reg, const linear_expression_t& right_svalue, const int finite_width,
                                   const Bin::Op op) {
    using namespace crab;

    const int bits = _movsx_bits(op);
    const reg_pack_t dst = reg_pack(dst_reg);
    interval_t right_interval = m_inv.eval_interval(right_svalue);
    type_inv.assign_type(m_inv, dst_reg, T_NUM);
    havoc_offsets(dst_reg);
    const int64_t span = 1ULL << bits;
    if (right_interval.ub() - right_interval.lb() >= span) {
        // Interval covers the full space.
        if (bits == 64) {
            havoc(dst.svalue);
            return;
        }
        right_interval = interval_t::signed_int(bits);
    }
    const int64_t mask = 1ULL << (bits - 1);

    // Sign extend each bound.
    int64_t lb = right_interval.lb().number().value().cast_to<int64_t>();
    lb &= span - 1;
    lb = (lb ^ mask) - mask;
    int64_t ub = right_interval.ub().number().value().cast_to<int64_t>();
    ub &= span - 1;
    ub = (ub ^ mask) - mask;
    m_inv.set(dst.svalue, interval_t{lb, ub});

    if (finite_width) {
        m_inv.assign(dst.uvalue, dst.svalue);
        overflow_signed(m_inv, dst.svalue, finite_width);
        overflow_unsigned(m_inv, dst.uvalue, finite_width);
    }
}

void ebpf_transformer::ashr(const Reg& dst_reg, const linear_expression_t& right_svalue, int finite_width) {
    using namespace crab;

    reg_pack_t dst = reg_pack(dst_reg);
    if (m_inv.entail(type_is_number(dst))) {
        interval_t left_interval = interval_t::bottom();
        interval_t right_interval = interval_t::bottom();
        interval_t left_interval_positive = interval_t::bottom();
        interval_t left_interval_negative = interval_t::bottom();
        get_signed_intervals(m_inv, finite_width == 64, dst.svalue, dst.uvalue, right_svalue, left_interval,
                             right_interval, left_interval_positive, left_interval_negative);
        if (auto sn = right_interval.singleton()) {
            // The BPF ISA requires masking the imm.
            int64_t imm = sn->cast_to<int64_t>() & (finite_width - 1);

            int64_t lb_n = std::numeric_limits<int64_t>::min() >> imm;
            int64_t ub_n = std::numeric_limits<int64_t>::max() >> imm;
            if (left_interval.finite_size()) {
                const auto [lb, ub] = left_interval.pair_number();
                if (finite_width == 64) {
                    lb_n = lb.cast_to<int64_t>() >> imm;
                    ub_n = ub.cast_to<int64_t>() >> imm;
                } else {
                    number_t lb_w = lb.cast_to_sint(finite_width) >> gsl::narrow<int>(imm);
                    number_t ub_w = ub.cast_to_sint(finite_width) >> gsl::narrow<int>(imm);
                    if (lb_w.cast_to<uint32_t>() <= ub_w.cast_to<uint32_t>()) {
                        lb_n = lb_w.cast_to<uint32_t>();
                        ub_n = ub_w.cast_to<uint32_t>();
                    }
                }
            }
            m_inv.set(dst.svalue, interval_t{lb_n, ub_n});
            m_inv.assign(dst.uvalue, dst.svalue);
            overflow_signed(m_inv, dst.svalue, finite_width);
            overflow_unsigned(m_inv, dst.uvalue, finite_width);
            return;
        }
    }
    havoc(dst.svalue);
    havoc(dst.uvalue);
    havoc_offsets(dst_reg);
}

static void apply(NumAbsDomain& inv, const binop_t& op, const variable_t x, const variable_t y, const variable_t z) {
    inv.apply(op, x, y, z, 0);
}

void ebpf_transformer::operator()(const Bin& bin) {
    using namespace crab::dsl_syntax;

    auto dst = reg_pack(bin.dst);
    int finite_width = bin.is64 ? 64 : 32;

    if (auto pimm = std::get_if<Imm>(&bin.v)) {
        // dst += K
        int64_t imm;
        if (bin.is64) {
            // Use the full signed value.
            imm = to_signed(pimm->v);
        } else {
            // Use only the low 32 bits of the value.
            imm = gsl::narrow_cast<int32_t>(pimm->v);
            bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
            // If this is a 32-bit operation and the destination is not a number, forget everything about the register.
            if (!type_inv.has_type(m_inv, bin.dst, T_NUM)) {
                havoc_register(m_inv, bin.dst);
                havoc_offsets(bin.dst);
                havoc(dst.type);
            }
        }
        switch (bin.op) {
        case Bin::Op::MOV:
            assign(dst.svalue, imm);
            assign(dst.uvalue, imm);
            overflow_unsigned(m_inv, dst.uvalue, bin.is64 ? 64 : 32);
            type_inv.assign_type(m_inv, bin.dst, T_NUM);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32: CRAB_ERROR("Unsupported operation");
        case Bin::Op::ADD:
            if (imm == 0) {
                return;
            }
            add(bin.dst, gsl::narrow<int>(imm), finite_width);
            break;
        case Bin::Op::SUB:
            if (imm == 0) {
                return;
            }
            add(bin.dst, gsl::narrow<int>(-imm), finite_width);
            break;
        case Bin::Op::MUL:
            mul(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            udiv(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            urem(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            sdiv(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            srem(dst.svalue, dst.uvalue, imm, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            bitwise_or(dst.svalue, dst.uvalue, imm);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            bitwise_and(dst.svalue, dst.uvalue, imm);
            if (gsl::narrow<int32_t>(imm) > 0) {
                // AND with immediate is only a 32-bit operation so svalue and uvalue are the same.
                assume(dst.svalue <= imm);
                assume(dst.uvalue <= imm);
                assume(0 <= dst.svalue);
                assume(0 <= dst.uvalue);
            }
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH: shl(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::RSH: lshr(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::ARSH: ashr(bin.dst, gsl::narrow<int32_t>(imm), finite_width); break;
        case Bin::Op::XOR:
            bitwise_xor(dst.svalue, dst.uvalue, imm);
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
                add_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
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
                                    if (const auto dst_offset = dom.get_type_offset_variable(bin.dst, src_type)) {
                                        crab::apply(inv, arith_binop_t::ADD, dst_offset.value(), dst.svalue,
                                                    dom.get_type_offset_variable(src_reg, src_type).value());
                                    }
                                    if (src_type == T_SHARED) {
                                        inv.assign(dst.shared_region_size, src.shared_region_size);
                                    }
                                } else if (dst_type != T_NUM && src_type == T_NUM) {
                                    // ptr += num
                                    type_inv.assign_type(inv, bin.dst, dst_type);
                                    if (const auto dst_offset = dom.get_type_offset_variable(bin.dst, dst_type)) {
                                        crab::apply(inv, arith_binop_t::ADD, dst_offset.value(), dst_offset.value(),
                                                    src.svalue);
                                        if (dst_type == T_STACK) {
                                            // Reduce the numeric size.
                                            using namespace crab::dsl_syntax;
                                            if (m_inv.intersect(src.svalue < 0)) {
                                                inv -= dst.stack_numeric_size;
                                                recompute_stack_numeric_size(inv, dst.type);
                                            } else {
                                                apply_signed(inv, arith_binop_t::SUB, dst.stack_numeric_size,
                                                             dst.stack_numeric_size, dst.stack_numeric_size, src.svalue,
                                                             0);
                                            }
                                        }
                                    }
                                } else if (dst_type == T_NUM && src_type == T_NUM) {
                                    // dst and src don't necessarily have the same type, but among the possibilities
                                    // enumerated is the case where they are both numbers.
                                    apply_signed(inv, arith_binop_t::ADD, dst.svalue, dst.uvalue, dst.svalue,
                                                 src.svalue, finite_width);
                                } else {
                                    // We ignore the cases here that do not match the assumption described
                                    // above.  Joining bottom with another results will leave the other
                                    // results unchanged.
                                    inv.set_to_bottom();
                                }
                            });
                    });
                // careful: change dst.value only after dealing with offset
                apply_signed(m_inv, arith_binop_t::ADD, dst.svalue, dst.uvalue, dst.svalue, src.svalue, finite_width);
            }
            break;
        }
        case Bin::Op::SUB: {
            if (type_inv.same_type(m_inv, bin.dst, std::get<Reg>(bin.v))) {
                // src and dest have the same type.
                m_inv = type_inv.join_over_types(m_inv, bin.dst, [&](NumAbsDomain& inv, const type_encoding_t type) {
                    switch (type) {
                    case T_NUM:
                        // This is: sub_overflow(inv, dst.value, src.value, finite_width);
                        apply_signed(inv, arith_binop_t::SUB, dst.svalue, dst.uvalue, dst.svalue, src.svalue,
                                     finite_width);
                        type_inv.assign_type(inv, bin.dst, T_NUM);
                        crab::havoc_offsets(inv, bin.dst);
                        break;
                    default:
                        // ptr -= ptr
                        // Assertions should make sure we only perform this on non-shared pointers.
                        if (const auto dst_offset = dom.get_type_offset_variable(bin.dst, type)) {
                            apply_signed(inv, arith_binop_t::SUB, dst.svalue, dst.uvalue, dst_offset.value(),
                                         dom.get_type_offset_variable(src_reg, type).value(), finite_width);
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
                if (type_inv.get_type(m_inv, std::get<Reg>(bin.v)) != T_NUM) {
                    type_inv.havoc_type(m_inv, bin.dst);
                    havoc(dst.svalue);
                    havoc(dst.uvalue);
                    havoc_offsets(bin.dst);
                } else {
                    sub_overflow(dst.svalue, dst.uvalue, src.svalue, finite_width);
                    if (auto dst_offset = dom.get_type_offset_variable(bin.dst)) {
                        sub(dst_offset.value(), src.svalue);
                        if (type_inv.has_type(m_inv, dst.type, T_STACK)) {
                            // Reduce the numeric size.
                            using namespace crab::dsl_syntax;
                            if (m_inv.intersect(src.svalue > 0)) {
                                m_inv -= dst.stack_numeric_size;
                                recompute_stack_numeric_size(m_inv, dst.type);
                            } else {
                                crab::apply(m_inv, arith_binop_t::ADD, dst.stack_numeric_size, dst.stack_numeric_size,
                                            src.svalue);
                            }
                        }
                    }
                }
            }
            break;
        }
        case Bin::Op::MUL:
            mul(dst.svalue, dst.uvalue, src.svalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UDIV:
            udiv(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::UMOD:
            urem(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SDIV:
            sdiv(dst.svalue, dst.uvalue, src.svalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::SMOD:
            srem(dst.svalue, dst.uvalue, src.svalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::OR:
            bitwise_or(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::AND:
            bitwise_and(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::LSH:
            if (m_inv.entail(type_is_number(src_reg))) {
                auto src_interval = m_inv.eval_interval(src.uvalue);
                if (std::optional<number_t> sn = src_interval.singleton()) {
                    // truncate to uint64?
                    uint64_t imm = sn->cast_to<uint64_t>() & (bin.is64 ? 63 : 31);
                    if (imm <= std::numeric_limits<int32_t>::max()) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
                        }
                        shl(bin.dst, gsl::narrow_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            shl_overflow(dst.svalue, dst.uvalue, src.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::RSH:
            if (m_inv.entail(type_is_number(src_reg))) {
                auto src_interval = m_inv.eval_interval(src.uvalue);
                if (std::optional<number_t> sn = src_interval.singleton()) {
                    uint64_t imm = sn->cast_to<uint64_t>() & (bin.is64 ? 63 : 31);
                    if (imm <= std::numeric_limits<int32_t>::max()) {
                        if (!bin.is64) {
                            // Use only the low 32 bits of the value.
                            bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
                        }
                        lshr(bin.dst, gsl::narrow_cast<int32_t>(imm), finite_width);
                        break;
                    }
                }
            }
            havoc(dst.svalue);
            havoc(dst.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::ARSH:
            if (m_inv.entail(type_is_number(src_reg))) {
                ashr(bin.dst, src.svalue, finite_width);
                break;
            }
            havoc(dst.svalue);
            havoc(dst.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::XOR:
            bitwise_xor(dst.svalue, dst.uvalue, src.uvalue, finite_width);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32:
            // Keep relational information if operation is a no-op.
            if (dst.svalue == src.svalue &&
                m_inv.eval_interval(dst.svalue) <= interval_t::signed_int(_movsx_bits(bin.op))) {
                return;
            }
            if (m_inv.entail(type_is_number(src_reg))) {
                sign_extend(bin.dst, src.svalue, finite_width, bin.op);
                break;
            }
            havoc(dst.svalue);
            havoc(dst.uvalue);
            havoc_offsets(bin.dst);
            break;
        case Bin::Op::MOV:
            // Keep relational information if operation is a no-op.
            if (dst.svalue == src.svalue &&
                m_inv.eval_interval(dst.uvalue) <= interval_t::unsigned_int(bin.is64 ? 64 : 32)) {
                return;
            }
            assign(dst.svalue, src.svalue);
            assign(dst.uvalue, src.uvalue);
            havoc_offsets(bin.dst);
            m_inv = type_inv.join_over_types(m_inv, src_reg, [&](NumAbsDomain& inv, const type_encoding_t type) {
                switch (type) {
                case T_CTX:
                    if (bin.is64) {
                        inv.assign(dst.type, type);
                        inv.assign(dst.ctx_offset, src.ctx_offset);
                    }
                    break;
                case T_MAP:
                case T_MAP_PROGRAMS:
                    if (bin.is64) {
                        inv.assign(dst.type, type);
                        inv.assign(dst.map_fd, src.map_fd);
                    }
                    break;
                case T_PACKET:
                    if (bin.is64) {
                        inv.assign(dst.type, type);
                        inv.assign(dst.packet_offset, src.packet_offset);
                    }
                    break;
                case T_SHARED:
                    if (bin.is64) {
                        inv.assign(dst.type, type);
                        inv.assign(dst.shared_region_size, src.shared_region_size);
                        inv.assign(dst.shared_offset, src.shared_offset);
                    }
                    break;
                case T_STACK:
                    if (bin.is64) {
                        inv.assign(dst.type, type);
                        inv.assign(dst.stack_offset, src.stack_offset);
                        inv.assign(dst.stack_numeric_size, src.stack_numeric_size);
                    }
                    break;
                default: inv.assign(dst.type, type); break;
                }
            });
            if (bin.is64) {
                // Add dst.type=src.type invariant.
                if (bin.dst.v != std::get<Reg>(bin.v).v || type_inv.get_type(m_inv, dst.type) == T_UNINIT) {
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
        bitwise_and(dst.svalue, dst.uvalue, std::numeric_limits<uint32_t>::max());
    }
}

void ebpf_transformer::initialize_loop_counter(const label_t& label) {
    m_inv.assign(variable_t::loop_counter(to_string(label)), 0);
}

void ebpf_transformer::operator()(const IncrementLoopCounter& ins) {
    const auto counter = variable_t::loop_counter(to_string(ins.name));
    this->add(counter, 1);
}

void ebpf_domain_initialize_loop_counter(ebpf_domain_t& dom, const label_t& label) {
    ebpf_transformer{dom}.initialize_loop_counter(label);
}

} // namespace crab
