// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include <optional>
#include <utility>

#include "crab/dsl_syntax.hpp"
#include "crab/finite_domain.hpp"
#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

namespace crab::domains {

static std::vector<linear_constraint_t>
assume_unsigned_64bit_gt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                         const interval_t& left_interval_low, const interval_t& left_interval_high,
                         const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                         const interval_t& right_interval) {
    using namespace dsl_syntax;

    const auto rlb = right_interval.lb();
    const auto llub = left_interval_low.truncate_to_uint(true).ub();
    const auto lhlb = left_interval_high.truncate_to_uint(true).lb();

    if ((right_interval <= interval_t::nonnegative_int(true)) && (strict ? (llub <= rlb) : (llub < rlb))) {
        // The low interval is out of range.
        return {(strict) ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue),
                (*lhlb.number() == number_t(std::numeric_limits<uint64_t>::max())) ? (left_uvalue == *lhlb.number())
                                                                                   : (left_uvalue >= *lhlb.number()),
                left_svalue < 0};
    } else if (right_interval <= interval_t::unsigned_high(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue),
                strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    } else if ((left_interval_low | left_interval_high) <= interval_t::nonnegative_int(true) &&
               right_interval <= interval_t::nonnegative_int(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue),
                strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    } else {
        // Interval can only be represented as a uvalue.
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue)};
    }
}

static std::vector<linear_constraint_t>
assume_signed_64bit_lt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                       const interval_t& left_interval_positive, const interval_t& left_interval_negative,
                       const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                       const interval_t& right_interval) {

    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::negative_int(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1].
        return {strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue), number_t{0} <= left_uvalue,
                strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue)};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::nonnegative_int(true) &&
               right_interval <= interval_t::nonnegative_int(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        return {strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue), number_t{0} <= left_uvalue,
                strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue)};
    } else {
        // Interval can only be represented as an svalue.
        return {strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    }
}

void FiniteDomain::overflow_bounds(variable_t lhs, number_t span, int finite_width, bool is_signed) {
    using namespace crab::dsl_syntax;
    auto interval = (*this)[lhs];
    if (interval.ub() - interval.lb() >= span) {
        // Interval covers the full space.
        (*this) -= lhs;
        return;
    }
    if (interval.is_bottom()) {
        (*this) -= lhs;
        return;
    }
    number_t lb_value = interval.lb().number().value();
    number_t ub_value = interval.ub().number().value();

    // Compute the interval, taking overflow into account.
    // For a signed result, we need to ensure the signed and unsigned results match
    // so for a 32-bit operation, 0x80000000 should be a positive 64-bit number not
    // a sign extended negative one.
    number_t lb = lb_value.truncate_to_unsigned_finite_width(finite_width);
    number_t ub = ub_value.truncate_to_unsigned_finite_width(finite_width);
    if (is_signed) {
        lb = lb.truncate_to_sint64();
        ub = ub.truncate_to_sint64();
    }
    if (lb > ub) {
        // Range wraps in the middle, so we cannot represent as an unsigned interval.
        (*this) -= lhs;
        return;
    }
    auto new_interval = crab::interval_t{lb, ub};
    if (new_interval != interval) {
        // Update the variable, which will lose any relationships to other variables.
        set(lhs, new_interval);
    }
}

void FiniteDomain::sign_extend(const variable_t svalue, const variable_t uvalue,
                               const linear_expression_t& right_svalue, const int finite_width, const int bits) {
    using namespace crab;

    interval_t right_interval = eval_interval(right_svalue);
    const int64_t span = 1ULL << bits;
    if (right_interval.ub() - right_interval.lb() >= number_t{span}) {
        // Interval covers the full space.
        if (bits == 64) {
            dom -= svalue;
            return;
        }
        right_interval = interval_t::signed_int(bits);
    }
    const int64_t mask = 1ULL << (bits - 1);

    // Sign extend each bound.
    int64_t lb = right_interval.lb().number().value().cast_to_sint64();
    lb &= span - 1;
    lb = (lb ^ mask) - mask;
    int64_t ub = right_interval.ub().number().value().cast_to_sint64();
    ub &= span - 1;
    ub = (ub ^ mask) - mask;
    set(svalue, interval_t{number_t{lb}, number_t{ub}});

    if (finite_width) {
        assign(uvalue, svalue);
        overflow_signed(svalue, finite_width);
        overflow_unsigned(uvalue, finite_width);
    }
}

void FiniteDomain::shl(const variable_t svalue, const variable_t uvalue, int imm, const int finite_width) {
    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;

    const auto interval = eval_interval(uvalue);
    if (interval.finite_size()) {
        const number_t lb = interval.lb().number().value();
        const number_t ub = interval.ub().number().value();
        uint64_t lb_n = lb.cast_to_uint64();
        uint64_t ub_n = ub.cast_to_uint64();
        const uint64_t uint_max = (finite_width == 64) ? UINT64_MAX : UINT32_MAX;
        if ((lb_n >> (finite_width - imm)) != (ub_n >> (finite_width - imm))) {
            // The bits that will be shifted out to the left are different,
            // which means all combinations of remaining bits are possible.
            lb_n = 0;
            ub_n = (uint_max << imm) & uint_max;
        } else {
            // The bits that will be shifted out to the left are identical
            // for all values in the interval, so we can safely shift left
            // to get a new interval.
            lb_n = (lb_n << imm) & uint_max;
            ub_n = (ub_n << imm) & uint_max;
        }
        set(uvalue, interval_t{number_t(lb_n), number_t(ub_n)});
        if (static_cast<int64_t>(ub_n) >= static_cast<int64_t>(lb_n)) {
            assign(svalue, uvalue);
        } else {
            dom -= svalue;
        }
        return;
    }
    shl_overflow(svalue, uvalue, imm);
}

void FiniteDomain::lshr(const variable_t svalue, const variable_t uvalue, int imm, int finite_width) {
    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;

    auto interval = eval_interval(uvalue);
    number_t lb_n{0};
    number_t ub_n{UINT64_MAX >> imm};
    if (interval.finite_size()) {
        number_t lb = interval.lb().number().value();
        number_t ub = interval.ub().number().value();
        if (finite_width == 64) {
            lb_n = lb.cast_to_uint64() >> imm;
            ub_n = ub.cast_to_uint64() >> imm;
        } else {
            number_t lb_w = lb.cast_to_signed_finite_width(finite_width);
            number_t ub_w = ub.cast_to_signed_finite_width(finite_width);
            lb_n = lb_w.cast_to_uint32() >> imm;
            ub_n = ub_w.cast_to_uint32() >> imm;

            // The interval must be valid since a signed range crossing 0
            // was earlier converted to a full unsigned range.
            assert(lb_n <= ub_n);
        }
    }
    set(uvalue, interval_t{lb_n, ub_n});
    if (static_cast<int64_t>(ub_n) >= static_cast<int64_t>(lb_n)) {
        // ? m_inv.set(dst.svalue, crab::interval_t{number_t{(int64_t)lb_n}, number_t{(int64_t)ub_n}});
        assign(svalue, uvalue);
    } else {
        dom -= svalue;
    }
}

bool FiniteDomain::ashr(const variable_t svalue, const variable_t uvalue, const linear_expression_t& right_svalue,
                        int finite_width) {
    using namespace crab;

    interval_t left_interval = interval_t::bottom();
    interval_t right_interval = interval_t::bottom();
    interval_t left_interval_positive = interval_t::bottom();
    interval_t left_interval_negative = interval_t::bottom();
    get_signed_intervals(finite_width == 64, svalue, uvalue, right_svalue, left_interval, right_interval,
                         left_interval_positive, left_interval_negative);
    if (auto sn = right_interval.singleton()) {
        // The BPF ISA requires masking the imm.
        int64_t imm = sn->cast_to_sint64() & (finite_width - 1);

        int64_t lb_n = INT64_MIN >> imm;
        int64_t ub_n = INT64_MAX >> imm;
        if (left_interval.finite_size()) {
            number_t lb = left_interval.lb().number().value();
            number_t ub = left_interval.ub().number().value();
            if (finite_width == 64) {
                lb_n = lb.cast_to_sint64() >> imm;
                ub_n = ub.cast_to_sint64() >> imm;
            } else {
                number_t lb_w = lb.cast_to_signed_finite_width(finite_width) >> static_cast<int>(imm);
                number_t ub_w = ub.cast_to_signed_finite_width(finite_width) >> static_cast<int>(imm);
                if (lb_w.cast_to_uint32() <= ub_w.cast_to_uint32()) {
                    lb_n = lb_w.cast_to_uint32();
                    ub_n = ub_w.cast_to_uint32();
                }
            }
        }
        set(svalue, crab::interval_t{number_t{lb_n}, number_t{ub_n}});
        if (static_cast<uint64_t>(ub_n) >= static_cast<uint64_t>(lb_n)) {
            assign(uvalue, svalue);
        } else {
            dom -= uvalue;
        }
        return true;
    } else {
        dom -= svalue;
        dom -= uvalue;
        return false;
    }
}

std::vector<linear_constraint_t>
FiniteDomain::assume_unsigned_64bit_lt(const bool strict, variable_t left_svalue, variable_t left_uvalue,
                                       const interval_t& left_interval_low, const interval_t& left_interval_high,
                                       const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                                       const interval_t& right_interval) const {
    using namespace dsl_syntax;

    auto rub = right_interval.ub();
    auto lllb = left_interval_low.truncate_to_uint(true).lb();
    if ((right_interval <= interval_t::nonnegative_int(true)) && (strict ? (lllb >= rub) : (lllb > rub))) {
        // The high interval is out of range.
        if (auto lsubn = eval_interval(left_svalue).ub().number()) {
            return {left_uvalue >= 0, ((strict) ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue),
                    left_uvalue <= *lsubn, left_svalue >= 0};
        } else {
            return {left_uvalue >= 0, ((strict) ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue),
                    left_svalue >= 0};
        }
    }
    auto lhlb = left_interval_high.truncate_to_uint(true).lb();
    if ((right_interval <= interval_t::unsigned_high(true)) && (strict ? (lhlb >= rub) : (lhlb > rub))) {
        // The high interval is out of range.
        if (auto lsubn = eval_interval(left_svalue).ub().number()) {
            return {left_uvalue >= 0, ((strict) ? left_uvalue < *rub.number() : left_uvalue <= *rub.number()),
                    left_uvalue <= *lsubn, left_svalue >= 0};
        } else {
            return {left_uvalue >= 0, ((strict) ? left_uvalue < *rub.number() : left_uvalue <= *rub.number()),
                    left_svalue >= 0};
        }
    }
    if (right_interval <= interval_t::signed_int(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        auto llub = left_interval_low.truncate_to_uint(true).ub();
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue),
                left_uvalue <= *llub.number(), number_t{0} <= left_svalue,
                strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    } else if (left_interval_low.is_bottom() && right_interval <= interval_t::unsigned_high(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MAX+1, UINT_MAX].
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue),
                strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    } else if ((left_interval_low | left_interval_high) == interval_t::unsigned_int(true)) {
        // Interval can only be represented as a uvalue, and was TOP before.
        return {strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue)};
    } else {
        // Interval can only be represented as a uvalue.
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue)};
    }
}

std::vector<linear_constraint_t> FiniteDomain::assume_unsigned_32bit_lt(const bool strict, variable_t left_svalue,
                                                                        variable_t left_uvalue,
                                                                        const linear_expression_t& right_svalue,
                                                                        const linear_expression_t& right_uvalue,
                                                                        const interval_t& right_interval) const {
    using namespace dsl_syntax;
    auto left_uinterval = eval_interval(left_uvalue);
    auto right_uinterval = eval_interval(right_uvalue);
    auto left_sinterval = eval_interval(left_svalue);
    auto right_sinterval = eval_interval(right_svalue);
    if (left_uinterval <= interval_t::nonnegative_int(false) && right_interval <= interval_t::nonnegative_int(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT32_MAX].
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue),
                strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    } else if (left_sinterval <= interval_t::negative_int(false) &&
               right_sinterval <= interval_t::negative_int(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT32_MIN, -1].
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue),
                strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    } else if (left_uinterval <= interval_t::unsigned_int(false) &&
               right_uinterval <= interval_t::unsigned_int(false)) {
        // Interval can only be represented as a uvalue.
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue)};
    } else {
        // We can't directly compare the uvalues since they may differ in high order bits.
        return {};
    }
}

std::vector<linear_constraint_t> FiniteDomain::assume_unsigned_32bit_gt(const bool strict, const variable_t left_svalue,
                                                                        const variable_t left_uvalue,
                                                                        const linear_expression_t& right_svalue,
                                                                        const linear_expression_t& right_uvalue,
                                                                        const interval_t& right_interval) const {
    using namespace dsl_syntax;

    if (right_interval <= interval_t::unsigned_high(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT32_MAX+1, UINT32_MAX].
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue),
                strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    } else if (eval_interval(left_uvalue) <= interval_t::unsigned_int(false) &&
               eval_interval(right_uvalue) <= interval_t::unsigned_int(false)) {
        // Interval can only be represented as a uvalue.
        return {number_t{0} <= left_uvalue, strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue)};
    } else {
        // We can't directly compare the uvalues since they may differ in high order bits.
        return {};
    };
}

// Given left and right values, get the left and right intervals, and also split
// the left interval into separate low and high intervals.
void FiniteDomain::get_unsigned_intervals(bool is64, const variable_t left_svalue, const variable_t left_uvalue,
                                          const linear_expression_t& right_uvalue, interval_t& left_interval,
                                          interval_t& right_interval, interval_t& left_interval_low,
                                          interval_t& left_interval_high) const {
    using namespace crab::dsl_syntax;

    // Get intervals as 32-bit or 64-bit as appropriate.
    left_interval = eval_interval(left_uvalue);
    right_interval = eval_interval(right_uvalue);
    if (!is64) {
        if ((left_interval <= interval_t::nonnegative_int(false) &&
             right_interval <= interval_t::nonnegative_int(false)) ||
            (left_interval <= interval_t::unsigned_high(false) && right_interval <= interval_t::unsigned_high(false))) {
            is64 = true;
            // fallthrough as 64bit, including deduction of relational information
        } else {
            for (interval_t* interval : {&left_interval, &right_interval}) {
                if (!(*interval <= interval_t::unsigned_int(false))) {
                    *interval = interval->truncate_to_uint(false);
                }
            }
            // continue as 32bit
        }
    }

    if (!left_interval.is_top()) {
        left_interval_low = left_interval & interval_t::nonnegative_int(true);
        left_interval_high = left_interval & interval_t::unsigned_high(true);
    } else {
        left_interval = eval_interval(left_svalue);
        if (!left_interval.is_top()) {
            // The interval is TOP as an unsigned interval but is represented precisely as a signed interval,
            // so split into two unsigned intervals that can be treated separately.
            left_interval_low = interval_t(number_t{0}, left_interval.ub()).truncate_to_uint(true);
            left_interval_high = interval_t(left_interval.lb(), number_t{-1}).truncate_to_uint(true);
        } else {
            left_interval_low = interval_t::nonnegative_int(true);
            left_interval_high = interval_t::unsigned_high(true);
        }
    }

    for (interval_t* interval : {&left_interval, &right_interval}) {
        if (!(*interval <= interval_t::unsigned_int(true))) {
            *interval = interval->truncate_to_uint(true);
        }
    }
}

static std::vector<linear_constraint_t>
assume_signed_64bit_eq(const variable_t left_svalue, const variable_t left_uvalue, const interval_t& right_interval,
                       const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue) {
    using namespace crab::dsl_syntax;
    if (right_interval <= interval_t::nonnegative_int(true) && !right_interval.is_singleton()) {
        return {(left_svalue == right_svalue), (left_uvalue == right_uvalue), eq(left_svalue, left_uvalue)};
    } else {
        return {(left_svalue == right_svalue), (left_uvalue == right_uvalue)};
    }
}

static std::vector<linear_constraint_t> assume_signed_32bit_eq(const variable_t left_svalue,
                                                               const variable_t left_uvalue,
                                                               const interval_t& right_interval,
                                                               const interval_t& left_interval) {
    using namespace crab::dsl_syntax;
    if (const auto rn = right_interval.singleton()) {
        if (auto size = left_interval.finite_size()) {
            // Find the lowest 64-bit svalue whose low 32 bits match the singleton.

            // Get lower bound as a 64-bit value.
            int64_t lb = left_interval.lb().number()->cast_to_sint64();

            // Use the high 32-bits from the left lower bound and the low 32-bits from the right singleton.
            // The result might be lower than the lower bound.
            const int64_t lb_match = ((lb & 0xFFFFFFFF00000000) | (rn->cast_to_sint64() & 0xFFFFFFFF));
            if (lb_match < lb) {
                // The result is lower than the left interval, so try the next higher matching 64-bit value.
                // It's ok if this goes higher than the left upper bound.
                lb += 0x100000000;
            }

            // Find the highest 64-bit svalue whose low 32 bits match the singleton.

            // Get upper bound as a 64-bit value.
            const int64_t ub = left_interval.ub().number()->cast_to_sint64();

            // Use the high 32-bits from the left upper bound and the low 32-bits from the right singleton.
            // The result might be higher than the upper bound.
            const int64_t ub_match = ((ub & 0xFFFFFFFF00000000) | (rn->cast_to_sint64() & 0xFFFFFFFF));
            if (ub_match > ub) {
                // The result is higher than the left interval, so try the next lower matching 64-bit value.
                // It's ok if this goes lower than the left lower bound.
                lb -= 0x100000000;
            }

            if (static_cast<uint64_t>(lb_match) <= static_cast<uint64_t>(ub_match)) {
                // The interval is also valid when cast to a uvalue, meaning
                // both bounds are positive or both are negative.
                return {left_svalue >= lb_match, left_svalue <= ub_match,
                        left_uvalue >= number_t(static_cast<uint64_t>(lb_match)),
                        left_uvalue <= number_t(static_cast<uint64_t>(ub_match))};
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
void FiniteDomain::get_signed_intervals(bool is64, const variable_t left_svalue, const variable_t left_uvalue,
                                        const linear_expression_t& right_svalue, interval_t& left_interval,
                                        interval_t& right_interval, interval_t& left_interval_positive,
                                        interval_t& left_interval_negative) const {

    using namespace crab::dsl_syntax;

    // Get intervals as 32-bit or 64-bit as appropriate.
    left_interval = eval_interval(left_svalue);
    right_interval = eval_interval(right_svalue);
    if (!is64) {
        if ((left_interval <= interval_t::nonnegative_int(false) &&
             right_interval <= interval_t::nonnegative_int(false)) ||
            (left_interval <= interval_t::negative_int(false) && right_interval <= interval_t::negative_int(false))) {
            is64 = true;
            // fallthrough as 64bit, including deduction of relational information
        } else {
            for (interval_t* interval : {&left_interval, &right_interval}) {
                if (!(*interval <= interval_t::signed_int(false))) {
                    *interval = interval->truncate_to_sint(false);
                }
            }
            // continue as 32bit
        }
    }

    if (!left_interval.is_top()) {
        left_interval_positive = left_interval & interval_t::nonnegative_int(true);
        left_interval_negative = left_interval & interval_t::negative_int(true);
    } else {
        left_interval = eval_interval(left_uvalue);
        if (!left_interval.is_top()) {
            // The interval is TOP as a signed interval but is represented precisely as an unsigned interval,
            // so split into two signed intervals that can be treated separately.
            left_interval_positive = left_interval & interval_t::nonnegative_int(true);
            const number_t lih_ub =
                left_interval.ub().number() ? left_interval.ub().number()->truncate_to_sint64() : -1;
            left_interval_negative = interval_t(number_t{std::numeric_limits<int64_t>::min()}, lih_ub);
        } else {
            left_interval_positive = interval_t::nonnegative_int(true);
            left_interval_negative = interval_t::negative_int(true);
        }
    }

    for (interval_t* interval : {&left_interval, &right_interval}) {
        if (!(*interval <= interval_t::signed_int(true))) {
            *interval = interval->truncate_to_sint(true);
        }
    }
}

std::vector<linear_constraint_t>
FiniteDomain::assume_signed_32bit_lt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                                     const interval_t& left_interval_positive, const interval_t& left_interval_negative,
                                     const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                                     const interval_t& right_interval) const {

    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::negative_int(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {left_uvalue >= (number_t{INT32_MAX} + 1),
                strict ? (left_uvalue < right_uvalue) : (left_uvalue <= right_uvalue),
                strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::nonnegative_int(false) &&
               right_interval <= interval_t::nonnegative_int(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX]
        const auto lpub = left_interval_positive.truncate_to_sint(false).ub();
        return {left_svalue >= 0,
                strict ? left_svalue < right_svalue : left_svalue <= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if (eval_interval(left_svalue) <= interval_t::signed_int(false) &&
               eval_interval(right_svalue) <= interval_t::signed_int(false)) {
        // Interval can only be represented as an svalue.
        return {strict ? (left_svalue < right_svalue) : (left_svalue <= right_svalue)};
    } else {
        // We can't directly compare the svalues since they may differ in high order bits.
        return {};
    }
}

std::vector<linear_constraint_t>
assume_signed_64bit_gt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                       const interval_t& left_interval_positive, const interval_t& left_interval_negative,
                       const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                       const interval_t& right_interval) {

    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::nonnegative_int(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        const auto lpub = left_interval_positive.truncate_to_sint(true).ub();
        return {left_svalue >= 0,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::negative_int(true) &&
               right_interval <= interval_t::negative_int(true)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {left_uvalue >= (number_t{INT64_MAX} + 1),
                strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue),
                strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    } else {
        // Interval can only be represented as an svalue.
        return {strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    }
}

std::vector<linear_constraint_t>
FiniteDomain::assume_signed_32bit_gt(const bool strict, const variable_t left_svalue, const variable_t left_uvalue,
                                     const interval_t& left_interval_positive, const interval_t& left_interval_negative,
                                     const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                                     const interval_t& right_interval) const {

    using namespace crab::dsl_syntax;

    if (right_interval <= interval_t::nonnegative_int(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [0, INT_MAX].
        const auto lpub = left_interval_positive.truncate_to_sint(false).ub();
        return {left_svalue >= 0,
                strict ? left_svalue > right_svalue : left_svalue >= right_svalue,
                left_svalue <= left_uvalue,
                left_svalue >= left_uvalue,
                left_uvalue >= 0,
                strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue,
                left_uvalue <= *lpub.number()};
    } else if ((left_interval_negative | left_interval_positive) <= interval_t::negative_int(false) &&
               right_interval <= interval_t::negative_int(false)) {
        // Interval can be represented as both an svalue and a uvalue since it fits in [INT_MIN, -1],
        // aka [INT_MAX+1, UINT_MAX].
        return {left_uvalue >= (number_t{INT32_MAX} + 1),
                strict ? (left_uvalue > right_uvalue) : (left_uvalue >= right_uvalue),
                strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    } else if (eval_interval(left_svalue) <= interval_t::signed_int(false) &&
               eval_interval(right_svalue) <= interval_t::signed_int(false)) {
        // Interval can only be represented as an svalue.
        return {strict ? (left_svalue > right_svalue) : (left_svalue >= right_svalue)};
    } else {
        // We can't directly compare the svalues since they may differ in high order bits.
        return {};
    }
}

std::vector<linear_constraint_t> FiniteDomain::assume_bit_cst_interval(Condition::Op op, bool is64,
                                                                       variable_t dst_uvalue,
                                                                       interval_t src_interval) const {
    using namespace crab::dsl_syntax;
    using Op = Condition::Op;

    auto dst_interval = eval_interval(dst_uvalue);
    std::optional<number_t> dst_n = dst_interval.singleton();
    if (!dst_n || !dst_n.value().fits_cast_to_int64()) {
        return {};
    }

    std::optional<number_t> src_n = src_interval.singleton();
    if (!src_n || !src_n->fits_cast_to_int64()) {
        return {};
    }
    uint64_t src_int_value = src_n.value().cast_to_uint64();
    if (!is64) {
        src_int_value = static_cast<uint32_t>(src_int_value);
    }

    bool result;
    switch (op) {
    case Op::SET: result = ((dst_n.value().cast_to_uint64() & src_int_value) != 0); break;
    case Op::NSET: result = ((dst_n.value().cast_to_uint64() & src_int_value) == 0); break;
    default: throw std::exception();
    }

    return {result ? linear_constraint_t::true_const() : linear_constraint_t::false_const()};
}

std::vector<linear_constraint_t>
FiniteDomain::assume_signed_cst_interval(Condition::Op op, bool is64, variable_t left_svalue, variable_t left_uvalue,
                                         const linear_expression_t& right_svalue,
                                         const linear_expression_t& right_uvalue) const {

    using namespace crab::dsl_syntax;

    interval_t left_interval = interval_t::bottom();
    interval_t right_interval = interval_t::bottom();
    interval_t left_interval_positive = interval_t::bottom();
    interval_t left_interval_negative = interval_t::bottom();
    get_signed_intervals(is64, left_svalue, left_uvalue, right_svalue, left_interval, right_interval,
                         left_interval_positive, left_interval_negative);

    if (op == Condition::Op::EQ) {
        // Handle svalue == right.
        if (is64) {
            return assume_signed_64bit_eq(left_svalue, left_uvalue, right_interval, right_svalue, right_uvalue);
        } else {
            return assume_signed_32bit_eq(left_svalue, left_uvalue, right_interval, eval_interval(left_svalue));
        }
    }

    const bool is_lt = op == Condition::Op::SLT || op == Condition::Op::SLE;
    bool strict = op == Condition::Op::SLT || op == Condition::Op::SGT;

    auto llb = left_interval.lb();
    auto lub = left_interval.ub();
    auto rlb = right_interval.lb();
    auto rub = right_interval.ub();
    if (!is_lt && (strict ? (lub <= rlb) : (lub < rlb))) {
        // Left signed interval is lower than right signed interval.
        return {linear_constraint_t::false_const()};
    } else if (is_lt && (strict ? (llb >= rub) : (llb > rub))) {
        // Left signed interval is higher than right signed interval.
        return {linear_constraint_t::false_const()};
    }
    if (is_lt && (strict ? (lub < rlb) : (lub <= rlb))) {
        // Left signed interval is lower than right signed interval.
        return {linear_constraint_t::true_const()};
    } else if (!is_lt && (strict ? (llb > rub) : (llb >= rub))) {
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
            return assume_signed_32bit_lt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        } else {
            return assume_signed_32bit_gt(strict, left_svalue, left_uvalue, left_interval_positive,
                                          left_interval_negative, right_svalue, right_uvalue, right_interval);
        }
    }
}

std::vector<linear_constraint_t>
FiniteDomain::assume_unsigned_cst_interval(Condition::Op op, bool is64, variable_t left_svalue, variable_t left_uvalue,
                                           const linear_expression_t& right_svalue,
                                           const linear_expression_t& right_uvalue) const {
    using namespace dsl_syntax;

    interval_t left_interval = interval_t::bottom();
    interval_t right_interval = interval_t::bottom();
    interval_t left_interval_low = interval_t::bottom();
    interval_t left_interval_high = interval_t::bottom();
    get_unsigned_intervals(is64, left_svalue, left_uvalue, right_uvalue, left_interval, right_interval,
                           left_interval_low, left_interval_high);

    // Handle uvalue != right.
    if (op == Condition::Op::NE) {
        if (auto rn = right_interval.singleton()) {
            if (rn == left_interval.truncate_to_uint(is64).lb().number()) {
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

    auto llb = left_interval.lb();
    auto lub = left_interval.ub();
    auto rlb = right_interval.lb();
    auto rub = right_interval.ub();
    if (!is_lt && (strict ? (lub <= rlb) : (lub < rlb))) {
        // Left unsigned interval is lower than right unsigned interval.
        return {linear_constraint_t::false_const()};
    } else if (is_lt && (strict ? (llb >= rub) : (llb > rub))) {
        // Left unsigned interval is higher than right unsigned interval.
        return {linear_constraint_t::false_const()};
    }
    if (is_lt && (strict ? (lub < rlb) : (lub <= rlb))) {
        // Left unsigned interval is lower than right unsigned interval. We still add a
        // relationship for use when widening, such as is used in the prime conformance test.
        if (is64) {
            return {strict ? left_uvalue < right_uvalue : left_uvalue <= right_uvalue};
        } else {
            return {linear_constraint_t::true_const()};
        }
    } else if (!is_lt && (strict ? (llb > rub) : (llb >= rub))) {
        // Left unsigned interval is higher than right unsigned interval. We still add a
        // relationship for use when widening, such as is used in the prime conformance test.
        if (is64) {
            return {strict ? left_uvalue > right_uvalue : left_uvalue >= right_uvalue};
        } else {
            return {linear_constraint_t::true_const()};
        }
    }

    if (is64) {
        if (is_lt) {
            return assume_unsigned_64bit_lt(strict, left_svalue, left_uvalue, left_interval_low, left_interval_high,
                                            right_svalue, right_uvalue, right_interval);
        } else {
            return assume_unsigned_64bit_gt(strict, left_svalue, left_uvalue, left_interval_low, left_interval_high,
                                            right_svalue, right_uvalue, right_interval);
        }
    } else {
        if (is_lt) {
            return assume_unsigned_32bit_lt(strict, left_svalue, left_uvalue, right_svalue, right_uvalue,
                                            right_interval);
        } else {
            return assume_unsigned_32bit_gt(strict, left_svalue, left_uvalue, right_svalue, right_uvalue,
                                            right_interval);
        }
    }
}

} // namespace crab::domains
