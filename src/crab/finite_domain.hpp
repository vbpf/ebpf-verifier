// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <utility>

#include "crab/interval.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/split_dbm.hpp"
#include "crab/thresholds.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

namespace crab::domains {

class FiniteDomain final {
    SplitDBM dom;

    explicit FiniteDomain(const SplitDBM& dom) : dom{dom} {}

  public:
    explicit FiniteDomain() = default;

    FiniteDomain(const FiniteDomain& o) = default;
    FiniteDomain(FiniteDomain&& o) = default;

    FiniteDomain& operator=(const FiniteDomain& o) = default;
    FiniteDomain& operator=(FiniteDomain&& o) = default;

    void operator+=(const linear_constraint_t& cst) { dom.add_constraint(cst); }

    void operator-=(const variable_t v) { dom -= v; }

    void assign(const variable_t x, const linear_expression_t& e) { dom.assign(x, e); }
    void assign(const variable_t x, const int64_t e) { dom.set(x, crab::interval_t(number_t(e))); }

    void apply(const arith_binop_t op, const variable_t x, const variable_t y, const number_t& z,
               const int finite_width) {
        dom.apply(op, x, y, z, finite_width);
    }

    void apply(const arith_binop_t op, const variable_t x, const variable_t y, const variable_t z,
               const int finite_width) {
        dom.apply(op, x, y, z, finite_width);
    }

    void apply(const bitwise_binop_t op, const variable_t x, const variable_t y, const variable_t z,
               const int finite_width) {
        dom.apply(op, x, y, z, finite_width);
    }

    void apply(const bitwise_binop_t op, const variable_t x, const variable_t y, const number_t& k,
               const int finite_width) {
        dom.apply(op, x, y, k, finite_width);
    }

    void apply(binop_t op, variable_t x, variable_t y, const number_t& z, int finite_width) {
        std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
    }

    void apply(binop_t op, variable_t x, variable_t y, variable_t z, int finite_width) {
        std::visit([&](auto top) { apply(top, x, y, z, finite_width); }, op);
    }

    void overflow_bounds(variable_t lhs, number_t span, int finite_width, bool is_signed);

    void overflow_signed(const variable_t lhs, const int finite_width) {
        const auto span{finite_width == 64   ? z_number{std::numeric_limits<uint64_t>::max()}
                        : finite_width == 32 ? z_number{std::numeric_limits<uint32_t>::max()}
                                             : throw std::exception()};
        overflow_bounds(lhs, span, finite_width, true);
    }

    void overflow_unsigned(const variable_t lhs, const int finite_width) {
        const auto span{finite_width == 64   ? z_number{std::numeric_limits<uint64_t>::max()}
                        : finite_width == 32 ? z_number{std::numeric_limits<uint32_t>::max()}
                                             : throw std::exception()};
        overflow_bounds(lhs, span, finite_width, false);
    }

    void apply_signed(const binop_t& op, const variable_t xs, const variable_t xu, const variable_t y,
                      const number_t& z, const int finite_width) {
        apply(op, xs, y, z, finite_width);
        if (finite_width) {
            assign(xu, xs);
            overflow_signed(xs, finite_width);
            overflow_unsigned(xu, finite_width);
        }
    }

    void apply_unsigned(const binop_t& op, const variable_t xs, const variable_t xu, const variable_t y,
                        const number_t& z, const int finite_width) {
        apply(op, xu, y, z, finite_width);
        if (finite_width) {
            assign(xs, xu);
            overflow_signed(xs, finite_width);
            overflow_unsigned(xu, finite_width);
        }
    }

    void apply_signed(const binop_t& op, const variable_t xs, const variable_t xu, const variable_t y,
                      const variable_t z, const int finite_width) {
        apply(op, xs, y, z, finite_width);
        if (finite_width) {
            assign(xu, xs);
            overflow_signed(xs, finite_width);
            overflow_unsigned(xu, finite_width);
        }
    }

    void apply_unsigned(const binop_t& op, const variable_t xs, const variable_t xu, const variable_t y,
                        const variable_t z, const int finite_width = 0) {
        apply(op, xu, y, z, finite_width);
        if (finite_width) {
            assign(xs, xu);
            overflow_signed(xs, finite_width);
            overflow_unsigned(xu, finite_width);
        }
    }

    void sign_extend(variable_t svalue, variable_t uvalue, const linear_expression_t& right_svalue, int finite_width,
                     int bits);
    void add(const variable_t lhs, const variable_t op2) { apply_signed(arith_binop_t::ADD, lhs, lhs, lhs, op2, 0); }
    void add(const variable_t lhs, const number_t& op2) { apply_signed(arith_binop_t::ADD, lhs, lhs, lhs, op2, 0); }
    void sub(const variable_t lhs, const variable_t op2) { apply_signed(arith_binop_t::SUB, lhs, lhs, lhs, op2, 0); }
    void sub(const variable_t lhs, const number_t& op2) { apply_signed(arith_binop_t::SUB, lhs, lhs, lhs, op2, 0); }

    // Add/subtract with overflow are both signed and unsigned. We can use either one of the two to compute the
    // result before adjusting for overflow, though if one is top we want to use the other to retain precision.
    void add_overflow(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_signed(arith_binop_t::ADD, lhss, lhsu, ((!dom.eval_interval(lhss).is_top()) ? lhss : lhsu), op2,
                     finite_width);
    }
    void add_overflow(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_signed(arith_binop_t::ADD, lhss, lhsu, ((!dom.eval_interval(lhss).is_top()) ? lhss : lhsu), op2,
                     finite_width);
    }
    void sub_overflow(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_signed(arith_binop_t::SUB, lhss, lhsu, ((!dom.eval_interval(lhss).is_top()) ? lhss : lhsu), op2,
                     finite_width);
    }
    void sub_overflow(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_signed(arith_binop_t::SUB, lhss, lhsu, ((!dom.eval_interval(lhss).is_top()) ? lhss : lhsu), op2,
                     finite_width);
    }

    void neg(const variable_t lhss, const variable_t lhsu, const int finite_width) {
        apply_signed(arith_binop_t::MUL, lhss, lhsu, lhss, (number_t)-1, finite_width);
    }
    void mul(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_signed(arith_binop_t::MUL, lhss, lhsu, lhss, op2, finite_width);
    }
    void mul(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_signed(arith_binop_t::MUL, lhss, lhsu, lhss, op2, finite_width);
    }
    void sdiv(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_signed(arith_binop_t::SDIV, lhss, lhsu, lhss, op2, finite_width);
    }
    void sdiv(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_signed(arith_binop_t::SDIV, lhss, lhsu, lhss, op2, finite_width);
    }
    void udiv(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_unsigned(arith_binop_t::UDIV, lhss, lhsu, lhsu, op2, finite_width);
    }
    void udiv(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_unsigned(arith_binop_t::UDIV, lhss, lhsu, lhsu, op2, finite_width);
    }
    void srem(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_signed(arith_binop_t::SREM, lhss, lhsu, lhss, op2, finite_width);
    }
    void srem(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_signed(arith_binop_t::SREM, lhss, lhsu, lhss, op2, finite_width);
    }
    void urem(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_unsigned(arith_binop_t::UREM, lhss, lhsu, lhsu, op2, finite_width);
    }
    void urem(const variable_t lhss, const variable_t lhsu, const number_t& op2, const int finite_width) {
        apply_unsigned(arith_binop_t::UREM, lhss, lhsu, lhsu, op2, finite_width);
    }

    void bitwise_and(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_unsigned(bitwise_binop_t::AND, lhss, lhsu, lhsu, op2, finite_width);
    }
    void bitwise_and(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
        // Use finite width 64 to make the svalue be set as well as the uvalue.
        apply_unsigned(bitwise_binop_t::AND, lhss, lhsu, lhsu, op2, 64);
    }
    void bitwise_or(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_unsigned(bitwise_binop_t::OR, lhss, lhsu, lhsu, op2, finite_width);
    }
    void bitwise_or(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
        apply_unsigned(bitwise_binop_t::OR, lhss, lhsu, lhsu, op2, 64);
    }
    void bitwise_xor(const variable_t lhss, const variable_t lhsu, const variable_t op2, const int finite_width) {
        apply_unsigned(bitwise_binop_t::XOR, lhss, lhsu, lhsu, op2, finite_width);
    }
    void bitwise_xor(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
        apply_unsigned(bitwise_binop_t::XOR, lhss, lhsu, lhsu, op2, 64);
    }
    void shl_overflow(const variable_t lhss, const variable_t lhsu, const variable_t op2) {
        apply_unsigned(bitwise_binop_t::SHL, lhss, lhsu, lhsu, op2, 64);
    }
    void shl_overflow(const variable_t lhss, const variable_t lhsu, const number_t& op2) {
        apply_unsigned(bitwise_binop_t::SHL, lhss, lhsu, lhsu, op2, 64);
    }

    void shl(variable_t svalue, variable_t uvalue, int imm, int finite_width);

    void lshr(variable_t svalue, variable_t uvalue, int imm, int finite_width);

    bool ashr(variable_t svalue, variable_t uvalue, const linear_expression_t& right_svalue, int finite_width);

  private:
    std::vector<linear_constraint_t>
    assume_unsigned_64bit_lt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                             const interval_t& left_interval_low, const interval_t& left_interval_high,
                             const linear_expression_t& right_svalue, const linear_expression_t& right_uvalue,
                             const interval_t& right_interval) const;

    std::vector<linear_constraint_t> assume_unsigned_32bit_lt(bool strict, variable_t left_svalue,
                                                              variable_t left_uvalue,
                                                              const linear_expression_t& right_svalue,
                                                              const linear_expression_t& right_uvalue,
                                                              const interval_t& right_interval) const;

    std::vector<linear_constraint_t> assume_unsigned_32bit_gt(bool strict, variable_t left_svalue,
                                                              variable_t left_uvalue,
                                                              const linear_expression_t& right_svalue,
                                                              const linear_expression_t& right_uvalue,
                                                              const interval_t& right_interval) const;

    // Given left and right values, get the left and right intervals, and also split
    // the left interval into separate low and high intervals.
    void get_unsigned_intervals(bool is64, variable_t left_svalue, variable_t left_uvalue,
                                const linear_expression_t& right_uvalue, interval_t& left_interval,
                                interval_t& right_interval, interval_t& left_interval_low,
                                interval_t& left_interval_high) const;

    // Given left and right values, get the left and right intervals, and also split
    // the left interval into separate negative and positive intervals.
    void get_signed_intervals(bool is64, variable_t left_svalue, variable_t left_uvalue,
                              const linear_expression_t& right_svalue, interval_t& left_interval,
                              interval_t& right_interval, interval_t& left_interval_positive,
                              interval_t& left_interval_negative) const;
    std::vector<linear_constraint_t> assume_signed_32bit_lt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& left_interval_positive,
                                                            const interval_t& left_interval_negative,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue,
                                                            const interval_t& right_interval) const;

    std::vector<linear_constraint_t> assume_signed_32bit_gt(bool strict, variable_t left_svalue, variable_t left_uvalue,
                                                            const interval_t& left_interval_positive,
                                                            const interval_t& left_interval_negative,
                                                            const linear_expression_t& right_svalue,
                                                            const linear_expression_t& right_uvalue,
                                                            const interval_t& right_interval) const;

  public:
    std::vector<linear_constraint_t> assume_bit_cst_interval(Condition::Op op, bool is64, variable_t dst_uvalue,
                                                             interval_t src_interval) const;

    std::vector<linear_constraint_t> assume_signed_cst_interval(Condition::Op op, bool is64, variable_t left_svalue,
                                                                variable_t left_uvalue,
                                                                const linear_expression_t& right_svalue,
                                                                const linear_expression_t& right_uvalue) const;

    std::vector<linear_constraint_t> assume_unsigned_cst_interval(Condition::Op op, bool is64, variable_t left_svalue,
                                                                  variable_t left_uvalue,
                                                                  const linear_expression_t& right_svalue,
                                                                  const linear_expression_t& right_uvalue) const;
    void set_to_top() { dom.set_to_top(); }

    static FiniteDomain top() { return FiniteDomain(); }

    [[nodiscard]]
    bool is_top() const {
        return dom.is_top();
    }

    bool operator<=(const FiniteDomain& o) const { return dom <= o.dom; }

    // FIXME: can be done more efficient
    void operator|=(const FiniteDomain& o) { *this = *this | o; }
    void operator|=(FiniteDomain&& o) { *this = *this | std::move(o); }

    FiniteDomain operator|(const FiniteDomain& o) const& { return FiniteDomain{dom | o.dom}; }

    FiniteDomain operator|(FiniteDomain&& o) && { return FiniteDomain{std::move(dom) | o.dom}; }

    FiniteDomain operator|(const FiniteDomain& o) && { return FiniteDomain{std::move(dom) | o.dom}; }

    FiniteDomain operator|(FiniteDomain&& o) const& { return FiniteDomain{dom | o.dom}; }

    [[nodiscard]]
    FiniteDomain widen(const FiniteDomain& o) const {
        return FiniteDomain{dom.widen(o.dom)};
    }

    [[nodiscard]]
    FiniteDomain widening_thresholds(const FiniteDomain& o, const thresholds_t& ts) const {
        // TODO: use thresholds
        return this->widen(o);
    }

    std::optional<FiniteDomain> meet(const FiniteDomain& o) const {
        const auto res = dom.meet(o.dom);
        if (!res) {
            return {};
        }
        return FiniteDomain{*res};
    }

    [[nodiscard]]
    FiniteDomain narrow(const FiniteDomain& o) const {
        return FiniteDomain{dom.narrow(o.dom)};
    }
    void assign(auto lhs, auto e) { dom.assign(lhs, e); }

    void apply(auto op, auto x, auto y, auto z, int finite_width = 0) { dom.apply(op, x, y, z, finite_width); }

    bool add_constraint(const linear_constraint_t& cst) { return dom.add_constraint(cst); }

    [[nodiscard]]
    interval_t eval_interval(const linear_expression_t& e) const {
        return dom.eval_interval(e);
    }

    interval_t operator[](const variable_t x) const { return dom[x]; }

    void set(const variable_t x, const interval_t& intv) { dom.set(x, intv); }

    void forget(auto variables) { dom.forget(variables); }

    [[nodiscard]]
    std::pair<std::size_t, std::size_t> size() const {
        return dom.size();
    }

    // Return true if inv intersects with cst.
    [[nodiscard]]
    bool intersect(const linear_constraint_t& cst) const {
        return dom.intersect(cst);
    }

    // Return true if entails rhs.
    [[nodiscard]]
    bool entail(const linear_constraint_t& rhs) const {
        return dom.entail(rhs);
    }

    friend std::ostream& operator<<(std::ostream& o, const FiniteDomain& dom) { return o << dom.dom; }

    [[nodiscard]]
    string_invariant to_set() const {
        return dom.to_set();
    }

    static void clear_thread_local_state() { SplitDBM::clear_thread_local_state(); }
}; // class FiniteDomain

} // namespace crab::domains
