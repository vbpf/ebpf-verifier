// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// ReSharper disable CppMemberFunctionMayBeStatic

// This file is eBPF-specific, not derived from CRAB.
#include <functional>
#include <optional>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/type_domain.hpp"
#include "crab/variable.hpp"

#include "asm_unmarshal.hpp"
#include "dsl_syntax.hpp"
#include "string_constraints.hpp"

namespace crab {

void TypeDomain::add_extra_invariant(const NumAbsDomain& dst, std::map<variable_t, interval_t>& extra_invariants,
                                     const variable_t type_variable, const type_encoding_t type, const data_kind_t kind,
                                     const NumAbsDomain& src) const {
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

void TypeDomain::selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain& src) const {
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

    std::map<variable_t, interval_t> extra_invariants;
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

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const type_encoding_t t) {
    inv.assign(reg_pack(lhs).type, t);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs) {
    inv.assign(reg_pack(lhs).type, reg_pack(rhs).type);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const std::optional<variable_t> lhs, const Reg& rhs) {
    inv.assign(lhs, reg_pack(rhs).type);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const std::optional<variable_t> lhs, const number_t& rhs) {
    inv.assign(lhs, rhs);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs) {
    inv.assign(reg_pack(lhs).type, rhs);
}

void TypeDomain::havoc_type(NumAbsDomain& inv, const Reg& r) { inv -= reg_pack(r).type; }

int TypeDomain::get_type(const NumAbsDomain& inv, const Reg& r) const {
    const auto res = inv[reg_pack(r).type].singleton();
    if (!res) {
        return T_UNINIT;
    }
    return static_cast<int>(*res);
}

int TypeDomain::get_type(const NumAbsDomain& inv, const variable_t v) const {
    const auto res = inv[v].singleton();
    if (!res) {
        return T_UNINIT;
    }
    return static_cast<int>(*res);
}

int TypeDomain::get_type(const NumAbsDomain& inv, const number_t& t) const { return static_cast<int>(t); }

// Check whether a given type value is within the range of a given type variable's value.
bool TypeDomain::has_type(const NumAbsDomain& inv, const Reg& r, const type_encoding_t type) const {
    const interval_t interval = inv[reg_pack(r).type];
    if (interval.is_top()) {
        return true;
    }
    return interval.lb().number().value_or(INT_MIN) <= type && interval.ub().number().value_or(INT_MAX) >= type;
}

bool TypeDomain::has_type(const NumAbsDomain& inv, const variable_t v, const type_encoding_t type) const {
    const interval_t interval = inv[v];
    if (interval.is_top()) {
        return true;
    }
    return interval.lb().number().value_or(INT_MIN) <= type && interval.ub().number().value_or(INT_MAX) >= type;
}

bool TypeDomain::has_type(const NumAbsDomain& inv, const number_t& t, const type_encoding_t type) const {
    return t == number_t{type};
}

NumAbsDomain TypeDomain::join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                         const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const {
    interval_t types = inv.eval_interval(reg_pack(reg).type);
    if (types.is_bottom()) {
        return NumAbsDomain::bottom();
    }
    if (types.is_top()) {
        NumAbsDomain res(inv);
        transition(res, T_UNINIT);
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

NumAbsDomain TypeDomain::join_by_if_else(const NumAbsDomain& inv, const linear_constraint_t& condition,
                                         const std::function<void(NumAbsDomain&)>& if_true,
                                         const std::function<void(NumAbsDomain&)>& if_false) const {
    NumAbsDomain true_case(inv.when(condition));
    if_true(true_case);

    NumAbsDomain false_case(inv.when(condition.negate()));
    if_false(false_case);

    return true_case | false_case;
}

static linear_constraint_t eq_types(const Reg& a, const Reg& b) {
    using namespace crab::dsl_syntax;
    return eq(reg_pack(a).type, reg_pack(b).type);
}

bool TypeDomain::same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const {
    return inv.entail(eq_types(a, b));
}

bool TypeDomain::implies_type(const NumAbsDomain& inv, const linear_constraint_t& a,
                              const linear_constraint_t& b) const {
    return inv.when(a).entail(b);
}

bool TypeDomain::is_in_group(const NumAbsDomain& inv, const Reg& r, const TypeGroup group) const {
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

} // namespace crab