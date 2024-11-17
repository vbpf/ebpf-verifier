// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
// ReSharper disable CppMemberFunctionMayBeStatic

// This file is eBPF-specific, not derived from CRAB.
#include <functional>
#include <map>
#include <optional>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/type_domain.hpp"
#include "crab/type_encoding.hpp"
#include "crab/variable.hpp"
#include "crab_utils/debug.hpp"
#include "dsl_syntax.hpp"

namespace crab {

template <is_enum T>
static void operator++(T& t) {
    t = static_cast<T>(1 + static_cast<std::underlying_type_t<T>>(t));
}

std::vector<data_kind_t> iterate_kinds(const data_kind_t lb, const data_kind_t ub) {
    if (lb > ub) {
        CRAB_ERROR("lower bound ", lb, " is greater than upper bound ", ub);
    }
    if (lb < KIND_MIN || ub > KIND_MAX) {
        CRAB_ERROR("bounds ", lb, " and ", ub, " are out of range");
    }
    std::vector<data_kind_t> res;
    for (data_kind_t i = lb; i <= ub; ++i) {
        res.push_back(i);
    }
    return res;
}

std::vector<type_encoding_t> iterate_types(const type_encoding_t lb, const type_encoding_t ub) {
    if (lb > ub) {
        CRAB_ERROR("lower bound ", lb, " is greater than upper bound ", ub);
    }
    if (lb < T_MIN || ub > T_MAX) {
        CRAB_ERROR("bounds ", lb, " and ", ub, " are out of range");
    }
    std::vector<type_encoding_t> res;
    for (type_encoding_t i = lb; i <= ub; ++i) {
        res.push_back(i);
    }
    return res;
}

static constexpr auto S_UNINIT = "uninit";
static constexpr auto S_STACK = "stack";
static constexpr auto S_PACKET = "packet";
static constexpr auto S_CTX = "ctx";
static constexpr auto S_MAP_PROGRAMS = "map_fd_programs";
static constexpr auto S_MAP = "map_fd";
static constexpr auto S_NUM = "number";
static constexpr auto S_SHARED = "shared";

std::string name_of(const data_kind_t kind) {
    switch (kind) {
    case data_kind_t::ctx_offsets: return "ctx_offset";
    case data_kind_t::map_fds: return "map_fd";
    case data_kind_t::packet_offsets: return "packet_offset";
    case data_kind_t::shared_offsets: return "shared_offset";
    case data_kind_t::shared_region_sizes: return "shared_region_size";
    case data_kind_t::stack_numeric_sizes: return "stack_numeric_size";
    case data_kind_t::stack_offsets: return "stack_offset";
    case data_kind_t::svalues: return "svalue";
    case data_kind_t::types: return "type";
    case data_kind_t::uvalues: return "uvalue";
    }
    return {};
}

data_kind_t regkind(const std::string& s) {
    static const std::map<std::string, data_kind_t> string_to_kind{
        {"type", data_kind_t::types},
        {"ctx_offset", data_kind_t::ctx_offsets},
        {"map_fd", data_kind_t::map_fds},
        {"packet_offset", data_kind_t::packet_offsets},
        {"shared_offset", data_kind_t::shared_offsets},
        {"stack_offset", data_kind_t::stack_offsets},
        {"shared_region_size", data_kind_t::shared_region_sizes},
        {"stack_numeric_size", data_kind_t::stack_numeric_sizes},
        {"svalue", data_kind_t::svalues},
        {"uvalue", data_kind_t::uvalues},
    };
    if (string_to_kind.contains(s)) {
        return string_to_kind.at(s);
    }
    throw std::runtime_error(std::string() + "Bad kind: " + s);
}

std::ostream& operator<<(std::ostream& os, const type_encoding_t s) {
    switch (s) {
    case T_SHARED: return os << S_SHARED;
    case T_STACK: return os << S_STACK;
    case T_PACKET: return os << S_PACKET;
    case T_CTX: return os << S_CTX;
    case T_NUM: return os << S_NUM;
    case T_MAP: return os << S_MAP;
    case T_MAP_PROGRAMS: return os << S_MAP_PROGRAMS;
    case T_UNINIT: return os << S_UNINIT;
    default: CRAB_ERROR("Unsupported type encoding", s);
    }
}

type_encoding_t string_to_type_encoding(const std::string& s) {
    static std::map<std::string, type_encoding_t> string_to_type{
        {S_UNINIT, T_UNINIT}, {S_MAP_PROGRAMS, T_MAP_PROGRAMS},
        {S_MAP, T_MAP},       {S_NUM, T_NUM},
        {S_CTX, T_CTX},       {S_STACK, T_STACK},
        {S_PACKET, T_PACKET}, {S_SHARED, T_SHARED},
    };
    if (string_to_type.contains(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(std::string("Unsupported type name: ") + s);
}
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

void TypeDomain::selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain&& src) const {
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
    for (const auto& [variable, interval] : extra_invariants) {
        dst.set(variable, interval);
    }
}

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs) {
    inv.assign(reg_pack(lhs).type, reg_pack(rhs).type);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const std::optional<variable_t> lhs, const linear_expression_t& t) {
    inv.assign(lhs, t);
}

void TypeDomain::assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs) {
    inv.assign(reg_pack(lhs).type, rhs);
}

void TypeDomain::havoc_type(NumAbsDomain& inv, const Reg& r) { inv -= reg_pack(r).type; }

type_encoding_t TypeDomain::get_type(const NumAbsDomain& inv, const linear_expression_t& v) const {
    const auto res = inv.eval_interval(v).singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<type_encoding_t>();
}

type_encoding_t TypeDomain::get_type(const NumAbsDomain& inv, const Reg& r) const {
    const auto res = inv[reg_pack(r).type].singleton();
    if (!res) {
        return T_UNINIT;
    }
    return res->narrow<type_encoding_t>();
}

// Check whether a given type value is within the range of a given type variable's value.
bool TypeDomain::has_type(const NumAbsDomain& inv, const Reg& r, const type_encoding_t type) const {
    const interval_t interval = inv[reg_pack(r).type];
    return interval.contains(type);
}

bool TypeDomain::has_type(const NumAbsDomain& inv, const linear_expression_t& v, const type_encoding_t type) const {
    const interval_t interval = inv.eval_interval(v);
    return interval.contains(type);
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
    auto [lb, ub] = types.bound(T_MIN, T_MAX);
    for (type_encoding_t type : iterate_types(lb, ub)) {
        NumAbsDomain tmp(inv);
        transition(tmp, type);
        selectively_join_based_on_type(res, std::move(tmp)); // res |= tmp;
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
    case TypeGroup::mem: return inv.entail(t >= T_PACKET);
    case TypeGroup::mem_or_num: return inv.entail(t >= T_NUM) && inv.entail(t != T_CTX);
    case TypeGroup::pointer: return inv.entail(t >= T_CTX);
    case TypeGroup::ptr_or_num: return inv.entail(t >= T_NUM);
    case TypeGroup::stack_or_packet: return inv.entail(t >= T_PACKET) && inv.entail(t <= T_STACK);
    case TypeGroup::singleton_ptr: return inv.entail(t >= T_CTX) && inv.entail(t <= T_STACK);
    default: CRAB_ERROR("Unsupported type group", group);
    }
}

std::string typeset_to_string(const std::vector<type_encoding_t>& items) {
    std::stringstream ss;
    ss << "{";
    for (auto it = items.begin(); it != items.end(); ++it) {
        ss << *it;
        if (std::next(it) != items.end()) {
            ss << ", ";
        }
    }
    ss << "}";
    return ss.str();
}

bool is_singleton_type(const TypeGroup t) {
    switch (t) {
    case TypeGroup::number:
    case TypeGroup::map_fd:
    case TypeGroup::map_fd_programs:
    case TypeGroup::ctx:
    case TypeGroup::packet:
    case TypeGroup::stack:
    case TypeGroup::shared: return true;
    default: return false;
    }
}

std::ostream& operator<<(std::ostream& os, const TypeGroup ts) {
    using namespace crab;
    static const std::map<TypeGroup, std::string> string_to_type{
        {TypeGroup::number, S_NUM},
        {TypeGroup::map_fd, S_MAP},
        {TypeGroup::map_fd_programs, S_MAP_PROGRAMS},
        {TypeGroup::ctx, S_CTX},
        {TypeGroup::packet, S_PACKET},
        {TypeGroup::stack, S_STACK},
        {TypeGroup::shared, S_SHARED},
        {TypeGroup::mem, typeset_to_string({T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::pointer, typeset_to_string({T_CTX, T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::ptr_or_num, typeset_to_string({T_NUM, T_CTX, T_STACK, T_PACKET, T_SHARED})},
        {TypeGroup::stack_or_packet, typeset_to_string({T_STACK, T_PACKET})},
        {TypeGroup::singleton_ptr, typeset_to_string({T_CTX, T_STACK, T_PACKET})},
        {TypeGroup::mem_or_num, typeset_to_string({T_NUM, T_STACK, T_PACKET, T_SHARED})},
    };
    if (string_to_type.contains(ts)) {
        return os << string_to_type.at(ts);
    }
    CRAB_ERROR("Unsupported type group", ts);
}

} // namespace crab
