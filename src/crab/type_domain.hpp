// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

namespace crab {

using domains::NumAbsDomain;

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

inline reg_pack_t reg_pack(const int i) {
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
inline reg_pack_t reg_pack(const Reg r) { return reg_pack(r.v); }

struct TypeDomain {
    void assign_type(NumAbsDomain& inv, const Reg& lhs, type_encoding_t t);
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const Reg& rhs);
    void assign_type(NumAbsDomain& inv, const Reg& lhs, const std::optional<linear_expression_t>& rhs);
    void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const Reg& rhs);
    void assign_type(NumAbsDomain& inv, std::optional<variable_t> lhs, const number_t& rhs);

    void havoc_type(NumAbsDomain& inv, const Reg& r);

    [[nodiscard]]
    int get_type(const NumAbsDomain& inv, variable_t v) const;
    [[nodiscard]]
    int get_type(const NumAbsDomain& inv, const Reg& r) const;
    [[nodiscard]]
    int get_type(const NumAbsDomain& inv, const number_t& t) const;

    [[nodiscard]]
    bool has_type(const NumAbsDomain& inv, variable_t v, type_encoding_t type) const;
    [[nodiscard]]
    bool has_type(const NumAbsDomain& inv, const Reg& r, type_encoding_t type) const;
    [[nodiscard]]
    bool has_type(const NumAbsDomain& inv, const number_t& t, type_encoding_t type) const;

    [[nodiscard]]
    bool same_type(const NumAbsDomain& inv, const Reg& a, const Reg& b) const;
    [[nodiscard]]
    bool implies_type(const NumAbsDomain& inv, const linear_constraint_t& a, const linear_constraint_t& b) const;

    [[nodiscard]]
    NumAbsDomain join_over_types(const NumAbsDomain& inv, const Reg& reg,
                                 const std::function<void(NumAbsDomain&, type_encoding_t)>& transition) const;
    [[nodiscard]]
    NumAbsDomain join_by_if_else(const NumAbsDomain& inv, const linear_constraint_t& condition,
                                 const std::function<void(NumAbsDomain&)>& if_true,
                                 const std::function<void(NumAbsDomain&)>& if_false) const;
    void selectively_join_based_on_type(NumAbsDomain& dst, NumAbsDomain& src) const;
    void add_extra_invariant(const NumAbsDomain& dst, std::map<variable_t, interval_t>& extra_invariants,
                             variable_t type_variable, type_encoding_t type, data_kind_t kind,
                             const NumAbsDomain& src) const;

    [[nodiscard]]
    bool is_in_group(const NumAbsDomain& inv, const Reg& r, TypeGroup group) const;
};

} // namespace crab