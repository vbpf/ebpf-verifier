// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include <iosfwd>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

#include "crab_utils/bignums.hpp"
#include "crab_utils/debug.hpp"
using index_t = uint64_t;

/* Basic type definitions */

namespace crab {

// data_kind_t is eBPF-specific.
enum class data_kind_t { types, values, ctx_offsets, map_fds, packet_offsets, shared_offsets, stack_offsets, shared_region_sizes, stack_numeric_sizes };
std::ostream& operator<<(std::ostream& o, const data_kind_t& s);

// Wrapper for typed variables used by the crab abstract domains and linear_constraints.
// Being a class (instead of a type alias) enables overloading in dsl_syntax
class variable_t final {
    index_t _id;

    explicit variable_t(index_t id) : _id(id) {}

  public:
    [[nodiscard]] std::size_t hash() const { return (size_t)_id; }

    bool operator==(variable_t o) const { return _id == o._id; }

    bool operator!=(variable_t o) const { return (!(operator==(o))); }

    // for flat_map
    bool operator<(variable_t o) const { return _id < o._id; }


    [[nodiscard]] std::string name() const { return names.at(_id); }

    [[nodiscard]] bool is_type() const { return names.at(_id).find(".type") != std::string::npos; }

    friend std::ostream& operator<<(std::ostream& o, variable_t v)  { return o << names.at(v._id); }

    // var_factory portion.
    // This singleton is eBPF-specific, to avoid lifetime issues and/or passing factory explicitly everywhere:
  private:
    static variable_t make(const std::string& name);
    static thread_local std::vector<std::string> names;

  public:
    static void clear_thread_local_state();

    static std::vector<variable_t> get_type_variables();
    static variable_t reg(data_kind_t, int);
    static variable_t cell_var(data_kind_t array, index_t offset, unsigned size);
    static variable_t kind_var(data_kind_t kind, variable_t type_variable);
    static variable_t meta_offset();
    static variable_t packet_size();
    static variable_t instruction_count();
    [[nodiscard]] bool is_in_stack() const;

    struct Hasher {
        std::size_t operator()(const variable_t& v) const { return v.hash(); }
    };
}; // class variable_t

} // namespace crab
