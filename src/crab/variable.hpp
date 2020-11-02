#pragma once

#include <iosfwd>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

#include "crab_utils/bignums.hpp"
#include "crab_utils/debug.hpp"
#include "crab_utils/patricia_trees.hpp"

/* Basic type definitions */

namespace crab {

enum class data_kind_t { types, values, offsets };
std::ostream& operator<<(std::ostream& o, const data_kind_t& s);

// Container for typed variables used by the crab abstract domains
// and linear_constraints.
class variable_t final {
    index_t _id;
    static std::vector<std::string> names;

    explicit variable_t(index_t id) : _id(id) {}
    static variable_t make(const std::string& name);

  public:
    variable_t(const variable_t& o) = default;
    variable_t(variable_t&& o) = default;

    variable_t& operator=(const variable_t& o) = default;

    index_t index() const { return _id; }

    std::size_t hash() const { return (size_t)_id; }

    bool operator==(const variable_t& o) const { return _id == o._id; }

    bool operator!=(const variable_t& o) const { return (!(operator==(o))); }

    bool operator<(const variable_t& o) const { return _id < o._id; }

    friend std::ostream& operator<<(std::ostream& o, const variable_t& v)  { return o << names.at(v._id); }
    std::string name() const { return names.at(_id); }

    static variable_t reg(data_kind_t, int);
    static variable_t cell_var(data_kind_t array, index_t offset, unsigned size);
    static variable_t map_value_size();
    static variable_t map_key_size();
    static variable_t meta_offset();
    static variable_t packet_size();
}; // class variable_t

inline size_t hash_value(const variable_t& v) { return v.hash(); }

} // namespace crab
