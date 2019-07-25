#pragma once

#include "crab/bignums.hpp"
#include "crab/debug.hpp"
#include "crab/os.hpp"

#include <iosfwd>
#include <limits>
#include <memory>
#include <optional>
#include <unordered_map>

/* Basic type definitions */

namespace crab {

// Numerical type for indexed objects
using index_t = uint64_t;

using number_t = z_number;

// Interface for writeable objects
class writeable {
  public:
    virtual void write(crab_os& o) = 0;
    virtual ~writeable() {}
}; // class writeable

inline crab_os& operator<<(crab_os& o, writeable& x) {
    x.write(o);
    return o;
}

enum class data_kind_t { regions, values, offsets };
crab_os& operator<<(crab_os& o, const data_kind_t& s);

// Container for typed variables used by the crab abstract domains
// and linear_constraints.
class variable_t final {
    index_t _id;
    static std::vector<std::string> names;

    explicit variable_t(index_t id) : _id(id) { }
    static variable_t make(std::string name);
  public:

    variable_t(const variable_t& o) = default;
    variable_t(variable_t&& o) = default;

    variable_t& operator=(const variable_t& o) = default;

    index_t index() const { return _id; }

    std::size_t hash() const { return (size_t)_id; }

    bool operator==(const variable_t& o) const { return _id == o._id; }

    bool operator!=(const variable_t& o) const { return (!(operator==(o))); }

    void write(crab_os& o) const { o << names.at(_id); }

    friend class less;
    struct less {
        bool operator()(variable_t x, variable_t y) const { return x._id < y._id; }
    };

    static variable_t reg(data_kind_t, int);
    static variable_t cell_var(data_kind_t array, index_t offset, unsigned size);
    static variable_t map_value_size();
    static variable_t map_key_size();
    static variable_t meta_size();
    static variable_t data_size();
}; // class variable_t

inline size_t hash_value(const variable_t& v) { return v.hash(); }

inline crab_os& operator<<(crab_os& o, const variable_t& v) {
    v.write(o);
    return o;
}

using label_t = std::string;

} // namespace crab
