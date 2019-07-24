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

class variable_factory;

using var_key = std::string;
// FIXME: we should use some unlimited precision type to avoid overflow.
// However, this change is a bit involving since we need to change the
// algorithm api's in patricia_trees.hpp because they assume index_t.

class indexed_string final {
    friend class variable_factory;

  private:
    std::optional<var_key> _s;
    index_t _id;
    std::string _name; // optional string name associated with _id
    variable_factory* _vfac;

    // NOT IMPLEMENTED
    indexed_string();

    indexed_string(index_t id, variable_factory* vfac, std::string name = "") : _id(id), _name(name), _vfac(vfac) {}

    indexed_string(var_key s, index_t id, variable_factory* vfac) : _s(s), _id(id), _name(""), _vfac(vfac) {}

  public:
    indexed_string(const indexed_string& is) : _s(is._s), _id(is._id), _name(is._name), _vfac(is._vfac) {}

    indexed_string& operator=(const indexed_string& is) {
        if (this != &is) {
            _s = is._s;
            _id = is._id;
            _name = is._name;
            _vfac = is._vfac;
        }
        return *this;
    }

    index_t index() const { return this->_id; }

    std::string str() const;

    std::optional<var_key> get() const { return _s ? *_s : std::optional<var_key>(); }

    variable_factory& get_var_factory() { return *_vfac; }

    bool operator<(indexed_string s) const { return (_id < s._id); }

    bool operator==(indexed_string s) const { return (_id == s._id); }

    void write(crab_os& o) const { o << str(); }

    friend crab_os& operator<<(crab_os& o, indexed_string s) {
        o << s.str();
        return o;
    }

    friend size_t hash_value(indexed_string s) {
        std::hash<index_t> hasher;
        return hasher(s.index());
    }
};

using varname_t = indexed_string;

// This variable factory creates a new variable associated to an
// element of type var_key. It can also create variables that are not
// associated to an element of type var_key. We call them shadow variables.
//
// The factory uses a counter of type index_t to generate variable
// id's that always increases.
class variable_factory final {
    using t_map_t = std::unordered_map<var_key, indexed_string>;
    using shadow_map_t = std::unordered_map<index_t, indexed_string>;

    index_t _next_id{1};
    t_map_t _map;
    shadow_map_t _shadow_map;
    std::vector<indexed_string> _shadow_vars;

    index_t get_and_increment_id();

    variable_factory() = default;
  public:
    static variable_factory vfac;

    variable_factory(variable_factory&&) = delete;
    variable_factory(const variable_factory&) = delete;

    // hook for generating indexed_string's without being
    // associated with a particular var_key (w/o caching).
    // XXX: do not use it unless strictly necessary.
    indexed_string get();

    // generate a shadow indexed_string's associated to some key
    indexed_string get(index_t key, std::string name = "");

    indexed_string operator[](var_key s);
};

// Container for typed variables used by the crab abstract domains
// and linear_constraints.
class variable_t final {
    // XXX: template parameter Number is required even if the class
    // does not use it.  This allows, e.g., linear_constraint to
    // deduce the kind of Number from constraints like x < y.

  public:
    using bitwidth_t = unsigned;

  private:
    varname_t _n;
    const bitwidth_t _width{64};

  public:
    variable_t(const varname_t& n) : _n(n) {}

    variable_t(const variable_t& o) : _n(o._n) {}

    variable_t(variable_t&& o) : _n(std::move(o._n))  {}

    variable_t& operator=(const variable_t& o) {
        if (this != &o) {
            _n = o._n;
        }
        return *this;
    }

    const varname_t& name() const { return _n; }

    // Cannot be const because from varname_t we might want to
    // access to its variable factory to create e.g., new
    // varname_t's.
    varname_t& name() { return _n; }

    index_t index() const { return _n.index(); }

    std::size_t hash() const { return (size_t)_n.index(); }

    bool operator==(const variable_t& o) const { return _n.index() == o._n.index(); }

    bool operator!=(const variable_t& o) const { return (!(operator==(o))); }

    void write(crab_os& o) const { o << _n; }

    friend class less;
    struct less {
        bool operator()(variable_t x, variable_t y) const { return x._n.index() < y._n.index(); }
    };
}; // class variable_t

inline size_t hash_value(const variable_t& v) { return v.hash(); }

inline crab_os& operator<<(crab_os& o, const variable_t& v) {
    v.write(o);
    return o;
}

using label_t = std::string;

} // namespace crab
