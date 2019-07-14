#pragma once

/*
 * Factories for variable names.
 */

#include "crab/types.hpp"

#include <optional>
#include <unordered_map>

#include <limits>

namespace crab {

class variable_factory;

using var_key = std::string;
// FIXME: we should use some unlimited precision type to avoid overflow.
// However, this change is a bit involving since we need to change the
// algorithm api's in patricia_trees.hpp because they assume ikos::index_t.
using ikos::index_t;

class indexed_string {
    friend class variable_factory;

  private:
    std::optional<var_key> _s;
    index_t _id;
    std::string _name; // optional string name associated with _id
    variable_factory *_vfac;

    // NOT IMPLEMENTED
    indexed_string();

    indexed_string(index_t id, variable_factory *vfac, std::string name = "") : _id(id), _name(name), _vfac(vfac) {}

    indexed_string(var_key s, index_t id, variable_factory *vfac) : _s(s), _id(id), _name(""), _vfac(vfac) {}

  public:
    indexed_string(const indexed_string &is) : _s(is._s), _id(is._id), _name(is._name), _vfac(is._vfac) {}

    indexed_string &operator=(const indexed_string &is) {
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

    variable_factory &get_var_factory() { return *_vfac; }

    bool operator<(indexed_string s) const { return (_id < s._id); }

    bool operator==(indexed_string s) const { return (_id == s._id); }

    void write(crab_os &o) const { o << str(); }

    friend crab_os &operator<<(crab_os &o, indexed_string s) {
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
class variable_factory {
    using t_map_t = std::unordered_map<var_key, indexed_string>;
    using shadow_map_t = std::unordered_map<index_t, indexed_string>;

    index_t _next_id{1};
    t_map_t _map;
    shadow_map_t _shadow_map;
    std::vector<indexed_string> _shadow_vars;

    index_t get_and_increment_id();

  public:
    variable_factory() {};
    variable_factory(const variable_factory &) = delete;

    // hook for generating indexed_string's without being
    // associated with a particular var_key (w/o caching).
    // XXX: do not use it unless strictly necessary.
    indexed_string get();

    // generate a shadow indexed_string's associated to some key
    indexed_string get(index_t key, std::string name = "");

    indexed_string operator[](var_key s);
};

} // end namespace crab
