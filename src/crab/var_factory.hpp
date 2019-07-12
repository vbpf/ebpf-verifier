#pragma once

/*
 * Factories for variable names.
 */

#include "crab/types.hpp"

#include <boost/noncopyable.hpp>
#include <boost/optional.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/unordered_map.hpp>

#include <limits>

namespace crab {
namespace cfg {
namespace var_factory_impl {
namespace indexed_string_impl {
template <typename T>
inline std::string get_str(T e);

template <>
inline std::string get_str(std::string e) {
    return e;
}
} // namespace indexed_string_impl

// This variable factory creates a new variable associated to an
// element of type T. It can also create variables that are not
// associated to an element of type T. We call them shadow variables.
//
// The factory uses a counter of type index_t to generate variable
// id's that always increases.
class variable_factory {
    using T = std::string;
    using variable_factory_t = variable_factory;

  public:
    class indexed_string {
        friend class variable_factory;

      public:
        // FIXME: we should use some unlimited precision type to avoid
        // overflow. However, this change is a bit involving since we
        // need to change the algorithm api's in patricia_trees.hpp because
        // they assume ikos::index_t.
        using index_t = ikos::index_t;

      private:
        boost::optional<T> _s;
        index_t _id;
        std::string _name; // optional string name associated with _id
        variable_factory *_vfac;

        // NOT IMPLEMENTED
        indexed_string();

        indexed_string(index_t id, variable_factory *vfac, std::string name = "") : _id(id), _name(name), _vfac(vfac) {}

        indexed_string(T s, index_t id, variable_factory *vfac) : _s(s), _id(id), _name(""), _vfac(vfac) {}

      public:
        ~indexed_string() {}

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

        std::string str() const {
            if (_s) {
                return indexed_string_impl::get_str<T>(*_s);
            } else {
                if (_name != "") {
                    return _name;
                } else {
                    // unlikely prefix
                    return "@V_" + std::to_string(_id);
                }
            }
        }

        boost::optional<T> get() const { return _s ? *_s : boost::optional<T>(); }

        variable_factory &get_var_factory() { return *_vfac; }

        bool operator<(indexed_string s) const { return (_id < s._id); }

        bool operator==(indexed_string s) const { return (_id == s._id); }

        void write(crab_os &o) const { o << str(); }

        friend crab_os &operator<<(crab_os &o, indexed_string s) {
            o << s.str();
            return o;
        }

        friend size_t hash_value(indexed_string s) {
            boost::hash<index_t> hasher;
            return hasher(s.index());
        }
    };

  public:
    using index_t = typename indexed_string::index_t;

  private:
    using t_map_t = boost::unordered_map<T, indexed_string>;
    using shadow_map_t = boost::unordered_map<index_t, indexed_string>;

    index_t _next_id;
    t_map_t _map;
    shadow_map_t _shadow_map;
    std::vector<indexed_string> _shadow_vars;

    index_t get_and_increment_id(void) {
        if (_next_id == std::numeric_limits<index_t>::max()) {
            CRAB_ERROR("Reached limit of ", std::numeric_limits<index_t>::max(), " variables");
        }
        index_t res = _next_id;
        ++_next_id;
        return res;
    }

  public:
    using varname_t = indexed_string;
    using var_range = boost::iterator_range<typename std::vector<indexed_string>::iterator>;
    using const_var_range = boost::iterator_range<typename std::vector<indexed_string>::const_iterator>;

    variable_factory(const variable_factory&) = delete;

    variable_factory() : _next_id(1) {}

    variable_factory(index_t start_id) : _next_id(start_id) {}

    virtual ~variable_factory() {}

    // hook for generating indexed_string's without being
    // associated with a particular T (w/o caching).
    // XXX: do not use it unless strictly necessary.
    virtual indexed_string get() {
        indexed_string is(get_and_increment_id(), this);
        _shadow_vars.push_back(is);
        return is;
    }

    // generate a shadow indexed_string's associated to some key
    virtual indexed_string get(index_t key, std::string name = "") {
        auto it = _shadow_map.find(key);
        if (it == _shadow_map.end()) {
            indexed_string is(get_and_increment_id(), this, name);
            _shadow_map.insert(typename shadow_map_t::value_type(key, is));
            _shadow_vars.push_back(is);
            return is;
        } else {
            return it->second;
        }
    }

    virtual indexed_string operator[](T s) {
        auto it = _map.find(s);
        if (it == _map.end()) {
            indexed_string is(s, get_and_increment_id(), this);
            _map.insert(typename t_map_t::value_type(s, is));
            return is;
        } else {
            return it->second;
        }
    }

    // return all the shadow variables created by the factory.
    virtual const_var_range get_shadow_vars() const {
        return boost::make_iterator_range(_shadow_vars.begin(), _shadow_vars.end());
    }
};

using str_variable_factory = variable_factory;

} // end namespace var_factory_impl
} // end namespace cfg
} // end namespace crab
