/*
 * Factories for variable names.
 */

#include "crab/types.hpp"

namespace crab {
static std::string get_str(std::string e) {
    return e;
}

std::string indexed_string::str() const {
    if (_s) {
        return get_str(*_s);
    } else {
        if (_name != "") {
            return _name;
        } else {
            // unlikely prefix
            return "@V_" + std::to_string(_id);
        }
    }
}

index_t variable_factory::get_and_increment_id(void) {
    if (_next_id == std::numeric_limits<index_t>::max()) {
        CRAB_ERROR("Reached limit of ", std::numeric_limits<index_t>::max(), " variables");
    }
    index_t res = _next_id;
    ++_next_id;
    return res;
}

// hook for generating indexed_string's without being
// associated with a particular T (w/o caching).
// XXX: do not use it unless strictly necessary.
indexed_string variable_factory::get() {
    indexed_string is(get_and_increment_id(), this);
    _shadow_vars.push_back(is);
    return is;
}

// generate a shadow indexed_string's associated to some key
indexed_string variable_factory::get(index_t key, std::string name) {
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

indexed_string variable_factory::operator[](var_key s) {
    auto it = _map.find(s);
    if (it == _map.end()) {
        indexed_string is(s, get_and_increment_id(), this);
        _map.insert(typename t_map_t::value_type(s, is));
        return is;
    } else {
        return it->second;
    }
}

} // end namespace crab
