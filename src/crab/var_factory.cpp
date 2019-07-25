/*
 * Factories for variable names.
 */

#include "crab/types.hpp"

namespace crab {
static std::string get_str(std::string e) { return e; }

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

index_t variable_factory::get_and_increment_id() {
    if (_next_id == std::numeric_limits<index_t>::max()) {
        CRAB_ERROR("Reached limit of ", std::numeric_limits<index_t>::max(), " variables");
    }
    index_t res = _next_id;
    ++_next_id;
    return res;
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


variable_factory variable_factory::vfac;
static variable_t make(std::string name) { return variable_factory::vfac[name]; }

std::map<std::string, variable_t> variable_t::vars {
    { "r0",  make("r0")  }, { "off0",  make("off0")  }, { "t0",  make("t0")  },
    { "r1",  make("r1")  }, { "off1",  make("off1")  }, { "t1",  make("t1")  },
    { "r2",  make("r2")  }, { "off2",  make("off2")  }, { "t2",  make("t2")  },
    { "r3",  make("r3")  }, { "off3",  make("off3")  }, { "t3",  make("t3")  },
    { "r4",  make("r4")  }, { "off4",  make("off4")  }, { "t4",  make("t4")  },
    { "r5",  make("r5")  }, { "off5",  make("off5")  }, { "t5",  make("t5")  },
    { "r6",  make("r6")  }, { "off6",  make("off6")  }, { "t6",  make("t6")  },
    { "r7",  make("r7")  }, { "off7",  make("off7")  }, { "t7",  make("t7")  },
    { "r8",  make("r8")  }, { "off8",  make("off8")  }, { "t8",  make("t8")  },
    { "r9",  make("r9")  }, { "off9",  make("off9")  }, { "t9",  make("t9")  },
    { "r10", make("r10") }, { "off10", make("off10") }, { "t10", make("t10") },
    { "S_r", make("S_r") }, { "S_off", make("S_off") }, { "S_t", make("S_t") },
    { "data_size", make("data_size") },
    { "meta_size", make("meta_size") },
    { "map_value_size", make("map_value_size") },
    { "map_key_size", make("map_key_size") },
};

static std::string name_of(data_kind_t kind) {
    switch (kind) {
        case data_kind_t::offsets: return "off";
        case data_kind_t::values: return "r";
        case data_kind_t::regions: return "t";
    }
}

variable_t variable_t::reg(data_kind_t kind, int i) {
    return vars.at(name_of(kind) + std::to_string(i));
}

variable_t variable_t::array(data_kind_t kind) {
    return variable_t::vars.at("S_" + name_of(kind));
}

variable_t variable_t::map_value_size() { return vars.at("map_value_size"); }
variable_t variable_t::map_key_size() { return vars.at("map_key_size"); }
variable_t variable_t::meta_size() { return vars.at("meta_size"); }
variable_t variable_t::data_size() { return vars.at("data_size"); }

} // end namespace crab
