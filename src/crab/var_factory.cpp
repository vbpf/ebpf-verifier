// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
/*
 * Factories for variable names.
 */

#include "crab/variable.hpp"

namespace crab {

variable_t variable_t::make(const std::string& name) {
    auto it = std::find(names.begin(), names.end(), name);
    if (it == names.end()) {
        names.emplace_back(name);
        return variable_t(names.size() - 1);
    } else {
        return variable_t(std::distance(names.begin(), it));
    }
}

std::vector<std::string> variable_t::names{"r0",          "off0",      "t0",
                                           "r1",          "off1",      "t1",
                                           "r2",          "off2",      "t2",
                                           "r3",          "off3",      "t3",
                                           "r4",          "off4",      "t4",
                                           "r5",          "off5",      "t5",
                                           "r6",          "off6",      "t6",
                                           "r7",          "off7",      "t7",
                                           "r8",          "off8",      "t8",
                                           "r9",          "off9",      "t9",
                                           "r10",         "off10",     "t10",
                                           "S_r",         "S_off",     "S_t",
                                           "data_size",   "meta_size", "map_value_size",
                                           "map_key_size"};

static std::string name_of(data_kind_t kind) {
    switch (kind) {
    case data_kind_t::offsets: return "off";
    case data_kind_t::values: return "r";
    case data_kind_t::types: return "t";
    }
    return {};
}

variable_t variable_t::reg(data_kind_t kind, int i) { return make(name_of(kind) + std::to_string(i)); }

std::ostream& operator<<(std::ostream& o, const data_kind_t& s) {
    return o << name_of(s);
}

static std::string mk_scalar_name(data_kind_t kind, int o, int size) {
    std::stringstream os;
    os << "S_" << name_of(kind) << "[" << o;
    if (size != 1) {
        os << "..." << o + size - 1;
    }
    os << "]";
    return os.str();
}

variable_t variable_t::cell_var(data_kind_t array, index_t offset, unsigned size) {
    return make(mk_scalar_name(array, - (512 - (int)offset), (int)size));
}

variable_t variable_t::map_value_size() { return make("map_value_size"); }
variable_t variable_t::map_key_size() { return make("map_key_size"); }
variable_t variable_t::meta_offset() { return make("meta_offset"); }
variable_t variable_t::packet_size() { return make("packet_size"); }

} // end namespace crab
