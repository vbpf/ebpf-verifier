// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <set>
#include <regex>

#include <boost/lexical_cast.hpp>

#include "string_constraints.hpp"

#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/dsl_syntax.hpp"

using crab::data_kind_t;
using crab::variable_t;

using std::regex;
using std::string;
using std::map;

#define REG R"_(\s*(r\d\d?)\s*)_"
#define KIND R"_(\s*(type|value|ctx_offset|map_fd|packet_offset|shared_offset|stack_offset|shared_region_size|stack_numeric_size)\s*)_"
#define IMM R"_(\s*\[?([-+]?\d+)\]?\s*)_"
#define INTERVAL R"_(\s*\[([-+]?\d+),\s*([-+]?\d+)\]?\s*)_"
#define ARRAY_RANGE R"_(\s*\[([-+]?\d+)\.\.\.\s*([-+]?\d+)\]?\s*)_"

#define DOT "[.]"
#define TYPE R"_(\s*(shared|number|packet|stack|ctx|map_fd|map_fd_program)\s*)_"

static uint8_t regnum(const string& s) {
    return (uint8_t)boost::lexical_cast<uint16_t>(s.substr(1));
}

static crab::data_kind_t regkind(const string& s) {
    if (s == "type") return crab::data_kind_t::types;
    if (s == "ctx_offset") return crab::data_kind_t::ctx_offsets;
    if (s == "map_fd") return crab::data_kind_t::map_fds;
    if (s == "packet_offset") return crab::data_kind_t::packet_offsets;
    if (s == "shared_offset") return crab::data_kind_t::shared_offsets;
    if (s == "stack_offset") return crab::data_kind_t::stack_offsets;
    if (s == "shared_region_size") return crab::data_kind_t::shared_region_sizes;
    if (s == "stack_numeric_size") return crab::data_kind_t::stack_numeric_sizes;
    if (s == "value") return crab::data_kind_t::values;
    throw std::runtime_error(string() + "Bad kind: " + s);
}

static long number(const string& s) {
    try {
        return (long)boost::lexical_cast<int64_t>(s);
    } catch (const boost::bad_lexical_cast&) {
        throw std::invalid_argument("number too large");
    }
}

static type_encoding_t string_to_type_encoding(const string& s) {
    static map<string, type_encoding_t> string_to_type{
        {string("uninit"), T_UNINIT},
        {string("map_fd_programs"), T_MAP_PROGRAMS},
        {string("map_fd"), T_MAP},
        {string("number"), T_NUM},
        {string("ctx"), T_CTX},
        {string("stack"), T_STACK},
        {string("packet"), T_PACKET},
        {string("shared"), T_SHARED},
    };
    if (string_to_type.count(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(string("Unsupported type name: ") + s);
}

std::vector<linear_constraint_t> parse_linear_constraints(const std::set<string>& constraints, std::vector<crab::interval_t>& numeric_ranges) {
    using namespace crab::dsl_syntax;

    std::vector<linear_constraint_t> res;
    for (const string& cst_text : constraints) {
        std::smatch m;
        if (regex_match(cst_text, m, regex("meta_offset" "=" IMM))) {
            res.push_back(variable_t::meta_offset() == number(m[1]));
        } else if (regex_match(cst_text, m, regex("packet_size" "=" INTERVAL))) {
            variable_t d = variable_t::packet_size();
            res.push_back(number(m[1]) <= d);
            res.push_back(d <= number(m[2]));
        } else if (regex_match(cst_text, m, regex("packet_size" "=" REG DOT KIND))) {
            variable_t d = variable_t::packet_size();
            variable_t s = variable_t::reg(regkind(m[2]), regnum(m[1]));
            res.push_back(equals(d, s));
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" "packet_size"))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            res.push_back(equals(d, variable_t::packet_size()));
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" REG DOT KIND))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            variable_t s = variable_t::reg(regkind(m[4]), regnum(m[3]));
            res.push_back(equals(d, s));
        } else if (regex_match(cst_text, m, regex(REG DOT "type" "=" TYPE))) {
            variable_t d = variable_t::reg(data_kind_t::types, regnum(m[1]));
            res.push_back(d == string_to_type_encoding(m[2]));
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" IMM))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            res.push_back(d == number(m[3]));
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" INTERVAL))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            res.push_back(number(m[3]) <= d);
            res.push_back(d <= number(m[4]));
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "-" REG DOT KIND "<=" IMM))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            variable_t s = variable_t::reg(regkind(m[4]), regnum(m[3]));
            long diff = number(m[5]);
            res.push_back(d - s <= number_t(diff));
        } else if (regex_match(cst_text, m, regex("s" ARRAY_RANGE DOT "type" "=" TYPE))) {
            type_encoding_t type = string_to_type_encoding(m[3]);
            if (type == type_encoding_t::T_NUM) {
                numeric_ranges.push_back(crab::interval_t(number(m[1]), number(m[2])));
            } else {
                long lb = number(m[1]);
                long ub = number(m[2]);
                variable_t d = variable_t::cell_var(data_kind_t::types, lb, ub - lb + 1);
                res.push_back(d == type);
            }
        } else {
            throw std::runtime_error(string("Unknown constraint: ") + cst_text);
        }
    }
    return res;
}

// return a-b, taking account potential optional-none
string_invariant string_invariant::operator-(const string_invariant& b) const {
    if (this->is_bottom()) return string_invariant::bottom();
    string_invariant res = string_invariant::top();
    for (const std::string& cst : this->value()) {
        if (b.is_bottom() || !b.contains(cst))
            res.maybe_inv->insert(cst);
    }
    return res;
}

// return a+b, taking account potential optional-none
string_invariant string_invariant::operator+(const string_invariant& b) const {
    if (this->is_bottom())
        return b;
    string_invariant res = *this;
    for (const std::string& cst : b.value()) {
        if (res.is_bottom() || !res.contains(cst))
            res.maybe_inv->insert(cst);
    }
    return res;
}

std::ostream& operator<<(std::ostream& o, const string_invariant& inv) {
    if (inv.is_bottom()) {
        return o << "_|_";
    }
    // Intervals
    bool first = true;
    o << "[";
    auto& set = inv.maybe_inv.value();
    std::string lastbase;
    for (const auto& item : set) {
        if (first)
            first = false;
        else
            o << ", ";
        size_t pos = item.find_first_of(".=[");
        std::string base = item.substr(0, pos);
        if (base != lastbase) {
            o << "\n    ";
            lastbase = base;
        }
        o << item;
    }
    o << "]";
    return o;
}
