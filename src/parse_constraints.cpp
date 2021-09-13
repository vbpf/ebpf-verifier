// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <set>
#include <regex>

#include <boost/lexical_cast.hpp>

#include "parse_constraints.hpp"

#include "crab/variable.hpp"
#include "crab/linear_constraint.hpp"
#include "crab/dsl_syntax.hpp"

using crab::data_kind_t;
using crab::variable_t;

using std::regex;
using std::string;
using std::map;

#define REG R"_(\s*(r\d\d?)\s*)_"
#define KIND R"_(\s*(type|value|offset)\s*)_"
#define IMM R"_(\s*\[?([-+]?\d+)\]?\s*)_"
#define INTERVAL R"_(\s*\[([-+]?\d+),\s*([-+]?\d+)\]?\s*)_"

#define DOT "[.]"
#define TYPE R"_(\s*(shared|number|packet|stack|ctx|map_fd|map_fd_program)\s*)_"

static uint8_t regnum(const string& s) {
    return (uint8_t)boost::lexical_cast<uint16_t>(s.substr(1));
}

static crab::data_kind_t regkind(const string& s) {
    if (s == "type") return crab::data_kind_t::types;
    if (s == "offset") return crab::data_kind_t::offsets;
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

static int type(const string& s) {
    static map<string, int> string_to_type{
        {string("uninit"), T_UNINIT},
        {string("map_fd_programs"), T_MAP_PROGRAMS},
        {string("map"), T_MAP},
        {string("number"), T_NUM},
        {string("ctx"), T_CTX},
        {string("stack"), T_STACK},
        {string("packet"), T_PACKET},
    };
    if (string_to_type.count(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(string("Unsupported type name: ") + s);
}

std::vector<linear_constraint_t> parse_linear_constraints(const std::set<string>& constraints) {
    using namespace crab::dsl_syntax;

    std::vector<linear_constraint_t> res;
    for (const string& cst_text : constraints) {
        std::smatch m;
        if (regex_match(cst_text, m, regex(REG DOT KIND "=" REG DOT KIND))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            variable_t s = variable_t::reg(regkind(m[4]), regnum(m[3]));
            res.push_back(equals(d, s));
        } else if (regex_match(cst_text, m, regex(REG DOT "type" "=" TYPE))) {
            variable_t d = variable_t::reg(data_kind_t::types, regnum(m[1]));
            res.push_back(d == type(m[2]));
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
        } else {
            throw std::runtime_error(string("Unknown constraint: ") + cst_text);
        }
    }
    return res;
}
