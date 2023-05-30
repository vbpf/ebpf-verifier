// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <map>
#include <regex>
#include <unordered_set>
#include <sstream>
#include <string>

#include <boost/lexical_cast.hpp>

#include "asm_parse.hpp"
#include "asm_unmarshal.hpp"
#include "crab/dsl_syntax.hpp"
#include "crab/linear_constraint.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"


using std::regex;
using std::regex_match;

using crab::number_t;
using crab::linear_constraint_t;
using crab::linear_expression_t;

#define REG R"_(\s*(r\d\d?)\s*)_"
#define WREG R"_(\s*([wr]\d\d?)\s*)_"
#define IMM R"_(\s*\[?([-+]?(?:0x)?[0-9a-f]+)\]?\s*)_"
#define REG_OR_IMM R"_(\s*([+-]?(?:0x)?[0-9a-f]+|r\d\d?)\s*)_"

#define FUNC IMM
#define OPASSIGN R"_(\s*(\S*)=\s*)_"
#define ASSIGN R"_(\s*=\s*)_"
#define LONGLONG R"_(\s*(ll|)\s*)_"
#define UNOP R"_((-|be16|be32|be64))_"

#define PLUSMINUS R"_((\s*[+-])\s*)_"
#define LPAREN R"_(\s*\(\s*)_"
#define RPAREN R"_(\s*\)\s*)_"
#define PAREN(x) LPAREN x RPAREN
#define STAR R"_(\s*\*\s*)_"
#define DEREF STAR PAREN("u(\\d+)" STAR)

#define CMPOP R"_(\s*(&?[=!]=|s?[<>]=?)\s*)_"
#define LABEL R"_((<\w[a-zA-Z_0-9]*>))_"
#define WRAPPED_LABEL "\\s*" LABEL "\\s*"

#define SPECIAL_VAR R"_(\s*(packet_size|meta_offset)\s*)_"
#define KIND R"_(\s*(type|svalue|uvalue|ctx_offset|map_fd|packet_offset|shared_offset|stack_offset|shared_region_size|stack_numeric_size)\s*)_"
#define INTERVAL R"_(\s*\[([-+]?\d+),\s*([-+]?\d+)\]?\s*)_"
#define ARRAY_RANGE R"_(\s*\[([-+]?\d+)\.\.\.\s*([-+]?\d+)\]?\s*)_"

#define DOT "[.]"
#define TYPE R"_(\s*(shared|number|packet|stack|ctx|map_fd|map_fd_program)\s*)_"

static const std::map<std::string, Bin::Op> str_to_binop = {
    {"", Bin::Op::MOV},   {"+", Bin::Op::ADD},  {"-", Bin::Op::SUB},    {"*", Bin::Op::MUL},
    {"/", Bin::Op::UDIV}, {"%", Bin::Op::UMOD}, {"|", Bin::Op::OR},     {"&", Bin::Op::AND},
    {"<<", Bin::Op::LSH}, {">>", Bin::Op::RSH}, {"s>>", Bin::Op::ARSH}, {"^", Bin::Op::XOR},
};

static const std::map<std::string, Un::Op> str_to_unop = {
    {"be16", Un::Op::BE16},
    {"be32", Un::Op::BE32},
    {"be64", Un::Op::BE64},
    {"le16", Un::Op::LE16},
    {"le32", Un::Op::LE32},
    {"le64", Un::Op::LE64},
    {"-", Un::Op::NEG},
};

static const std::map<std::string, Condition::Op> str_to_cmpop = {
    {"==", Condition::Op::EQ},  {"!=", Condition::Op::NE},   {"&==", Condition::Op::SET}, {"&!=", Condition::Op::NSET},
    {"<", Condition::Op::LT},   {"<=", Condition::Op::LE},   {">", Condition::Op::GT},    {">=", Condition::Op::GE},
    {"s<", Condition::Op::SLT}, {"s<=", Condition::Op::SLE}, {"s>", Condition::Op::SGT},  {"s>=", Condition::Op::SGE},
};

static const std::map<std::string, int> str_to_width = {
    {"8", 1},
    {"16", 2},
    {"32", 4},
    {"64", 8},
};

static Reg reg(const std::string& s) {
    assert(s.at(0) == 'r' || s.at(0) == 'w');
    uint8_t res = (uint8_t)boost::lexical_cast<uint16_t>(s.substr(1));
    return Reg{res};
}

static Imm imm(const std::string& s, bool lddw) {
    int base = s.find("0x") != std::string::npos ? 16 : 10;

    if (lddw) {
        if (s.at(0) == '-')
            return Imm{(uint64_t)std::stoll(s, nullptr, base)};
        else
            return Imm{std::stoull(s, nullptr, base)};
    } else {
        if (s.at(0) == '-')
            return Imm{(uint64_t)(int64_t)std::stol(s, nullptr, base)};
        else
            return Imm{(uint64_t)(int64_t)(int32_t)std::stoul(s, nullptr, base)};
    }
}

static number_t signed_number(const std::string& s) {
    return static_cast<int64_t>(std::stoll(s));
}

static number_t unsigned_number(const std::string& s) {
    return static_cast<uint64_t>(std::stoull(s));
}

static Value reg_or_imm(const std::string& s) {
    if (s.at(0) == 'w' || s.at(0) == 'r')
        return reg(s);
    else
        return imm(s, false);
}

static Deref deref(const std::string& width, const std::string& basereg, const std::string& sign, const std::string& _offset) {
    int offset = boost::lexical_cast<int>(_offset);
    return Deref{
        .width = str_to_width.at(width),
        .basereg = reg(basereg),
        .offset = (sign == "-" ? -offset : +offset),
    };
}

Instruction parse_instruction(const std::string& line, const std::map<std::string, label_t>& label_name_to_label) {
    // treat ";" as a comment
    std::string text = line.substr(0, line.find(';'));
    size_t end = text.find_last_not_of(" ");
    if (end != std::string::npos)
        text = text.substr(0, end + 1);
    std::smatch m;
    if (regex_match(text, m, regex("exit"))) {
        return Exit{};
    }
    if (regex_match(text, m, regex("call " FUNC))) {
        int func = boost::lexical_cast<int>(m[1]);
        return make_call(func, g_ebpf_platform_linux);
    }
    if (regex_match(text, m, regex(WREG OPASSIGN REG))) {
        std::string r = m[1];
        return Bin{.op = str_to_binop.at(m[2]), .dst = reg(r), .v = reg(m[3]), .is64 = r.at(0) != 'w', .lddw = false};
    }
    if (regex_match(text, m, regex(WREG ASSIGN UNOP WREG))) {
        if (m[1] != m[3]) throw std::invalid_argument(std::string("Invalid unary operation: ") + text);
        std::string r = m[1];
        bool is64 = r.at(0) != 'w';
        return Un{.op = str_to_unop.at(m[2]), .dst = reg(m[1]), .is64 = is64};
    }
    if (regex_match(text, m, regex(WREG OPASSIGN IMM LONGLONG))) {
        std::string r = m[1];
        bool is64 = r.at(0) != 'w';
        bool lddw = !m[4].str().empty();
        return Bin{
            .op = str_to_binop.at(m[2]), .dst = reg(r), .v = imm(m[3], lddw), .is64 = is64, .lddw = lddw};
    }
    if (regex_match(text, m, regex(REG ASSIGN DEREF PAREN(REG PLUSMINUS IMM)))) {
        return Mem{
            .access = deref(m[2], m[3], m[4], m[5]),
            .value = reg(m[1]),
            .is_load = true,
        };
    }
    if (regex_match(text, m, regex(DEREF PAREN(REG PLUSMINUS IMM) ASSIGN REG_OR_IMM))) {
        return Mem{
            .access = deref(m[1], m[2], m[3], m[4]),
            .value = reg_or_imm(m[5]),
            .is_load = false,
        };
    }
    if (regex_match(text, m, regex("lock " DEREF PAREN(REG PLUSMINUS IMM) " [+]= " REG))) {
        return LockAdd{.access = deref(m[1], m[2], m[3], m[4]), .valreg = reg(m[5])};
    }
    if (regex_match(text, m, regex("r0 = " DEREF "skb\\[(.*)\\]"))) {
        auto width = str_to_width.at(m[1]);
        std::string access = m[2].str();
        if (regex_match(access, m, regex(REG)))
            return Packet{.width = width, .offset = 0, .regoffset = reg(m[1])};
        if (regex_match(access, m, regex(IMM)))
            return Packet{.width = width, .offset = (int32_t)imm(m[1], false).v, .regoffset = {}};
        if (regex_match(access, m, regex(REG PLUSMINUS REG)))
            return Packet{.width = width, .offset = 0 /* ? */, .regoffset = reg(m[2])};
        if (regex_match(access, m, regex(REG PLUSMINUS IMM)))
            return Packet{.width = width, .offset = (int32_t)imm(m[2], false).v, .regoffset = reg(m[1])};
        return Undefined{0};
    }
    if (regex_match(text, m, regex("assume " WREG CMPOP REG_OR_IMM))) {
        Assume res{
            Condition{
                .op = str_to_cmpop.at(m[2]),
                .left = reg(m[1]),
                .right = reg_or_imm(m[3]),
                .is64 = (((const std::string&)m[1]).at(0) == 'r')
            }
        };
        return res;
    }
    if (regex_match(text, m, regex("(?:if " WREG CMPOP REG_OR_IMM " )?goto\\s+(?:" IMM ")?" WRAPPED_LABEL))) {
        // We ignore second IMM
        Jmp res{.cond = {}, .target = label_name_to_label.at(m[5])};
        if (m[1].matched) {
            res.cond = Condition{
                .op = str_to_cmpop.at(m[2]),
                .left = reg(m[1]),
                .right = reg_or_imm(m[3]),
                .is64 = (((const std::string&)m[1]).at(0) == 'r')
            };
        }
        return res;
    }
    return Undefined{0};
}

[[maybe_unused]]
static InstructionSeq parse_program(std::istream& is) {
    std::string line;
    std::vector<label_t> pc_to_label;
    InstructionSeq labeled_insts;
    std::set<label_t> seen_labels;
    std::optional<label_t> next_label;
    while (std::getline(is, line)) {
        std::smatch m;
        if (regex_search(line, m, regex(LABEL ":"))) {
            next_label = label_t(boost::lexical_cast<int>(m[1]));
            if (seen_labels.count(*next_label) != 0)
                throw std::invalid_argument("duplicate labels");
            line = m.suffix();
        }
        if (regex_search(line, m, regex(R"(^\s*(\d+:)?\s*)"))) {
            line = m.suffix();
        }
        if (line.empty())
            continue;
        Instruction ins = parse_instruction(line, {});
        if (std::holds_alternative<Undefined>(ins))
            continue;

        if (!next_label)
            next_label = label_t(static_cast<int>(labeled_insts.size()));
        labeled_insts.emplace_back(*next_label, ins, std::optional<btf_line_info_t>());
        next_label = {};
    }
    return labeled_insts;
}

static uint8_t regnum(const std::string& s) {
    return (uint8_t)boost::lexical_cast<uint16_t>(s.substr(1));
}

static crab::variable_t special_var(const std::string& s) {
    if (s == "packet_size") return crab::variable_t::packet_size();
    if (s == "meta_offset") return crab::variable_t::meta_offset();
    throw std::runtime_error(std::string() + "Bad special variable: " + s);
}

static crab::data_kind_t regkind(const std::string& s) {
    if (s == "type") return crab::data_kind_t::types;
    if (s == "ctx_offset") return crab::data_kind_t::ctx_offsets;
    if (s == "map_fd") return crab::data_kind_t::map_fds;
    if (s == "packet_offset") return crab::data_kind_t::packet_offsets;
    if (s == "shared_offset") return crab::data_kind_t::shared_offsets;
    if (s == "stack_offset") return crab::data_kind_t::stack_offsets;
    if (s == "shared_region_size") return crab::data_kind_t::shared_region_sizes;
    if (s == "stack_numeric_size") return crab::data_kind_t::stack_numeric_sizes;
    if (s == "svalue") return crab::data_kind_t::svalues;
    if (s == "uvalue") return crab::data_kind_t::uvalues;
    throw std::runtime_error(std::string() + "Bad kind: " + s);
}

static type_encoding_t string_to_type_encoding(const std::string& s) {
    static std::map<std::string, type_encoding_t> string_to_type{
        {std::string("uninit"), T_UNINIT},
        {std::string("map_fd_programs"), T_MAP_PROGRAMS},
        {std::string("map_fd"), T_MAP},
        {std::string("number"), T_NUM},
        {std::string("ctx"), T_CTX},
        {std::string("stack"), T_STACK},
        {std::string("packet"), T_PACKET},
        {std::string("shared"), T_SHARED},
    };
    if (string_to_type.count(s)) {
        return string_to_type[s];
    }
    throw std::runtime_error(std::string("Unsupported type name: ") + s);
}

std::vector<linear_constraint_t> parse_linear_constraints(const std::set<std::string>& constraints, std::vector<crab::interval_t>& numeric_ranges) {
    using namespace crab::dsl_syntax;
    using crab::variable_t;

    std::vector<linear_constraint_t> res;
    for (const std::string& cst_text : constraints) {
        std::smatch m;
        if (regex_match(cst_text, m, regex(SPECIAL_VAR "=" IMM))) {
            res.push_back(special_var(m[1]) == signed_number(m[2]));
        } else if (regex_match(cst_text, m, regex(SPECIAL_VAR "=" INTERVAL))) {
            variable_t d = special_var(m[1]);
            number_t lb{signed_number(m[2])};
            number_t ub{signed_number(m[3])};
            res.push_back(lb <= d);
            res.push_back(d <= ub);
        } else if (regex_match(cst_text, m, regex(SPECIAL_VAR "=" REG DOT KIND))) {
            linear_expression_t d = special_var(m[1]);
            linear_expression_t s = variable_t::reg(regkind(m[3]), regnum(m[2]));
            res.push_back(d == s);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" SPECIAL_VAR))) {
            linear_expression_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            linear_expression_t s = special_var(m[3]);
            res.push_back(d == s);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" REG DOT KIND))) {
            linear_expression_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            linear_expression_t s = variable_t::reg(regkind(m[4]), regnum(m[3]));
            res.push_back(d == s);
        } else if (regex_match(cst_text, m, regex(REG DOT "type" "=" TYPE))) {
            variable_t d = variable_t::reg(crab::data_kind_t::types, regnum(m[1]));
            res.push_back(d == string_to_type_encoding(m[2]));
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" IMM))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            number_t value;
            if (m[2] == "uvalue") {
                value = unsigned_number(m[3]);
            } else {
                value = signed_number(m[3]);
            }
            res.push_back(d == value);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "=" INTERVAL))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            number_t lb, ub;
            if (m[2] == "uvalue") {
                lb = unsigned_number(m[3]);
                ub = unsigned_number(m[4]);
            } else {
                lb = signed_number(m[3]);
                ub = signed_number(m[4]);
            }
            res.push_back(lb <= d);
            res.push_back(d <= ub);
        } else if (regex_match(cst_text, m, regex(REG DOT KIND "-" REG DOT KIND "<=" IMM))) {
            variable_t d = variable_t::reg(regkind(m[2]), regnum(m[1]));
            variable_t s = variable_t::reg(regkind(m[4]), regnum(m[3]));
            number_t diff = signed_number(m[5]);
            res.push_back(d - s <= diff);
        } else if (regex_match(cst_text, m, regex("s" ARRAY_RANGE DOT "type" "=" TYPE))) {
            type_encoding_t type = string_to_type_encoding(m[3]);
            if (type == type_encoding_t::T_NUM) {
                numeric_ranges.emplace_back(signed_number(m[1]), signed_number(m[2]));
            } else {
                number_t lb = signed_number(m[1]);
                number_t ub = signed_number(m[2]);
                variable_t d = variable_t::cell_var(crab::data_kind_t::types, lb, ub - lb + 1);
                res.push_back(d == type);
            }
        } else if (regex_match(cst_text, m, regex("s" ARRAY_RANGE DOT "svalue" "=" IMM))) {
            number_t lb = signed_number(m[1]);
            number_t ub = signed_number(m[2]);
            variable_t d = variable_t::cell_var(crab::data_kind_t::svalues, lb, ub - lb + 1);
            res.push_back(d == signed_number(m[3]));
        } else if (regex_match(cst_text, m, regex("s" ARRAY_RANGE DOT "uvalue" "=" IMM))) {
            number_t lb = signed_number(m[1]);
            number_t ub = signed_number(m[2]);
            variable_t d = variable_t::cell_var(crab::data_kind_t::uvalues, lb, ub - lb + 1);
            res.push_back(d == unsigned_number(m[3]));
        } else {
            throw std::runtime_error(std::string("Unknown constraint: ") + cst_text);
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
