// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <map>
#include <regex>
#include <tuple>
#include <unordered_set>

#include "asm_parse.hpp"

using std::regex;
using std::regex_match;

#define REG R"_((r\d\d?)\s*)_"
#define IMM R"_(([-+]?\d+))_"
#define REG_OR_IMM R"_(([+-]?\d+|r\d\d?)\s*)_"

#define FUNC IMM
#define OPASSIGN R"_(\s*(\S*)=\s*)_"
#define ASSIGN R"_(\s*=\s*)_"
#define LONGLONG R"_(\s*(ll|)\s*)_"

#define PLUSMINUS R"_((\s*[+-])\s*)_"
#define LPAREN R"_(\s*\(\s*)_"
#define RPAREN R"_(\s*\)\s*)_"
#define PAREN(x) LPAREN x RPAREN
#define STAR R"_(\s*\*\s*)_"
#define DEREF STAR PAREN("u(\\d+)" STAR)

#define CMPOP R"_(\s*(&?[=!]=|s?[<>]=?)\s*)_"
#define LABEL R"_((\w[a-zA-Z_0-9]*))_"
#define WRAPPED_LABEL "\\s*<" LABEL ">\\s*"

const std::map<std::string, Bin::Op> str_to_binop = {
    {"", Bin::Op::MOV},   {"+", Bin::Op::ADD},  {"-", Bin::Op::SUB},    {"*", Bin::Op::MUL},
    {"/", Bin::Op::DIV},  {"%", Bin::Op::MOD},  {"|", Bin::Op::OR},     {"&", Bin::Op::AND},
    {"<<", Bin::Op::LSH}, {">>", Bin::Op::RSH}, {">>>", Bin::Op::ARSH}, {"^", Bin::Op::XOR},
};

const std::map<std::string, Condition::Op> str_to_cmpop = {
    {"==", Condition::Op::EQ},  {"!=", Condition::Op::NE},   {"&==", Condition::Op::SET}, {"&!=", Condition::Op::NSET},
    {"<", Condition::Op::LT},   {"<=", Condition::Op::LE},   {">", Condition::Op::GT},    {">=", Condition::Op::GE},
    {"s<", Condition::Op::SLT}, {"s<=", Condition::Op::SLE}, {"s>", Condition::Op::SGT},  {"s>=", Condition::Op::SGE},
};

const std::map<std::string, int> str_to_width = {
    {"8", 1},
    {"16", 2},
    {"32", 4},
    {"64", 8},
};

Reg reg(std::string s) {
    assert(s.at(0) == 'r');
    uint8_t res = (uint8_t)boost::lexical_cast<uint16_t>(s.substr(1));
    return Reg{res};
}

Imm imm(std::string s) {
    try {
        return Imm{boost::lexical_cast<uint64_t>(s)};
    } catch (const boost::bad_lexical_cast&) {
        throw std::invalid_argument("number too large");
    }
}

Value reg_or_imm(std::string s) {
    if (s.at(0) == 'r')
        return reg(s);
    else
        return imm(s);
}

static Deref deref(const std::string& width, const std::string& basereg, const std::string& sign, const std::string& _offset) {
    int offset = boost::lexical_cast<int>(_offset);
    return Deref{
        .width = str_to_width.at(width),
        .basereg = reg(basereg),
        .offset = (sign == "-" ? -offset : +offset),
    };
}

Instruction parse_instruction(const std::string& text) {
    std::smatch m;
    if (regex_match(text, m, regex("exit"))) {
        return Exit{};
    }
    if (regex_match(text, m, regex("call " FUNC))) {
        int func = boost::lexical_cast<int>(m[1]);
        return Call{.func = func};
    }
    if (regex_match(text, m, regex(REG OPASSIGN REG))) {
        return Bin{.op = str_to_binop.at(m[2]), .is64 = true, .dst = reg(m[1]), .v = reg(m[3]), .lddw = false};
    }
    if (regex_match(text, m, regex(REG OPASSIGN IMM LONGLONG))) {
        return Bin{
            .op = str_to_binop.at(m[2]), .is64 = true, .dst = reg(m[1]), .v = imm(m[3]), .lddw = !m[4].str().empty()};
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
            return Packet{.width = width, .offset = (int)imm(m[1]).v, .regoffset = {}};
        if (regex_match(access, m, regex(REG PLUSMINUS REG)))
            return Packet{.width = width, .offset = 0 /* ? */, .regoffset = reg(m[2])};
        if (regex_match(access, m, regex(REG PLUSMINUS IMM)))
            return Packet{.width = width, .offset = (int)imm(m[2]).v, .regoffset = reg(m[1])};
        return Undefined{0};
    }
    if (regex_match(text, m, regex("(if " REG CMPOP REG_OR_IMM " )?goto " IMM WRAPPED_LABEL))) {
        // We ignore second IMM
        Jmp res{.cond = {}, .target = label_t(boost::lexical_cast<int>(m[6]))};
        if (m[1].matched) {
            res.cond = Condition{
                .op = str_to_cmpop.at(m[3]),
                .left = reg(m[2]),
                .right = reg_or_imm(m[4]),
            };
        }
        return res;
    }
    return Undefined{0};
}

std::vector<std::tuple<label_t, Instruction>> parse_program(std::istream& is) {
    std::string line;
    int lineno = 0;
    std::vector<label_t> pc_to_label;
    std::vector<std::tuple<label_t, Instruction>> labeled_insts;
    std::set<label_t> seen_labels;
    std::optional<label_t> next_label;
    while (std::getline(is, line)) {
        lineno++;
        std::smatch m;
        if (regex_search(line, m, regex("^" LABEL ":"))) {
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
        Instruction ins = parse_instruction(line);
        if (std::holds_alternative<Undefined>(ins))
            continue;

        if (!next_label)
            next_label = label_t(labeled_insts.size());
        labeled_insts.emplace_back(*next_label, ins);
        next_label = {};
    }
    return labeled_insts;
}
