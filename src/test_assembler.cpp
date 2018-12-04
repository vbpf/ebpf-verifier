#include "catch.hpp"
#include "asm.hpp"

#include <map>
#include <unordered_set>
#include <regex>
#include <tuple>
#include <algorithm>
#include <boost/lexical_cast.hpp>

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
#define WRAPPED_LABEL  "\\s*<" LABEL ">\\s*"


const std::map<std::string, Bin::Op> str_to_binop =
{
    {""   , Bin::Op::MOV },
    {"+"  , Bin::Op::ADD },
    {"-"  , Bin::Op::SUB },
    {"*"  , Bin::Op::MUL },
    {"/"  , Bin::Op::DIV },
    {"%"  , Bin::Op::MOD },
    {"|"  , Bin::Op::OR  },
    {"&"  , Bin::Op::AND },
    {"<<" , Bin::Op::LSH },
    {">>" , Bin::Op::RSH },
    {">>>", Bin::Op::ARSH},
    {"^"  , Bin::Op::XOR },
};

const std::map<std::string, Condition::Op> str_to_cmpop =
{
    {"==" , Condition::Op::EQ  },
    {"!=" , Condition::Op::NE  },
    {"&==", Condition::Op::SET },
    {"&!=", Condition::Op::NSET},
    {"<"  , Condition::Op::LT  },
    {"<=" , Condition::Op::LE  },
    {">"  , Condition::Op::GT  },
    {">=" , Condition::Op::GE  },
    {"s<" , Condition::Op::SLT },
    {"s<=", Condition::Op::SLE },
    {"s>" , Condition::Op::SGT },
    {"s>=", Condition::Op::SGE },
};

const std::map<std::string, Width> str_to_width =
{
    {"8" , Width::B },
    {"16", Width::H },
    {"32", Width::W },
    {"64", Width::DW },
};

Reg reg(std::string s) {
    assert(s.at(0) == 'r');
    uint8_t res = (uint8_t)boost::lexical_cast<uint16_t>(s.substr(1));
    return Reg{res};
}

Imm imm(std::string s) {
    //s.erase(std::remove_if(s.begin(), s.end(), isspace));
    return Imm{boost::lexical_cast<int32_t>(s)};
}

Value reg_or_imm(std::string s) {
    if(s.at(0) == 'r')
        return reg(s);
    else
        return imm(s);
}

static Deref deref(std::string width, std::string basereg, std::string sign, std::string _offset) {
    int offset = boost::lexical_cast<int>(_offset);
    return Deref{
        .width = str_to_width.at(width),
        .basereg = reg(basereg),
        .offset = (sign == "-" ? -offset : +offset),
    };
}

Instruction assemble(std::string text) {
    std::smatch m;
    if (regex_match(text, m, regex("exit"))) {
        return Exit{};
    }
    if (regex_match(text, m, regex("call " FUNC))) {
        int func = boost::lexical_cast<int>(m[1]);
        return Call {
            .func = func
        };
    }
    if (regex_match(text, m, regex(REG OPASSIGN REG))) {
        return Bin {
            .op = str_to_binop.at(m[2]),
            .is64 = true,
            .dst = reg(m[1]),
            .v = reg(m[3]),
            .lddw = false
        };
    }
    if (regex_match(text, m, regex(REG OPASSIGN IMM LONGLONG))) {
        return Bin {
            .op = str_to_binop.at(m[2]),
            .is64 = true,
            .dst = reg(m[1]),
            .v = imm(m[3]),
            .lddw = !m[4].str().empty()
        };
    }
    if (regex_match(text, m, regex(REG ASSIGN DEREF PAREN(REG PLUSMINUS IMM)))) {
        // TODO: remove redundancy: Load / StoreReg / StoreImm
        return Mem {
            .access = deref(m[2], m[3], m[4], m[5]),
            .value = reg(m[1]),
            ._is_load = true,
        };
    }
    if (regex_match(text, m, regex(DEREF PAREN(REG PLUSMINUS IMM) ASSIGN REG_OR_IMM))) {
        return Mem {
            .access = deref(m[1], m[2], m[3], m[4]),
            .value = reg_or_imm(m[5]),
            ._is_load = false,
        };
    }
    if (regex_match(text, m, regex("lock " DEREF PAREN(REG PLUSMINUS IMM) " [+]= " REG))) {
        return LockAdd {
            .access = deref(m[1], m[2], m[3], m[4]),
            .valreg = reg(m[5])
        };
    }
    if (regex_match(text, m, regex("r0 = " DEREF "skb\\[(.*)\\]"))) {
        auto width = str_to_width.at(m[1]);
        std::string access = m[2].str();
        if (regex_match(access, m, regex(REG)))
            return Packet { .width = width, .offset = 0, .regoffset = reg(m[1]) };
        if (regex_match(access, m, regex(IMM)))
            return Packet { .width = width, .offset = (int)imm(m[1]).v, .regoffset = {} };
        if (regex_match(access, m, regex(REG PLUSMINUS REG)))
            return Packet { .width = width, .offset = 0/* ? */, .regoffset = reg(m[2]) };
        if (regex_match(access, m, regex(REG PLUSMINUS IMM)))
            return Packet { .width = width, .offset = (int)imm(m[2]).v, .regoffset = reg(m[1]) };
        return Undefined{ 0 };
    }
    if (regex_match(text, m, regex("if " REG CMPOP REG_OR_IMM " goto " IMM WRAPPED_LABEL))) {
        // We ignore second IMM
        return Jmp {
            .cond = Condition{
                .op = str_to_cmpop.at(m[2]),
                .left = reg(m[1]),
                .right = reg_or_imm(m[3]),
            },
            .target = m[5]
        };
    }
    return Undefined{ 0 };
}

#define assemble_disasm(text) do { REQUIRE(to_string(assemble(text)) == text); } while(0)


TEST_CASE( "assembler", "[assemble][disasm]" ) {
    SECTION( "Bin" ) {
        SECTION( "rX op= rY" ) {
            assemble_disasm("r1 = r0");
            assemble_disasm("r0 = r1");
            assemble_disasm("r5 = r6");

            assemble_disasm("r8 += r7");
            assemble_disasm("r9 -= r10");
            assemble_disasm("r8 *= r9");
            assemble_disasm("r7 >>= r6");
            assemble_disasm("r4 >>>= r5");
            REQUIRE_THROWS(assemble("r3 //= r2"));
        }
        SECTION( "rX op= Y" ) {
            assemble_disasm("r1 = 2");
            //assemble_disasm("r0 = -3");
            assemble_disasm("r5 = 6");

            assemble_disasm("r8 += 7");
            assemble_disasm("r9 &= 10");
            assemble_disasm("r9 *= 11");
            assemble_disasm("r9 >>= 8");
            //assemble_disasm("r6 >>>= -7");

            REQUIRE_THROWS(assemble("r5 //= 4"));
        }
        SECTION( "rX op= Y ll" ) {
            assemble_disasm("r8 = 1 ll");
            assemble_disasm("r10 = 2 ll");
            assemble_disasm("r3 = 10 ll");

            assemble_disasm("r8 += 1 ll");
            assemble_disasm("r10 -= 2 ll");
            assemble_disasm("r3 *= 10 ll");
            assemble_disasm("r3 >>= 10 ll");
            assemble_disasm("r3 >>>= 10 ll");

            REQUIRE_THROWS(assemble("r3 //= 10 ll"));
        }
    }

    SECTION( "Un" ) {
        
    }

    SECTION( "Call" ) {
        assemble_disasm("call 0");
        assemble_disasm("call 1");
        assemble_disasm("call 100");
    }

    SECTION( "Exit" ) {
        assemble_disasm("exit");
    }
    
    SECTION( "Mem" ) {
        SECTION( "Load" ) {
            assemble_disasm("r0 = *(u8 *)(r2 + 1)");
            assemble_disasm("r1 = *(u16 *)(r0 + 12)");
            assemble_disasm("r5 = *(u32 *)(r10 + 31)");
            assemble_disasm("r9 = *(u64 *)(r1 + 43)");

            assemble_disasm("r1 = *(u8 *)(r2 - 1)");
            assemble_disasm("r3 = *(u16 *)(r0 - 12)");
            assemble_disasm("r4 = *(u32 *)(r10 - 31)");
            assemble_disasm("r8 = *(u64 *)(r1 - 43)");

            REQUIRE_THROWS(assemble("r8 = *(u15 *)(r1 - 43)"));
        }
        SECTION( "Store Reg" ) {
            assemble_disasm("*(u8 *)(r2 + 1) = r0");
            assemble_disasm("*(u16 *)(r0 + 12) = r1");
            assemble_disasm("*(u32 *)(r10 + 31) = r5");
            assemble_disasm("*(u64 *)(r1 + 43) = r9");
            assemble_disasm("*(u8 *)(r2 - 1) = r1");
            assemble_disasm("*(u16 *)(r0 - 12) = r3");
            assemble_disasm("*(u32 *)(r10 - 31) = r4");
            assemble_disasm("*(u64 *)(r1 - 43) = r8");

            REQUIRE_THROWS(assemble("*(u15 *)(r1 - 43) = r8"));
        }
        SECTION( "Store Imm" ) {
            assemble_disasm("*(u8 *)(r2 + 1) = 0");
            assemble_disasm("*(u16 *)(r0 + 12) = 1");
            assemble_disasm("*(u32 *)(r10 + 31) = 5");
            assemble_disasm("*(u64 *)(r1 + 43) = 9");
            assemble_disasm("*(u8 *)(r2 - 1) = 1");
            assemble_disasm("*(u16 *)(r0 - 12) = 3");
            assemble_disasm("*(u32 *)(r10 - 31) = 4");
            assemble_disasm("*(u64 *)(r1 - 43) = 8");

            REQUIRE_THROWS(assemble("*(u15 *)(r1 - 43) = 8"));
        }
    }

    SECTION( "Packet" ) {
        assemble_disasm("r0 = *(u32 *)skb[r7]");
        assemble_disasm("r0 = *(u16 *)skb[53]");

        // TODO: add examples for r1 + 5, r2 + r3 - or disallow in disassembler
    }

    SECTION( "LockAdd" ) {
        assemble_disasm("lock *(u8 *)(r0 + 0) += r1");
        assemble_disasm("lock *(u16 *)(r1 + 33) += r3");
        assemble_disasm("lock *(u32 *)(r10 - 2) += r10");
        assemble_disasm("lock *(u64 *)(r10 - 100) += r3");
    }
}

std::string labeler(Label l) {
    const std::map<std::string, std::string> labelmap = {
        {"LBB0_44", "+21 <LBB0_44>" },
        {"LBB0_14", "-303 <LBB0_14>" },
        {"LBB0_31", "+0 <LBB0_31>" },
    };
    return labelmap.at(l);
}

#define jmp_assemble_disasm(text) do { REQUIRE(to_string(assemble(text), labeler) == text); } while(0)

TEST_CASE( "Jmp assembler", "[assemble][disasm]" ) {
    SECTION( "register cmp imm" ) {
        jmp_assemble_disasm("if r1 == 54 goto +21 <LBB0_44>");
        jmp_assemble_disasm("if r0 != 13 goto +21 <LBB0_44>");
        jmp_assemble_disasm("if r1 == 0 goto +21 <LBB0_44>");
        jmp_assemble_disasm("if r3 < 3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r3 <= 3 goto +0 <LBB0_31>");

        REQUIRE_THROWS(assemble("r3 &!= 10 ll"));
    }
    SECTION( "register cmp register" ) {
        jmp_assemble_disasm("if r2 > r3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r2 >= r3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r4 s> r1 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r2 s>= r3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r3 s< r2 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r1 s<= r4 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r1 &== r4 goto -303 <LBB0_14>");
    }
}


std::vector<std::tuple<Label, Instruction>> assemble_program(std::istream& is) {
    std::string line;
    int lineno = 0;
    std::vector<Label> pc_to_label;
    std::vector<std::tuple<Label, Instruction>> labeled_insts;
    std::unordered_set<Label> seen_labels;
    std::optional<std::string> next_label;
    while (std::getline(is, line)) {
        lineno++;
        std::smatch m;
        if (regex_search(line, m, regex("^" LABEL ":"))) {
            next_label = m[1];
            if (seen_labels.count(m[1]) != 0)
                throw std::invalid_argument("duplicate labels");
            line = m.suffix();
        }
        if (regex_search(line, m, regex("^\\s*(\\d+:)?\\s*"))) {
            line = m.suffix();
        }
        if (line.empty())
            continue;
        Instruction ins = assemble(line);
        if (std::holds_alternative<Undefined>(ins))
            continue;

        if (!next_label)
            next_label = std::to_string(labeled_insts.size());
        labeled_insts.emplace_back(*next_label, ins);
        next_label = {};
        // Mimic unmarshalled code, to prepare for build_cfg
        if (std::holds_alternative<Bin>(ins) && std::get<Bin>(ins).lddw) {
            labeled_insts.emplace_back(std::to_string(labeled_insts.size()), Undefined{0});
        }
    }
    return labeled_insts;
}

std::unordered_set<Label> get_labels(Cfg const& cfg) {
    std::unordered_set<Label> labels(cfg.size());
    for (auto const& [key, _] : cfg)
        labels.insert(key);
    return labels;
}

std::ostream& operator<<(std::ostream& os, std::tuple<Label, Instruction> const& labeled_ins) {
    auto [label, ins] = labeled_ins;
    return os << "(" << label << ", " << ins << ")";
}

TEST_CASE( "Full assembler minimal", "[assemble][full-assemble]") {
    std::string code = R"code(
sockex1_kern.o:	file format ELF64-BPF

Disassembly of section socket1:
bpf_prog1:
       0:	r0 = 1
       1:	exit
    )code";

    std::vector<std::tuple<Label, Instruction>> expected{
        {"bpf_prog1", assemble("r0 = 1")},
        {"1",         assemble("exit")},
    };

    std::istringstream is(code);
    auto labeled_insts = assemble_program(is);

    REQUIRE(labeled_insts == expected);
}

TEST_CASE( "Full assembler jump", "[assemble][full-assemble]") {
    std::string code = R"code(
sockex1_kern.o:	file format ELF64-BPF

Disassembly of section socket1:
bpf_prog1:
       0:	r0 = 1
       1:	if r0 != 4 goto +1 <LBB0_1>
       2:	r0 = 2

LBB0_1:
       3:	exit
    )code";

    std::vector<std::tuple<Label, Instruction>> expected = {
       {"bpf_prog1", assemble("r0 = 1")},
       {"1",         assemble("if r0 != 4 goto +1 <LBB0_1>")},
       {"2",         assemble("r0 = 2")},
       {"LBB0_1",    assemble("exit")},
    };

    std::istringstream is(code);
    auto labeled_insts = assemble_program(is);

    REQUIRE(labeled_insts == expected);
}
