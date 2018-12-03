#include "catch.hpp"
#include "asm.hpp"

#include <map>
#include <regex>
#include <algorithm>
#include <boost/lexical_cast.hpp>

using std::regex;
using std::regex_match;

#define REG R"_(r(\d+)\s*)_"
#define IMM R"_(([-+]?\d+))_"
#define OPASSIGN R"_(\s*(\S*)=\s*)_"
#define ASSIGN R"_(\s*=\s*)_"
#define LONGLONG R"_(\s*(ll|)\s*)_"

#define PLUSMINUS R"_((\s*[+-])\s*)_"
#define LPAREN R"_(\s*\(\s*)_"
#define RPAREN R"_(\s*\)\s*)_"
#define PAREN(x) LPAREN x RPAREN
#define STAR R"_(\s*\*\s*)_"
#define DEREF STAR PAREN("u(\\d+)" STAR) PAREN(REG PLUSMINUS IMM)

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

const std::map<std::string, Width> str_to_width =
{
    {"8" , Width::B },
    {"16", Width::H },
    {"32", Width::W },
    {"64", Width::DW },
};

Reg reg(std::string s) {
    return Reg{boost::lexical_cast<int>(s)};
}

Imm imm(std::string s) {
    //s.erase(std::remove_if(s.begin(), s.end(), isspace));
    return Imm{boost::lexical_cast<int>(s)};
}

Instruction assemble(std::string text) {
    std::smatch m;
    if (regex_match(text, m, regex("exit"))) {
        return Exit{};
    }
    if (regex_match(text, m, regex(R"_(call\s(\d+))_"))) {
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
    if (regex_match(text, m, regex(REG ASSIGN DEREF))) {
        // TODO: remove redundancy: Load / StoreReg / StoreImm
        int offset = boost::lexical_cast<int>(m[5]);
        return Mem {
            .width = str_to_width.at(m[2]),
            .basereg = reg(m[3]),
            .offset =  (m[4].str() == "-" ? -offset : +offset),
            .value = (Mem::Load)boost::lexical_cast<int>(m[1]),
        };
    }
    if (regex_match(text, m, regex(DEREF ASSIGN REG))) {
        int offset = boost::lexical_cast<int>(m[4]);
        return Mem {
            .width = str_to_width.at(m[1]),
            .basereg = reg(m[2]),
            .offset =  (m[3].str() == "-" ? -offset : +offset),
            .value = (Mem::StoreReg)boost::lexical_cast<int>(m[5]),
        };
    }
    if (regex_match(text, m, regex(DEREF ASSIGN IMM))) {
        //std::cout << m[0] << " , " << m[1] << " , " << m[2] << " , " << m[3] << " , " << m[4] << "\n";
        int offset = boost::lexical_cast<int>(m[4]);
        return Mem {
            .width = str_to_width.at(m[1]),
            .basereg = reg(m[2]),
            .offset =  (m[3].str() == "-" ? -offset : +offset),
            .value = (Mem::StoreImm)boost::lexical_cast<int>(m[5]),
        };
    }
    return Undefined{ 0 };
}

#define assemble_disasm(text) do { REQUIRE(to_string(assemble(text)) == text); } while(0)


TEST_CASE( "assembler", "[assemble][disasm]" ) {
    SECTION( "Bin" ) {
        SECTION( "Reg" ) {
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
        SECTION( "Imm" ) {
            assemble_disasm("r1 = 2");
            assemble_disasm("r0 = -3");
            assemble_disasm("r5 = 6");

            assemble_disasm("r8 += 7");
            assemble_disasm("r9 &= 10");
            assemble_disasm("r9 *= 11");
            assemble_disasm("r9 >>= 8");
            assemble_disasm("r6 >>>= -7");

            REQUIRE_THROWS(assemble("r5 //= 4"));
        }
        SECTION( "Imm ll" ) {
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

    SECTION( "Jmp" ) {
        
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
        
    }

    SECTION( "LockAdd" ) {
        
    }
}
