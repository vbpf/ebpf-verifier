#include "catch.hpp"
#include "asm.hpp"

#include <map>
#include <regex>
#include <boost/lexical_cast.hpp>

#define REG R"_(r(\d|10))_"
#define IMM R"_(([-+]?\d+))_"
//#define REG_OR_IMM R"_((r(\d+)|(\d+)))_"
#define ASSIGN R"_(\s*(\S*)=\s*)_"
#define DW R"_(\s*(ll|)\s*)_"

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

Reg reg(std::string s) {
    return Reg{boost::lexical_cast<int>(s)};
}
Imm imm(std::string s) {
    return Imm{boost::lexical_cast<int>(s)};
}

Instruction assemble(std::string text) {
    std::smatch m;
    if (std::regex_match(text, m, std::regex(R"_(call\s(\d+))_"))) {
        int func = boost::lexical_cast<int>(m[1]);
        return Call {
            .func = func
        };
    }
    if (std::regex_match(text, m, std::regex(REG ASSIGN REG))) {
        return Bin {
            .op = str_to_binop.at(m[2]),
            .is64 = true,
            .dst = reg(m[1]),
            .v = reg(m[3]),
            .lddw = false
        };
    }
    if (std::regex_match(text, m, std::regex(REG ASSIGN IMM DW))) {
        return Bin {
            .op = str_to_binop.at(m[2]),
            .is64 = true,
            .dst = reg(m[1]),
            .v = imm(m[3]),
            .lddw = !m[4].str().empty()
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
        
    }
    
    SECTION( "Mem" ) {

    }

    SECTION( "Packet" ) {
        
    }

    SECTION( "LockAdd" ) {
        
    }
}
