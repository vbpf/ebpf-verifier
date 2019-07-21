#include "catch.hpp"

#include "asm_ostream.hpp"
#include "asm_parse.hpp"

#include <map>

#define assemble_disasm(text)                                                                                          \
    do {                                                                                                               \
        REQUIRE(to_string(parse_instruction(text)) == text);                                                           \
    } while (0)

TEST_CASE("assembler", "[assemble][disasm]") {
    SECTION("Bin") {
        SECTION("rX op= rY") {
            assemble_disasm("r1 = r0");
            assemble_disasm("r0 = r1");
            assemble_disasm("r5 = r6");

            assemble_disasm("r8 += r7");
            assemble_disasm("r9 -= r10");
            assemble_disasm("r8 *= r9");
            assemble_disasm("r7 >>= r6");
            assemble_disasm("r4 >>>= r5");
            REQUIRE_THROWS(parse_instruction("r3 //= r2"));
        }
        SECTION("rX op= Y") {
            assemble_disasm("r1 = 2");
            assemble_disasm("r0 = -3");
            assemble_disasm("r5 = 6");

            assemble_disasm("r8 += 7");
            assemble_disasm("r9 &= 10");
            assemble_disasm("r9 *= 11");
            assemble_disasm("r9 >>= 8");
            assemble_disasm("r6 >>>= -7");

            REQUIRE_THROWS(parse_instruction("r5 //= 4"));
        }
        SECTION("rX op= Y ll") {
            assemble_disasm("r8 = 1 ll");
            assemble_disasm("r10 = 2 ll");
            assemble_disasm("r3 = 10 ll");

            assemble_disasm("r8 += 1 ll");
            assemble_disasm("r10 -= 2 ll");
            assemble_disasm("r3 *= 10 ll");
            assemble_disasm("r3 >>= 10 ll");
            assemble_disasm("r3 >>>= 10 ll");

            // This is how llvm-objdump prints
            // assemble_disasm("r2 = 4294967295 ll");

            REQUIRE_THROWS(parse_instruction("r3 //= 10 ll"));
        }
    }

    SECTION("Un") {}

    SECTION("Call") {}

    SECTION("Exit") { assemble_disasm("exit"); }

    SECTION("Mem") {
        SECTION("Load") {
            assemble_disasm("r0 = *(u8 *)(r2 + 1)");
            assemble_disasm("r1 = *(u16 *)(r0 + 12)");
            assemble_disasm("r5 = *(u32 *)(r10 + 31)");
            assemble_disasm("r9 = *(u64 *)(r1 + 43)");

            assemble_disasm("r1 = *(u8 *)(r2 - 1)");
            assemble_disasm("r3 = *(u16 *)(r0 - 12)");
            assemble_disasm("r4 = *(u32 *)(r10 - 31)");
            assemble_disasm("r8 = *(u64 *)(r1 - 43)");

            REQUIRE_THROWS(parse_instruction("r8 = *(u15 *)(r1 - 43)"));
        }
        SECTION("Store Reg") {
            assemble_disasm("*(u8 *)(r2 + 1) = r0");
            assemble_disasm("*(u16 *)(r0 + 12) = r1");
            assemble_disasm("*(u32 *)(r10 + 31) = r5");
            assemble_disasm("*(u64 *)(r1 + 43) = r9");
            assemble_disasm("*(u8 *)(r2 - 1) = r1");
            assemble_disasm("*(u16 *)(r0 - 12) = r3");
            assemble_disasm("*(u32 *)(r10 - 31) = r4");
            assemble_disasm("*(u64 *)(r1 - 43) = r8");

            REQUIRE_THROWS(parse_instruction("*(u15 *)(r1 - 43) = r8"));
        }
        SECTION("Store Imm") {
            assemble_disasm("*(u8 *)(r2 + 1) = 0");
            assemble_disasm("*(u16 *)(r0 + 12) = 1");
            assemble_disasm("*(u32 *)(r10 + 31) = 5");
            assemble_disasm("*(u64 *)(r1 + 43) = 9");
            assemble_disasm("*(u8 *)(r2 - 1) = 1");
            assemble_disasm("*(u16 *)(r0 - 12) = 3");
            assemble_disasm("*(u32 *)(r10 - 31) = 4");
            assemble_disasm("*(u64 *)(r1 - 43) = 8");

            REQUIRE_THROWS(parse_instruction("*(u15 *)(r1 - 43) = 8"));
        }
    }

    SECTION("Packet") {
        assemble_disasm("r0 = *(u32 *)skb[r7]");
        assemble_disasm("r0 = *(u16 *)skb[53]");

        // TODO: add examples for r1 + 5, r2 + r3 - or disallow in disassembler
    }

    SECTION("LockAdd") {
        assemble_disasm("lock *(u8 *)(r0 + 0) += r1");
        assemble_disasm("lock *(u16 *)(r1 + 33) += r3");
        assemble_disasm("lock *(u32 *)(r10 - 2) += r10");
        assemble_disasm("lock *(u64 *)(r10 - 100) += r3");
    }
}

std::string labeler(label_t l) {
    const std::map<std::string, std::string> labelmap = {
        {"LBB0_44", "+21 <LBB0_44>"},
        {"LBB0_14", "-303 <LBB0_14>"},
        {"LBB0_31", "+0 <LBB0_31>"},
        {"LBB0_18", "+130 <LBB0_18>"},
    };
    return labelmap.at(l);
}

#define jmp_assemble_disasm(text)                                                                                      \
    do {                                                                                                               \
        REQUIRE(to_string(parse_instruction(text), labeler) == text);                                                  \
    } while (0)

TEST_CASE("Jmp assembler", "[assemble][disasm]") {
    SECTION("unconditional") {
        jmp_assemble_disasm("goto +21 <LBB0_44>");
        jmp_assemble_disasm("goto -303 <LBB0_14>");
        jmp_assemble_disasm("goto +0 <LBB0_31>");
    }
    SECTION("register cmp imm") {
        jmp_assemble_disasm("if r1 == 54 goto +21 <LBB0_44>");
        jmp_assemble_disasm("if r0 != 13 goto +21 <LBB0_44>");
        jmp_assemble_disasm("if r1 == 0 goto +21 <LBB0_44>");
        jmp_assemble_disasm("if r3 < 3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r3 <= 3 goto +0 <LBB0_31>");
        jmp_assemble_disasm("if r6 > 8 goto +130 <LBB0_18>");

        REQUIRE_THROWS(parse_instruction("r3 &!= 10 ll"));
    }
    SECTION("register cmp register") {
        jmp_assemble_disasm("if r2 > r3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r2 >= r3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r4 s> r1 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r2 s>= r3 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r3 s< r2 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r1 s<= r4 goto -303 <LBB0_14>");
        jmp_assemble_disasm("if r1 &== r4 goto -303 <LBB0_14>");
    }
}

std::ostream& operator<<(std::ostream& os, std::tuple<label_t, Instruction> const& labeled_ins) {
    auto [label, ins] = labeled_ins;
    return os << "(" << label << ", " << ins << ")";
}

TEST_CASE("Full assembler minimal", "[assemble][full-assemble]") {
    std::string code = R"code(
sockex1_kern.o:	file format ELF64-BPF

Disassembly of section socket1:
bpf_prog1:
       0:	r0 = 1
       1:	exit
    )code";

    std::vector<std::tuple<label_t, Instruction>> expected{
        {"bpf_prog1", parse_instruction("r0 = 1")},
        {"1", parse_instruction("exit")},
    };

    std::istringstream is(code);
    auto labeled_insts = parse_program(is);

    REQUIRE(labeled_insts == expected);
}

TEST_CASE("Full assembler jump", "[assemble][full-assemble]") {
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

    std::vector<std::tuple<label_t, Instruction>> expected = {
        {"bpf_prog1", parse_instruction("r0 = 1")},
        {"1", parse_instruction("if r0 != 4 goto +1 <LBB0_1>")},
        {"2", parse_instruction("r0 = 2")},
        {"LBB0_1", parse_instruction("exit")},
    };

    std::istringstream is(code);
    auto labeled_insts = parse_program(is);

    REQUIRE(labeled_insts == expected);
}

TEST_CASE("Full assembler jump after ll", "[assemble][full-assemble]") {
    std::string code = R"code(
sockex1_kern.o:	file format ELF64-BPF

Disassembly of section socket1:
bpf_prog1:
       0:	r0 = 1
       1:	if r0 != 4 goto +1 <LBB0_1>
       2:	r0 = 2 ll

LBB0_1:
       4:	exit
    )code";

    std::vector<std::tuple<label_t, Instruction>> expected = {
        {"bpf_prog1", parse_instruction("r0 = 1")},
        {"1", parse_instruction("if r0 != 4 goto +1 <LBB0_1>")},
        {"2", parse_instruction("r0 = 2 ll")},
        {"LBB0_1", parse_instruction("exit")},
    };

    std::istringstream is(code);
    auto labeled_insts = parse_program(is);

    REQUIRE(labeled_insts == expected);
}
