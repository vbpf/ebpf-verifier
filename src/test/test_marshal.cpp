// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "asm_ostream.hpp"
#include "asm_marshal.hpp"
#include "asm_unmarshal.hpp"

static void compare_marshal_unmarshal(const Instruction& ins, bool double_cmd = false) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    InstructionSeq parsed = std::get<InstructionSeq>(unmarshal(raw_program{"", "", marshal(ins, 0), info}));
    REQUIRE(parsed.size() == 1);
    auto [_, single, _2] = parsed.back();
    (void)_;  // unused
    (void)_2; // unused
    REQUIRE(single == ins);
}

static void check_marshal_unmarshal_fail(const Instruction& ins, std::string expected_error_message) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    std::string error_message = std::get<std::string>(unmarshal(raw_program{"", "", marshal(ins, 0), info}));
    REQUIRE(error_message == expected_error_message);
}

static void check_unmarshal_fail(ebpf_inst inst, std::string expected_error_message) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    std::vector<ebpf_inst> insns = {inst};
    std::string error_message = std::get<std::string>(unmarshal(raw_program{"", "", insns, info}));
    REQUIRE(error_message == expected_error_message);
}

static const auto ws = {1, 2, 4, 8};

TEST_CASE("disasm_marshal", "[disasm][marshal]") {
    SECTION("Bin") {
        auto ops = {Bin::Op::MOV, Bin::Op::ADD, Bin::Op::SUB, Bin::Op::MUL, Bin::Op::UDIV,  Bin::Op::UMOD,
                    Bin::Op::OR,  Bin::Op::AND, Bin::Op::LSH, Bin::Op::RSH, Bin::Op::ARSH, Bin::Op::XOR};
        SECTION("Reg src") {
            for (auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = true});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = false});
            }
        }
        SECTION("Imm src") {
            for (auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Imm{2}, .is64 = false});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Imm{2}, .is64 = true});
            }
            SECTION("LDDW") {
                compare_marshal_unmarshal(
                    Bin{.op = Bin::Op::MOV, .dst = Reg{1}, .v = Imm{2}, .is64 = true, .lddw = true}, true);
            }
            SECTION("r10") {
                check_marshal_unmarshal_fail(Bin{.op = Bin::Op::ADD, .dst = Reg{10}, .v = Imm{4}, .is64=true},
                                             "0: Invalid target r10\n");
            }
        }
    }

    SECTION("Un") {
        auto ops = {
            Un::Op::BE16,
            Un::Op::BE32,
            Un::Op::BE64,
            Un::Op::LE16,
            Un::Op::LE32,
            Un::Op::LE64,
            Un::Op::NEG,
        };
        for (auto op : ops)
            compare_marshal_unmarshal(Un{.op = op, .dst = Reg{1}});
    }

    SECTION("LoadMapFd") { compare_marshal_unmarshal(LoadMapFd{.dst = Reg{1}, .mapfd = 1}, true); }

    SECTION("Jmp") {
        auto ops = {Condition::Op::EQ, Condition::Op::GT, Condition::Op::GE, Condition::Op::SET,
            // Condition::Op::NSET, does not exist in ebpf
                    Condition::Op::NE, Condition::Op::SGT, Condition::Op::SGE, Condition::Op::LT, Condition::Op::LE,
                    Condition::Op::SLT, Condition::Op::SLE};
        SECTION("Reg right") {
            for (auto op : ops) {
                Condition cond{.op = op, .left = Reg{1}, .right = Reg{2}};
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = label_t(0)});

                // The following should fail unmarshalling since it jumps past the end of the instruction set.
                check_marshal_unmarshal_fail(Jmp{.cond = cond, .target = label_t(1)}, "0: jump out of bounds\n");
            }
        }
        SECTION("Imm right") {
            for (auto op : ops) {
                Condition cond{.op = op, .left = Reg{1}, .right = Imm{2}};
                compare_marshal_unmarshal(Jmp{.cond = cond, .target = label_t(0)});

                // The following should fail unmarshalling since it jumps past the end of the instruction set.
                check_marshal_unmarshal_fail(Jmp{.cond = cond, .target = label_t(1)}, "0: jump out of bounds\n");
            }
        }
    }

    SECTION("Call") {
        for (int func : {1, 17})
            compare_marshal_unmarshal(Call{func});
    }

    SECTION("Exit") { compare_marshal_unmarshal(Exit{}); }

    SECTION("Packet") {
        for (int w : ws) {
            compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = {}});
            compare_marshal_unmarshal(Packet{.width = w, .offset = 7, .regoffset = Reg{2}});
        }
    }

    SECTION("LockAdd") {
        for (int w : ws) {
            if (w == 4 || w == 8) {
                Deref access{.width = w, .basereg = Reg{2}, .offset = 17};
                compare_marshal_unmarshal(LockAdd{.access = access, .valreg = Reg{1}});
            }
        }
    }
}

TEST_CASE("marshal", "[disasm][marshal]") {
    SECTION("Load") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        Mem m{.access = access, .value = Reg{3}, .is_load = true};
        auto ins = marshal(m, 0).at(0);
        ebpf_inst expect{
            .opcode = (uint8_t)(INST_CLS_LD | (INST_MEM << 5) | width_to_opcode(1) | 0x1),
            .dst = 3,
            .src = 4,
            .offset = 6,
            .imm = 0,
        };
        REQUIRE(ins.dst == expect.dst);
        REQUIRE(ins.src == expect.src);
        REQUIRE(ins.offset == expect.offset);
        REQUIRE(ins.imm == expect.imm);
        REQUIRE(ins.opcode == expect.opcode);
    }
    SECTION("Load Imm") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        REQUIRE_THROWS(marshal(Mem{.access = access, .value = Imm{3}, .is_load = true}, 0));
    }
    SECTION("Store") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        auto ins = marshal(Mem{.access = access, .value = Reg{3}, .is_load = false}, 0).at(0);
        REQUIRE(ins.src == 3);
        REQUIRE(ins.dst == 4);
        REQUIRE(ins.offset == 6);
        REQUIRE(ins.imm == 0);
        REQUIRE(ins.opcode == (uint8_t)(INST_CLS_ST | (INST_MEM << 5) | width_to_opcode(1) | 0x1));
    }
    SECTION("StoreImm") {
        Deref access{.width = 1, .basereg = Reg{4}, .offset = 6};
        auto ins = marshal(Mem{.access = access, .value = Imm{3}, .is_load = false}, 0).at(0);
        REQUIRE(ins.src == 0);
        REQUIRE(ins.dst == 4);
        REQUIRE(ins.offset == 6);
        REQUIRE(ins.imm == 3);
        REQUIRE(ins.opcode == (uint8_t)(INST_CLS_ST | (INST_MEM << 5) | width_to_opcode(1) | 0x0));
    }
}

TEST_CASE("disasm_marshal_Mem", "[disasm][marshal]") {
    SECTION("Load") {
        for (int w : ws) {
            Deref access;
            access.basereg = Reg{4};
            access.offset = 6;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Reg{3}, .is_load = true});
        }
    }
    SECTION("Load R10") {
        Deref access;
        access.basereg = Reg{0};
        access.offset = 0;
        access.width = 8;
        check_marshal_unmarshal_fail(Mem{.access = access, .value = Reg{10}, .is_load = true},
                                     "0: Cannot modify r10\n");
    }
    SECTION("Store Register") {
        for (int w : ws) {
            Deref access;
            access.basereg = Reg{9};
            access.offset = 8;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Reg{4}, .is_load = false});
        }
    }
    SECTION("Store Immediate") {
        for (int w : ws) {
            Deref access;
            access.basereg = Reg{10};
            access.offset = 2;
            access.width = w;
            compare_marshal_unmarshal(Mem{.access = access, .value = Imm{5}, .is_load = false});
        }
    }
}

TEST_CASE("fail unmarshal", "[disasm][marshal]") {
    check_unmarshal_fail(ebpf_inst{.opcode = ((INST_MEM << 5) | INST_SIZE_B | INST_CLS_LDX), .dst = 11, .imm = 8},
                         "0: Bad register\n");
    check_unmarshal_fail(ebpf_inst{.opcode = ((INST_MEM << 5) | INST_SIZE_W | INST_CLS_LD)},
                         "0: plain LD\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_ALU_OP_END | INST_END_LE | INST_CLS_ALU, .dst = 1, .imm = 8}, "0: invalid endian immediate\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_ALU_OP_END | INST_END_BE | INST_CLS_ALU, .dst = 1, .imm = 8}, "0: invalid endian immediate\n");
    check_unmarshal_fail(ebpf_inst{}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_CLS_LDX}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = ((INST_XADD << 5) | INST_CLS_ST)}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = ((INST_XADD << 5) | INST_SIZE_B | INST_CLS_STX)}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = ((INST_XADD << 5) | INST_SIZE_H | INST_CLS_STX)}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_OP_CALL | INST_SRC_REG}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_OP_LDDW_IMM}, "0: incomplete LDDW\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_ALU_OP_ADD | INST_SRC_IMM | INST_CLS_ALU64, .offset = 8},
                         "0: nonzero offset for register alu op\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_ALU_OP_ADD | INST_SRC_IMM | INST_CLS_ALU64, .src = 8},
                         "0: nonzero src for register alu op\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_ALU_OP_ADD | INST_SRC_REG | INST_CLS_ALU64, .imm = 8},
                         "0: nonzero imm for register alu op\n");
    check_unmarshal_fail(ebpf_inst{.opcode = (INST_ABS << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: ABS but not LD\n");
    check_unmarshal_fail(ebpf_inst{.opcode = (INST_IND << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: IND but not LD\n");
    check_unmarshal_fail(ebpf_inst{.opcode = (INST_LEN << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = (INST_MSH << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = (INST_MEM_UNUSED << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = INST_CLS_JMP32}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = 0x90 | INST_CLS_JMP32}, "0: Bad instruction\n");
    check_unmarshal_fail(ebpf_inst{.opcode = 0x10 | INST_CLS_JMP32}, "0: jump out of bounds\n");
}
