// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "asm_ostream.hpp"
#include "asm_marshal.hpp"
#include "asm_unmarshal.hpp"

// Verify that if we unmarshal an instruction and then re-marshal it,
// we get what we expect.
static void compare_unmarshal_marshal(const ebpf_inst& ins, const ebpf_inst& expected_result) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    const ebpf_inst exit{.opcode = INST_OP_EXIT};
    InstructionSeq parsed = std::get<InstructionSeq>(unmarshal(raw_program{"", "", {ins, exit, exit}, info}));
    REQUIRE(parsed.size() == 3);
    auto [_, single, _2] = parsed.front();
    (void)_;  // unused
    (void)_2; // unused
    std::vector<ebpf_inst> marshaled = marshal(single, 0);
    REQUIRE(marshaled.size() == 1);
    ebpf_inst result = marshaled.back();
    REQUIRE(memcmp(&expected_result, &result, sizeof(result)) == 0);
}

// Verify that if we unmarshal two instructions and then re-marshal it,
// we get what we expect.
static void compare_unmarshal_marshal(const ebpf_inst& ins1, const ebpf_inst& ins2, const ebpf_inst& expected_result) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    const ebpf_inst exit{.opcode = INST_OP_EXIT};
    InstructionSeq parsed = std::get<InstructionSeq>(unmarshal(raw_program{"", "", {ins1, ins2, exit, exit}, info}));
    REQUIRE(parsed.size() == 3);
    auto [_, single, _2] = parsed.front();
    (void)_;  // unused
    (void)_2; // unused
    std::vector<ebpf_inst> marshaled = marshal(single, 0);
    REQUIRE(marshaled.size() == 1);
    ebpf_inst result = marshaled.back();
    REQUIRE(memcmp(&expected_result, &result, sizeof(result)) == 0);
}

// Verify that if we unmarshal a 64-bit immediate instruction and then re-marshal it,
// we get what we expect.
static void compare_unmarshal_marshal(const ebpf_inst& ins1, const ebpf_inst& ins2, const ebpf_inst& expected_result1,
                                      const ebpf_inst& expected_result2) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    const ebpf_inst exit{.opcode = INST_OP_EXIT};
    InstructionSeq parsed = std::get<InstructionSeq>(unmarshal(raw_program{"", "", {ins1, ins2, exit, exit}, info}));
    REQUIRE(parsed.size() == 3);
    auto [_, single, _2] = parsed.front();
    (void)_;  // unused
    (void)_2; // unused
    std::vector<ebpf_inst> marshaled = marshal(single, 0);
    REQUIRE(marshaled.size() == 2);
    ebpf_inst result1 = marshaled.front();
    REQUIRE(memcmp(&expected_result1, &result1, sizeof(result1)) == 0);
    ebpf_inst result2 = marshaled.back();
    REQUIRE(memcmp(&expected_result2, &result2, sizeof(result2)) == 0);
}

// Verify that if we marshal an instruction and then unmarshal it,
// we get the original.
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
    auto result = unmarshal(raw_program{"", "", insns, info});
    REQUIRE(std::holds_alternative<std::string>(result));
    std::string error_message = std::get<std::string>(result);
    REQUIRE(error_message == expected_error_message);
}

// Check that unmarshaling a 64-bit immediate instruction fails.
static void check_unmarshal_fail(ebpf_inst inst1, ebpf_inst inst2, std::string expected_error_message) {
    program_info info{.platform = &g_ebpf_platform_linux,
                      .type = g_ebpf_platform_linux.get_program_type("unspec", "unspec")};
    std::vector<ebpf_inst> insns = {inst1, inst2};
    auto result = unmarshal(raw_program{"", "", insns, info});
    REQUIRE(std::holds_alternative<std::string>(result));
    std::string error_message = std::get<std::string>(result);
    REQUIRE(error_message == expected_error_message);
}

static const auto ws = {1, 2, 4, 8};

TEST_CASE("disasm_marshal", "[disasm][marshal]") {
    SECTION("Bin") {
        SECTION("Reg src") {
            auto ops = {Bin::Op::MOV,  Bin::Op::ADD,  Bin::Op::SUB,    Bin::Op::MUL,     Bin::Op::UDIV,   Bin::Op::UMOD,
                        Bin::Op::OR,   Bin::Op::AND,  Bin::Op::LSH,    Bin::Op::RSH,     Bin::Op::ARSH,   Bin::Op::XOR,
                        Bin::Op::SDIV, Bin::Op::SMOD, Bin::Op::MOVSX8, Bin::Op::MOVSX16, Bin::Op::MOVSX32};
            for (auto op : ops) {
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = true});
                compare_marshal_unmarshal(Bin{.op = op, .dst = Reg{1}, .v = Reg{2}, .is64 = false});
            }
        }
        SECTION("Imm src") {
            // MOVSX* instructions are not defined for Imm, only Reg.
            auto ops = {Bin::Op::MOV,  Bin::Op::ADD, Bin::Op::SUB,  Bin::Op::MUL, Bin::Op::UDIV,
                        Bin::Op::UMOD, Bin::Op::OR,  Bin::Op::AND,  Bin::Op::LSH, Bin::Op::RSH,
                        Bin::Op::ARSH, Bin::Op::XOR, Bin::Op::SDIV, Bin::Op::SMOD};
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
            Un::Op::SWAP16,
            Un::Op::SWAP32,
            Un::Op::SWAP64
        };
        for (auto op : ops)
            compare_marshal_unmarshal(Un{.op = op, .dst = Reg{1}, .is64 = true});
    }

    SECTION("LoadMapFd") { compare_marshal_unmarshal(LoadMapFd{.dst = Reg{1}, .mapfd = 1}, true); }

    SECTION("Jmp") {
        auto ops = {Condition::Op::EQ, Condition::Op::GT, Condition::Op::GE, Condition::Op::SET,
            // Condition::Op::NSET, does not exist in ebpf
                    Condition::Op::NE, Condition::Op::SGT, Condition::Op::SGE, Condition::Op::LT, Condition::Op::LE,
                    Condition::Op::SLT, Condition::Op::SLE};
        SECTION("goto offset") {
            ebpf_inst jmp_offset{.opcode = INST_OP_JA16, .offset = 1};
            compare_unmarshal_marshal(jmp_offset, jmp_offset);

            // JA32 +1 is equivalent to JA16 +1 since the offset fits in 16 bits.
            compare_unmarshal_marshal(ebpf_inst{.opcode = INST_OP_JA32, .imm = 1}, jmp_offset);
        }
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

TEST_CASE("unmarshal extension opcodes", "[disasm][marshal]") {
    // Merge (rX <<= 32; rX >>>= 32) into wX = rX.
    compare_unmarshal_marshal(
        ebpf_inst{.opcode = INST_ALU_OP_LSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
        ebpf_inst{.opcode = INST_ALU_OP_RSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
        ebpf_inst{.opcode = INST_ALU_OP_MOV | INST_SRC_REG | INST_CLS_ALU, .dst = 1, .src = 1});

    // Merge (rX <<= 32; rX >>= 32)  into rX s32= rX.
    compare_unmarshal_marshal(
        ebpf_inst{.opcode = INST_ALU_OP_LSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
        ebpf_inst{.opcode = INST_ALU_OP_ARSH | INST_SRC_IMM | INST_CLS_ALU64, .dst = 1, .imm = 32},
        ebpf_inst{.opcode = INST_ALU_OP_MOV | INST_SRC_REG | INST_CLS_ALU64, .dst = 1, .src = 1, .offset = 32});
}

TEST_CASE("fail unmarshal invalid opcodes", "[disasm][marshal]") {
    // The following opcodes are undefined and should generate bad instruction errors.
    uint8_t bad_opcodes[] = {
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0d, 0x0e, 0x10, 0x11, 0x12, 0x13, 0x19, 0x1a, 0x1b, 0x60,
        0x68, 0x70, 0x78, 0x80, 0x81, 0x82, 0x83, 0x86, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
        0x92, 0x93, 0x96, 0x98, 0x99, 0x9a, 0x9b, 0x9d, 0x9e, 0xa0, 0xa1, 0xa2, 0xa3, 0xa8, 0xa9, 0xaa, 0xab, 0xb0,
        0xb1, 0xb2, 0xb3, 0xb8, 0xb9, 0xba, 0xbb, 0xc0, 0xc1, 0xc2, 0xc8, 0xc9, 0xca, 0xcb, 0xd0, 0xd1, 0xd2, 0xd3,
        0xd8, 0xd9, 0xda, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
        0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    for (int i = 0; i < sizeof(bad_opcodes); i++) {
        std::ostringstream oss;
        oss << "0: Bad instruction op 0x" << std::hex << (int)bad_opcodes[i] << std::endl;
        check_unmarshal_fail(ebpf_inst{.opcode = bad_opcodes[i]}, oss.str().c_str());
    }
}

TEST_CASE("fail unmarshal src0 opcodes", "[disasm][marshal]") {
    // The following opcodes are only defined for src = 0.
    uint8_t src0_opcodes[] = {0x04, 0x05, 0x06, 0x07, 0x14, 0x15, 0x16, 0x17, 0x24, 0x25, 0x26, 0x27, 0x34, 0x35, 0x36,
                              0x37, 0x44, 0x45, 0x46, 0x47, 0x54, 0x55, 0x56, 0x57, 0x62, 0x64, 0x65, 0x66, 0x67, 0x6a,
                              0x72, 0x74, 0x75, 0x76, 0x77, 0x7a, 0x84, 0x87, 0x94, 0x95, 0x97, 0xa4, 0xa5, 0xa6, 0xa7,
                              0xb4, 0xb5, 0xb6, 0xb7, 0xc4, 0xc5, 0xc6, 0xc7, 0xd4, 0xd5, 0xd6, 0xd7, 0xdc};
    for (int i = 0; i < sizeof(src0_opcodes); i++) {
        std::ostringstream oss;
        oss << "0: nonzero src for register op 0x" << std::hex << (int)src0_opcodes[i] << std::endl;
        check_unmarshal_fail(ebpf_inst{.opcode = src0_opcodes[i], .src = 1}, oss.str().c_str());
    }
}

TEST_CASE("fail unmarshal imm0 opcodes", "[disasm][marshal]") {
    // The following opcodes are only defined for imm = 0.
    uint8_t imm0_opcodes[] = {0x05, 0x0c, 0x0f, 0x1c, 0x1d, 0x1e, 0x1f, 0x2c, 0x2d, 0x2e, 0x2f, 0x3d, 0x3e, 0x3f, 0x4c,
                              0x4d, 0x4e, 0x4f, 0x5c, 0x5d, 0x5e, 0x5f, 0x61, 0x63, 0x69, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                              0x71, 0x73, 0x79, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x84, 0x87, 0x95, 0x9c, 0x9f, 0xac, 0xad,
                              0xae, 0xaf, 0xbc, 0xbd, 0xbe, 0xbf, 0xcc, 0xcd, 0xce, 0xcf, 0xdd, 0xde};
    for (int i = 0; i < sizeof(imm0_opcodes); i++) {
        std::ostringstream oss;
        oss << "0: nonzero imm for op 0x" << std::hex << (int)imm0_opcodes[i] << std::endl;
        check_unmarshal_fail(ebpf_inst{.opcode = imm0_opcodes[i], .imm = 1}, oss.str().c_str());
    }
}

TEST_CASE("fail unmarshal off0 opcodes", "[disasm][marshal]") {
    // The following opcodes are only defined for offset = 0.
    uint8_t off0_opcodes[] = {0x04, 0x06, 0x07, 0x0c, 0x0f, 0x14, 0x17, 0x1c, 0x1f, 0x24, 0x27, 0x2c, 0x2f, 0x44, 0x47,
                              0x4c, 0x4f, 0x54, 0x57, 0x5c, 0x5f, 0x64, 0x67, 0x6c, 0x6f, 0x74, 0x77, 0x7c, 0x7f, 0x84,
                              0x85, 0x87, 0x95, 0xa4, 0xa7, 0xac, 0xaf, 0xc4, 0xc7, 0xcc, 0xcf, 0xd4, 0xd7, 0xdc};
    for (int i = 0; i < sizeof(off0_opcodes); i++) {
        std::ostringstream oss;
        oss << "0: nonzero offset for op 0x" << std::hex << (int)off0_opcodes[i] << std::endl;
        check_unmarshal_fail(ebpf_inst{.opcode = off0_opcodes[i], .offset = 1}, oss.str().c_str());
    }
}

TEST_CASE("fail unmarshal offset opcodes", "[disasm][marshal]") {
    // The following opcodes are defined for multiple other offset values, but not offset = 2 for example.
    uint8_t off2_opcodes[] = {0x34, 0x37, 0x3c, 0x3f, 0x94, 0x97, 0x9c, 0x9f, 0xb4, 0xb7, 0xbc, 0xbf};
    for (int i = 0; i < sizeof(off2_opcodes); i++) {
        std::ostringstream oss;
        oss << "0: invalid offset for op 0x" << std::hex << (int)off2_opcodes[i] << std::endl;
        check_unmarshal_fail(ebpf_inst{.opcode = off2_opcodes[i], .offset = 2}, oss.str().c_str());
    }
}

TEST_CASE("unmarshal 64bit immediate", "[disasm][marshal]") {
    compare_unmarshal_marshal(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, ebpf_inst{.imm = 2},
                              ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, ebpf_inst{.imm = 2});
    compare_unmarshal_marshal(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, ebpf_inst{},
                              ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = 0, .imm = 1}, ebpf_inst{});

    for (uint8_t src = 0; src <= 7; src++) {
        check_unmarshal_fail(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src}, "0: incomplete LDDW\n");
        check_unmarshal_fail(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src},
                             ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM}, "0: invalid LDDW\n");
    }

    // No supported src values use the offset field.
    for (uint8_t src = 0; src <= 1; src++) {
        check_unmarshal_fail(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src, .offset = 1}, ebpf_inst{},
                             "0: LDDW uses reserved fields\n");
    }

    // Verify that unsupported src values fail.
    // TODO: support src = 2 through 6.
    for (uint8_t src = 2; src <= 7; src++) {
        check_unmarshal_fail(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src}, ebpf_inst{},
                             "0: LDDW uses reserved fields\n");
    }

    // When src = {1, 3, 4, 5}, next_imm must be 0.
    for (uint8_t src : {1, 3, 4, 5}) {
        check_unmarshal_fail(ebpf_inst{.opcode = /* 0x18 */ INST_OP_LDDW_IMM, .src = src}, ebpf_inst{.imm = 1},
                             "0: LDDW uses reserved fields\n");
    }
}

TEST_CASE("fail unmarshal misc", "[disasm][marshal]") {
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0x06 */ INST_CLS_JMP32}, "0: jump out of bounds\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0x16 */ 0x10 | INST_CLS_JMP32}, "0: jump out of bounds\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0x21 */ (INST_ABS << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: ABS but not LD\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0x41 */ (INST_IND << 5) | INST_SIZE_W | INST_CLS_LDX, .imm = 8},
                         "0: IND but not LD\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0x71 */ ((INST_MEM << 5) | INST_SIZE_B | INST_CLS_LDX), .dst = 11, .imm = 8},
                         "0: Bad register\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0x71 */ ((INST_MEM << 5) | INST_SIZE_B | INST_CLS_LDX), .dst = 1, .src = 11},
                         "0: Bad register\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xb4 */ (INST_ALU_OP_MOV | INST_SRC_IMM | INST_CLS_ALU), .dst = 11, .imm = 8},
                         "0: Bad register\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xb4 */ INST_ALU_OP_MOV | INST_SRC_IMM | INST_CLS_ALU, .offset = 8},
                         "0: invalid offset for op 0xb4\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xbc */ (INST_ALU_OP_MOV | INST_SRC_REG | INST_CLS_ALU), .dst = 1, .src = 11},
                         "0: Bad register\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xd4 */ INST_ALU_OP_END | INST_END_LE | INST_CLS_ALU, .dst = 1, .imm = 8},
                         "0: invalid endian immediate\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xd4 */ INST_ALU_OP_END | INST_END_LE | INST_CLS_ALU, .imm = 0},
                         "0: invalid endian immediate\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xd7 */ INST_ALU_OP_END | INST_END_LE | INST_CLS_ALU64, .imm = 0},
                         "0: invalid endian immediate\n");
    check_unmarshal_fail(ebpf_inst{.opcode = /* 0xdc */ INST_ALU_OP_END | INST_END_BE | INST_CLS_ALU, .dst = 1, .imm = 8},
                         "0: invalid endian immediate\n");
}
