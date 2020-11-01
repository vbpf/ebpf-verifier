#pragma once
#include <cinttypes>

struct ebpf_inst {
    std::uint8_t opcode;
    std::uint8_t dst : 4;
    std::uint8_t src : 4;
    std::int16_t offset;
    std::int32_t imm;
};

enum {
    INST_CLS_MASK = 0x07,

    INST_CLS_LD = 0x00,
    INST_CLS_LDX = 0x01,
    INST_CLS_ST = 0x02,
    INST_CLS_STX = 0x03,
    INST_CLS_ALU = 0x04,
    INST_CLS_JMP = 0x05,
    INST_CLS_UNUSED = 0x06,
    INST_CLS_ALU64 = 0x07,

    INST_SRC_IMM = 0x00,
    INST_SRC_REG = 0x08,

    INST_SIZE_W = 0x00,
    INST_SIZE_H = 0x08,
    INST_SIZE_B = 0x10,
    INST_SIZE_DW = 0x18,

    INST_SIZE_MASK = 0x18,

    INST_MODE_MASK = 0xe0,

    INST_ABS = 1,
    INST_IND = 2,
    INST_MEM = 3,
    INST_LEN = 4,
    INST_MSH = 5,
    INST_XADD = 6,
    INST_MEM_UNUSED = 7,

    INST_OP_LDDW_IMM = (INST_CLS_LD | INST_SRC_IMM | INST_SIZE_DW), // Special

    INST_OP_JA = (INST_CLS_JMP | 0x00),
    INST_OP_CALL = (INST_CLS_JMP | 0x80),
    INST_OP_EXIT = (INST_CLS_JMP | 0x90),
    INST_ALU_OP_MASK = 0xf0
};

int opcode_to_width(uint8_t opcode);
uint8_t width_to_opcode(int width);

inline uint64_t merge(int32_t imm, int32_t next_imm) { return (((uint64_t)next_imm) << 32) | (uint32_t)imm; }
inline std::tuple<int32_t, int32_t> split(uint64_t v) { return {(uint32_t)v, (uint32_t)(v >> 32)}; }
