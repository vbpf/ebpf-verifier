#pragma once
#include <inttypes.h>
#include <tuple>

struct ebpf_inst {
    uint8_t opcode;
    uint8_t dst : 4;
    uint8_t src : 4;
    int16_t offset;
    int32_t imm;
};

#define EBPF_ALU_OP_MASK 0xf0

#define EBPF_CLS_MASK 0x07

#define EBPF_CLS_LD 0x00
#define EBPF_CLS_LDX 0x01
#define EBPF_CLS_ST 0x02
#define EBPF_CLS_STX 0x03
#define EBPF_CLS_ALU 0x04
#define EBPF_CLS_JMP 0x05
#define EBPF_CLS_UNUSED 0x06
#define EBPF_CLS_ALU64 0x07

#define EBPF_SRC_IMM 0x00
#define EBPF_SRC_REG 0x08

#define EBPF_SIZE_W 0x00
#define EBPF_SIZE_H 0x08
#define EBPF_SIZE_B 0x10
#define EBPF_SIZE_DW 0x18

#define EBPF_SIZE_MASK 0x18 

#define EBPF_MODE_MASK 0xe0

#define EBPF_ABS 1
#define EBPF_IND 2
#define EBPF_MEM 3
#define EBPF_LEN 4
#define EBPF_MSH 5
#define EBPF_XADD 6
#define EBPF_MEM_UNUSED 7

#define EBPF_OP_LDDW_IMM      (EBPF_CLS_LD |EBPF_SRC_IMM|EBPF_SIZE_DW) // Special

#define EBPF_OP_JA       (EBPF_CLS_JMP|0x00)
#define EBPF_OP_CALL     (EBPF_CLS_JMP|0x80)
#define EBPF_OP_EXIT     (EBPF_CLS_JMP|0x90)

inline uint64_t merge(int32_t imm, int32_t next_imm) {
    return (((uint64_t)next_imm) << 32) | (uint32_t)imm;
}
inline std::tuple<int32_t, int32_t> split(uint64_t v) {
    return {(uint32_t)v, (uint32_t)(v >> 32) };
}

inline int opcode_to_width(uint8_t opcode)
{
    switch (opcode & EBPF_SIZE_MASK) {
        case EBPF_SIZE_B: return 1;
        case EBPF_SIZE_H: return 2;
        case EBPF_SIZE_W: return 4;
        case EBPF_SIZE_DW: return 8;
    }
	assert(false);
}

inline uint8_t width_to_opcode(int width)
{
    switch (width) {
        case 1: return EBPF_SIZE_B;
        case 2: return EBPF_SIZE_H;
        case 4: return EBPF_SIZE_W;
        case 8: return EBPF_SIZE_DW;
    }
	assert(false);
}
