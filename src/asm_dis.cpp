#include <variant>

#include "instructions.hpp"

#include "asm.hpp"

static Mem::Op getMemOp(uint8_t opcode) {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_ST : return Mem::Op::ST;
        case EBPF_CLS_STX: return Mem::Op::ST;
        case EBPF_CLS_LD : return Mem::Op::LD;
        case EBPF_CLS_LDX: return Mem::Op::LD;
    }
    return {};
}

static Width getMemWidth(uint8_t opcode) {
    switch (opcode & EBPF_SIZE_MASK) {
        case EBPF_SIZE_B : return Width::B;
        case EBPF_SIZE_H : return Width::H;
        case EBPF_SIZE_W : return Width::W;
        case EBPF_SIZE_DW: return Width::DW;
    }
	return {};
}

static bool getMemX(uint8_t opcode) {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD : return false; 
        case EBPF_CLS_ST : return false;
        case EBPF_CLS_LDX: return true;
        case EBPF_CLS_STX: return true;
    }
    return {};
}

static Bin::Op getBinOp(uint8_t opcode) {
    switch ((opcode >> 4) & 0xF) {
        case 0x0 : return Bin::Op::ADD;
        case 0x1 : return Bin::Op::SUB;
        case 0x2 : return Bin::Op::MUL;
        case 0x3 : return Bin::Op::DIV;
        case 0x4 : return Bin::Op::OR;
        case 0x5 : return Bin::Op::AND;
        case 0x6 : return Bin::Op::LSH;
        case 0x7 : return Bin::Op::RSH;

        case 0x9 : return Bin::Op::MOD;
        case 0xa : return Bin::Op::XOR;
        case 0xb : return Bin::Op::MOV;
        case 0xc: return Bin::Op::ARSH;
    }
    return Bin::Op::ARSH;
}

static Value getBinValue(ebpf_inst inst) {
    if (inst.opcode & EBPF_SRC_REG)
        return Reg{inst.src};
    else
        return Imm{inst.imm};
}

static Un::Op getUnOp(uint8_t opcode) {
    switch (opcode) {
        case EBPF_OP_NEG: return Un::Op::NEG;
        case EBPF_OP_LE : return Un::Op::LE;
        case EBPF_OP_BE : return Un::Op::BE;
    }
    return {};
}

static Jmp::Op getJmpOp(uint8_t opcode) {
    switch (opcode | EBPF_SRC_REG) {
        case EBPF_OP_JEQ_REG : return Jmp::Op::EQ;
        case EBPF_OP_JGT_REG : return Jmp::Op::GT;
        case EBPF_OP_JGE_REG : return Jmp::Op::GE;
        case EBPF_OP_JNE_REG : return Jmp::Op::NE;
        case EBPF_OP_JSET_REG: return Jmp::Op::SET;
        case EBPF_OP_JSGT_REG: return Jmp::Op::SGT;
        case EBPF_OP_JSGE_REG: return Jmp::Op::SGE;
        case EBPF_OP_JLT_REG : return Jmp::Op::LT;
        case EBPF_OP_JLE_REG : return Jmp::Op::LE;
        case EBPF_OP_JSLT_REG: return Jmp::Op::SLT;
        case EBPF_OP_JSLE_REG: return Jmp::Op::SLE;
    }
    return {};
}

static Instruction toasm(ebpf_inst inst, std::optional<int32_t> next_imm) {
    if (inst.opcode == EBPF_OP_LDDW_IMM) {
        return Bin{
            .op = Bin::Op::MOV,
            .is64 = true,
            .dst = Reg{ inst.dst },
            .v = Imm{ inst.imm, *next_imm  },
        };
    }
    switch (inst.opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD: case EBPF_CLS_LDX:
        case EBPF_CLS_ST: case EBPF_CLS_STX: {
            auto width = getMemWidth(inst.opcode);
            auto mode = inst.opcode & EBPF_MODE_MASK;
            switch (mode) {
                case EBPF_MODE_MEM: {
                    auto op = getMemOp(inst.opcode);
                    bool isLoad = op == Mem::Op::LD;
                    return Mem{ 
                        .op = op,
                        .width = width,
                        .valreg = Reg{isLoad ? inst.dst : inst.src},
                        .basereg = Reg{isLoad ? inst.src : inst.dst},
                        .offset = (inst.opcode & 1) ? (Target)Offset{inst.offset} : Reg{inst.imm},
                    };
                }
                case EBPF_MODE_ABS: return Packet{width, inst.imm, {} };
                case EBPF_MODE_IND: return Packet{width, inst.imm, Reg{inst.src} };
                case EBPF_MODE_LEN: return {};
                case EBPF_MODE_MSH: return {};
                case EBPF_XADD: return LockAdd {
                    .width = width,
                    .valreg = Reg{inst.src},
                    .basereg = Reg{inst.dst},
                    .offset = inst.offset,
                };
            }
            return Undefined{inst.opcode};
        }
        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64: 
            if (inst.opcode == EBPF_OP_NEG || inst.opcode == EBPF_OP_BE || inst.opcode == EBPF_OP_LE) {
                return Un{ 
                    .op = getUnOp(inst.opcode),
                    .dst=inst.dst 
                };
            } else {
                return Bin{ 
                    .op = getBinOp(inst.opcode), 
                    .is64 = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64,
                    .dst = Reg{ inst.dst },
                    .v = getBinValue(inst),
                };
            }

        case EBPF_CLS_JMP: 
            if (inst.opcode == EBPF_OP_JA) return Goto{ inst.offset };
            else if (inst.opcode == EBPF_OP_CALL) return Call{ inst.imm };
            else if (inst.opcode == EBPF_OP_EXIT) return Exit{};
            else return Jmp{
                .op = getJmpOp(inst.opcode),
                .left = Reg{inst.dst},
                .right = (inst.opcode & EBPF_SRC_REG) ? (Value)Reg{inst.src} : Imm{inst.imm},
                .offset = inst.offset,
            };
        case EBPF_CLS_UNUSED: return Undefined{};
    }
    return {};
}

IndexedInstruction toasm(uint16_t pc, ebpf_inst inst, std::optional<int32_t> next_imm) {
    return {pc, toasm(inst, next_imm)};
}
