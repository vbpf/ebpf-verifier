#include <variant>

#include "instructions.hpp"

#include "disasm.hpp"

static Mem::Mode getMemMode(uint8_t opcode) {
    switch (opcode & EBPF_MODE_MASK) {
        case EBPF_MODE_ABS: return Mem::Mode::ABS;
        case EBPF_MODE_IND: return Mem::Mode::IND;
        case EBPF_MODE_MEM: return Mem::Mode::MEM;
        case EBPF_MODE_LEN: return Mem::Mode::LEN;
        case EBPF_MODE_MSH: return Mem::Mode::MSH;
    }
    return {};
}

static Mem::Op getMemOp(uint8_t opcode) {
    switch (opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_ST : return Mem::Op::ST;
        case EBPF_CLS_STX: return Mem::Op::ST;
        case EBPF_CLS_LD : return Mem::Op::LD;
        case EBPF_CLS_LDX: return Mem::Op::LD;
    }
    return {};
}

static Mem::Width getMemWidth(uint8_t opcode) {
    switch (opcode & EBPF_SIZE_MASK) {
        case EBPF_SIZE_B : return Mem::Width::B;
        case EBPF_SIZE_H : return Mem::Width::H;
        case EBPF_SIZE_W : return Mem::Width::W;
        case EBPF_SIZE_DW: return Mem::Width::DW;
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
    switch (opcode | EBPF_SRC_REG) {
        case EBPF_OP_ADD_REG : return Bin::Op::ADD;
        case EBPF_OP_SUB_REG : return Bin::Op::SUB;
        case EBPF_OP_MUL_REG : return Bin::Op::MUL;
        case EBPF_OP_DIV_REG : return Bin::Op::DIV;
        case EBPF_OP_OR_REG  : return Bin::Op::OR;
        case EBPF_OP_AND_REG : return Bin::Op::AND;
        case EBPF_OP_LSH_REG : return Bin::Op::LSH;
        case EBPF_OP_RSH_REG : return Bin::Op::RSH;
        case EBPF_OP_MOD_REG : return Bin::Op::MOD;
        case EBPF_OP_XOR_REG : return Bin::Op::XOR;
        case EBPF_OP_MOV_REG : return Bin::Op::MOV;
        case EBPF_OP_ARSH_REG: return Bin::Op::ARSH;
    }
    return {};
}

static std::variant<Bin::Imm, Bin::Reg> getBinTarget(ebpf_inst inst) {
    if (inst.opcode & EBPF_SRC_REG)
        return Bin::Reg{inst.src};
    else
        return Bin::Imm{inst.imm};
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

InsCls toasm(ebpf_inst inst) {
    switch (inst.opcode & EBPF_CLS_MASK) {
        case EBPF_CLS_LD: case EBPF_CLS_LDX:
        case EBPF_CLS_ST: case EBPF_CLS_STX: {
            auto op = getMemOp(inst.opcode);
            bool isLoad = op == Mem::Op::LD;
            return Mem{ 
                .op = op,
                .x = getMemX(inst.opcode),
                .mode = getMemMode(inst.opcode),
                .width = getMemWidth(inst.opcode),
                .valreg = isLoad ? inst.dst : inst.src,
                .basereg = isLoad ? inst.src : inst.dst,
                .offset = inst.offset,
            };
        }
        case EBPF_CLS_ALU:
        case EBPF_CLS_ALU64: 
            if (inst.opcode == EBPF_OP_NEG || inst.opcode == EBPF_OP_BE || inst.opcode == EBPF_OP_LE) {
                return Un{ .op = getUnOp(inst.opcode) };
            } else {
                return Bin{ 
                    .op = getBinOp(inst.opcode), 
                    .is64 = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64,
                    .dst = inst.dst,
                    .target = getBinTarget(inst),
                };
            }

        case EBPF_CLS_JMP: 
            if (inst.opcode == EBPF_OP_JA) return Goto{ inst.offset };
            else if (inst.opcode == EBPF_OP_CALL) return Call{ inst.imm };
            else if (inst.opcode == EBPF_OP_EXIT) return Exit{};
            else return Jmp{
                .op = getJmpOp(inst.opcode),
                .leftreg = inst.dst,
                .rightreg = inst.src,
                .offset = inst.imm,
            };
        case EBPF_CLS_UNUSED: return Undefined{};
    }
    return {};
}
