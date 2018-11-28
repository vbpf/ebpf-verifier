#include <variant>

#include <iostream>

#include "instructions.hpp"

#include "disasm.hpp"

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

static Target getBinTarget(ebpf_inst inst) {
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

static Instruction toasm(ebpf_inst inst, int32_t next_imm) {
    if (inst.opcode == EBPF_OP_LDDW_IMM) {
        return Bin{
            .op = Bin::Op::MOV,
            .is64 = true,
            .dst = Reg{ inst.dst },
            .target = Imm{ next_imm  },
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
                        .offset = (inst.opcode & 1) ? (Target)Imm{inst.offset} : Reg{inst.imm},
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
                    .offset = Imm{inst.offset},
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
                    .target = getBinTarget(inst),
                };
            }

        case EBPF_CLS_JMP: 
            if (inst.opcode == EBPF_OP_JA) return Goto{ inst.offset };
            else if (inst.opcode == EBPF_OP_CALL) return Call{ inst.imm };
            else if (inst.opcode == EBPF_OP_EXIT) return Exit{};
            else return Jmp{
                .op = getJmpOp(inst.opcode),
                .left = Reg{inst.dst},
                .right = (inst.opcode & EBPF_SRC_REG) ? (Target)Reg{inst.src} : Imm{inst.offset},
                .offset = inst.offset,
            };
        case EBPF_CLS_UNUSED: return Undefined{};
    }
    return {};
}

IndexedInstruction toasm(uint16_t pc, ebpf_inst inst, int32_t next_imm) {
    return {pc, toasm(inst, next_imm)};
}

static std::string op(Bin::Op op) {
    switch (op) {
        case Bin::Op::MOV : return "";
        case Bin::Op::ADD : return "+";
        case Bin::Op::SUB : return "-";
        case Bin::Op::MUL : return "*";
        case Bin::Op::DIV : return "/";
        case Bin::Op::MOD : return "%";
        case Bin::Op::OR  : return "|";
        case Bin::Op::AND : return "&";
        case Bin::Op::LSH : return "<<";
        case Bin::Op::RSH : return ">>";
        case Bin::Op::ARSH: return ">>>";
        case Bin::Op::XOR : return "^";
    }
}

static std::string op(Jmp::Op op) {
    switch (op) {
        case Jmp::Op::EQ : return "==";
        case Jmp::Op::NE : return "!=";
        case Jmp::Op::SET: return "&==";
        case Jmp::Op::LT : return "<";
        case Jmp::Op::LE : return "<=";
        case Jmp::Op::GT : return ">";
        case Jmp::Op::GE : return ">=";
        case Jmp::Op::SLT: return "s<";
        case Jmp::Op::SLE: return "s<=";
        case Jmp::Op::SGT: return "s>";
        case Jmp::Op::SGE: return "s>=";
    }
}

static const char* size(Width w) {
    switch (w) {
        case Width::B : return "u8";
        case Width::H : return "u16";
        case Width::W : return "u32";
        case Width::DW: return "u64";
    }
}

struct InstructionVisitor {
    std::ostream& os_;

    InstructionVisitor(std::ostream& os) : os_{os} {}

    void operator()(Undefined const& a) {
        os_ << "Undefined{" << a.opcode << "}";
    }

    void operator()(Bin const& b) {
        os_ << "r" << b.dst << " " << op(b.op) << "= ";
        std::visit(*this, b.target);
        if (!b.is64)
            os_ << " & 0xFFFFFFFF";
    }

    void operator()(Un const& b) {
        switch (b.op) {
            case Un::Op::BE: os_ << "be()"; break;
            case Un::Op::LE: os_ << "le()"; break;
            case Un::Op::NEG:
                os_ << "r" << b.dst << " = -r" << b.dst;
                break;
        }
    }

    void operator()(Call const& b) {
        os_ << "call " << b.func << "()";
    }

    void operator()(Exit const& b) {
        os_ << "return r0";
    }

    void operator()(Goto const& b) {
        os_ << "goto +" << b.offset;
    }

    void operator()(Jmp const& b) {
        os_ << "if "
            << "r" << b.left
            << " " << op(b.op) << " ";
        std::visit(*this, b.right);
        os_ << " goto +" << b.offset;
    }

    void operator()(Packet const& b) {
        /* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
        /* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */
        const char* s = size(b.width);
        os_ << "r0 = ";
        os_ << "*(" << s << " *)skb[";
        if (b.regoffset)
            os_ << "r" << *b.regoffset;
        if (b.offset != 0) {
            if (b.regoffset) os_ << " + ";
            os_ << b.offset;
        }
        os_ << "]";
    }

    void operator()(Mem const& b) {
        const char* s = size(b.width);
        if (b.op == Mem::Op::LD) {
            os_ << "r" << b.valreg << " = ";
        }
        os_ << "*(" << s << "*)(r" << b.basereg << " + ";
        std::visit(*this, b.offset);
        os_ << ")";
        if (b.op == Mem::Op::ST) {
            os_ << " = " "r" << b.valreg;
        }
    }

    void operator()(LockAdd const& b) {
        const char* s = size(b.width);
        os_ << "lock ";
        os_ << "*(" << s << "*)(r" << b.basereg << " + " << b.offset << ")";
        os_ << " += r" << b.valreg;
    }

    void operator()(Imm imm) {
        os_ << imm;
    }
    void operator()(Reg reg) {
        os_ << "r" << reg;
    }
};

static std::ostream& operator<< (std::ostream& os, Instruction const& v) {
    std::visit(InstructionVisitor{os}, v);
    os << ";";
    return os;
}

std::ostream& operator<< (std::ostream& os, IndexedInstruction const& v) {
    os << v.pc << " : " << v.ins;
    return os;
}
