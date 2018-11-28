#include <variant>

#include <iostream>

#include "instructions.hpp"

#include "asm.hpp"

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
        std::visit(*this, b.v);
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
        os_ << "call " << b.func;
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
        if (imm.v >= 0xFFFFFFFFLL)
            os_ << imm.v << " ll";
        else
            os_ << (int32_t)imm.v;
    }
    void operator()(Offset off) {
        os_ << static_cast<int16_t>(off);
    }
    void operator()(Reg reg) {
        os_ << "r" << reg;
    }
};

static std::ostream& operator<< (std::ostream& os, Instruction const& v) {
    std::visit(InstructionVisitor{os}, v);
    os << "";
    return os;
}

std::ostream& operator<< (std::ostream& os, IndexedInstruction const& v) {
    os << "    " << v.pc << " :        " << v.ins;
    return os;
}
