#include <variant>

#include <iostream>

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

static std::string op(Condition::Op op) {
    switch (op) {
        case Condition::Op::EQ : return "==";
        case Condition::Op::NE : return "!=";
        case Condition::Op::SET: return "&==";
        case Condition::Op::NSET: return "&!="; // not in ebpf
        case Condition::Op::LT : return "<";
        case Condition::Op::LE : return "<=";
        case Condition::Op::GT : return ">";
        case Condition::Op::GE : return ">=";
        case Condition::Op::SLT: return "s<";
        case Condition::Op::SLE: return "s<=";
        case Condition::Op::SGT: return "s>";
        case Condition::Op::SGE: return "s>=";
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
    std::function<auto(std::string)->int16_t> label_to_offset;

    void operator()(Undefined const& a) {
        os_ << "Undefined{" << a.opcode << "}";
    }

    void operator()(LoadMapFd const& b) {
        os_ << "r" << b.dst << " = fd " << b.mapfd;
    }

    void operator()(Bin const& b) {
        os_ << "r" << b.dst << " " << op(b.op) << "= ";
        std::visit(*this, b.v);
        if (!b.is64)
            os_ << " & 0xFFFFFFFF";
    }

    void operator()(Un const& b) {
        switch (b.op) {
            case Un::Op::LE16: os_ << "le16()"; break;
            case Un::Op::LE32: os_ << "le32()"; break;
            case Un::Op::LE64: os_ << "le64()"; break;
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

    void operator()(Jmp const& b) {
        if (b.cond) {
            os_ << "if "
                << "r" << b.cond->left
                << " " << op(b.cond->op) << " ";
            std::visit(*this, b.cond->right);
            os_ << " ";
        }
        os_ << "goto ";
        auto target = label_to_offset(b.target);
        if (target > 0) os_ << "+";
        os_ << target;
    }

    void operator()(Assume const& b) {
        os_ << "assume "
            << "r" << b.cond.left
            << " " << op(b.cond.op) << " ";
        std::visit(*this, b.cond.right);
        os_ << " ";
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
        if (b.isLoad()) {
            os_ << "r" << (int)std::get<Mem::Load>(b.value) << " = ";
        }
        os_ << "*(" << s << " *)(r" << b.basereg << " + " << b.offset << ")";
        if (!b.isLoad()) {
            os_ << " = ";
            if (std::holds_alternative<Mem::StoreImm>(b.value))
                os_ << std::get<Mem::StoreImm>(b.value);
            else 
                os_ << "r" << std::get<Mem::StoreReg>(b.value);
        }
    }

    void operator()(LockAdd const& b) {
        const char* s = size(b.width);
        os_ << "lock ";
        os_ << "*(" << s << " *)(r" << b.basereg << " + " << b.offset << ")";
        os_ << " += r" << b.valreg;
    }

    void operator()(Imm imm) {
        if (imm.v >= 0xFFFFFFFFLL)
            os_ << imm.v << " ll";
        else
            os_ << (int32_t)imm.v;
    }
    void operator()(Reg reg) {
        os_ << "r" << reg;
    }
};

void print(std::ostream& os, Instruction const& v, pc_t pc) {
    std::visit(InstructionVisitor{os, label_to_offset(pc)}, v);
}

std::ostream& operator<< (std::ostream& os, IndexedInstruction const& v) {
    print(os, v.ins, v.pc);
    return os;
}

void print(const Program& prog) {
    pc_t pc = 0;
    for (auto ins : prog.code) {
        std::cout << "    " << pc << " :        " << IndexedInstruction{pc, ins} << "\n";
        pc++;
    }
}