#include <variant>

#include <iostream>
#include <iomanip>

#include "asm.hpp"

using std::string;
using std::vector;
using std::optional;


static string op(Bin::Op op) {
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

static string op(Condition::Op op) {
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

struct InstructionPrinterVisitor {
    std::ostream& os_;
    std::function<auto(Label)->string> label_to_target = [](Label l) { return l; };

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
        os_ << "goto " << label_to_target(b.target);
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

static int first_num(const string& s)
{
    return boost::lexical_cast<int>(s.substr(0, s.find_first_of(':')));
}

static int last_num(const string& s)
{
    return boost::lexical_cast<int>(s.substr(s.find_first_of(':')+1));
}

static bool cmp_labels(Label a, Label b) {
    if (first_num(a) < first_num(b)) return true;
    if (first_num(a) > first_num(b)) return false;
    return a < b;
}

static vector<Label> sorted_labels(const Cfg& cfg)
{
    vector<Label> labels;
    for (auto const& [label, bb] : cfg)
        labels.push_back(label);

    std::sort(labels.begin(), labels.end(), cmp_labels);
    return labels;
}

static vector<std::tuple<Label, optional<Label>>> slide(const vector<Label>& labels)
{
    if (labels.size() == 0) return {};
    vector<std::tuple<Label, optional<Label>>> label_pairs;
    Label prev = labels.at(0);
    bool first = true;
    for (auto label : labels) {
        if (first) { first = false; continue; }
        label_pairs.push_back({prev, label});
        prev = label;
    }
    label_pairs.push_back({prev, {}});
    return label_pairs;
}

void print(std::ostream& os, Instruction const& ins, pc_t pc) {
    std::visit(InstructionPrinterVisitor{os, label_to_offset_string(pc)}, ins);
}

string to_string(Instruction const& ins) {
    std::stringstream str;
    print(str, ins, 0);
    return str.str();
}

void print(const Program& prog) {
    pc_t pc = 0;
    for (auto ins : prog.code) {
        std::cout << std::setw(8) << pc << " : ";
        print(std::cout, ins, pc);
        std::cout << "\n";
        pc++;
    }
}

void print(const Cfg& cfg, bool nondet) {
    for (auto [label, next] : slide(sorted_labels(cfg))) {
        std::cout << std::setw(11) << label << " : ";
        const auto& bb = cfg.at(label);
        for (auto ins : bb.insts) {
            std::visit(InstructionPrinterVisitor{std::cout}, ins);
            std::cout << "\n";
        }
        if (nondet && bb.nextlist.size() > 0 && (!next || bb.nextlist != vector<Label>{*next})) {
            if (bb.insts.size() > 0)
                std::cout << std::setw(14) << "";
            std::cout << "goto ";
            for (Label label : bb.nextlist)
                std::cout << label << ", ";
            std::cout << "\n";
        }
    }
}
