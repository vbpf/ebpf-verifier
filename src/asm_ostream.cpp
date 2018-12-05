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
        case Condition::Op::NSET:return "&!="; // not in ebpf
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
    LabelTranslator labeler = [](Label l) { return l; };

    void operator()(Undefined const& a) {
        os_ << "Undefined{" << a.opcode << "}";
    }

    void operator()(LoadMapFd const& b) {
        os_ << b.dst << " = fd " << b.mapfd;
    }

    void operator()(Bin const& b) {
        os_ << b.dst << " " << op(b.op) << "= ";
        if (b.lddw)
            os_ << std::get<Imm>(b.v).v << " ll";
        else
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
                os_ << b.dst << " = -" << b.dst;
                break;
        }
    }

    void operator()(Call const& b) {
        os_ << "call " << b.func;
    }

    void operator()(Exit const& b) {
        os_ << "exit";
    }

    void operator()(Jmp const& b) {
        if (b.cond) {
            os_ << "if "
                << b.cond->left
                << " " << op(b.cond->op) << " ";
            std::visit(*this, b.cond->right);
            os_ << " ";
        }
        os_ << "goto " << labeler(b.target);
    }

    void operator()(Assume const& b) {
        os_ << "assume "
            << b.cond.left
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
            os_ << *b.regoffset;
        if (b.offset != 0) {
            if (b.regoffset) os_ << " + ";
            os_ << b.offset;
        }
        os_ << "]";
    }

    void print(Deref const& access) {
        string sign = access.offset < 0 ? " - " : " + ";
        int offset = std::abs(access.offset); // what about INT_MIN? 
        os_ << "*(" << size(access.width) << " *)";
        os_ << "(" << access.basereg << sign << offset << ")";
    }

    void operator()(Mem const& b) {
        if (b.isLoad()) {
            std::visit(*this, b.value);
            os_ << " = ";
        }
        print(b.access);
        if (!b.isLoad()) {
            os_ << " = ";
            std::visit(*this, b.value);
        }
    }

    void operator()(LockAdd const& b) {
        os_ << "lock ";
        print(b.access);
        os_ << " += " << b.valreg;
    }

    void operator()(Imm imm) {
        if (imm.v >= 0xFFFFFFFFLL)
            os_ << imm.v << " ll";
        else
            os_ << imm.v;
    }
    void operator()(Reg reg) {
        os_ << reg;
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

void print(std::ostream& os, LabeledInstruction labeled_inst, pc_t pc) {
    auto [label, ins] = labeled_inst;
    if (std::holds_alternative<Jmp>(ins))
        std::get<Jmp>(ins).target = label_to_offset_string(pc)(std::get<Jmp>(ins).target);
    std::visit(InstructionPrinterVisitor{os}, ins);
}

string to_string(Instruction const& ins, LabelTranslator labeler) {
    std::stringstream str;
    std::visit(InstructionPrinterVisitor{str, labeler}, ins);
    return str.str();
}

std::ostream& operator<<(std::ostream& os, Instruction const& ins) {
    std::visit(InstructionPrinterVisitor{os, [](Label l){ return string("<") + l + ">";}}, ins);
    return os;
}

string to_string(Instruction const& ins) {
    return to_string(ins, [](Label l){ return string("<") + l + ">";});
}

void print(const InstructionSeq& insts) {
    pc_t pc = 0;
    for (auto inst : insts) {
        std::cout << std::setw(8) << pc << " : ";
        print(std::cout, inst, pc);
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
