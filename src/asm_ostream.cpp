#include <variant>

#include <iostream>
#include <iomanip>
#include <unordered_map>

#include "asm_syntax.hpp"
#include "asm_ostream.hpp"
#include "asm_cfg.hpp"

using std::string;
using std::vector;
using std::optional;
using std::cout;


static string op(Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
        case Op::MOV : return "";
        case Op::ADD : return "+";
        case Op::SUB : return "-";
        case Op::MUL : return "*";
        case Op::DIV : return "/";
        case Op::MOD : return "%";
        case Op::OR  : return "|";
        case Op::AND : return "&";
        case Op::LSH : return "<<";
        case Op::RSH : return ">>";
        case Op::ARSH: return ">>>";
        case Op::XOR : return "^";
    }
}

static string op(Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
        case Op::EQ : return "==";
        case Op::NE : return "!=";
        case Op::SET: return "&==";
        case Op::NSET:return "&!="; // not in ebpf
        case Op::LT : return "<";
        case Op::LE : return "<=";
        case Op::GT : return ">";
        case Op::GE : return ">=";
        case Op::SLT: return "s<";
        case Op::SLE: return "s<=";
        case Op::SGT: return "s>";
        case Op::SGE: return "s>=";
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
        os_ << b.dst << " = ";
        switch (b.op) {
            case Un::Op::LE16: os_ << "be16 "; break;
            case Un::Op::LE32: os_ << "be32 "; break;
            case Un::Op::LE64: os_ << "be64 "; break;
            case Un::Op::NEG:  os_ << "-";  break;
        }
        os_ << b.dst;
    }

    void operator()(Call const& b) {
        os_ << "call " << b.func;
    }

    void operator()(Exit const& b) {
        os_ << "exit";
    }

    void operator()(Jmp const& b) {
        if (b.cond) {
            os_ << "if ";
            print(*b.cond);
            os_ << " ";
        }
        os_ << "goto " << labeler(b.target);
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

    void print(Condition const& cond) {
        os_ << cond.left << " " << op(cond.op) << " ";
        std::visit(*this, cond.right);
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

    void operator()(Assume const& b) {
        os_ << "assume ";
        print(b.cond);
    }

    void operator()(Assert const& a) {
        os_ << "assert ";
        for (auto h : a.holds) { os_ << h << " && "; }
        for (auto [x, y] : a.implies_type) { os_ << x << " -> " << y << " && "; }
        for (auto [t, r, o, w, v] : a.implies) { os_ << t << " -> 0 <= " << r << " + " << o << ".." << o + w << " <= " << v << " && "; }
    }

    void operator()(Imm imm) {
        os_ << (int32_t)imm.v;
    }
    void operator()(Reg reg) {
        os_ << reg;
    }
};

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

int size(Instruction inst) {
    if (std::holds_alternative<Bin>(inst)) {
        if (std::get<Bin>(inst).lddw)
            return 2;
    }
    if (std::holds_alternative<LoadMapFd>(inst)) {
        return 2;
    }
    return 1;
}

auto get_labels(const InstructionSeq& insts) {
    pc_t pc = 0;
    std::unordered_map<string, pc_t> pc_of_label;
    for (auto [label, inst] : insts) {
        pc_of_label[label] = pc;
        pc += size(inst);
    }
    return pc_of_label;
}

void print(const InstructionSeq& insts) {
    auto pc_of_label = get_labels(insts);
    pc_t pc = 0;
    InstructionPrinterVisitor visitor{cout};
    for (LabeledInstruction labeled_inst : insts) {
        auto [label, ins] = labeled_inst;
        if (!std::all_of(label.begin(), label.end(), isdigit)) {
            cout << "\n";
            cout << label << ":\n";
        }
        cout << std::setw(8) << pc << ":\t";
        if (std::holds_alternative<Jmp>(ins)) {
            auto jmp = std::get<Jmp>(ins);
            if (pc_of_label.count(jmp.target) == 0)
                throw std::runtime_error(string("Cannot find label ") + jmp.target);
            pc_t target_pc = pc_of_label.at(jmp.target);
            string sign = (target_pc > pc) ? "+" : "";
            string offset = std::to_string(target_pc - pc - 1);
            jmp.target = sign + offset + " <" + jmp.target + ">";
            visitor(jmp);
        } else {
            std::visit(visitor, ins);
        }
        cout << "\n";
        pc += size(ins);
    }
}

void print(const Cfg& cfg, bool nondet) {
    for (auto [label, next] : slide(cfg.keys())) {
        cout << std::setw(8) << label << ":\t";
        bool first = true;
        const auto& bb = cfg.at(label);
        for (auto ins : bb.insts) {
            first = false;
            std::visit(InstructionPrinterVisitor{cout}, ins);
            cout << "\n" << std::setw(17);
        }
        if (nondet && bb.nextlist.size() > 0 && (!next || bb.nextlist != vector<Label>{*next})) {
            cout << "goto ";
            for (Label label : bb.nextlist)
                cout << label << ", ";
            cout << "\n";
        }
    }
}


void print_dot(const Cfg& cfg) {
    cout << "digraph program {\n";
    cout << "    node [shape = rectangle];\n";
    for (auto label : cfg.keys()) {
        cout << "    \"" << label << "\"[label=\"";

        const auto& bb = cfg.at(label);
        for (auto ins : bb.insts) {
            cout << ins << "\\l";
        }

        cout << "\"];\n";
        for (Label next : bb.nextlist)
            cout << "    \"" << label << "\" -> \"" << next << "\";\n";
        cout << "\n";
    }
    cout << "}\n";
}
