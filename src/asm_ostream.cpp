#include <variant>

#include <iostream>
#include <iomanip>
#include <unordered_map>

#include "asm_syntax.hpp"
#include "asm_ostream.hpp"
#include "asm_cfg.hpp"
#include "spec_assertions.hpp"

using std::string;
using std::vector;
using std::optional;

std::ostream& operator<<(std::ostream& os, ArgSingle::Kind kind) {
    switch (kind) {
        case ArgSingle::Kind::ANYTHING: return os << "";
        case ArgSingle::Kind::PTR_TO_CTX: return os << "CTX";
        case ArgSingle::Kind::CONST_MAP_PTR: return os << "FD";
        case ArgSingle::Kind::PTR_TO_MAP_KEY: return os << "K";
        case ArgSingle::Kind::PTR_TO_MAP_VALUE: return os << "V";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgPair::Kind kind) {
    switch (kind) {
        case ArgPair::Kind::PTR_TO_MEM : return os << "MEM";
        case ArgPair::Kind::PTR_TO_MEM_OR_NULL: return os << "MEM?";
        case ArgPair::Kind::PTR_TO_UNINIT_MEM: return os << "OUT";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgSingle arg) {
    return os << arg.reg << ":" << arg.kind;
}

std::ostream& operator<<(std::ostream& os, ArgPair arg) {
    os << arg.mem << ":" << arg.kind << "[" << arg.size;
    if (arg.can_be_zero ) os << "?";
    os << "]";
    return os;
}

std::ostream& operator<<(std::ostream& os, Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
        case Op::MOV : return os;
        case Op::ADD : return os << "+";
        case Op::SUB : return os << "-";
        case Op::MUL : return os << "*";
        case Op::DIV : return os << "/";
        case Op::MOD : return os << "%";
        case Op::OR  : return os << "|";
        case Op::AND : return os << "&";
        case Op::LSH : return os << "<<";
        case Op::RSH : return os << ">>";
        case Op::ARSH: return os << ">>>";
        case Op::XOR : return os << "^";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
        case Op::EQ : return os << "==";
        case Op::NE : return os << "!=";
        case Op::SET: return os << "&==";
        case Op::NSET:return os << "&!="; // not in ebpf
        case Op::LT : return os << "<";
        case Op::LE : return os << "<=";
        case Op::GT : return os << ">";
        case Op::GE : return os << ">=";
        case Op::SLT: return os << "s<";
        case Op::SLE: return os << "s<=";
        case Op::SGT: return os << "s>";
        case Op::SGE: return os << "s>=";
    }
    assert(false);
    return os;
}

static string size(int w) {
    return string("u") + std::to_string(w * 8);
}

struct InstructionPrinterVisitor {
    std::ostream& os_;
    LabelTranslator labeler = [](Label l) { return l; };

    template <typename T>
    void visit(const T& item) {
        std::visit(*this, item);
    }

    void operator()(Undefined const& a) {
        os_ << "Undefined{" << a.opcode << "}";
    }

    void operator()(LoadMapFd const& b) {
        os_ << b.dst << " = fd " << b.mapfd;
    }

    void operator()(Bin const& b) {
        os_ << b.dst << " " << b.op << "= " << b.v; 
        if (b.lddw)
            os_ << " ll";
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

    void operator()(Call const& call) {
        os_ << "r0 = " << call.name << ":" << call.func << "(";
        bool first = true;
        for (auto single : call.singles) {
            if (!first) os_ << ", ";
            first = false;
            os_ << single;
        }
        for (auto pair : call.pairs) {
            if (!first) os_ << ", ";
            first = false;
            os_ << pair;
        }
        os_ << ")";
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
        string s = size(b.width);
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
        os_ << cond.left << " " << cond.op << " " << cond.right;
    }

    void operator()(Mem const& b) {
        if (b.is_load) {
            os_ << b.value << " = ";
        }
        print(b.access);
        if (!b.is_load) {
            os_ << " = " << b.value;
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
        os_ << "assert " << *a.p;
        if (a.satisfied) os_ << " V";
    }
};


static vector<std::tuple<Label, optional<Label>>> slide(const vector<Label>& labels)
{
    if (labels.size() == 0) return {};
    vector<std::tuple<Label, optional<Label>>> label_pairs;
    Label prev;
    for (auto label : labels) {
        if (!prev.empty()) label_pairs.push_back({prev, label});
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

std::ostream& operator<<(std::ostream& os, Types ts) {
    os << "|";
    bool all_maps = true;
    for (size_t i=0; i < ts.size() - TypeSet::nonmaps; i++) {
        if (!ts[i]) all_maps = false;
    }
    if (all_maps)
        os << "MAP|";
    else
        for (size_t i=0; i < ts.size() - TypeSet::nonmaps; i++) {
            if (ts[i]) {
                os << "M" << i << "|";
            }
        }
    if (ts[ts.size()+T_NUM]) os << "N" << "|"; 
    if (ts[ts.size()+T_FD]) os << "FD" << "|";
    if (ts[ts.size()+T_CTX]) os << "C" << "|" ; 
    if (ts[ts.size()+T_DATA]) os  << "P" << "|" ; 
    if (ts[ts.size()+T_STACK]) os << "S" << "|";
    return os;
}

std::ostream& operator<<(std::ostream& os, TypeConstraint::RT const& a) {
    return os << a.reg << " : " << a.types;
}

std::ostream& operator<<(std::ostream& os, LinearConstraint const& a) {
    if (!a.when_types.all()) {
        os << TypeConstraint::RT{a.reg, a.when_types} << " -> ";
    }
    os << a.reg;
    string sign = a.offset < 0 ? " - " : " + ";
    int offset = std::abs(a.offset); // what about INT_MIN? 
    if (offset != 0)
        os << sign << offset;
    if (std::holds_alternative<Imm>(a.width)) {
        int imm = (int)std::get<Imm>(a.width).v;
        string sign = imm < 0 ? " - " : " + ";
        imm = std::abs(imm); // what about INT_MIN? 
        if (imm != 0)
            os << sign << imm;
    } else {
        os << " + " << a.width;
    }
    os << " " << a.op << " " << a.v;
    return os;
}

std::ostream& operator<<(std::ostream& os, TypeConstraint const& tc) {
    if (tc.given) {
        os << *tc.given << " -> ";
    }
    return os << tc.then;
}

std::ostream& operator<<(std::ostream& os, Assertion const& a) {
    if (std::holds_alternative<TypeConstraint>(a.cst)) {
        return os << std::get<TypeConstraint>(a.cst);
    } else {
        return os << std::get<LinearConstraint>(a.cst);
    }
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

static bool is_satisfied(Instruction ins) {
    return std::holds_alternative<Assert>(ins) && std::get<Assert>(ins).satisfied;
}

void print(const InstructionSeq& insts, std::ostream& out) {
    auto pc_of_label = get_labels(insts);
    pc_t pc = 0;
    InstructionPrinterVisitor visitor{out};
    for (LabeledInstruction labeled_inst : insts) {
        auto [label, ins] = labeled_inst;
        if (is_satisfied(ins)) continue;
        if (!std::all_of(label.begin(), label.end(), isdigit)) {
            out << "\n";
            out << label << ":\n";
        }
        out << std::setw(8) << pc << ":\t";
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
        out << "\n";
        pc += size(ins);
    }
}
void print(const InstructionSeq& insts) {
    print(insts, std::cout);
}

void print(const Cfg& cfg, bool nondet, std::ostream& out) {
    for (auto [label, next] : slide(cfg.keys())) {
        out << std::setw(10) << label << ":\t";
        const auto& bb = cfg.at(label);
        bool first = true;
        int i = 0;
        for (auto ins : bb.insts) {
            if (is_satisfied(ins)) continue;
            if (!first) out << std::setw(10) << " \t";
            first = false;
            if (!bb.pres.empty()) out << std::setw(10) << " \t" << "                             " << bb.pres.at(i) << "\n";
            std::visit(InstructionPrinterVisitor{out}, ins);
            out << "\n";
            if (!bb.posts.empty()) out << std::setw(10) << " \t" << "                             " << bb.posts.at(i) << "\n";
            ++i;
        }
        if (nondet && bb.nextlist.size() > 0 && (!next || bb.nextlist != vector<Label>{*next})) {
            if (!first) out << std::setw(10) << " \t";
            first = false;
            out << "goto ";
            for (Label label : bb.nextlist)
                out << label << ", ";
            out << "\n";
        }
    }
}
void print(const Cfg& cfg, bool nondet) {
    print(cfg, nondet, std::cout);
}


void print_dot(const Cfg& cfg, std::ostream& out) {
    out << "digraph program {\n";
    out << "    node [shape = rectangle];\n";
    for (auto label : cfg.keys()) {
        out << "    \"" << label << "\"[xlabel=\"" << label << "\",label=\"";

        const auto& bb = cfg.at(label);
        for (auto ins : bb.insts) {
            if (is_satisfied(ins)) continue;
            out << ins << "\\l";
        }

        out << "\"];\n";
        for (Label next : bb.nextlist)
            out << "    \"" << label << "\" -> \"" << next << "\";\n";
        out << "\n";
    }
    out << "}\n";
}
void print_dot(const Cfg& cfg) {
    print_dot(cfg, std::cout);
}