#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <variant>
#include <vector>

#include "asm_ostream.hpp"
#include "asm_syntax.hpp"
#include "config.hpp"
#include "crab/cfg.hpp"

using std::optional;
using std::string;
using std::vector;

std::ostream& operator<<(std::ostream& os, ArgSingle::Kind kind) {
    switch (kind) {
    case ArgSingle::Kind::ANYTHING: return os << "";
    case ArgSingle::Kind::PTR_TO_CTX: return os << "CTX";
    case ArgSingle::Kind::MAP_FD: return os << "FD";
    case ArgSingle::Kind::PTR_TO_MAP_KEY: return os << "K";
    case ArgSingle::Kind::PTR_TO_MAP_VALUE: return os << "V";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgPair::Kind kind) {
    switch (kind) {
    case ArgPair::Kind::PTR_TO_MEM: return os << "MEM";
    case ArgPair::Kind::PTR_TO_MEM_OR_NULL: return os << "MEM?";
    case ArgPair::Kind::PTR_TO_UNINIT_MEM: return os << "OUT";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgSingle arg) {
    os << arg.reg;
    if (arg.kind != ArgSingle::Kind::ANYTHING)
        os << ":" << arg.kind;
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgPair arg) {
    os << arg.mem << ":" << arg.kind << "[" << arg.size;
    if (arg.can_be_zero)
        os << "?";
    os << "]";
    return os;
}

std::ostream& operator<<(std::ostream& os, Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
    case Op::MOV: return os;
    case Op::ADD: return os << "+";
    case Op::SUB: return os << "-";
    case Op::MUL: return os << "*";
    case Op::DIV: return os << "/";
    case Op::MOD: return os << "%";
    case Op::OR: return os << "|";
    case Op::AND: return os << "&";
    case Op::LSH: return os << "<<";
    case Op::RSH: return os << ">>";
    case Op::ARSH: return os << ">>>";
    case Op::XOR: return os << "^";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return os << "==";
    case Op::NE: return os << "!=";
    case Op::SET: return os << "&==";
    case Op::NSET: return os << "&!="; // not in ebpf
    case Op::LT: return os << "<";
    case Op::LE: return os << "<=";
    case Op::GT: return os << ">";
    case Op::GE: return os << ">=";
    case Op::SLT: return os << "s<";
    case Op::SLE: return os << "s<=";
    case Op::SGT: return os << "s>";
    case Op::SGE: return os << "s>=";
    }
    assert(false);
    return os;
}

static string size(int w) { return string("u") + std::to_string(w * 8); }

std::ostream& operator<<(std::ostream& os, TypeGroup ts) {
    switch (ts) {
    case TypeGroup::num: return os << "num";
    case TypeGroup::map_fd: return os << "map_fd";
    case TypeGroup::ctx: return os << "ctx";
    case TypeGroup::packet: return os << "packet";
    case TypeGroup::stack: return os << "stack";
    case TypeGroup::shared: return os << "shared";
    case TypeGroup::mem: return os << "mem";
    case TypeGroup::ptr: return os << "ptr";
    case TypeGroup::non_map_fd: return os << "non_map_fd";
    case TypeGroup::ptr_or_num: return os << "ptr_or_num";
    case TypeGroup::stack_or_packet: return os << "stack_or_packet";
    case TypeGroup::mem_or_num: return os << "mem_or_num";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, ValidStore const& a) {
    return os << "!stack(" << a.mem << ") -> num(" << a.val << ")";
}

std::ostream& operator<<(std::ostream& os, ValidAccess const& a) {
    if (a.or_null)
        os << a.reg << " == 0 or ";
    return os << "valid_access(" << a.reg << ", " << a.offset << ":" << a.width << ")";
}

std::ostream& operator<<(std::ostream& os, ValidSize const& a) {
    auto op = a.can_be_zero ? " >= " : " > ";
    return os << a.reg << op << 0;
}

std::ostream& operator<<(std::ostream& os, ValidMapKeyValue const& a) {
    return os << "within stack(" << a.access_reg << ":" << (a.key ? "key_size" : "value_size") << "(" << a.map_fd_reg
              << "))";
}

std::ostream& operator<<(std::ostream& os, Comparable const& a) {
    return os << "type(" << a.r1 << ") == type(" << a.r2 << ")";
}

std::ostream& operator<<(std::ostream& os, Addable const& a) {
    return os << a.ptr << " : ptr -> " << a.num << " : num";
}

std::ostream& operator<<(std::ostream& os, TypeConstraint const& tc) { return os << tc.reg << " : " << tc.types; }

std::ostream& operator<<(std::ostream& os, AssertionConstraint const& a) {
    return std::visit([&](const auto& a) -> std::ostream& { return os << a; }, a);
}

struct InstructionPrinterVisitor {
    std::ostream& os_;
    LabelTranslator labeler = [](label_t l) { return l; };

    template <typename T>
    void visit(const T& item) {
        std::visit(*this, item);
    }

    void operator()(Undefined const& a) { os_ << "Undefined{" << a.opcode << "}"; }

    void operator()(LoadMapFd const& b) { os_ << b.dst << " = map_fd " << b.mapfd; }

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
        case Un::Op::NEG: os_ << "-"; break;
        }
        os_ << b.dst;
    }

    void operator()(Call const& call) {
        os_ << "r0 = " << call.name << ":" << call.func << "(";
        bool first = true;
        for (auto single : call.singles) {
            if (!first)
                os_ << ", ";
            first = false;
            os_ << single;
        }
        for (auto pair : call.pairs) {
            if (!first)
                os_ << ", ";
            first = false;
            os_ << pair;
        }
        os_ << ")";
    }

    void operator()(Exit const& b) { os_ << "exit"; }

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
            if (b.regoffset)
                os_ << " + ";
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

    void print(Condition const& cond) { os_ << cond.left << " " << cond.op << " " << cond.right; }

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
        os_ << "assert " << a.cst;
        if (a.satisfied)
            os_ << " V";
    }
};

string to_string(Instruction const& ins, LabelTranslator labeler) {
    std::stringstream str;
    std::visit(InstructionPrinterVisitor{str, labeler}, ins);
    return str.str();
}

std::ostream& operator<<(std::ostream& os, Instruction const& ins) {
    std::visit(InstructionPrinterVisitor{os, [](label_t l) { return string("<") + l + ">"; }}, ins);
    return os;
}

string to_string(Instruction const& ins) {
    return to_string(ins, [](label_t l) { return string("<") + l + ">"; });
}

string to_string(AssertionConstraint const& constraint) {
    std::stringstream str;
    str << constraint;
    return str.str();
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
        if (is_satisfied(ins))
            continue;
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

void print(const InstructionSeq& insts, std::string outfile) {
    std::ofstream out{outfile};
    print(insts, out);
}

void print(const InstructionSeq& insts) { print(insts, std::cout); }

void print(const cfg_t& cfg, bool nondet, std::ostream& out) {
    if (!global_options.print_invariants)
        return;
    return;
    /*
    for (auto [label, next] : slide(cfg.keys())) {
        out << std::setw(10) << label << ":\t";
        const auto& bb = cfg.get_node(label);
        bool first = true;
        int i = 0;
        for (auto ins : bb) {
            if (is_satisfied(ins))
                continue;
            if (!first)
                out << std::setw(10) << " \t";
            first = false;
            if (!bb.pres.empty())
                out << std::setw(10) << " \t"
                    << "                             " << bb.pres.at(i) << "\n";
            std::visit(InstructionPrinterVisitor{out}, ins);
            out << "\n";
            if (!bb.posts.empty())
                out << std::setw(10) << " \t"
                    << "                             " << bb.posts.at(i) << "\n";
            ++i;
        }
        if (nondet && bb.nextlist.size() > 0 && (!next || bb.nextlist != vector<label_t>{*next})) {
            if (!first)
                out << std::setw(10) << " \t";
            first = false;
            out << "goto ";
            for (label_t label : bb.nextlist)
                out << label << ", ";
            out << "\n";
        }
    }
    */
}

void print(const cfg_t& cfg, bool nondet, std::string outfile) {
    std::ofstream out{outfile};
    if (out.fail())
        throw std::runtime_error(std::string("Could not open file ") + outfile);
    print(cfg, nondet, out);
}

void print(const cfg_t& cfg, bool nondet) { print(cfg, nondet, std::cout); }

void print_dot(const cfg_t& cfg, std::ostream& out) {
    out << "digraph program {\n";
    out << "    node [shape = rectangle];\n";
    for (const auto& [label, _] : cfg) {
        out << "    \"" << label << "\"[xlabel=\"" << label << "\",label=\"";

        const auto& bb = cfg.get_node(label);
        for (auto ins : bb) {
            if (is_satisfied(ins))
                continue;
            out << ins << "\\l";
        }

        out << "\"];\n";
        auto [b, e] = bb.next_blocks();
        for (label_t next : std::vector<label_t>(b, e))
            out << "    \"" << label << "\" -> \"" << next << "\";\n";
        out << "\n";
    }
    out << "}\n";
}

void print_dot(const cfg_t& cfg, std::string outfile) {
    std::ofstream out{outfile};
    if (out.fail())
        throw std::runtime_error(std::string("Could not open file ") + outfile);
    print_dot(cfg, out);
}

void print_dot(const cfg_t& cfg) { print_dot(cfg, std::cout); }
