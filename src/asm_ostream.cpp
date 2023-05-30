// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <fstream>
#include <iomanip>
#include <iostream>
#include <variant>
#include <vector>

#include "asm_ostream.hpp"
#include "asm_syntax.hpp"
#include "crab/cfg.hpp"
#include "crab/interval.hpp"
#include "crab/variable.hpp"

using std::optional;
using std::string;
using std::vector;

std::ostream& operator<<(std::ostream& os, ArgSingle::Kind kind) {
    switch (kind) {
    case ArgSingle::Kind::ANYTHING: return os << "uint64_t";
    case ArgSingle::Kind::PTR_TO_CTX: return os << "ctx";
    case ArgSingle::Kind::MAP_FD: return os << "map_fd";
    case ArgSingle::Kind::MAP_FD_PROGRAMS: return os << "map_fd_programs";
    case ArgSingle::Kind::PTR_TO_MAP_KEY: return os << "map_key";
    case ArgSingle::Kind::PTR_TO_MAP_VALUE: return os << "map_value";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgPair::Kind kind) {
    switch (kind) {
    case ArgPair::Kind::PTR_TO_READABLE_MEM: return os << "mem";
    case ArgPair::Kind::PTR_TO_READABLE_MEM_OR_NULL: return os << "mem?";
    case ArgPair::Kind::PTR_TO_WRITABLE_MEM: return os << "out";
    }
    assert(false);
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgSingle arg) {
    os << arg.kind << " " << arg.reg;
    return os;
}

std::ostream& operator<<(std::ostream& os, ArgPair arg) {
    os << arg.kind << " " << arg.mem << "[" << arg.size;
    if (arg.can_be_zero)
        os << "?";
    os << "], uint64_t " << arg.size;
    return os;
}

std::ostream& operator<<(std::ostream& os, Bin::Op op) {
    using Op = Bin::Op;
    switch (op) {
    case Op::MOV: return os;
    case Op::ADD: return os << "+";
    case Op::SUB: return os << "-";
    case Op::MUL: return os << "*";
    case Op::UDIV: return os << "/";
    case Op::UMOD: return os << "%";
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
    case Op::LT: return os << "<"; // TODO: os << "u<";
    case Op::LE: return os << "<="; // TODO: os << "u<=";
    case Op::GT: return os << ">"; // TODO: os << "u>";
    case Op::GE: return os << ">="; // TODO: os << "u>=";
    case Op::SLT: return os << "s<";
    case Op::SLE: return os << "s<=";
    case Op::SGT: return os << "s>";
    case Op::SGE: return os << "s>=";
    }
    assert(false);
    return os;
}

static string size(int w) { return string("u") + std::to_string(w * 8); }

static std::string to_string(TypeGroup ts) {
    switch (ts) {
    case TypeGroup::number: return "number";
    case TypeGroup::map_fd: return "map_fd";
    case TypeGroup::map_fd_programs: return "map_fd_programs";
    case TypeGroup::ctx: return "ctx";
    case TypeGroup::packet: return "packet";
    case TypeGroup::stack: return "stack";
    case TypeGroup::shared: return "shared";
    case TypeGroup::mem: return "{stack, packet, shared}";
    case TypeGroup::pointer: return "{ctx, stack, packet, shared}";
    case TypeGroup::non_map_fd: return "non_map_fd";
    case TypeGroup::ptr_or_num: return "{number, ctx, stack, packet, shared}";
    case TypeGroup::stack_or_packet: return "{stack, packet}";
    case TypeGroup::singleton_ptr: return "{ctx, stack, packet}";
    case TypeGroup::mem_or_num: return "{number, stack, packet, shared}";
    default: assert(false);
    }
    return {};
}

std::ostream& operator<<(std::ostream& os, TypeGroup ts) {
    return os << to_string(ts);
}

std::ostream& operator<<(std::ostream& os, ValidStore const& a) {
    return os << a.mem << ".type != stack -> " << TypeConstraint{a.val, TypeGroup::number};
}

std::ostream& operator<<(std::ostream& os, ValidAccess const& a) {
    if (a.or_null)
        os << "(" << TypeConstraint{a.reg, TypeGroup::number} << " and " << a.reg << ".value == 0) or ";
    os << "valid_access(" << a.reg << ".offset";
    if (a.offset > 0)
        os << "+" << a.offset;
    else if (a.offset < 0)
        os << a.offset;

    if (a.width == (Value)Imm{0}) {
        // a.width == 0, meaning we only care it's an in-bound pointer,
        // so it can be compared with another pointer to the same region.
        os << ") for comparison/subtraction";
    } else {
        os << ", width=" << a.width << ") for ";
        if (a.access_type == AccessType::read)
            os << "read";
        else
            os << "write";
    }
    return os;
}

static crab::variable_t typereg(const Reg& r) {
    return crab::variable_t::reg(crab::data_kind_t::types, r.v);
}

std::ostream& operator<<(std::ostream& os, ValidSize const& a) {
    auto op = a.can_be_zero ? " >= " : " > ";
    return os << a.reg << ".value" << op << 0;
}

std::ostream& operator<<(std::ostream& os, ValidMapKeyValue const& a) {
    return os << "within stack(" << a.access_reg << ":" << (a.key ? "key_size" : "value_size") << "(" << a.map_fd_reg << "))";
}

std::ostream& operator<<(std::ostream& os, ZeroCtxOffset const& a) {
    return os << crab::variable_t::reg(crab::data_kind_t::ctx_offsets, a.reg.v) << " == 0";
}

std::ostream& operator<<(std::ostream& os, Comparable const& a) {
    if (a.or_r2_is_number)
        os << TypeConstraint{a.r2, TypeGroup::number} << " or ";
    return os << typereg(a.r1) << " == "
              << typereg(a.r2) << " in " << to_string(TypeGroup::singleton_ptr);
}

std::ostream& operator<<(std::ostream& os, Addable const& a) {
    return os << TypeConstraint{a.ptr, TypeGroup::pointer} << " -> " << TypeConstraint{a.num, TypeGroup::number};
}

std::ostream& operator<<(std::ostream& os, ValidDivisor const& a) {
    return os << a.reg << " != 0";
}

std::ostream& operator<<(std::ostream& os, TypeConstraint const& tc) {
    string types = to_string(tc.types);
    string cmp_op = types[0] == '{' ? "in" : "==";
    return os << typereg(tc.reg) << " " << cmp_op << " " << tc.types;
}

std::ostream& operator<<(std::ostream& os, AssertionConstraint const& a) {
    return std::visit([&](const auto& a) -> std::ostream& { return os << a; }, a);
}

struct InstructionPrinterVisitor {
    std::ostream& os_;

    template <typename T>
    void visit(const T& item) {
        std::visit(*this, item);
    }

    void operator()(Undefined const& a) { os_ << "Undefined{" << a.opcode << "}"; }

    void operator()(LoadMapFd const& b) { os_ << b.dst << " = map_fd " << b.mapfd; }

    // llvm-objdump uses "w<number>" for 32-bit operations and "r<number>" for 64-bit operations.
    // We use the same convention here for consistency.
    static std::string reg_name(Reg const& a, bool is64) { return ((is64) ? "r" : "w") + std::to_string(a.v); }

    void operator()(Bin const& b) {
        os_ << reg_name(b.dst, b.is64) << " " << b.op << "= " << b.v;
        if (b.lddw)
            os_ << " ll";
    }

    void operator()(Un const& b) {
        os_ << b.dst << " = ";
        switch (b.op) {
        case Un::Op::BE16: os_ << "be16 "; break;
        case Un::Op::BE32: os_ << "be32 "; break;
        case Un::Op::BE64: os_ << "be64 "; break;
        case Un::Op::LE16: os_ << "le16 "; break;
        case Un::Op::LE32: os_ << "le32 "; break;
        case Un::Op::LE64: os_ << "le64 "; break;
        case Un::Op::NEG: os_ << "-"; break;
        }
        os_ << b.dst;
    }

    void operator()(Call const& call) {
        os_ << "r0 = " << call.name << ":" << call.func << "(";
        for (uint8_t r = 1; r <= 5; r++) {
            // Look for a singleton.
            std::vector<ArgSingle>::const_iterator single =
                std::find_if(call.singles.begin(), call.singles.end(), [r](ArgSingle arg) { return arg.reg.v == r; });
            if (single != call.singles.end()) {
                if (r > 1)
                    os_ << ", ";
                os_ << *single;
                continue;
            }

            // Look for the start of a pair.
            std::vector<ArgPair>::const_iterator pair =
                std::find_if(call.pairs.begin(), call.pairs.end(), [r](ArgPair arg) { return arg.mem.v == r; });
            if (pair != call.pairs.end()) {
                if (r > 1)
                    os_ << ", ";
                os_ << *pair;
                r++;
                continue;
            }

            // Not found.
            break;
        }
        os_ << ")";
    }

    void operator()(Exit const& b) { os_ << "exit"; }

    void operator()(Jmp const& b) {
        // A "standalone" jump instruction.
        // Print the label without offset calculations.
        if (b.cond) {
            os_ << "if ";
            print(*b.cond);
            os_ << " ";
        }
        os_ << "goto label <" << to_string(b.target) << ">";
    }

    void operator()(Jmp const& b, int offset) {
        string sign = offset > 0 ? "+" : "";
        string target = sign + std::to_string(offset) + " <" + to_string(b.target) + ">";

        if (b.cond) {
            os_ << "if ";
            print(*b.cond);
            os_ << " ";
        }
        os_ << "goto " << target;
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

    void print(Condition const& cond) { os_ << cond.left << " " << ((!cond.is64) ? "w" : "") << cond.op << " " << cond.right; }

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
    }

};

string to_string(label_t const& label) {
    std::stringstream str;
    str << label;
    return str.str();
}

std::ostream& operator<<(std::ostream& os, Instruction const& ins) {
    std::visit(InstructionPrinterVisitor{os}, ins);
    return os;
}

string to_string(Instruction const& ins) {
    std::stringstream str;
    str << ins;
    return str.str();
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
    std::map<label_t, pc_t> pc_of_label;
    for (auto [label, inst, _] : insts) {
        pc_of_label[label] = pc;
        pc += size(inst);
    }
    return pc_of_label;
}

void print(const InstructionSeq& insts, std::ostream& out, std::optional<const label_t> label_to_print,
           bool print_line_info) {
    auto pc_of_label = get_labels(insts);
    pc_t pc = 0;
    std::string previous_source;
    InstructionPrinterVisitor visitor{out};
    for (const LabeledInstruction& labeled_inst : insts) {
        const auto& [label, ins, line_info] = labeled_inst;
        if (!label_to_print.has_value() || (label == label_to_print)) {
            if (line_info.has_value() && print_line_info) {
                auto& [file, source, line, column] = line_info.value();
                // Only decorate the first instruction associated with a source line.
                if (source != previous_source) {
                    out << line_info.value();
                    previous_source = source;
                }
            }
            if (label.isjump()) {
                out << "\n";
                out << label << ":\n";
            }
            if (label_to_print.has_value()) {
                out << pc << ": ";
            } else {
                out << std::setw(8) << pc << ":\t";
            }
            if (std::holds_alternative<Jmp>(ins)) {
                auto const& jmp = std::get<Jmp>(ins);
                if (pc_of_label.count(jmp.target) == 0)
                    throw std::runtime_error(string("Cannot find label ") + to_string(jmp.target));
                pc_t target_pc = pc_of_label.at(jmp.target);
                visitor(jmp, target_pc - (int)pc - 1);
            } else {
                std::visit(visitor, ins);
            }
            out << "\n";
        }
        pc += size(ins);
    }
}

std::ostream& operator<<(std::ostream& o, const EbpfMapDescriptor& desc) {
    return o << "("
    << "original_fd = " << desc.original_fd << ", "
    << "inner_map_fd = " << desc.inner_map_fd << ", "
    << "type = " << desc.type << ", "
    << "max_entries = " << desc.max_entries << ", "
    << "value_size = " << desc.value_size << ", "
    << "key_size = " << desc.key_size <<
    ")";
}

void print_map_descriptors(const std::vector<EbpfMapDescriptor>& descriptors, std::ostream& o) {
    int i = 0;
    for (const auto& desc : descriptors) {
        o << "map " << i << ":" << desc << "\n";
        i++;
    }
}

void print_dot(const cfg_t& cfg, std::ostream& out) {
    out << "digraph program {\n";
    out << "    node [shape = rectangle];\n";
    for (const auto& label : cfg.labels()) {
        out << "    \"" << label << "\"[xlabel=\"" << label << "\",label=\"";

        const auto& bb = cfg.get_node(label);
        for (const auto& ins : bb) {
            out << ins << "\\l";
        }

        out << "\"];\n";
        for (const label_t& next : bb.next_blocks_set())
            out << "    \"" << label << "\" -> \"" << next << "\";\n";
        out << "\n";
    }
    out << "}\n";
}

void print_dot(const cfg_t& cfg, const std::string& outfile) {
    std::ofstream out{outfile};
    if (out.fail())
        throw std::runtime_error(std::string("Could not open file ") + outfile);
    print_dot(cfg, out);
}

std::ostream& operator<<(std::ostream& o, const basic_block_t& bb) {
    o << bb.label() << ":\n";
    for (auto const& s : bb) {
        o << "  " << s << ";\n";
    }
    auto [it, et] = bb.next_blocks();
    if (it != et) {
        o << "  "
          << "goto ";
        for (; it != et;) {
            o << *it;
            ++it;
            if (it == et) {
                o << ";";
            } else {
                o << ",";
            }
        }
    }
    o << "\n";
    return o;
}

std::ostream& operator<<(std::ostream& o, const crab::basic_block_rev_t& bb) {
    o << bb.label() << ":\n";
    for (auto const& s : bb) {
        o << "  " << s << ";\n";
    }
    o << "--> [";
    for (const label_t& label : bb.next_blocks_set()) {
        o << label << ";";
    }
    o << "]\n";
    return o;
}

std::ostream& operator<<(std::ostream& o, const cfg_t& cfg) {
    for (const label_t& label : cfg.sorted_labels()) {
        o << cfg.get_node(label);
    }
    return o;
}

std::ostream& operator<<(std::ostream& os, const btf_line_info_t& line_info) {
    os << "; " << line_info.file_name << ":" << line_info.line_number << "\n";
    os << "; " << line_info.source_line << "\n";
    return os;
}


std::string crab::z_number::to_string() const { return _n.str(); }

std::string crab::interval_t::to_string() const {
    std::ostringstream s;
    s << *this;
    return s.str();
}
