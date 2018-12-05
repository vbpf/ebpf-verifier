#pragma once

#include <iostream>
#include <fstream>
#include <variant>
#include <optional>
#include <vector>
#include <tuple>
#include <string>
#include <unordered_map>

#include <boost/lexical_cast.hpp>

#include "linux_ebpf.hpp"

using Label = std::string;

struct Imm {
    uint64_t v{};
    explicit Imm(int32_t v) : v{(uint32_t)v} { }
    explicit Imm(uint64_t v) : v{v} { }
};

struct Reg {
    uint8_t v;
};

using Value = std::variant<Imm, Reg>;

struct Bin {
    enum class Op {
        MOV,
        ADD, SUB, MUL, DIV, MOD,
        OR, AND, LSH, RSH, ARSH, XOR, 
    };

    Op op;
    bool is64{};
    Reg dst;
    Value v;
    bool lddw{};
};

struct Un {
    enum class Op {
        LE16, LE32, LE64, NEG,
    };

    Op op;
    Reg dst;
};

struct LoadMapFd {
    Reg dst;
    int mapfd{};
};

struct Condition {
    enum class Op { 
        EQ, NE, SET, NSET, // NSET does not exist in ebpf
        LT, LE, GT, GE,
        SLT, SLE, SGT, SGE,
    };

    Op op;
    Reg left;
    Value right;
};

struct Jmp {
    std::optional<Condition> cond;
    std::string target;
};

struct Assume {
    Condition cond;
};

struct Call {
    int32_t func{};
};

struct Exit {
};

enum class Width {
    B=1, H=2, W=4, DW=8
};

struct Deref {
    Width width;
    Reg basereg;
    int offset{};
};

struct Mem {
    Deref access;
    Value value;
    bool _is_load{};

    bool isLoad() const {
        return _is_load; // std::holds_alternative<Load>(value);
    };
};

struct Packet {
    Width width;
    int offset{};
    std::optional<Reg> regoffset;
};

struct LockAdd {
    Deref access;
    Reg valreg;
};

struct Undefined { int opcode; };

using Instruction = std::variant<
    Undefined,
    Bin,
    Un,
    LoadMapFd,
    Call,
    Exit,
    Jmp,
    Mem,
    Packet,
    LockAdd,
    Assume
>;

using pc_t = uint16_t;

constexpr int STACK_SIZE=512;

using LabeledInstruction = std::tuple<Label, Instruction>;
using InstructionSeq = std::vector<LabeledInstruction>;

std::variant<InstructionSeq, std::string> unmarshal(std::istream& is, size_t nbytes);
std::vector<LabeledInstruction> unmarshal(std::vector<ebpf_inst> const& insts);

std::tuple<std::ifstream, size_t> open_binary_file(std::string path);

std::vector<ebpf_inst> marshal(Instruction ins, pc_t pc);
std::vector<ebpf_inst> marshal(std::vector<Instruction> insts);


Instruction parse_instruction(std::string text);
std::vector<std::tuple<Label, Instruction>> parse_program(std::istream& is);

std::ifstream open_asm_file(std::string path);

inline pc_t label_to_pc(Label label) {
    try {
        return boost::lexical_cast<pc_t>(label);
    } catch(const boost::bad_lexical_cast &) {
        throw std::invalid_argument(std::string("Cannot convert ") + label + " to pc_t");
    }
}

using LabelTranslator = std::function<std::string(Label)>;

inline std::function<int16_t(Label)> label_to_offset(pc_t pc) {
    return [=](Label label) {
        return label_to_pc(label) - pc - 1;
    };
}

inline LabelTranslator label_to_offset_string(pc_t pc) {
    return [=](Label label) {
        int16_t target = label_to_offset(pc)(label);
        return std::string(target > 0 ? "+" : "") + std::to_string(target);
    };
}

struct BasicBlock {
    std::vector<Instruction> insts;
    std::vector<Label> nextlist;
    std::vector<Label> prevlist;
};

class Cfg {
    std::unordered_map<Label, BasicBlock> graph;
    std::vector<Label> ordered_labels;
public:
    void encountered(Label l) { ordered_labels.push_back(l); }
    BasicBlock& operator[](Label l) { return graph[l]; }
    BasicBlock const& at(Label l) const { return graph.at(l); }
    std::vector<Label> const& keys() const { return ordered_labels; }
};

Cfg build_cfg(const InstructionSeq& labeled_insts);
             
Cfg to_nondet(const Cfg& simple_cfg);

void print(const InstructionSeq& prog);
void print(const Cfg& cfg, bool nondet);

std::ostream& operator<<(std::ostream& os, Instruction const& ins);
std::string to_string(Instruction const& ins);
std::string to_string(Instruction const& ins, LabelTranslator labeler);

void print_stats(const Cfg& prog);

// Helpers:

struct InstructionVisitorPrototype {
    void operator()(Undefined const& a);
    void operator()(LoadMapFd const& a);
    void operator()(Bin const& a);
    void operator()(Un const& a);
    void operator()(Call const& a);
    void operator()(Exit const& a);
    void operator()(Jmp const& a);
    void operator()(Assume const& a);
    void operator()(Packet const& a);
    void operator()(Mem const& a);
    void operator()(LockAdd const& a);
};

inline std::ostream& operator<<(std::ostream& os, Imm const& a) { return os << a.v; }
inline std::ostream& operator<<(std::ostream& os, Reg const& a) { return os << "r" << (int)a.v; }
inline std::ostream& operator<<(std::ostream& os, Value const& a) { 
    if (std::holds_alternative<Imm>(a))
        return os << std::get<Imm>(a);
    return os << std::get<Reg>(a);
}

inline std::ostream& operator<<(std::ostream& os, Undefined const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LoadMapFd const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Bin const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Un const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Call const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Exit const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Jmp const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assume const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Packet const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Mem const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LockAdd const& a) { return os << (Instruction)a; }

inline bool operator==(Imm const& a, Imm const& b) {
    return a.v == b.v;
}
inline bool operator==(Reg const& a, Reg const& b) {
    return a.v == b.v;
}
inline bool operator==(Deref const& a, Deref const& b) {
    return a.basereg == b.basereg && a.offset == b.offset && a.width == b.width;
}
inline bool operator==(Condition const& a, Condition const& b) {
    return a.left == b.left && a.op == b.op && a.right == b.right;
}
inline bool operator==(Undefined const& a, Undefined const& b){ 
    return a.opcode == b.opcode;
}
inline bool operator==(LoadMapFd const& a, LoadMapFd const& b){ 
    return a.dst == b.dst && a.mapfd == b.mapfd;
}
inline bool operator==(Bin const& a, Bin const& b){ 
    return a.op == b.op && a.dst == b.dst && a.is64 == b.is64 && a.v == b.v && a.lddw == b.lddw;
}
inline bool operator==(Un const& a, Un const& b){ 
    return a.op == b.op && a.dst == b.dst;
}
inline bool operator==(Call const& a, Call const& b){ 
    return a.func == b.func;
}
inline bool operator==(Exit const& a, Exit const& b){ 
    return true;
}
inline bool operator==(Jmp const& a, Jmp const& b){ 
    return a.cond == b.cond && a.target == b.target;
}
inline bool operator==(Assume const& a, Assume const& b){ 
    return a.cond == b.cond;
}
inline bool operator==(Packet const& a, Packet const& b){ 
    return a.offset == b.offset && a.regoffset == b.regoffset && a.width == b.width;
}
inline bool operator==(Mem const& a, Mem const& b){ 
    return a.access == b.access && a.value == b.value && a._is_load == b._is_load;
}
inline bool operator==(LockAdd const& a, LockAdd const& b){ 
    return a.access == b.access && a.valreg == b.valreg;
}

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
