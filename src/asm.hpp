#pragma once

#include <iostream>
#include <variant>
#include <optional>
#include <vector>
#include <string>
#include <unordered_map>

#include <boost/lexical_cast.hpp>

using Label = std::string;

struct Imm {
    uint64_t v;
    Imm(int32_t v) : v{(uint32_t)v} { }
    Imm(uint64_t v) : v{v} { }
};

enum Reg : int {};

using Value = std::variant<Imm, Reg>;

struct Bin {
    enum class Op {
        MOV,
        ADD, SUB, MUL, DIV, MOD,
        OR, AND, LSH, RSH, ARSH, XOR, 
    };

    Op op;
    bool is64;
    Reg dst;
    Value v;
    bool lddw;
};

struct Un {
    enum class Op {
        LE16, LE32, LE64, NEG,
    };

    Op op;
    int dst;
};

struct LoadMapFd {
    Reg dst;
    int mapfd;
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
    int32_t func;
};

struct Exit {
};

enum class Width {
    B=1, H=2, W=4, DW=8
};

struct Mem {
    enum Load : int {};
    enum StoreReg : int {};
    enum StoreImm : int {};
    using Value = std::variant<Load, StoreReg, StoreImm>;

    Width width;
    Reg basereg;
    int offset;
    Value value;

    bool isLoad() const {
        return std::holds_alternative<Load>(value);
    };
};

struct Packet {
    Width width;
    int offset;
    std::optional<Reg> regoffset;
};

struct LockAdd {
    Width width;
    Reg valreg;
    Reg basereg;
    int16_t offset;
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

struct Program {
    std::vector<Instruction> code;
};

constexpr int STACK_SIZE=512;

std::variant<Program, std::string> parse(std::istream& is, size_t nbytes);


inline pc_t label_to_pc(Label label) {
    return boost::lexical_cast<pc_t>(label);
}

inline std::function<auto(Label)->int16_t> label_to_offset(pc_t pc) {
    return [=](Label label) {
        return label_to_pc(label) - pc - 1;
    };
}

inline std::function<auto(Label)->std::string> label_to_offset_string(pc_t pc) {
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

using Cfg = std::unordered_map<Label, BasicBlock>;

Cfg build_cfg(const Program& prog);
Cfg to_nondet(const Cfg& simple_cfg);

void print(const Program& prog);
void print(const Cfg& cfg, bool nondet);

void print_stats(const Program& prog);

// Helpers:

struct InstructionVisitorPrototype {
    void operator()(Undefined const& a);
    void operator()(LoadMapFd const& b);
    void operator()(Bin const& b);
    void operator()(Un const& b);
    void operator()(Call const& b);
    void operator()(Exit const& b);
    void operator()(Jmp const& b);
    void operator()(Assume const& b);
    void operator()(Packet const& b);
    void operator()(Mem const& b);
    void operator()(LockAdd const& b);
};

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
