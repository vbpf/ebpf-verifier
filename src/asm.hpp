#pragma once

#include <iostream>
#include <variant>
#include <optional>
#include <vector>
#include <string>

struct Imm {
    uint64_t v;
    Imm(int32_t v) : v{(uint32_t)v} { }
    Imm(uint64_t v) : v{v} { }
};

enum Offset : int16_t {};
enum Reg : int {};

using Value = std::variant<Imm, Reg>;
using Target = std::variant<Offset, Reg>;

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
        LE, BE, NEG,
    };

    Op op;
    int dst;
};

struct Jmp {
    enum class Op { 
        EQ, NE, SET,
        LT, LE, GT, GE,
        SLT, SLE, SGT, SGE,
    };

    Op op;
    Reg left;
    Value right;
    int offset;
};

struct Goto {
    int offset;
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
    Call,
    Exit,
    Goto,
    Jmp,
    Mem,
    Packet,
    LockAdd
>;

struct IndexedInstruction {
    uint16_t pc;
    Instruction ins;
};


struct Program {
    std::vector<Instruction> code;
};

constexpr int STACK_SIZE=512;

std::variant<Program, std::string> parse(std::istream& is, size_t nbytes);

std::ostream& operator<<(std::ostream& os, IndexedInstruction const& v);
void print(Program& prog);

// Helpers:

struct InstructionVisitorPrototype {
    void operator()(Undefined const& a);
    void operator()(Bin const& b);
    void operator()(Un const& b);
    void operator()(Call const& b);
    void operator()(Exit const& b);
    void operator()(Goto const& b);
    void operator()(Jmp const& b);
    void operator()(Packet const& b);
    void operator()(Mem const& b);
    void operator()(LockAdd const& b);
};

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
