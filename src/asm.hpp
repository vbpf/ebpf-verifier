#pragma once

#include <iostream>
#include <variant>
#include <optional>

#include "instructions.hpp"

enum Imm : int32_t {};
enum Reg : int {};
using Target = std::variant<Imm, Reg>;

struct Bin {
    enum class Op {
        MOV,
        ADD, SUB, MUL, DIV, MOD,
        OR, AND, LSH, RSH, ARSH, XOR, 
    };

    Op op;
    bool is64;
    Reg dst;
    Target target;
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
    Target right;
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
    enum class Op {
        ST, LD,
    };

    Op op;
    Width width;
    Reg valreg;
    Reg basereg;
    Target offset;
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
    Imm offset;
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


IndexedInstruction toasm(uint16_t pc, ebpf_inst inst, int32_t next_imm);
std::ostream& operator<< (std::ostream& os, IndexedInstruction const& v);
