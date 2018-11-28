#pragma once

#include <iostream>
#include <variant>
#include <optional>

#include "instructions.hpp"

struct Imm {
    int32_t current;
    std::optional<int32_t> next;
    uint64_t u64() {
        return uint64_t(*next) << 32 | current;
    }
    uint32_t i32() {
        return current;
    }
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


IndexedInstruction toasm(uint16_t pc, ebpf_inst inst, std::optional<int32_t> next_imm);
std::ostream& operator<< (std::ostream& os, IndexedInstruction const& v);
