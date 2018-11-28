#pragma once

#include <iostream>
#include <variant>

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
    int dst;
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
    int leftreg;
    int rightreg;
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

struct Mem {
    enum class Op {
        ST, LD,
    };
    
    enum class Mode {
        MEM, ABS, IND, LEN, MSH
    };

    enum class Width {
        B=1, H=2, W=4, DW=8
    };

    Op op;
    bool x;
    Mode mode;
    Width width;
    int valreg;
    int basereg;
    Target offset;
};

struct Undefined {};

using Instruction = std::variant<
    Undefined,
    Bin,
    Un,
    Call,
    Exit,
    Goto,
    Jmp,
    Mem
>;

Instruction toasm(ebpf_inst inst);
std::ostream& operator<< (std::ostream& os, Instruction const& v);
