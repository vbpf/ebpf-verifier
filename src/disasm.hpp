#pragma once

#include <variant>

#include "instructions.hpp"

struct Bin {
    enum class Op {
        ADD, SUB, MUL, DIV, MOD,
        OR, AND, LSH, RSH, ARSH, XOR, 
        MOV,
    };


    enum Imm : int32_t {};
    enum Reg : int {};

    Op op;
    bool is64;
    int dst;
    std::variant<Imm, Reg> target;
};

struct Un {
    enum class Op {
        LE, BE, NEG,
    };

    Op op;
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
    } op;
    
    bool x;

    enum class Mode {
        MEM, ABS, IND, LEN, MSH
    } mode;

    enum class Width {
        B=1, H=2, W=4, DW=8
    } width;

    int valreg;
    int basereg;
    int offset;
};

struct Undefined {};

using InsCls = std::variant<Undefined, Bin, Un, Call, Exit, Goto, Jmp, Mem>;

InsCls toasm(ebpf_inst inst);
