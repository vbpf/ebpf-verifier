#pragma once

#include <variant>
#include <optional>
#include <string>
#include <tuple>

#include <boost/lexical_cast.hpp>

#include "linux_ebpf.hpp" // ?

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
    Label target;
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
        return _is_load;
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


struct Assume {
    Condition cond;
};

enum class Type { SECRET, NUM, CTX, STACK, PACKET, MAP, PTR, NONSECRET };

struct Assert {
    struct False { };
    struct True { };

    struct LinearConstraint {
        Condition::Op op;
        Reg reg;
        int offset;
        Value width;
        Value v;
    };

    struct TypeConstraint {
        Reg reg;
        Type type;
        Assert implies(LinearConstraint cst) {
            return {*this, cst};
        }
        Assert impliesType(TypeConstraint cst) {
            return {*this, cst};
        }
    };

    using Conclusion = std::variant<TypeConstraint, LinearConstraint, False>;
    using Given = std::variant<TypeConstraint, True>;
    Given given;
    Conclusion then;
    Assert(Given given, Conclusion then) : given{given}, then{then} { }
    Assert(Conclusion then) : given{True{}}, then{then} { }
};

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
    Assume, 
    Assert
>;

using LabeledInstruction = std::tuple<Label, Instruction>;
using InstructionSeq = std::vector<LabeledInstruction>;

using pc_t = uint16_t;

constexpr int STACK_SIZE=512;



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

inline bool operator==(Imm const& a, Imm const& b) {
    return a.v == b.v;
}
inline bool operator==(Reg const& a, Reg const& b) {
    return a.v == b.v;
}
inline bool operator==(Assert::True const& a, Assert::True const& b) {
    return true;
}
inline bool operator==(Assert::False const& a, Assert::False const& b) {
    return true;
}
inline bool operator==(Deref const& a, Deref const& b) {
    return a.basereg == b.basereg && a.offset == b.offset && a.width == b.width;
}
inline bool operator==(Condition const& a, Condition const& b) {
    return a.left == b.left && a.op == b.op && a.right == b.right;
}
inline bool operator==(Assert::TypeConstraint const& a, Assert::TypeConstraint const& b) {
    return a.reg == b.reg && a.type == b.type;
}
inline bool operator==(Assert::LinearConstraint const& a, Assert::LinearConstraint const& b) {
    return a.op == b.op && a.reg == b.reg && a.offset == b.offset && a.width == b.width && a.v == b.v;
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
inline bool operator==(Packet const& a, Packet const& b){ 
    return a.offset == b.offset && a.regoffset == b.regoffset && a.width == b.width;
}
inline bool operator==(Mem const& a, Mem const& b){ 
    return a.access == b.access && a.value == b.value && a._is_load == b._is_load;
}
inline bool operator==(LockAdd const& a, LockAdd const& b){ 
    return a.access == b.access && a.valreg == b.valreg;
}
inline bool operator==(Assume const& a, Assume const& b){ 
    return a.cond == b.cond;
}
inline bool operator==(Assert const& a, Assert const& b){ 
    return a.given == b.given && a.then == b.then;
}

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
