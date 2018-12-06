#pragma once

#include <ostream>
#include <variant>
#include <functional>

#include "asm_syntax.hpp"
#include "asm_cfg.hpp"

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

void print(const InstructionSeq& prog);
void print(const Cfg& cfg, bool nondet);

void print_dot(const Cfg& cfg);

void print_stats(const Cfg& prog);

std::ostream& operator<<(std::ostream& os, Instruction const& ins);
std::string to_string(Instruction const& ins);
std::string to_string(Instruction const& ins, LabelTranslator labeler);

inline std::ostream& operator<<(std::ostream& os, Imm const& a) { return os << a.v; }
inline std::ostream& operator<<(std::ostream& os, Reg const& a) { return os << "r" << (int)a.v; }
inline std::ostream& operator<<(std::ostream& os, Value const& a) { 
    if (std::holds_alternative<Imm>(a))
        return os << std::get<Imm>(a);
    return os << std::get<Reg>(a);
}

inline std::ostream& operator<<(std::ostream& os, Type const& a) {
    switch (a) {
        case Type::SECRET: os << "SECRET"; break;
        case Type::NUM: os << "NUM"; break;
        case Type::STACK: os << "STACK"; break;
        case Type::CTX: os << "CTX"; break;
        case Type::PACKET: os << "PACKET"; break;
        case Type::MAP: os << "MAP"; break;
        case Type::PTR: os << "PTR"; break;
        case Type::NONSECRET: os << "NONSECRET"; break;
    }
    return os;
}

inline std::ostream& operator<<(std::ostream& os, Assert::Typeof const& a) {
    return os << a.reg << " : " << a.type;
}


inline std::ostream& operator<<(std::ostream& os, Undefined const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LoadMapFd const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Bin const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Un const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Call const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Exit const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Jmp const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Packet const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Mem const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, LockAdd const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assume const& a) { return os << (Instruction)a; }
inline std::ostream& operator<<(std::ostream& os, Assert const& a) { return os << (Instruction)a; }
