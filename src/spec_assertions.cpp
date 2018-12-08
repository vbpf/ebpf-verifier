#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <iostream>
#include <optional>
#include <iostream>

#include "asm_cfg.hpp"
#include "asm_ostream.hpp"

#include "spec_prototypes.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;


static int access_width(Width w)
{
    switch (w) {
        case Width::B: return 1;
        case Width::H: return 2;
        case Width::W: return 4;
        case Width::DW: return 8;
    }
	assert(false);
}

Assert operator!(Assert::TypeConstraint tc) {
    return {tc, Assert::False{}};
}

Value end(Type t) {
    switch (t) {
        case Type::CTX: return Imm{256};
        case Type::MAP_VALUE: return Imm{4098};
        case Type::PACKET: return Reg{13};
        case Type::STACK: return Imm{0};
        case Type::MAP_STRUCT: assert(false);
        case Type::NUM: assert(false);
        case Type::PTR: assert(false);
        case Type::SECRET: assert(false);
        case Type::NONSECRET: assert(false);
    }
}

Value start(Type t) {
    switch (t) {
        case Type::CTX: return Imm{0};
        case Type::MAP_VALUE: return Imm{0};
        case Type::PACKET: return Imm{0};
        case Type::STACK: return Imm{-256};
        case Type::MAP_STRUCT: assert(false);
        case Type::NUM: assert(false);
        case Type::PTR: assert(false);
        case Type::SECRET: assert(false);
        case Type::NONSECRET: assert(false);
    }
}

void checkAccess(vector<Assert>& assumptions, Type t, Reg reg, int offset, Value width) {
    using T = Assert::TypeConstraint;
    using Op = Condition::Op;
    assumptions.emplace_back(
        T{reg, t}.implies({Op::LE, reg, offset, width, end(t)})
    );
    assumptions.emplace_back(
        T{reg, t}.implies({Op::GE, reg, offset, Imm{0}, start(t)})
    );
}

static bool is_priviledged() {
    return false;
}

struct AssertionExtractor {
    template <typename T>
    vector<Assert> operator()(T ins) { return {}; }

    vector<Assert> operator()(Exit const& e) {
        return { Assert(Assert::TypeConstraint{Reg{0}, Type::NUM}) };
    }

    vector<Assert> operator()(Call const& call) {
        using T = Assert::TypeConstraint;
        using L = Assert::LinearConstraint;
        using Op = Condition::Op;
        bpf_func_proto proto = get_prototype(call.func);
        vector<Assert> res;
        uint8_t i = 0;
        std::array<Arg, 5> args = {{proto.arg1_type, proto.arg2_type, proto.arg3_type, proto.arg4_type, proto.arg5_type}};
        for (Arg t : args) {
            Reg reg{++i};
            if (t == Arg::DONTCARE)
                break;
            switch (t) {
            case Arg::DONTCARE:
                assert(false);
                break;
            case Arg::ANYTHING:
                // avoid pointer leakage:
                if (!is_priviledged())
                    res.emplace_back(T{reg, Type::NUM});
                break;
            case Arg::CONST_SIZE:
                // TODO: reg is constant (or maybe it's not important)
                res.emplace_back(T{reg, Type::NUM});
                res.push_back(T{reg, Type::NUM}.implies({Op::GT, reg, 0, Imm{0}, Imm{0}}));
                checkAccess(res, Type::STACK, Reg{(uint8_t)(i-1)}, 0, reg);
                break;
            case Arg::CONST_SIZE_OR_ZERO:
                // TODO: reg is constant (or maybe it's not important)
                res.emplace_back(T{reg, Type::NUM});
                res.push_back(T{reg, Type::NUM}.implies({Op::GE, reg, 0, Imm{0}, Imm{0}}));
                checkAccess(res, Type::STACK, Reg{(uint8_t)(i-1)}, 0, reg);
                break;
            case Arg::CONST_MAP_PTR:
                res.emplace_back(T{reg, Type::MAP_STRUCT});
                break;
            case Arg::PTR_TO_CTX:
                res.emplace_back(T{reg, Type::CTX});
                // TODO: the kernel has some other conditions here - 
                // maybe offset == 0
                break;
            case Arg::PTR_TO_MAP_KEY:
                // what other conditions?
                res.emplace_back(T{reg, Type::PTR});
                break;
            case Arg::PTR_TO_MAP_VALUE:
                res.emplace_back(T{reg, Type::STACK});
                break;
            case Arg::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                res.push_back(!T{reg, Type::CTX});
                res.emplace_back(T{reg, Type::PTR});
                break;
            case Arg::PTR_TO_MEM_OR_NULL:
                res.push_back(T{reg, Type::NUM}.implies({Op::EQ, reg, 0, Imm{0}, Imm{0}}));
                res.emplace_back(!T{reg, Type::SECRET});
                res.push_back(!T{reg, Type::CTX});
                break;
            case Arg::PTR_TO_UNINIT_MEM:
                res.push_back(T{reg, Type::PTR}.impliesType({reg, Type::PTR}));
                break;
            }
        }
        return res;
    }

    vector<Assert> operator()(Mem ins) { 
        using T = Assert::TypeConstraint;
        using Op = Condition::Op;
        vector<Assert> res;
        Reg reg = ins.access.basereg;
        Imm width = Imm{access_width(ins.access.width)};
        int offset = ins.access.offset;
        if (reg.v != 10) {
            res.emplace_back(T{reg, Type::PTR});
            for (auto t : {Type::MAP_VALUE, Type::CTX, Type::PACKET}) {
                checkAccess(res, t, reg, offset, width);
                if (!is_priviledged() && !ins.isLoad() && std::holds_alternative<Reg>(ins.value)) {
                    res.push_back(
                        T{reg, t}.impliesType({std::get<Reg>(ins.value), Type::NUM})
                    );
                }
            }
        }
        checkAccess(res, Type::STACK, reg, offset, width);
        return res;
    };

    vector<Assert> operator()(LockAdd ins) {
        return (*this)(Mem{.access = ins.access, .value = ins.valreg, ._is_load = false});
    };

    vector<Assert> operator()(Bin ins) {
        using T = Assert::TypeConstraint;
        switch (ins.op) {
            case Bin::Op::MOV:
                return {};
            case Bin::Op::ADD:
                if (std::holds_alternative<Reg>(ins.v)) {
                    Reg reg = std::get<Reg>(ins.v);
                    return {
                        T{ins.dst, Type::PTR}.impliesType({reg, Type::NUM}),
                        T{ins.dst, Type::NUM}.impliesType({reg, Type::PTR})
                    };
                }
                return {};
            case Bin::Op::SUB:
                if (std::holds_alternative<Reg>(ins.v)) {
                    return {!T{std::get<Reg>(ins.v), Type::PTR}};
                }
                return {};
            default:
                return {!T{ins.dst, Type::PTR}};
        }
    }
};

void explicate_assertions(Cfg& cfg) {
    for (auto const& this_label : cfg.keys()) {
        vector<Instruction>& old_insts = cfg[this_label].insts;
        vector<Instruction> insts;

        for (auto ins : old_insts) {
            for (auto a : std::visit(AssertionExtractor{}, ins))
                insts.push_back(a);
            insts.push_back(ins);
        }

        old_insts = insts;
    }
}
