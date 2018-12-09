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


static Imm access_width(Width w)
{
    switch (w) {
        case Width::B: return Imm{1};
        case Width::H: return Imm{2};
        case Width::W: return Imm{4};
        case Width::DW: return Imm{8};
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
        std::optional<vector<Type>> previous_types;
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
                previous_types = {};
                break;
            case Arg::CONST_SIZE:
                // TODO: reg is constant (or maybe it's not important)
                res.emplace_back(T{reg, Type::NUM});
                res.push_back(T{reg, Type::NUM}.implies({Op::GT, reg, 0, Imm{0}, Imm{0}}));
                for (auto t : *previous_types)
                    checkAccess(res, t, Reg{(uint8_t)(i-1)}, 0, reg);
                previous_types = {};
                break;
            case Arg::CONST_SIZE_OR_ZERO:
                // TODO: reg is constant (or maybe it's not important)
                res.emplace_back(T{reg, Type::NUM});
                res.push_back(T{reg, Type::NUM}.implies({Op::GE, reg, 0, Imm{0}, Imm{0}}));
                for (auto t : *previous_types)
                    checkAccess(res, t, Reg{(uint8_t)(i-1)}, 0, reg);
                previous_types = {};
                break;
            case Arg::CONST_MAP_PTR:
                res.emplace_back(T{reg, Type::MAP_STRUCT});
                previous_types = {};
                break;
            case Arg::PTR_TO_CTX:
                res.emplace_back(T{reg, Type::CTX});
                // TODO: the kernel has some other conditions here - 
                // maybe offset == 0
                previous_types = {Type::CTX};
                break;
            case Arg::PTR_TO_MAP_KEY:
                // what other conditions?
                res.emplace_back(T{reg, Type::STACK});
                previous_types = {Type::STACK};
                break;
            case Arg::PTR_TO_MAP_VALUE:
                res.emplace_back(T{reg, Type::MAP_VALUE});
                previous_types = {Type::MAP_VALUE};
                break;
            case Arg::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                res.push_back(!T{reg, Type::CTX});
                res.emplace_back(T{reg, Type::PTR});
                previous_types = {Type::STACK, Type::PACKET, Type::MAP_VALUE};
                break;
            case Arg::PTR_TO_MEM_OR_NULL:
                res.push_back(T{reg, Type::NUM}.implies({Op::EQ, reg, 0, Imm{0}, Imm{0}}));
                res.emplace_back(!T{reg, Type::SECRET});
                res.push_back(!T{reg, Type::CTX});
                // NUM should not be in previous_types
                previous_types = {Type::STACK, Type::PACKET, Type::MAP_VALUE};
                break;
            case Arg::PTR_TO_UNINIT_MEM:
                res.emplace_back(T{reg, Type::PTR});
                previous_types = {Type::STACK, Type::PACKET, Type::MAP_VALUE};
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
        Imm width = access_width(ins.access.width);
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
        vector<Assert> res;
        res.emplace_back(Assert::TypeConstraint{ins.access.basereg, Type::MAP_VALUE});
        checkAccess(res, Type::MAP_VALUE, ins.access.basereg, ins.access.offset, access_width(ins.access.width));
        return res;
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
                    Reg src = std::get<Reg>(ins.v);
                    vector<Assert> res{
                        T{ins.dst, Type::NUM}.impliesType({src, Type::NUM})
                    };
                    for (auto t : {Type::MAP_VALUE, Type::CTX, Type::PACKET}) {
                        res.push_back(
                            T{ins.dst, t}.impliesType({src, t})
                        );
                    }
                    return res;
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
