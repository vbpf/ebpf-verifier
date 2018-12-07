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

struct AssertionExtractor {
    template <typename T>
    Assert operator()(T ins) { return {}; }

    Assert operator()(Call const& call) {
        using Typeof = Assert::Typeof;
        bpf_func_proto proto = get_prototype(call.func);
        Assert res;
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
                // if (!is_priviledged()) {
                res.holds.push_back({reg, Type::NUM});
                break;
            case Arg::CONST_SIZE:
                res.holds.push_back({reg, Type::NUM});
                res.implies.emplace_back(Typeof{reg, Type::NUM}, 
                                        reg, 0, 0, (Value)Imm{0}); // FIX: is <=, should be >=
                // TODO: reg is constant
                break;
            case Arg::CONST_SIZE_OR_ZERO:
                res.holds.push_back({reg, Type::NUM});
                res.implies.emplace_back(Typeof{reg, Type::NUM}, 
                                        reg, 0, 0, (Value)Imm{0}); // FIX: is <=, should be >=
                // TODO: reg is constant
                break;
            case Arg::CONST_MAP_PTR:
                res.implies.emplace_back(Typeof{reg, Type::NUM}, 
                                        reg, 0, 0, (Value)Imm{0}); // FIX: should be == 0
                break;
            case Arg::PTR_TO_CTX:
                res.holds.push_back({reg, Type::CTX});
                // TODO: the kernel has some other conditions here - 
                // maybe offset == 0
                break;
            case Arg::PTR_TO_MAP_KEY:
                // what other conditions?
                res.holds.emplace_back(Typeof{reg, Type::PTR});
                break;
            case Arg::PTR_TO_MAP_VALUE:
                res.holds.emplace_back(Typeof{reg, Type::STACK});
                // TODO: add assertion about next (size)
                break;
            case Arg::PTR_TO_MEM_OR_NULL:
                res.implies.emplace_back(Typeof{reg, Type::NUM}, 
                                        reg, 0, 0, (Value)Imm{1});
                // PTR -> true
                res.implies_type.emplace_back(Typeof{reg, Type::PTR}, Typeof{reg, Type::PTR});
                // TODO: MEM means some specific regions. which?
                // TODO: add assertion about next (size)
                break;
            case Arg::PTR_TO_MEM:
                // TODO: assert memory is initialized?
                res.holds.emplace_back(Typeof{reg, Type::PTR});
                // TODO: add assertion about next (size)
                break;
            case Arg::PTR_TO_UNINIT_MEM:
                res.implies_type.emplace_back(Typeof{reg, Type::PTR}, Typeof{reg, Type::PTR});
                // TODO: add assertion about next (size)
                break;
            }
        }
        return res;
    }

    Assert operator()(Mem ins) { 
        using Typeof = Assert::Typeof;
        Assert res;
        Reg reg = ins.access.basereg;
        int width = access_width(ins.access.width);
        int offset = ins.access.offset;
        if (reg.v != 10) {
            res.holds.push_back({reg, Type::PTR});
            res.implies.emplace_back(Typeof{reg, Type::MAP   }, reg, offset, width, (Value)Imm{4098});
            res.implies.emplace_back(Typeof{reg, Type::PACKET}, reg, offset, width, (Value)Reg{15});
        }
        res.implies.emplace_back(Typeof{reg, Type::STACK }, reg, offset, width, (Value)Imm{256});
        return res;
    };

    Assert operator()(Bin ins) {
        using Typeof = Assert::Typeof;
        Assert res;
        switch (ins.op) {
            case Bin::Op::MOV: return { };
            case Bin::Op::ADD: {
                Assert res; 
                if (std::holds_alternative<Reg>(ins.v)) {
                    Reg reg = std::get<Reg>(ins.v);
                    res.implies_type.emplace_back(Typeof{ins.dst, Type::PTR}, Typeof{reg, Type::NUM});
                    res.implies_type.emplace_back(Typeof{reg, Type::NUM}, Typeof{ins.dst, Type::PTR});
                }
                return res;
            }
            case Bin::Op::SUB:{
                Assert res; 
                if (std::holds_alternative<Reg>(ins.v)) {
                    Reg reg = std::get<Reg>(ins.v);
                    res.holds.push_back({reg, Type::NUM});
                }
                return res;
            }
            default: {
                Assert res;
                res.holds.push_back({ins.dst, Type::NUM});
                return res;
            }
        }
    }
};

static bool is_empty(Assert const& a) {
    return a.holds.empty()
        && a.implies_type.empty()
        && a.implies.empty();
}

void explicate_assertions(Cfg& cfg) {
    for (auto const& this_label : cfg.keys()) {
        vector<Instruction>& old_insts = cfg[this_label].insts;
        vector<Instruction> insts;

        for (auto ins : old_insts) {
            auto assertion = std::visit(AssertionExtractor{}, ins);
            if (!is_empty(assertion))
                insts.push_back(assertion);
            insts.push_back(ins);
        }

        old_insts = insts;
    }
}
