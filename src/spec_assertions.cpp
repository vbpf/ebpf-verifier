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

static Assert extract_assertions(Instruction ins) {
    using Typeof = Assert::Typeof;
    return std::visit(overloaded{
        [](auto ins) -> Assert { return {}; },
        [](Mem ins) -> Assert { 
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
        },
        [](Bin ins) -> Assert { 
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
        },
    }, ins);
}

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
            auto assertion = extract_assertions(ins);
            if (!is_empty(assertion))
                insts.push_back(assertion);
            insts.push_back(ins);
        }

        old_insts = insts;
    }
}
