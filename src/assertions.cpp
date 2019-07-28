#include <assert.h>
#include <inttypes.h>

#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include "asm_cfg.hpp"
#include "asm_ostream.hpp"
#include "asm_syntax.hpp"
#include "config.hpp"
#include "assertions.hpp"
#include "spec_type_descriptors.hpp"

using std::string;
using std::to_string;
using std::vector;

// implement here, where Assertion is complete
Assert::~Assert() = default;
Assert::Assert(const Assert& a) : p{std::make_unique<Assertion>(*a.p)}, satisfied{a.satisfied} {}
Assert::Assert(AssertionPtr&& p) : p{std::move(p)} {}
void Assert::operator=(const Assert& a) {
    *p = *a.p;
    satisfied = a.satisfied;
}
bool operator==(const Assert& a, const Assert& b) { return *a.p == *b.p && a.satisfied == b.satisfied; }

class AssertionExtractor {
    program_info info;
    std::vector<size_t> type_indices;
    bool is_privileged = info.program_type == BpfProgType::KPROBE;

    auto type_of(Reg r, TypeGroup t) {
        return Assertion{TypeConstraint{r, t}};
    };

    void check_access(vector<Assertion>& assumptions, Reg reg, int offset, Value width, bool or_null=false) {
        assumptions.push_back(Assertion{ValidAccess{reg, offset, width, or_null}});
    }

  public:
    AssertionExtractor(program_info info) : info{info} {
        for (size_t i = 0; i < info.map_defs.size(); i++) {
            type_indices.push_back(i);
        }
        type_indices.push_back(ALL_TYPES + T_CTX);
        type_indices.push_back(ALL_TYPES + T_STACK);
        type_indices.push_back(ALL_TYPES + T_PACKET);
        type_indices.push_back(ALL_TYPES + T_NUM);
        type_indices.push_back(ALL_TYPES + T_MAP);
    }

    template <typename T>
    vector<Assertion> operator()(T ins) {
        return {};
    }

    vector<Assertion> operator()(Packet const& ins) {
        return {type_of(Reg{6}, TypeGroup::ctx)};
    }

    vector<Assertion> operator()(Exit const& e) { return {type_of(Reg{0}, TypeGroup::num)}; }

    vector<Assertion> operator()(Call const& call) {
        vector<Assertion> res;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!is_privileged)
                    res.push_back(type_of(arg.reg, TypeGroup::num));
                break;
            case ArgSingle::Kind::MAP_FD: res.push_back(type_of(arg.reg, TypeGroup::map_fd)); break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
                // what other conditions?
                // looks like packet is valid
                // TODO: maybe arg.packet_access?
                res.push_back(type_of(arg.reg, TypeGroup::stack_or_packet));
                // TODO: check_access
                break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                res.push_back(type_of(arg.reg, TypeGroup::stack_or_packet));
                // TODO: check_access
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                res.push_back(type_of(arg.reg, TypeGroup::ctx));
                // TODO: the kernel has some other conditions here -
                // maybe offset == 0
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            bool or_null = false;
            switch (arg.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                res.push_back(type_of(arg.mem, TypeGroup::mem_or_num));
                //res.push_back(Assertion{OnlyZeroIfNum{arg.mem}});
                or_null = true;
                break;
            case ArgPair::Kind::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                // TODO: check initialization
                res.push_back(type_of(arg.mem, TypeGroup::mem));
                break;
            case ArgPair::Kind::PTR_TO_UNINIT_MEM:
                // memory may be uninitialized, i.e. write only
                res.push_back(type_of(arg.mem, TypeGroup::mem));
                break;
            }
            // TODO: reg is constant (or maybe it's not important)
            res.push_back(type_of(arg.size, TypeGroup::num));
            res.push_back(Assertion{ValidSize{arg.size, arg.can_be_zero}});
            check_access(res, arg.mem, 0, arg.size, or_null);
        }
        return res;
    }

    vector<Assertion> explicate(Condition cond) {
        if (is_privileged)
            return {};
        vector<Assertion> res;
        if (std::holds_alternative<Imm>(cond.right)) {
            if (std::get<Imm>(cond.right).v != 0) {
                res.push_back(type_of(cond.left, TypeGroup::num));
            } else {
                // OK - map_fd is just another pointer
                // Everything can be compared to 0
            }
        } else {
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.push_back(type_of(cond.left, TypeGroup::non_map_fd));
            }
            same_type(res, cond.left, std::get<Reg>(cond.right));
        }
        return res;
    }

    vector<Assertion> operator()(Assume ins) { return explicate(ins.cond); }

    vector<Assertion> operator()(Jmp ins) {
        if (!ins.cond)
            return {};
        return explicate(*ins.cond);
    }

    vector<Assertion> operator()(Mem ins) {
        vector<Assertion> res;
        Reg reg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (reg.v == 10) {
            check_access(res, reg, offset, width);
        } else {
            res.emplace_back(type_of(reg, TypeGroup::ptr));
            check_access(res, reg, offset, width);
            if (!is_privileged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                auto valreg = std::get<Reg>(ins.value);
                if (width.v != 8)
                    res.push_back(Assertion{TypeConstraint{valreg, TypeGroup::num}});
                else
                    res.push_back(Assertion{ValidStore{ins.access.basereg, valreg}});
            }
        }
        return res;
    };

    vector<Assertion> operator()(LockAdd ins) {
        vector<Assertion> res;
        res.push_back(type_of(ins.access.basereg, TypeGroup::shared));
        check_access(res, ins.access.basereg, ins.access.offset,
                     Imm{static_cast<uint32_t>(ins.access.width)});
        return res;
    };

    void same_type(vector<Assertion>& res, Reg r1, Reg r2) {
        res.push_back(Assertion{Comparable{r1, r2}});
    }

    vector<Assertion> operator()(Bin ins) {
        switch (ins.op) {
        case Bin::Op::MOV: return {};
        case Bin::Op::ADD:
            if (std::holds_alternative<Reg>(ins.v)) {
                Reg reg = std::get<Reg>(ins.v);
                return {Assertion{Addable{reg, ins.dst,}},
                        Assertion{Addable{ins.dst, reg}}};
            }
            return {};
        case Bin::Op::SUB:
            if (std::holds_alternative<Reg>(ins.v)) {
                vector<Assertion> res;
                // disallow map-map since same type does not mean same offset
                // Todo: map identities
                res.push_back(type_of(ins.dst, TypeGroup::ptr_or_num));
                same_type(res, std::get<Reg>(ins.v), ins.dst);
                return res;
            }
            return {};
        default: return {type_of(ins.dst, TypeGroup::num)};
        }
    }
};

void explicate_assertions(Cfg& cfg, program_info info) {
    for (auto& [this_label, bb] : cfg) {
        vector<Instruction> insts;
        for (auto ins : vector<Instruction>(bb.begin(), bb.end())) {
            for (auto a : std::visit(AssertionExtractor{info}, ins))
                insts.push_back(std::make_unique<Assertion>(a));
            insts.push_back(ins);
        }
        bb.swap_instructions(insts);
    }
}
