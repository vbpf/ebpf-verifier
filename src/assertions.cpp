// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cinttypes>

#include <utility>
#include <vector>

#include "asm_syntax.hpp"
#include "platform.hpp"
#include "crab/cfg.hpp"

using std::string;
using std::to_string;
using std::vector;

class AssertExtractor {
    program_info info;

    static Reg reg(Value v) {
        return std::get<Reg>(v);
    }

    static Imm imm(Value v) {
        return std::get<Imm>(v);
    }

    static vector<Assert> zero_offset_ctx(Reg reg) {
        vector<Assert> res;
        res.emplace_back(TypeConstraint{reg, TypeGroup::ctx});
        res.emplace_back(ZeroCtxOffset{reg});
        return res;
    }

  public:
    explicit AssertExtractor(program_info info) : info{std::move(info)} {}

    vector<Assert> operator()(Undefined const& ins) const { assert(false); return {}; }

    vector<Assert> operator()(Assert const& ins) const { assert(false); return {}; }

    vector<Assert> operator()(LoadMapFd const& ins) const { return {}; }

    /// Packet access implicitly uses R6, so verify that R6 still has a pointer to the context.
    vector<Assert> operator()(Packet const& ins) const { return zero_offset_ctx({6}); }

    /// Verify that Exit returns a number.
    vector<Assert> operator()(Exit const& e) const { return {Assert{TypeConstraint{Reg{R0_RETURN_VALUE}, TypeGroup::number}}}; }

    vector<Assert> operator()(Call const& call) const {
        vector<Assert> res;
        std::optional<Reg> map_fd_reg;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!info.type.is_privileged) {
                    res.emplace_back(TypeConstraint{arg.reg, TypeGroup::number});
                }
                break;
            case ArgSingle::Kind::MAP_FD_PROGRAMS:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::map_fd_programs});
                // Do not update map_fd_reg
                break;
            case ArgSingle::Kind::MAP_FD:
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::map_fd});
                map_fd_reg = arg.reg;
                break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                assert(map_fd_reg);
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::stack_or_packet});
                res.emplace_back(ValidMapKeyValue{arg.reg, *map_fd_reg,
                                                  arg.kind == ArgSingle::Kind::PTR_TO_MAP_KEY});
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                for (const Assert& a: zero_offset_ctx(arg.reg)) {
                    res.emplace_back(a);
                }
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            res.emplace_back(TypeConstraint{arg.size, TypeGroup::number});
            res.emplace_back(ValidSize{arg.size, arg.can_be_zero});
            switch (arg.kind) {
            case ArgPair::Kind::PTR_TO_READABLE_MEM_OR_NULL:
                res.emplace_back(TypeConstraint{arg.mem, TypeGroup::mem_or_num});
                res.emplace_back(ValidAccess{arg.mem, 0, arg.size, true, AccessType::read});
                break;
            case ArgPair::Kind::PTR_TO_READABLE_MEM:
                /* pointer to valid memory (stack, packet, map value) */
                res.emplace_back(TypeConstraint{arg.mem, TypeGroup::mem});
                res.emplace_back(ValidAccess{arg.mem, 0, arg.size, false, AccessType::read});
                break;
            case ArgPair::Kind::PTR_TO_WRITABLE_MEM:
                // memory may be uninitialized, i.e. write only
                res.emplace_back(TypeConstraint{arg.mem, TypeGroup::mem});
                res.emplace_back(ValidAccess{arg.mem, 0, arg.size, false, AccessType::write});
                break;
            }
            // TODO: reg is constant (or maybe it's not important)
        }
        return res;
    }

    [[nodiscard]]
    vector<Assert> explicate(Condition cond) const {
        if (info.type.is_privileged)
            return {};
        vector<Assert> res;
        if (std::holds_alternative<Imm>(cond.right)) {
            if (imm(cond.right).v != 0) {
                // no need to check for valid access, it must be a number
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::number});
            } else {
                res.emplace_back(ValidAccess{cond.left});
                // OK - map_fd is just another pointer
                // Anything can be compared to 0
            }
        } else {
            res.emplace_back(ValidAccess{cond.left});
            res.emplace_back(ValidAccess{reg(cond.right)});
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::non_map_fd});
            }
            res.emplace_back(Comparable{.r1=cond.left, .r2=reg(cond.right), .or_r2_is_number=false});
        }
        return res;
    }

    vector<Assert> operator()(Assume ins) const { return explicate(ins.cond); }

    vector<Assert> operator()(Jmp ins) const {
        if (!ins.cond)
            return {};
        return explicate(*ins.cond);
    }

    vector<Assert> operator()(Mem ins) const {
        vector<Assert> res;
        Reg basereg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (basereg.v == R10_STACK_POINTER) {
            // We know we are accessing the stack.
            if (offset < -EBPF_STACK_SIZE || offset + (int)width.v >= 0) {
                // This assertion will fail
                res.emplace_back(ValidAccess{basereg, offset, width, false, ins.is_load ? AccessType::read : AccessType::write});
            }
        } else {
            res.emplace_back(TypeConstraint{basereg, TypeGroup::pointer});
            res.emplace_back(
                ValidAccess{basereg, offset, width, false, ins.is_load ? AccessType::read : AccessType::write});
            if (!info.type.is_privileged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                if (width.v != 8)
                    res.emplace_back(TypeConstraint{reg(ins.value), TypeGroup::number});
                else
                    res.emplace_back(ValidStore{ins.access.basereg, reg(ins.value)});
            }
        }
        return res;
    }

    vector<Assert> operator()(LockAdd ins) const {
        vector<Assert> res;
        res.emplace_back(TypeConstraint{ins.access.basereg, TypeGroup::shared});
        res.emplace_back(ValidAccess{ins.access.basereg, ins.access.offset,
                                     Imm{static_cast<uint32_t>(ins.access.width)}, false});
        return res;
    }

    vector<Assert> operator()(Un ins) {
        return {
            Assert{TypeConstraint{ins.dst, TypeGroup::number}}
        };
    }

    vector<Assert> operator()(Bin ins) const {
        switch (ins.op) {
        case Bin::Op::MOV: return {};
        case Bin::Op::ADD:
            if (std::holds_alternative<Reg>(ins.v)) {
                auto src = reg(ins.v);
                return {
                    Assert{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}},
                    Assert{TypeConstraint{src, TypeGroup::ptr_or_num}},
                    Assert{Addable{src, ins.dst}},
                    Assert{Addable{ins.dst, src}}
                };
            } else {
                return {
                    Assert{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}}
                };
            }
        case Bin::Op::SUB:
            if (std::holds_alternative<Reg>(ins.v)) {
                vector<Assert> res;
                // disallow map-map since same type does not mean same offset
                // TODO: map identities
                res.emplace_back(TypeConstraint{ins.dst, TypeGroup::ptr_or_num});
                res.emplace_back(Comparable{.r1=ins.dst, .r2=reg(ins.v), .or_r2_is_number=true});
                return res;
            } else {
                return {
                    Assert{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}}
                };
            }
        case Bin::Op::UDIV:
        case Bin::Op::UMOD:
            if (std::holds_alternative<Reg>(ins.v)) {
                auto src = reg(ins.v);
                return {Assert{TypeConstraint{ins.dst, TypeGroup::number}}, Assert{ValidDivisor{src}}};
            } else {
                return {Assert{TypeConstraint{ins.dst, TypeGroup::number}}};
            }
        default:
            return { Assert{TypeConstraint{ins.dst, TypeGroup::number}} };
        }
        assert(false);
        return {};
    }
};

/// Annotate the CFG by adding explicit assertions for all the preconditions
/// of any instruction. For example, jump instructions are asserted not to
/// compare numbers and pointers, or pointers to potentially distinct memory
/// regions. The verifier will use these assertions to treat the program as
/// unsafe unless it can prove that the assertions can never fail.
void explicate_assertions(cfg_t& cfg, const program_info& info) {
    for (auto& [label, bb] : cfg) {
        (void)label; // unused
        vector<Instruction> insts;
        for (const auto& ins : vector<Instruction>(bb.begin(), bb.end())) {
            for (auto a : std::visit(AssertExtractor{info}, ins))
                insts.emplace_back(a);
            insts.push_back(ins);
        }
        bb.swap_instructions(insts);
    }
}
