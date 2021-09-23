// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cinttypes>

#include <utility>
#include <vector>

#include "asm_syntax.hpp"
#include "ebpf_vm_isa.hpp"
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

    static Assert zero_offset_ctx(Reg reg) {
        return Assert{{
            TypeConstraint{reg, TypeGroup::ctx},
            ZeroOffset{reg}
        }};
    }

  public:
    explicit AssertExtractor(program_info info) : info{std::move(info)} {}

    Assert operator()(Undefined const& ins) const { assert(0); return {}; }

    Assert operator()(Assert const& ins) const { assert(0); return {}; }

    Assert operator()(LoadMapFd const& ins) const { return {}; }

    /// Packet access implicitly uses R6, so verify that R6 still has a pointer to the context.
    Assert operator()(Packet const& ins) const { return zero_offset_ctx({6}); }

    /// Verify that Exit returns a number.
    Assert operator()(Exit const& e) const {
        return Assert{{
            TypeConstraint{Reg{R0_RETURN_VALUE}, TypeGroup::number}
        }};
    }

    Assert operator()(Call const& call) const {
        Assert res;
        std::optional<Reg> map_fd_reg;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!info.type.is_privileged) {
                    res.insert(TypeConstraint{arg.reg, TypeGroup::number});
                }
                break;
            case ArgSingle::Kind::MAP_FD_PROGRAMS:
                res.insert(TypeConstraint{arg.reg, TypeGroup::map_fd_programs});
                // Do not update map_fd_reg
                break;
            case ArgSingle::Kind::MAP_FD:
                res.insert(TypeConstraint{arg.reg, TypeGroup::map_fd});
                map_fd_reg = arg.reg;
                break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                assert(map_fd_reg);
                res.insert(TypeConstraint{arg.reg, TypeGroup::stack_or_packet});
                res.insert(ValidMapKeyValue{arg.reg, *map_fd_reg,
                                            arg.kind == ArgSingle::Kind::PTR_TO_MAP_KEY});
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                for (const auto& cst: zero_offset_ctx(arg.reg).csts) {
                    res.insert(cst);
                }
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            switch (arg.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                res.insert(TypeConstraint{arg.mem, TypeGroup::mem_or_num});
                break;
            case ArgPair::Kind::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                // TODO: check initialization
                res.insert(TypeConstraint{arg.mem, TypeGroup::mem});
                break;
            case ArgPair::Kind::PTR_TO_UNINIT_MEM:
                // memory may be uninitialized, i.e. write only
                res.insert(TypeConstraint{arg.mem, TypeGroup::mem});
                break;
            }
            // TODO: reg is constant (or maybe it's not important)
            res.insert(TypeConstraint{arg.size, TypeGroup::number});
            res.insert(ValidSize{arg.size, arg.can_be_zero});
            res.insert(ValidAccess{arg.mem, 0, arg.size,
                                   arg.kind == ArgPair::Kind::PTR_TO_MEM_OR_NULL});
        }
        return res;
    }

    [[nodiscard]]
    Assert explicate(Condition cond) const {
        if (info.type.is_privileged)
            return {};
        Assert res;
        res.insert(ValidAccess{cond.left});
        if (std::holds_alternative<Imm>(cond.right)) {
            if (imm(cond.right).v != 0) {
                res.insert(TypeConstraint{cond.left, TypeGroup::number});
            } else {
                res.insert(ValidAccess{cond.left});
                // OK - map_fd is just another pointer
                // Anything can be compared to 0
            }
        } else {
            res.insert(ValidAccess{cond.left});
            res.insert(ValidAccess{reg(cond.right)});
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.insert(TypeConstraint{cond.left, TypeGroup::non_map_fd});
            }
            res.insert(Comparable{cond.left, reg(cond.right)});
        }
        return res;
    }

    Assert operator()(Assume ins) const { return explicate(ins.cond); }

    Assert operator()(Jmp ins) const {
        if (!ins.cond)
            return {};
        return explicate(*ins.cond);
    }

    Assert operator()(Mem ins) const {
        Assert res;
        Reg basereg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (basereg.v == R10_STACK_POINTER) {
            // We know we are accessing the stack.
            if (offset < -EBPF_STACK_SIZE || offset + (int)width.v >= 0) {
                // This assertion will fail
                res.insert(ValidAccess{basereg, offset, width, false});
            }
        } else {
            res.insert(TypeConstraint{basereg, TypeGroup::pointer});
            res.insert(ValidAccess{basereg, offset, width, false});
            if (!info.type.is_privileged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                if (width.v != 8)
                    res.insert(TypeConstraint{reg(ins.value), TypeGroup::number});
                else
                    res.insert(ValidStore{ins.access.basereg, reg(ins.value)});
            }
        }
        return res;
    }

    Assert operator()(LockAdd ins) const {
        return Assert{{
            TypeConstraint{ins.access.basereg, TypeGroup::shared},
            ValidAccess{ins.access.basereg, ins.access.offset,
                        Imm{static_cast<uint32_t>(ins.access.width)}, false}
        }};
    }

    Assert operator()(Un ins) {
        return Assert{{
            TypeConstraint{ins.dst, TypeGroup::number}
        }};
    }

    Assert operator()(Bin ins) const {
        switch (ins.op) {
        case Bin::Op::MOV:
            return {};
        case Bin::Op::ADD:
            if (std::holds_alternative<Reg>(ins.v)) {
                auto src = reg(ins.v);
                return Assert{{
                    TypeConstraint{ins.dst, TypeGroup::ptr_or_num},
                    TypeConstraint{src, TypeGroup::ptr_or_num},
                    Addable{src, ins.dst},
                    Addable{ins.dst, src}
                }};
            } else {
                return Assert{{
                    TypeConstraint{ins.dst, TypeGroup::ptr_or_num}
                }};
            }
        case Bin::Op::SUB:
            if (std::holds_alternative<Reg>(ins.v)) {
                // disallow map-map since same type does not mean same offset
                // TODO: map identities
                return Assert{{
                    TypeConstraint{ins.dst, TypeGroup::ptr_or_num},
                    Comparable{reg(ins.v), ins.dst}
                }};
            } else {
                return Assert{{
                    TypeConstraint{ins.dst, TypeGroup::ptr_or_num}
                }};
            }
        default:
            return Assert{{
                TypeConstraint{ins.dst, TypeGroup::number}
            }};
        }
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
            insts.emplace_back(std::visit(AssertExtractor{info}, ins));
            insts.push_back(ins);
        }
        bb.swap_instructions(insts);
    }
}
