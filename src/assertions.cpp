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
void explicate_assertions(crab::basic_block_t& bb, const program_info& info) {
    vector<Instruction> insts;
    for (const auto& ins : vector<Instruction>(bb.begin(), bb.end())) {
        insts.emplace_back(std::visit(AssertExtractor{info}, ins));
        insts.push_back(ins);
    }
    bb.swap_instructions(insts);
}

struct Propagator {
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Undefined&) { return {}; }
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Exit&) { assert(false); return {}; }
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Jmp&) { assert(false); return {}; }
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Assert&) { assert(false); return {}; }

    std::optional<AssertionConstraint> operator()(const Comparable&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Comparable&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const Addable&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidStore&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidSize&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Assume&) { return {}; }
};

static std::set<Reg> reg_and_maybe(const Reg& r, const Value& maybe) {
    std::set<Reg> res{r};
    const Reg* if_reg = std::get_if<Reg>(&maybe);
    if (if_reg)
        res.insert(*if_reg);
    return res;
}

struct DefFinder {
    std::set<Reg> operator()(const Bin& ins) {
        if (ins.op == Bin::Op::DIV || ins.op == Bin::Op::MOD) {
            // the semantics of division by zero mean ins.src is also affected; it is assumed to not be zero
            return reg_and_maybe(ins.dst, ins.v);
        }
        return {ins.dst};
    }
    std::set<Reg> operator()(const Un& ins) { return {ins.dst}; }
    std::set<Reg> operator()(const LoadMapFd& ins) { return {ins.dst}; }
    std::set<Reg> operator()(const Call& ins) { return {Reg{0}, Reg{1}, Reg{2}, Reg{3}, Reg{4}, Reg{5}}; } // TODO: consider side-effect on the stack
    std::set<Reg> operator()(const Mem& ins) {
        if (ins.is_load) return {std::get<Reg>(ins.value)};
        else return {}; // TODO: effect on stack
    }
    std::set<Reg> operator()(const Packet&) { return {Reg{0}, Reg{1}, Reg{2}, Reg{3}, Reg{4}, Reg{5}}; }
    std::set<Reg> operator()(const LockAdd&) { return {}; }
    std::set<Reg> operator()(const Assume& ins) {
        return {
            Reg{0}, Reg{1}, Reg{2}, Reg{3}, Reg{4},
            Reg{5}, Reg{6}, Reg{7}, Reg{8}, Reg{9},
        };
    }

    std::set<Reg> operator()(const Undefined&) { return {}; }
    std::set<Reg> operator()(const Exit&) { return {}; }
    std::set<Reg> operator()(const Jmp&) { return {}; }
    std::set<Reg> operator()(const Assert&) { assert(false); return {}; } // actually, return uses of assert.cst
};

struct UseFinder {
    std::set<Reg> operator()(const Comparable& cst) { return {cst.r1, cst.r2}; }
    std::set<Reg> operator()(const Addable& cst) { return {cst.num, cst.ptr}; }
    std::set<Reg> operator()(const ValidAccess& cst) { return reg_and_maybe(cst.reg, cst.width); }
    std::set<Reg> operator()(const ValidStore& cst) { return {cst.mem, cst.val}; }
    std::set<Reg> operator()(const ValidSize& cst) { return {cst.reg}; }
    std::set<Reg> operator()(const ValidMapKeyValue& cst) { return {cst.access_reg, cst.map_fd_reg}; }
    std::set<Reg> operator()(const TypeConstraint& cst) { return {cst.reg}; }
    std::set<Reg> operator()(const ZeroOffset& cst) { return {cst.reg}; }
};

static std::optional<AssertionConstraint> try_propagate(const AssertionConstraint& cst, const Instruction& ins) {
    auto cst_uses = std::visit(UseFinder{}, cst);
    auto ins_defs = std::visit(DefFinder{}, ins);
    for (const Reg& defined_in_instruction : ins_defs) {
        if (cst_uses.contains(defined_in_instruction)) {
            return std::visit(Propagator{}, cst, ins);
        }
    }
    // otherwise, the constraint can propagate unchanged
    return cst;
}

void propagate_assertions_backwards(crab::basic_block_t& block) {
    assert(block.size() % 2 == 0);
    int idx_next_assertion = ((int)block.size()) - 2;
    int idx_instruction = idx_next_assertion - 1;
    int idx_prev_assertion = idx_instruction - 1;

    while (idx_prev_assertion >= 0) {
        const Instruction& ins = block.at(idx_instruction);

        auto& next_assertion = std::get<Assert>(block.at(idx_next_assertion));
        auto& prev_assertion = std::get<Assert>(block.at(idx_prev_assertion));

        // iterate over copy
        auto next_csts = next_assertion.csts;
        for (const AssertionConstraint& cst : next_csts) {
            if (std::optional<AssertionConstraint> propagated_cst = try_propagate(cst, ins)) {
                next_assertion.csts.erase(cst);
                prev_assertion.insert(*propagated_cst);
            }
        }

        idx_next_assertion = idx_prev_assertion;
        idx_instruction = idx_next_assertion - 1;
        idx_prev_assertion = idx_instruction - 1;
    }
}
