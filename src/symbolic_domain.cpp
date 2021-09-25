// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cinttypes>

#include <utility>
#include <vector>

#include "asm_syntax.hpp"
#include "ebpf_vm_isa.hpp"
#include "platform.hpp"
#include "crab/cfg.hpp"

static constexpr AssertionConstraint TRUE_CONSTRAINT = TypeConstraint{Reg{10}, TypeGroup::stack};
static constexpr AssertionConstraint FALSE_CONSTRAINT = TypeConstraint{Reg{10}, TypeGroup::number};

static bool is_trivial(const AssertionConstraint& cst) {
    if (const auto* pcst = std::get_if<TypeConstraint>(&cst)) {
        if (pcst->reg == Reg{10}) {
            switch (pcst->types) {
            case TypeGroup::number:
            case TypeGroup::map_fd:
            case TypeGroup::map_fd_programs:
            case TypeGroup::ctx:
            case TypeGroup::shared:
                return false;
            default:
                return true;
            }
        }
    } else if (const auto* pcst = std::get_if<SameType>(&cst)) {
        return pcst->r1 == pcst->r2;
    } else if (const auto* pcst = std::get_if<ValidAccess>(&cst)) {
        return pcst->reg == Reg{10} && pcst->offset > -EBPF_STACK_SIZE
               && std::holds_alternative<Imm>(pcst->width) && pcst->offset + (long)std::get<Imm>(pcst->width).v <= 0;
    }
    return false;
}

struct Propagator {
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Undefined&) { return {}; }
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Exit&) { assert(false); return {}; }
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Jmp&) { assert(false); return {}; }
    template<typename Cst> std::optional<AssertionConstraint> operator()(const Cst&, const Assert&) { assert(false); return {}; }

    std::optional<AssertionConstraint> operator()(const SameType& cst, const Mov& bin) {
        if (std::holds_alternative<Imm>(bin.v)) {
            TypeGroup type = std::get<Imm>(bin.v).v == 0 ? TypeGroup::ptr_or_num : TypeGroup::number;
            if (bin.dst == cst.r1) return TypeConstraint{cst.r2, type};
            else if (bin.dst == cst.r2) return TypeConstraint{cst.r1, type};
            else assert(false);
            return {};
        } else {
            return {};
        }
    }
    std::optional<AssertionConstraint> operator()(const SameType& cst, const Bin& bin) {
        if (std::holds_alternative<Imm>(bin.v)) {
            // "x op= NUM" never changes the type of x
            return cst;
        } else {
            switch (bin.op) {
            case Bin::Op::ADD:
            case Bin::Op::SUB:
                return {};
            default:
                // Most binary operations do not change the type of dst
                return cst;
            }
        }
    }
    std::optional<AssertionConstraint> operator()(const SameType& cst, const Un&) { return cst; }
    std::optional<AssertionConstraint> operator()(const SameType&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const SameType&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const SameType&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const SameType&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const SameType&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const SameType&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const Addable& ins, const Mov& mov) {
        if (mov.dst == ins.num && std::holds_alternative<Imm>(mov.v))
            return TRUE_CONSTRAINT;
        if (mov.dst == ins.ptr && ins.ptr == Reg{10})
            return TypeConstraint{ins.num, TypeGroup::number};
        return {};
    }
    std::optional<AssertionConstraint> operator()(const Addable&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const Addable&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidAccess& cst, const Mov& mov) {
        if (cst.reg != mov.dst)
            return {};
        if (std::holds_alternative<Imm>(mov.v)) {
            if (cst.width == (Value)Imm{0}) {
                return TRUE_CONSTRAINT;
            }
        }
        return {};
    }
    std::optional<AssertionConstraint> operator()(ValidAccess cst, const Bin& bin) {
        if (cst.reg != bin.dst)
            return {};
        if (std::holds_alternative<Imm>(bin.v)) {
            auto offset = (int64_t)std::get<Imm>(bin.v).v;
            if (bin.op == Bin::Op::ADD) {
                cst.offset += offset;
                return cst;
            } else if (bin.op == Bin::Op::SUB) {
                cst.offset -= offset;
                return cst;
            }
        }
        return {};
    }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidAccess&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidStore&, const Mov&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidStore&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidSize& cst, const Mov& bin) {
        if (std::holds_alternative<Imm>(bin.v)) {
            assert(cst.reg == bin.dst);
            if (std::get<Imm>(bin.v).v >= (cst.can_be_zero ? 0 : 1))
                return TRUE_CONSTRAINT;
            else
                return FALSE_CONSTRAINT;
        }
        return {};
    }
    std::optional<AssertionConstraint> operator()(const ValidSize& cst, const Bin& bin) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidSize&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Mov&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Bin&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Call&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const ValidMapKeyValue&, const Assume&) { return {}; }

    std::optional<AssertionConstraint> operator()(const TypeConstraint& cst, const Mov& bin) {
        if (std::holds_alternative<Imm>(bin.v)) {
            assert(cst.reg == bin.dst);
            if (cst.types == TypeGroup::number) return TRUE_CONSTRAINT;
            if (cst.types == TypeGroup::ptr_or_num) return TRUE_CONSTRAINT;
            if (cst.types == TypeGroup::mem_or_num) return TRUE_CONSTRAINT;
            if (cst.types == TypeGroup::non_map_fd) return TRUE_CONSTRAINT;
            // not necessarily false, since checking against null is sometimes valid:
            return {};
        } else {
            return cst;
        }
    }

    std::optional<AssertionConstraint> operator()(const TypeConstraint& cst, const Bin& bin) {
        if (std::holds_alternative<Imm>(bin.v)) {
            assert(cst.reg == bin.dst);
            // "x op= NUM" never changes the type of x
            return cst;
        } else {
            switch (bin.op) {
            case Bin::Op::ADD:
            case Bin::Op::SUB:
                return {};
            default:
                // Most binary operations do not change the type of dst
                return cst;
            }
        }
    }

    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Un&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const LoadMapFd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint& cst, const Call& call) {
        if (cst.reg != Reg{0}) return {};
        if (call.is_map_lookup) {
            // Elaborated querying is needed to make sure this looks up the right map
            return {};
        } else {
            if (cst.types == TypeGroup::number || cst.types == TypeGroup::ptr_or_num || cst.types == TypeGroup::mem_or_num) {
                return TRUE_CONSTRAINT;
            }
        }
        return {};
    }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Mem&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const Packet&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint&, const LockAdd&) { return {}; }
    std::optional<AssertionConstraint> operator()(const TypeConstraint& cst, const Assume& ins) {
        if (std::holds_alternative<Imm>(ins.cond.right) && ins.cond.right != (Value)Imm{0}) {
            return this->operator()(cst, Mov{ins.cond.left, ins.cond.right});
        }
        return {};
    }

    std::optional<AssertionConstraint> operator()(const ZeroOffset&, const Mov&) { return {}; }
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
    std::set<Reg> operator()(const Mov& ins) {
        return {ins.dst};
    }
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
            Reg{5}, Reg{6}, Reg{7}, Reg{8}, Reg{9}, Reg{10}
        };
    }

    std::set<Reg> operator()(const Undefined&) { return {}; }
    std::set<Reg> operator()(const Exit&) { return {}; }
    std::set<Reg> operator()(const Jmp&) { return {}; }
    std::set<Reg> operator()(const Assert&) { assert(false); return {}; } // actually, return uses of assert.cst
};

struct UseFinder {
    std::set<Reg> operator()(const SameType& cst) { return {cst.r1, cst.r2}; }
    std::set<Reg> operator()(const Addable& cst) { return {cst.num, cst.ptr}; }
    std::set<Reg> operator()(const ValidAccess& cst) { return reg_and_maybe(cst.reg, cst.width); }
    std::set<Reg> operator()(const ValidStore& cst) { return {cst.mem, cst.val}; }
    std::set<Reg> operator()(const ValidSize& cst) { return {cst.reg}; }
    std::set<Reg> operator()(const ValidMapKeyValue& cst) { return {cst.access_reg, cst.map_fd_reg}; }
    std::set<Reg> operator()(const TypeConstraint& cst) { return {cst.reg}; }
    std::set<Reg> operator()(const ZeroOffset& cst) { return {cst.reg}; }
};

struct RegReplacer {
    // given dst = src, replace dst with src
    // e.g.: cst is "r1 < 0"
    // to propagate it before the assignment "r1 = r2"
    // we need to change it to "r2 < 0"
    const Reg& dst;
    const Value& src;

    void replace(Reg& candidate) {
        if (std::holds_alternative<Reg>(src))
            if (candidate == dst) candidate = std::get<Reg>(src);
    }
    void replace(Value& candidate) {
        if (candidate == (Value)dst) candidate = src;
    }
    template<typename... Args>
    void replace(Args&&... args) {
        (replace(args), ...);
    }

    template<class> static constexpr bool always_false_v = false;

    template<typename Cst>
    AssertionConstraint operator()(const Cst& cst) {
        Cst res = cst;
        if constexpr (std::is_same_v<Cst, SameType>)
            replace(res.r1, res.r2);
        else if constexpr (std::is_same_v<Cst, Addable>)
            replace(res.num, res.ptr);
        else if constexpr (std::is_same_v<Cst, ValidAccess>)
            replace(res.reg, res.width);
        else if constexpr (std::is_same_v<Cst, ValidStore>)
            replace(res.mem, res.val);
        else if constexpr (std::is_same_v<Cst, ValidSize>)
            replace(res.reg);
        else if constexpr (std::is_same_v<Cst, ValidMapKeyValue>)
            replace(res.access_reg, res.map_fd_reg);
        else if constexpr (std::is_same_v<Cst, TypeConstraint>)
            replace(res.reg);
        else if constexpr (std::is_same_v<Cst, ZeroOffset>)
            replace(res.reg);
        else
            static_assert(always_false_v<Cst>, "non-exhaustive visitor!");
        return res;
    }
};

static std::optional<AssertionConstraint> try_propagate(AssertionConstraint cst, const Instruction& ins) {
    if (const auto* pbin = std::get_if<Mov>(&ins)) {
        RegReplacer replacer{pbin->dst, pbin->v};
        std::optional<AssertionConstraint> maybe_cst = std::visit(replacer, cst);
        if (maybe_cst)
            cst = *maybe_cst;
    }
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
                if (!is_trivial(*propagated_cst)) {
                    prev_assertion.insert(*propagated_cst);
                }
            }
        }

        idx_next_assertion = idx_prev_assertion;
        idx_instruction = idx_next_assertion - 1;
        idx_prev_assertion = idx_instruction - 1;
    }
}
