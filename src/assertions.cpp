// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <cinttypes>

#include <utility>
#include <vector>

#include "asm_syntax.hpp"
#include "crab/cfg.hpp"
#include "platform.hpp"

using crab::TypeGroup;
using std::string;
using std::to_string;
using std::vector;

class AssertExtractor {
    program_info info;
    std::optional<label_t> current_label; ///< Pre-simplification label this assert is part of.

    static Imm imm(const Value& v) { return std::get<Imm>(v); }

    static vector<Assert> zero_offset_ctx(const Reg reg) {
        vector<Assert> res;
        res.emplace_back(TypeConstraint{reg, TypeGroup::ctx});
        res.emplace_back(ZeroCtxOffset{reg});
        return res;
    }

  public:
    explicit AssertExtractor(program_info info, std::optional<label_t> label)
        : info{std::move(info)}, current_label(label) {}

    vector<Assert> operator()(Undefined const&) const {
        assert(false);
        return {};
    }

    vector<Assert> operator()(Assert const&) const {
        assert(false);
        return {};
    }

    vector<Assert> operator()(IncrementLoopCounter) const {
        assert(false);
        return {};
    }

    vector<Assert> operator()(LoadMapFd const&) const { return {}; }

    /// Packet access implicitly uses R6, so verify that R6 still has a pointer to the context.
    vector<Assert> operator()(Packet const&) const { return zero_offset_ctx({6}); }

    vector<Assert> operator()(Exit const&) const {
        vector<Assert> res;
        if (current_label->stack_frame_prefix.empty()) {
            // Verify that Exit returns a number.
            res.emplace_back(TypeConstraint{Reg{R0_RETURN_VALUE}, TypeGroup::number});
        }
        return res;
    }

    vector<Assert> operator()(Call const& call) const {
        vector<Assert> res;
        std::optional<Reg> map_fd_reg;
        res.emplace_back(ValidCall{call.func, call.stack_frame_prefix});
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
                res.emplace_back(TypeConstraint{arg.reg, TypeGroup::mem});
                res.emplace_back(ValidMapKeyValue{arg.reg, *map_fd_reg, arg.kind == ArgSingle::Kind::PTR_TO_MAP_KEY});
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                for (const Assert& a : zero_offset_ctx(arg.reg)) {
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

    vector<Assert> operator()(CallLocal const& call) const { return {}; }

    vector<Assert> operator()(Callx const& callx) const {
        vector<Assert> res;
        res.emplace_back(TypeConstraint{callx.func, TypeGroup::number});
        res.emplace_back(FuncConstraint{callx.func});
        return res;
    }

    [[nodiscard]]
    vector<Assert> explicate(const Condition& cond) const {
        if (info.type.is_privileged) {
            return {};
        }
        vector<Assert> res;
        if (const auto pimm = std::get_if<Imm>(&cond.right)) {
            if (pimm->v != 0) {
                // no need to check for valid access, it must be a number
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::number});
            } else {
                res.emplace_back(ValidAccess{cond.left});
                // OK - map_fd is just another pointer
                // Anything can be compared to 0
            }
        } else {
            const auto reg_right = get<Reg>(cond.right);
            res.emplace_back(ValidAccess{cond.left});
            res.emplace_back(ValidAccess{reg_right});
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.emplace_back(TypeConstraint{cond.left, TypeGroup::ptr_or_num});
            }
            res.emplace_back(Comparable{.r1 = cond.left, .r2 = reg_right, .or_r2_is_number = false});
        }
        return res;
    }

    vector<Assert> operator()(const Assume& ins) const { return explicate(ins.cond); }

    vector<Assert> operator()(const Jmp& ins) const {
        if (!ins.cond) {
            return {};
        }
        return explicate(*ins.cond);
    }

    vector<Assert> operator()(const Mem& ins) const {
        vector<Assert> res;
        const Reg basereg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        const int offset = ins.access.offset;
        if (basereg.v == R10_STACK_POINTER) {
            // We know we are accessing the stack.
            if (offset < -EBPF_STACK_SIZE || offset + static_cast<int>(width.v) >= 0) {
                // This assertion will fail
                res.emplace_back(
                    ValidAccess{basereg, offset, width, false, ins.is_load ? AccessType::read : AccessType::write});
            }
        } else {
            res.emplace_back(TypeConstraint{basereg, TypeGroup::pointer});
            res.emplace_back(
                ValidAccess{basereg, offset, width, false, ins.is_load ? AccessType::read : AccessType::write});
            if (!info.type.is_privileged && !ins.is_load) {
                if (const auto preg = std::get_if<Reg>(&ins.value)) {
                    if (width.v != 8) {
                        res.emplace_back(TypeConstraint{*preg, TypeGroup::number});
                    } else {
                        res.emplace_back(ValidStore{ins.access.basereg, *preg});
                    }
                }
            }
        }
        return res;
    }

    vector<Assert> operator()(const Atomic& ins) const {
        vector<Assert> res;
        res.emplace_back(TypeConstraint{ins.access.basereg, TypeGroup::pointer});
        res.emplace_back(
            ValidAccess{ins.access.basereg, ins.access.offset, Imm{static_cast<uint32_t>(ins.access.width)}, false});
        if (ins.op == Atomic::Op::CMPXCHG) {
            // The memory contents pointed to by ins.access will be compared
            // against the value of the ins.valreg register.  Only numbers are
            // supported.
            res.emplace_back(TypeConstraint{ins.valreg, TypeGroup::number});
        }
        return res;
    }

    vector<Assert> operator()(const Un ins) const { return {Assert{TypeConstraint{ins.dst, TypeGroup::number}}}; }

    vector<Assert> operator()(const Bin& ins) const {
        switch (ins.op) {
        case Bin::Op::MOV: return {};
        case Bin::Op::MOVSX8:
        case Bin::Op::MOVSX16:
        case Bin::Op::MOVSX32:
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                return {Assert{TypeConstraint{*src, TypeGroup::number}}};
            }
            return {};
        case Bin::Op::ADD: {
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                return {Assert{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}},
                        Assert{TypeConstraint{*src, TypeGroup::ptr_or_num}}, Assert{Addable{*src, ins.dst}},
                        Assert{Addable{ins.dst, *src}}};
            }
            return {Assert{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}}};
        }
        case Bin::Op::SUB: {
            if (const auto reg = std::get_if<Reg>(&ins.v)) {
                vector<Assert> res;
                // disallow map-map since same type does not mean same offset
                // TODO: map identities
                res.emplace_back(TypeConstraint{ins.dst, TypeGroup::ptr_or_num});
                res.emplace_back(Comparable{.r1 = ins.dst, .r2 = *reg, .or_r2_is_number = true});
                return res;
            }
            return {Assert{TypeConstraint{ins.dst, TypeGroup::ptr_or_num}}};
        }
        case Bin::Op::UDIV:
        case Bin::Op::UMOD:
        case Bin::Op::SDIV:
        case Bin::Op::SMOD: {
            if (const auto src = std::get_if<Reg>(&ins.v)) {
                const bool is_signed = (ins.op == Bin::Op::SDIV || ins.op == Bin::Op::SMOD);
                return {Assert{TypeConstraint{ins.dst, TypeGroup::number}}, Assert{ValidDivisor{*src, is_signed}}};
            }
            return {Assert{TypeConstraint{ins.dst, TypeGroup::number}}};
        }
        default: return {Assert{TypeConstraint{ins.dst, TypeGroup::number}}};
        }
        assert(false);
    }
};

vector<Assert> get_assertions(Instruction ins, const program_info& info, const std::optional<label_t>& label) {
    return std::visit(AssertExtractor{info, label}, ins);
}

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
            for (auto a : get_assertions(ins, info, bb.label())) {
                insts.emplace_back(a);
            }
            insts.push_back(ins);
        }
        bb.swap_instructions(insts);
    }
}
