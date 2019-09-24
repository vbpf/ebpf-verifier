#include <cinttypes>

#include <utility>
#include <vector>

#include "asm_ostream.hpp"
#include "asm_syntax.hpp"
#include "crab/cfg.hpp"
#include "spec_type_descriptors.hpp"

using std::string;
using std::to_string;
using std::vector;

class AssertExtractor {
    program_info info;
    const bool is_privileged = info.program_type == BpfProgType::KPROBE;

    static auto type_of(Reg r, TypeGroup t) { return Assert{TypeConstraint{r, t}}; };

    static void check_access(vector<Assert>& assumptions, Reg reg, int offset, Value width, bool or_null = false) {
        assumptions.push_back(Assert{ValidAccess{reg, offset, width, or_null}});
    }

  public:
    explicit AssertExtractor(program_info info) : info{std::move(info)} {}

    template <typename T>
    vector<Assert> operator()(T ins) {
        return {};
    }

    vector<Assert> operator()(Packet const& ins) { return {type_of(Reg{6}, TypeGroup::ctx)}; }

    vector<Assert> operator()(Exit const& e) { return {type_of(Reg{0}, TypeGroup::num)}; }

    vector<Assert> operator()(Call const& call) {
        vector<Assert> res;
        std::optional<Reg> map_fd_reg;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!is_privileged)
                    res.push_back(type_of(arg.reg, TypeGroup::num));
                break;
            case ArgSingle::Kind::MAP_FD:
                res.push_back(type_of(arg.reg, TypeGroup::map_fd));
                map_fd_reg = arg.reg;
                break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                res.push_back(type_of(arg.reg, TypeGroup::stack_or_packet));
                res.push_back(
                    Assert{ValidMapKeyValue{arg.reg, *map_fd_reg, arg.kind == ArgSingle::Kind::PTR_TO_MAP_KEY}});
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
                // res.push_back(Assert{OnlyZeroIfNum{arg.mem}});
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
            res.push_back(Assert{ValidSize{arg.size, arg.can_be_zero}});
            check_access(res, arg.mem, 0, arg.size, or_null);
        }
        return res;
    }

    vector<Assert> explicate(Condition cond) {
        if (is_privileged)
            return {};
        vector<Assert> res;
        res.push_back(Assert{ValidAccess{cond.left}});
        if (std::holds_alternative<Imm>(cond.right)) {
            if (std::get<Imm>(cond.right).v != 0) {
                res.push_back(type_of(cond.left, TypeGroup::num));
            } else {
                // OK - map_fd is just another pointer
                // Everything can be compared to 0
            }
        } else {
            res.push_back(Assert{ValidAccess{std::get<Reg>(cond.right)}});
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.push_back(type_of(cond.left, TypeGroup::non_map_fd));
            }
            same_type(res, cond.left, std::get<Reg>(cond.right));
        }
        return res;
    }

    vector<Assert> operator()(Assume ins) { return explicate(ins.cond); }

    vector<Assert> operator()(Jmp ins) {
        if (!ins.cond)
            return {};
        return explicate(*ins.cond);
    }

    vector<Assert> operator()(Mem ins) {
        vector<Assert> res;
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
                    res.push_back(Assert{TypeConstraint{valreg, TypeGroup::num}});
                else
                    res.push_back(Assert{ValidStore{ins.access.basereg, valreg}});
            }
        }
        return res;
    };

    vector<Assert> operator()(LockAdd ins) {
        vector<Assert> res;
        res.push_back(type_of(ins.access.basereg, TypeGroup::shared));
        check_access(res, ins.access.basereg, ins.access.offset, Imm{static_cast<uint32_t>(ins.access.width)});
        return res;
    };

    static void same_type(vector<Assert>& res, Reg r1, Reg r2) { res.push_back(Assert{Comparable{r1, r2}}); }

    vector<Assert> operator()(Bin ins) {
        switch (ins.op) {
        case Bin::Op::MOV: return {};
        case Bin::Op::ADD:
            if (std::holds_alternative<Reg>(ins.v)) {
                Reg reg = std::get<Reg>(ins.v);
                return {Assert{Addable{
                            reg,
                            ins.dst,
                        }},
                        Assert{Addable{ins.dst, reg}}};
            }
            return {};
        case Bin::Op::SUB:
            if (std::holds_alternative<Reg>(ins.v)) {
                vector<Assert> res;
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

void explicate_assertions(cfg_t& cfg, const program_info& info) {
    for (auto& [this_label, bb] : cfg) {
        vector<Instruction> insts;
        for (const auto& ins : vector<Instruction>(bb.begin(), bb.end())) {
            for (auto a : std::visit(AssertExtractor{info}, ins))
                insts.emplace_back(a);
            insts.push_back(ins);
        }
        bb.swap_instructions(insts);
    }
}
