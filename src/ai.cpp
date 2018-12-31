#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <list>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <iostream>
#include <optional>
#include <bitset>
#include <functional>
#include <unordered_map>

#include "asm_syntax.hpp"
#include "asm_cfg.hpp"
#include "asm_ostream.hpp"
#include "spec_assertions.hpp"
#include "spec_prototypes.hpp"
#include "spec_type_descriptors.hpp"
#include "ai.hpp"
#include "ai_dom_set.hpp"
#include "ai_dom_rcp.hpp"

using std::optional;
using std::to_string;
using std::string;
using std::vector;

// implement here, where Assertion is complete
Assert::~Assert() = default;
Assert::Assert(const Assert& a) : p{std::make_unique<Assertion>(*a.p)}, satisfied{a.satisfied} { }
Assert::Assert(AssertionPtr&& p) : p{std::move(p)} { }
void Assert::operator=(const Assert& a) { *p = *a.p; satisfied = a.satisfied; }
bool operator==(const Assert& a, const Assert& b) { return *a.p == *b.p && a.satisfied == b.satisfied; }

struct RegsDomain {
    size_t nmaps;
    std::array<std::optional<RCP_domain>, 16> regs;
    RegsDomain(size_t nmaps) : nmaps{nmaps} {
        for (int i = 0; i < 16; i++)
            regs[i] = RCP_domain{nmaps};
        regs[10] = RCP_domain{nmaps}.with_stack(STACK_SIZE);
    }

    void init() {
        regs[0] = {};
        regs[1] = RCP_domain{nmaps}.with_ctx(0);
        for (int i = 2; i < 10; i++)
            regs[i] = {};
    }

    friend std::ostream& operator<<(std::ostream& os, const RegsDomain& d) {
        os << "<<";
        for (size_t i = 0; i < 10; i++) {
            if (d.regs[i]) os << *d.regs[i];
            else os << "*";
            os << ", ";
        }
        os << ">>";
        return os;
    }

    std::optional<RCP_domain>& reg(Value v) {
        return regs.at(std::get<Reg>(v).v);
    }

    RCP_domain eval(uint64_t v) {
        return RCP_domain{nmaps}.with_num(v);
    }

    std::optional<RCP_domain> eval(Value v) {
        if (std::holds_alternative<Imm>(v)) {
            return eval(std::get<Imm>(v).v);
        } else {
            return reg(v);
        }
    }

    void operator|=(const RegsDomain& o) {
        for (size_t i=0; i < regs.size(); i++) {
            if (!regs[i] || !o.regs[i])
                regs[i] = {};
            else
                *regs[i] |= *o.regs[i];
        }
    }

    void operator&=(const RegsDomain& o) {
        for (size_t i=0; i < regs.size(); i++)
            if (!regs[i] || !o.regs[i])
                regs[i] = {};
            else
                *regs[i] &= *o.regs[i];
    }

    bool operator==(RegsDomain o) const { return regs == o.regs; }
    bool operator!=(RegsDomain o) const { return regs != o.regs; }

    void operator()(Undefined const& a) { assert(false); }

    void operator()(LoadMapFd const& a) {
        RCP_domain res{nmaps};
        res.set_mapfd(a.mapfd);
        regs[a.dst.v] = res;
    }

    void operator()(Un const& a) { };
    void operator()(Bin const& a) { 
        using Op = Bin::Op;
        RCP_domain rhs = std::holds_alternative<Reg>(a.v) ? *reg(a.v) : RCP_domain{nmaps}.with_num(std::get<Imm>(a.v).v);
        if (a.op == Op::MOV) {
            regs[a.dst.v] = rhs;
            return;
        }
        if (!reg(a.dst)) return;
        if (std::holds_alternative<Reg>(a.v) && !reg(a.v)) reg(a.dst) = {};
        RCP_domain& lhs = *reg(a.dst);
        switch (a.op) {
            case Op::MOV: assert(false); return;
            case Op::ADD: lhs += rhs; return;
            case Op::SUB: lhs -= rhs; return;
            default: lhs.exec(a.op, rhs); return;
        }
        assert(false);
        return;
    }

    void operator()(Assume const& a) {
        assert(reg(a.cond.left));
        assert(eval(a.cond.right));
        RCP_domain::assume(*reg(a.cond.left), a.cond.op, *eval(a.cond.right));
    }

    void operator()(Assert const& a) { 
        // treat as assume
        if (std::holds_alternative<LinearConstraint>(a.p->cst)) {
            auto lc = std::get<LinearConstraint>(a.p->cst);
            const auto& right = *eval(lc.v) - *eval(lc.width) - eval(lc.offset);
            RCP_domain::assume(*reg(lc.reg), lc.op, right, lc.when_types);
        } else {
            auto tc = std::get<TypeConstraint>(a.p->cst);
            if (tc.given) {
                if (!reg(tc.given->reg)) return;
                RCP_domain::assume(*reg(tc.then.reg), tc.then.types, *reg(tc.given->reg), tc.given->types);
            } else {
                RCP_domain::assume(*reg(tc.then.reg), tc.then.types);
            }
        }
    }

    bool satisfied(Assert const& a) { 
        // treat as assume
        if (std::holds_alternative<LinearConstraint>(a.p->cst)) {
            auto lc = std::get<LinearConstraint>(a.p->cst);
            const auto& right = *eval(lc.v) - *eval(lc.width) - eval(lc.offset);
            return RCP_domain::satisfied(*reg(lc.reg), lc.op, right, lc.when_types);
        }
        auto tc = std::get<TypeConstraint>(a.p->cst);
        const auto& left = *reg(tc.then.reg);
        if (tc.given) {
            if (!reg(tc.given->reg)) return false;
            return RCP_domain::satisfied(left, tc.then.types, *reg(tc.given->reg), tc.given->types);
        }
        return RCP_domain::satisfied(left, tc.then.types);
    }

    void operator()(Exit const& a) { }

    void operator()(Jmp const& a) { }

    void operator()(Call const& call) {
        switch (get_prototype(call.func).ret_type) {
            case Ret::VOID: // actually noreturn - meaning < 0 when returns
            case Ret::INTEGER:
                regs[0] = RCP_domain{nmaps}.with_num(TOP);
                break;
            case Ret::PTR_TO_MAP_VALUE_OR_NULL:
                regs[0] = regs[1]->maps_from_fds().with_num(0);
                break;
        }
        for (int i=1; i < 6; i++)
            regs[i] = {};
    }

    void operator()(Packet const& a) { }

    void operator()(Mem const& a) {
        if (!a.is_load) return;
        regs[std::get<Reg>(a.value).v] = RCP_domain{nmaps, TOP};
    }

    void operator()(LockAdd const& a) { }

    void visit(Instruction ins) {
        std::visit(*this, ins);
    }
};

struct Analyzer {
    std::unordered_map<Label, RegsDomain> pre;
    std::unordered_map<Label, RegsDomain> post;

    Analyzer(const Cfg& cfg, size_t nmaps)  {
        for (auto l : cfg.keys()) {
            pre.emplace(l, nmaps);
            post.emplace(l, nmaps);
        }
        pre.at(cfg.keys().front()).init();
    }

    bool recompute(Label l, const BasicBlock& bb) {
        RegsDomain dom = pre.at(l);
        for (const Instruction& ins : bb.insts) {
            dom.visit(ins);
        }
        bool res = post.at(l) != dom;
        post.insert_or_assign(l, dom);
        return res;
    }

    void join(const std::vector<Label>& prevs, Label into) {
        RegsDomain new_pre = pre.at(into);
        for (Label l : prevs)
            new_pre |= post.at(l);
        pre.insert_or_assign(into, new_pre);
    }
};

void worklist(const Cfg& cfg, Analyzer& analyzer) {
    std::list<Label> w{cfg.keys().front()};
    while (!w.empty()) {
        Label label = w.front();
        w.pop_front();
        const BasicBlock& bb = cfg.at(label);
        analyzer.join(bb.prevlist, label);
        if (analyzer.recompute(label, bb)) {
            for (Label next_label : bb.nextlist)
                w.push_back(next_label);
            w.erase(std::unique(w.begin(), w.end()), w.end());
        }
    }
}

void analyze_rcp(Cfg& cfg, size_t nmaps) {
    Analyzer analyzer{cfg, nmaps};
    worklist(cfg, analyzer);

    for (auto l : cfg.keys()) {
        auto dom = analyzer.pre.at(l);
        //std::cout << dom << "\n";
        for (Instruction& ins : cfg[l].insts) {
            if (std::holds_alternative<Assert>(ins)) {
                Assert& a = std::get<Assert>(ins);
                if (!a.satisfied) {
                    a.satisfied = dom.satisfied(a);
                }
            }
            dom.visit(ins);
        }
        //std::cout << analyzer.post.at(l) << "\n";
    }
}

auto type_of(Reg r, Types t) {
    return Assertion{TypeConstraint{{r, t}}};
};

class AssertionExtractor {
    std::vector<size_t> map_sizes;
    bool is_priviledged = false;
    const TypeSet types;

    const Types num = types.num();
    const Types ctx = types.ctx();
    const Types stack = types.stack();
    const Types packet = types.packet();
    const Types maps = types.map_types();
    const Types mem = stack | packet | maps;
    const Types nonfd = mem | num;
    
    void checkAccess(vector<Assertion>& assumptions, Types t, Reg reg, int offset, Value width) {
        using TC = TypeConstraint;
        using Op = Condition::Op;
        assumptions.push_back(
            Assertion{LinearConstraint{Op::GE, reg, offset, Imm{0}, Imm{0}, t}}
        );
        for (size_t i=0; i < t.size(); i++) {
            if (!(bool)t[i]) continue;
            Types s = types.single(i);
            if (s == num) continue;
            Value end = Imm{256}; // context size
            if ((s & maps).any()) end = Imm{map_sizes.at(i)};
            else if (s == packet) end = Reg{13};
            else if (s == stack) end = Imm{STACK_SIZE};

            assumptions.push_back(
                Assertion{LinearConstraint{Op::LE, reg, offset, width, end, s}}
            );
        }
    }
public:
    AssertionExtractor(std::vector<size_t> map_sizes) : map_sizes{map_sizes}, types{map_sizes.size()} { }

    template <typename T>
    vector<Assertion> operator()(T ins) { return {}; }

    vector<Assertion> operator()(Exit const& e) {
        return { type_of(Reg{0}, types.num()) };
    }

    vector<Assertion> operator()(Call const& call) {
        using Op = Condition::Op;

        bpf_func_proto proto = get_prototype(call.func);
        vector<Assertion> res;
        Types previous_types;
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
                if (!is_priviledged)
                    res.push_back(type_of(reg, num));
                previous_types.reset();
                break;
            case Arg::CONST_MAP_PTR:
                res.push_back(type_of(reg, types.map_struct()));
                previous_types.reset();
                break;
            case Arg::CONST_SIZE:
            case Arg::CONST_SIZE_OR_ZERO: {
                // TODO: reg is constant (or maybe it's not important)
                Op op = t == Arg::CONST_SIZE_OR_ZERO ? Op::GE : Op::GT;
                res.push_back(type_of(reg, num));
                res.push_back(Assertion{LinearConstraint{op, reg, 0, Imm{0}, Imm{0}, num}});
                checkAccess(res, previous_types, Reg{(uint8_t)(i-1)}, 0, reg);
                previous_types.reset();
                break;
            }
            case Arg::PTR_TO_MEM_OR_NULL:
                res.push_back(type_of(reg, mem | num));
                res.push_back(Assertion{LinearConstraint{Op::EQ, reg, 0, Imm{0}, Imm{0}, num} });
                // NUM should not be in previous_types
                previous_types = mem;
                break;
            case Arg::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                res.push_back(type_of(reg, previous_types = mem));
                break;
            case Arg::PTR_TO_MAP_KEY:
                // what other conditions?
                res.push_back(type_of(reg, previous_types = stack));
                break;
            case Arg::PTR_TO_MAP_VALUE:
                res.push_back(type_of(reg, previous_types = maps));
                break;
            case Arg::PTR_TO_UNINIT_MEM:
                res.push_back(type_of(reg, previous_types = mem));
                break;
            case Arg::PTR_TO_CTX:
                res.push_back(type_of(reg, previous_types = ctx));
                // TODO: the kernel has some other conditions here - 
                // maybe offset == 0
                break;
            }
        }
        return res;
    }

    vector<Assertion> operator()(Assume ins) { 
        vector<Assertion> res;
        if (is_priviledged) {
            res.push_back(type_of(ins.cond.left, nonfd));
        } else {
            if (std::holds_alternative<Imm>(ins.cond.right)) {
                if (std::get<Imm>(ins.cond.right).v != 0) {
                    res.push_back(type_of(ins.cond.left, num));
                } else {
                    res.push_back(type_of(ins.cond.left, nonfd));
                }
            } else {
                res.push_back(type_of(ins.cond.left, nonfd));
                same_type(res, nonfd, ins.cond.left, std::get<Reg>(ins.cond.right));
            }
        }
        return res;
    }

    vector<Assertion> operator()(Mem ins) { 
        using RT = TypeConstraint::RT;
        vector<Assertion> res;
        Reg reg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (reg.v == 10) {
            checkAccess(res, stack, reg, offset, width);
        } else {
            res.emplace_back(type_of(reg, types.ptr()));
            checkAccess(res, types.ptr(), reg, offset, width);
            if (!is_priviledged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                for (auto t : {maps , ctx , packet}) {
                    res.push_back(
                        Assertion{ TypeConstraint{RT{std::get<Reg>(ins.value), num}, RT{reg, t}} }
                    );
                }
            }
        }
        return res;
    };

    vector<Assertion> operator()(LockAdd ins) {
        vector<Assertion> res;
        res.push_back(type_of(ins.access.basereg, maps));
        checkAccess(res, maps, ins.access.basereg, ins.access.offset, Imm{static_cast<uint32_t>(ins.access.width)});
        return res;
    };

    void same_type(vector<Assertion>& res, Types ts, Reg r1, Reg r2) {
        using RT = TypeConstraint::RT;
        for (size_t i=0; i < ts.size(); i++) {
            if (ts[i]) {
                Types t = ts.reset().set(i);
                res.push_back( Assertion{TypeConstraint{RT{r1, t}, RT{r2, t}} });
            }
        }
    }

    vector<Assertion> operator()(Bin ins) {
        using TC = TypeConstraint;
        using RT = TypeConstraint::RT;
        switch (ins.op) {
            case Bin::Op::MOV:
                return {};
            case Bin::Op::ADD:
                if (std::holds_alternative<Reg>(ins.v)) {
                    Reg reg = std::get<Reg>(ins.v);
                    return {
                        Assertion{ TC{RT{reg, num}, RT{ins.dst, types.ptr()}} },
                        Assertion{ TC{RT{ins.dst, num}, RT{reg, types.ptr()}} }
                    };
                }
                return {};
            case Bin::Op::SUB:
                if (std::holds_alternative<Reg>(ins.v)) {
                    vector<Assertion> res;
                    res.push_back(type_of(ins.dst, types.map_struct().flip()));
                    same_type(res, maps | ctx | packet, std::get<Reg>(ins.v), ins.dst);
                    res.push_back(type_of(std::get<Reg>(ins.v), types.map_struct().flip()));
                    return res;
                }
                return {};
            default:
                return { type_of(ins.dst, num) };
        }
    }
};

void explicate_assertions(Cfg& cfg, std::vector<size_t> maps_sizes) {
    for (auto const& this_label : cfg.keys()) {
        vector<Instruction>& old_insts = cfg[this_label].insts;
        vector<Instruction> insts;

        for (auto ins : old_insts) {
            for (auto a : std::visit(AssertionExtractor{maps_sizes}, ins))
                insts.emplace_back(std::make_unique<Assertion>(a));
            insts.push_back(ins);
        }

        old_insts = insts;
    }
}
