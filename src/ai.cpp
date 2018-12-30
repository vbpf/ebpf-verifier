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
Assert::Assert(const Assert& a) : p{std::make_unique<Assertion>(a.p->given, a.p->then)} { }
Assert::Assert(AssertionPtr&& p) : p{std::move(p)} { }
void Assert::operator=(const Assert& a) { *p = *a.p; }
bool operator==(const Assert& a, const Assert& b) { return *a.p == *b.p; }

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
        for (const auto& r : d.regs) {
            if (r) os << *r;
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

    void operator()(Assume const& a) { }
    void operator()(Assert const& a) { 
        using TC = Assertion::TypeConstraint;
        using LC = Assertion::LinearConstraint;
        // treat as assume
        Types given_types = TypeSet{nmaps}.ptr() | TypeSet{nmaps}.num();
        if (std::holds_alternative<TC>(a.p->given)) {
            TC given = std::get<TC>(a.p->given);
            if (!reg(given.reg))
                return;
            if (std::holds_alternative<TC>(a.p->then)) {
                TC then = std::get<TC>(a.p->then);
                RCP_domain::assume(*reg(given.reg), given.types, *reg(then.reg), then.types);
            } else if (std::holds_alternative<LC>(a.p->then)) {
                auto then = std::get<LC>(a.p->then);
                RCP_domain::assume(*reg(given.reg),
                                   eval(then.offset) + *eval(then.width), then.op, *eval(then.v), 
                                   given.types);
            } else {
                RCP_domain::assume_not(*reg(given.reg), given.types);
            }
        } else {
            if (std::holds_alternative<LC>(a.p->then)) {
                auto then = std::get<LC>(a.p->then);
                RCP_domain::assume(*reg(then.reg), eval(then.offset) + *eval(then.width), then.op, *eval(then.v));
            } else {
                auto then = std::get<TC>(a.p->then);
                RCP_domain::assume(*reg(then.reg), then.types);
            }
        }
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
                regs[0] = regs[1]->maps_from_fds();
                break;
        }
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

    bool recompute(Label l, BasicBlock& bb) {
        RegsDomain dom = pre.at(l);
        for (Instruction& ins : bb.insts) {
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

void worklist(Cfg& cfg, Analyzer& analyzer) {
    std::list<Label> w{cfg.keys().front()};
    while (!w.empty()) {
        Label label = w.front();
        w.pop_front();
        BasicBlock& bb = cfg[label];
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
        std::cout << l << "\n";
        auto dom = analyzer.pre.at(l);
        std::cout << dom << "\n";
        for (auto ins : cfg.at(l).insts) {
            std::cout << to_string(ins) << "\n";
            dom.visit(ins);
            //std::cout << ": " << dom << "\n";
        }
        std::cout << analyzer.post.at(l) << "\n";
        std::cout << "\n";
    }
}

Assertion operator!(Assertion::TypeConstraint tc) {
    return {tc, Assertion::False{}};
}

class AssertionExtractor {
    std::vector<size_t> map_sizes;
    bool is_priviledged = true;
    const TypeSet types;

    const Types num = types.num();
    const Types ctx = types.ctx();
    const Types stack = types.stack();
    const Types packet = types.packet();
    const Types maps = types.map_types();
    const Types mem = stack | packet | maps;
    
    void checkAccess(vector<Assertion>& assumptions, Types t, Reg reg, int offset, Value width) {
        using T = Assertion::TypeConstraint;
        using Op = Condition::Op;
        assumptions.emplace_back(
            T{reg, t}.implies({Op::GE, reg, offset, Imm{0}, Imm{0}})
        );
        for (size_t i=0; i < t.size(); i++) {
            if (!(bool)t[i]) continue;
            Types s = types.single(i);
            if (s == num) continue;
            Value end = Imm{256}; // context size
            if ((s & maps).any()) end = Imm{map_sizes.at(i)};
            else if (s == packet) end = Reg{13};
            else if (s == stack) end = Imm{STACK_SIZE};

            assumptions.emplace_back(
                T{reg, s}.implies({Op::LE, reg, offset, width, end})
            );
        }
    }
public:
    AssertionExtractor(std::vector<size_t> map_sizes) : map_sizes{map_sizes}, types{map_sizes.size()} { }

    template <typename T>
    vector<Assertion> operator()(T ins) { return {}; }

    vector<Assertion> operator()(Exit const& e) {
        return { Assertion(Assertion::TypeConstraint{Reg{0}, types.num()}) };
    }

    vector<Assertion> operator()(Call const& call) {
        using T = Assertion::TypeConstraint;
        using L = Assertion::LinearConstraint;
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
                    res.emplace_back(T{reg, num});
                previous_types.reset();
                break;
            case Arg::CONST_SIZE:
                // TODO: reg is constant (or maybe it's not important)
                res.emplace_back(T{reg, num});
                res.push_back(T{reg, num}.implies({Op::GT, reg, 0, Imm{0}, Imm{0}}));
                checkAccess(res, previous_types, Reg{(uint8_t)(i-1)}, 0, reg);
                previous_types.reset();
                break;
            case Arg::CONST_SIZE_OR_ZERO:
                // TODO: reg is constant (or maybe it's not important)
                res.emplace_back(T{reg, num});
                res.push_back(T{reg, num}.implies({Op::GE, reg, 0, Imm{0}, Imm{0}}));
                checkAccess(res, previous_types, Reg{(uint8_t)(i-1)}, 0, reg);
                previous_types.reset();
                break;
            case Arg::CONST_MAP_PTR:
                res.emplace_back(T{reg, types.map_struct()});
                previous_types.reset();
                break;
            case Arg::PTR_TO_CTX:
                res.emplace_back(T{reg, previous_types = ctx});
                // TODO: the kernel has some other conditions here - 
                // maybe offset == 0
                break;
            case Arg::PTR_TO_MAP_KEY:
                // what other conditions?
                res.emplace_back(T{reg, previous_types = stack});
                break;
            case Arg::PTR_TO_MAP_VALUE:
                res.emplace_back(T{reg, previous_types = maps});
                break;
            case Arg::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                res.emplace_back(T{reg, previous_types = mem});
                break;
            case Arg::PTR_TO_MEM_OR_NULL:
                res.emplace_back(T{reg, mem | num});
                res.push_back(T{reg, num}.implies({Op::EQ, reg, 0, Imm{0}, Imm{0}}));
                // NUM should not be in previous_types
                previous_types = mem;
                break;
            case Arg::PTR_TO_UNINIT_MEM:
                res.emplace_back(T{reg, previous_types = mem});
                break;
            }
        }
        return res;
    }

    vector<Assertion> operator()(Mem ins) { 
        using T = Assertion::TypeConstraint;
        using Op = Condition::Op;
        vector<Assertion> res;
        Reg reg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (reg.v == 10) {
            checkAccess(res, stack, reg, offset, width);
        } else {
            res.emplace_back(T{reg, types.ptr()});
            checkAccess(res, types.ptr(), reg, offset, width);
            if (!is_priviledged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                for (auto t : {maps , ctx , packet}) {
                    res.push_back(
                        T{reg, t}.impliesType({std::get<Reg>(ins.value), num})
                    );
                }
            }
        }
        return res;
    };

    vector<Assertion> operator()(LockAdd ins) {
        vector<Assertion> res;
        res.emplace_back(Assertion::TypeConstraint{ins.access.basereg, maps});
        checkAccess(res, maps, ins.access.basereg, ins.access.offset, Imm{static_cast<uint32_t>(ins.access.width)});
        return res;
    };

    vector<Assertion> operator()(Bin ins) {
        using T = Assertion::TypeConstraint;
        switch (ins.op) {
            case Bin::Op::MOV:
                return {};
            case Bin::Op::ADD:
                if (std::holds_alternative<Reg>(ins.v)) {
                    Reg reg = std::get<Reg>(ins.v);
                    return {
                        T{ins.dst, types.ptr()}.impliesType({reg, num}),
                        T{reg, types.ptr()}.impliesType({ins.dst, num})
                    };
                }
                return {};
            case Bin::Op::SUB:
                if (std::holds_alternative<Reg>(ins.v)) {
                    vector<Assertion> res;
                    res.push_back( { T{ins.dst, types.map_struct().flip()} });
                    for (auto t : {maps, ctx, packet}) {
                        res.push_back(T{ins.dst, t}.impliesType({std::get<Reg>(ins.v), t}));
                    }
                    res.push_back( { T{std::get<Reg>(ins.v), types.map_struct().flip()} });
                    return res;
                }
                return {};
            default:
                return { { T{ins.dst, num} } };
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
