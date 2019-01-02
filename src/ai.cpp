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

constexpr Reg DATA_END_REG = Reg{13};
constexpr Reg META_REG = Reg{14};

struct RegsDomain {
    std::array<std::optional<RCP_domain>, 16> regs;
    //int min_packet_size{0};
    program_info info;
    RCP_domain BOT;
    TypeSet types;

    RegsDomain(program_info info) : info{info}, BOT{info.map_sizes.size()}, types{info.map_sizes.size()} {
        for (auto& r : regs) r = BOT;
    }

    void init() {
        for (auto& r : regs) r = {};
        regs[1] = BOT.with_ctx(0);
        regs[10] = BOT.with_stack(STACK_SIZE);

        // initialized to num to be consistent with other bound checks that assume num
        // (therefore region->zero is added before checking assertion)
        regs[13] = BOT.with_num(TOP);
        regs[14] = BOT.with_num(TOP);
    }

    bool is_bot() {
        for (size_t i=0; i < 10; i++) {
            if (regs[i] && regs[i]->is_bot())
                return true;
        }
        return false;
    }

    friend std::ostream& operator<<(std::ostream& os, const RegsDomain& d) {
        os << "<<";
        for (size_t i = 0; i < 10; i++) {
            os << "r"<< i << ": ";
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
        return BOT.with_num(v);
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
        regs[a.dst.v] = BOT.with_fd(a.mapfd);
    }

    void operator()(Un const& a) { };
    void operator()(Bin const& a) { 
        using Op = Bin::Op;
        RCP_domain rhs = std::holds_alternative<Reg>(a.v)
                       ? (reg(a.v) ? *reg(a.v) : BOT)
                       : BOT.with_num(std::get<Imm>(a.v).v);
        if (a.op == Op::MOV) {
            regs[a.dst.v] = rhs;
            return;
        }
        if ((std::holds_alternative<Reg>(a.v) && !reg(a.v)) || !reg(a.dst)) {
            // No need to propagate uninitialized values - just mark as bot
            // TODO: what about assertion failures?
            regs[a.dst.v] = BOT;
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
        if (eval(a.cond.right))
            RCP_domain::assume(*reg(a.cond.left), a.cond.op, *eval(a.cond.right));
        else {
            std::cerr << a << " failed; " << a.cond.right << " is secret\n";
        }
    }

    void operator()(Assert const& a) { 
        // treat as assume
        if (std::holds_alternative<LinearConstraint>(a.p->cst)) {
            auto lc = std::get<LinearConstraint>(a.p->cst);
            assert(reg(lc.reg));
            assert(eval(lc.width));
            assert(eval(lc.v));
            assert((lc.when_types & types.num()).none()
                || (lc.when_types & types.ptr()).none());
            const RCP_domain right = reg(lc.reg)->zero() + (*eval(lc.v) - *eval(lc.width) - eval(lc.offset));
            RCP_domain::assume(*reg(lc.reg), lc.op, right, lc.when_types);
        } else {
            auto tc = std::get<TypeConstraint>(a.p->cst);
            if (!reg(tc.then.reg)) {
                reg(tc.then.reg) = BOT;
                return;
            }
            if (tc.given) {
                if (!reg(tc.given->reg)) return;
                RCP_domain::assume(*reg(tc.then.reg), tc.then.types, *reg(tc.given->reg), tc.given->types);
            } else {
                RCP_domain::assume(*reg(tc.then.reg), tc.then.types);
            }
        }
    }

    bool satisfied(Assert const& a) { 
        if (std::holds_alternative<LinearConstraint>(a.p->cst)) {
            auto lc = std::get<LinearConstraint>(a.p->cst);
            const RCP_domain right = reg(lc.reg)->zero() + (*eval(lc.v) - *eval(lc.width) - eval(lc.offset));
            assert(!right.is_bot()); // should be ignored really
            assert(!reg(lc.reg)->is_bot()); // should be ignored really
            return RCP_domain::satisfied(*reg(lc.reg), lc.op, right, lc.when_types);
        }
        auto tc = std::get<TypeConstraint>(a.p->cst);
        if (!reg(tc.then.reg)) return false;
        const RCP_domain left = *reg(tc.then.reg);
        //if (left.is_bot()) return false;
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
                regs[0] = BOT.with_num(TOP);
                break;
            case Ret::PTR_TO_MAP_VALUE_OR_NULL:
                regs[0] = regs[1]->maps_from_fds().with_num(0);
                break;
        }
        for (int i=1; i < 6; i++)
            regs[i] = {};
    }

    void operator()(Packet const& a) { 
        regs[0] = BOT.with_num(TOP);
    }

    void operator()(Mem const& a) {
        if (!a.is_load) return;
        if (!reg(a.access.basereg)) return;
        auto r = BOT;
        auto addr = *reg(a.access.basereg) + eval(a.access.offset);
        OffsetDomSet as_ctx = addr.get_ctx();
        if (!as_ctx.is_bot()) {
            if (as_ctx.is_single()) {
                auto d = info.descriptor;
                auto data_start = BOT.with_packet(0);
                if (d.data > -1 && as_ctx.contains(d.data))
                    r |= data_start;
                else if (d.end > -1 && as_ctx.contains(d.end))
                    r |= data_start + *reg(DATA_END_REG);
                else if (d.meta > -1 && as_ctx.contains(d.meta))
                    r |= data_start + *reg(META_REG);
                else 
                    r |= BOT.with_num(TOP);
            } else {
                r.havoc(); // TODO: disallow, or at least don't havoc fd
            }
        }
        if (!(addr & BOT.with_packet(TOP)).is_bot()
         || !(addr & BOT.with_maps(TOP)).is_bot())
            r |= BOT.with_num(TOP);
        if (!(addr & BOT.with_stack(TOP)).is_bot())
            r.havoc();
        reg(a.value) = r;
    }

    void operator()(LockAdd const& a) { }

    void visit(Instruction ins) {
        std::visit(*this, ins);
    }
};

struct Analyzer {
    std::unordered_map<Label, RegsDomain> pre;
    std::unordered_map<Label, RegsDomain> post;

    Analyzer(const Cfg& cfg, program_info info)  {
        for (auto l : cfg.keys()) {
            pre.emplace(l, info);
            post.emplace(l, info);
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
        for (Label l : prevs) {
            new_pre |= post.at(l);
        }
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

void analyze_rcp(Cfg& cfg, program_info info) {
    Analyzer analyzer{cfg, info};
    worklist(cfg, analyzer);

    for (auto l : cfg.keys()) {
        auto dom = analyzer.pre.at(l);
        for (Instruction& ins : cfg[l].insts) {
            bool unsatisfied_assertion = false;
            if (std::holds_alternative<Assert>(ins)) {
                Assert& a = std::get<Assert>(ins);
                if (!a.satisfied) { // && !dom.is_bot()
                    a.satisfied = dom.satisfied(a);
                    unsatisfied_assertion = !a.satisfied;
                    if (unsatisfied_assertion) {
                        std::cout << l << ":\n";
                        std::cout << dom << "\n";
                        std::cout << "\n" << ins << "\n";
                    }
                }
            }
            dom.visit(ins);
            if (unsatisfied_assertion) {
                std::cout << dom << "\n";
            }
        }
    }
}

class AssertionExtractor {
    program_info info;
    bool is_priviledged = false;
    const TypeSet types;

    const Types num = types.num();
    const Types ctx = types.ctx();
    const Types stack = types.stack();
    const Types packet = types.packet();
    const Types maps = types.map_types();
    const Types fd = types.map_struct();
    const Types mem = stack | packet | maps;
    const Types ptr = mem | ctx;
    const Types nonfd = ptr | num;
    
    auto type_of(Reg r, const Types t) {
        assert(t.size() == info.map_sizes.size() + 5);
        return Assertion{TypeConstraint{{r, t}}};
    };

    void check_access(vector<Assertion>& assumptions, Types t, Reg reg, int offset, Value width) {
        using Op = Condition::Op;
        assumptions.push_back(
            Assertion{LinearConstraint{Op::GE, reg, offset, Imm{0}, Imm{0}, t}}
        );
        for (size_t i=0; i < t.size(); i++) {
            if (!t[i]) continue;
            Types s = types.single(i);
            if (s == num) continue;
            Value end;
            if ((s & maps).any()) end = Imm{info.map_sizes.at(i)};
            else if (s == packet) end = DATA_END_REG;
            else if (s == stack) end = Imm{STACK_SIZE};
            else if (s == ctx) end = Imm{static_cast<uint64_t>(info.descriptor.size)};
            else assert(false);
            assumptions.push_back(
                Assertion{LinearConstraint{Op::LE, reg, offset, width, end, s}}
            );
        }
    }
public:
    AssertionExtractor(program_info info) : info{info}, types{info.map_sizes.size()} { }

    template <typename T>
    vector<Assertion> operator()(T ins) { return {}; }

    vector<Assertion> operator()(Exit const& e) {
        return { type_of(Reg{0}, num) };
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
                res.push_back(type_of(reg, fd));
                previous_types.reset();
                break;
            case Arg::CONST_SIZE:
            case Arg::CONST_SIZE_OR_ZERO: {
                // TODO: reg is constant (or maybe it's not important)
                Op op = t == Arg::CONST_SIZE_OR_ZERO ? Op::GE : Op::GT;
                res.push_back(type_of(reg, num));
                res.push_back(Assertion{LinearConstraint{op, reg, 0, Imm{0}, Imm{0}, num}});
                check_access(res, previous_types, Reg{(uint8_t)(i-1)}, 0, reg);
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
                res.push_back(type_of(reg, previous_types = stack | packet)); // looks like packet is valid
                break;
            case Arg::PTR_TO_MAP_VALUE:
                res.push_back(type_of(reg, previous_types = stack | packet)); // strangely, looks like it means stack or packet
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
        vector<Assertion> res;
        Reg reg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (reg.v == 10) {
            check_access(res, stack, reg, offset, width);
        } else {
            res.emplace_back(type_of(reg, ptr));
            check_access(res, ptr, reg, offset, width);
            if (!is_priviledged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                for (auto t : {maps , ctx , packet}) {
                    res.push_back(
                        Assertion{ TypeConstraint{{std::get<Reg>(ins.value), num}, {reg, t}} }
                    );
                }
            }
        }
        return res;
    };

    vector<Assertion> operator()(LockAdd ins) {
        vector<Assertion> res;
        res.push_back(type_of(ins.access.basereg, maps));
        check_access(res, maps, ins.access.basereg, ins.access.offset, Imm{static_cast<uint32_t>(ins.access.width)});
        return res;
    };

    void same_type(vector<Assertion>& res, Types ts, Reg r1, Reg r2) {
        for (size_t i=0; i < ts.size(); i++) {
            if (ts[i]) {
                Types t = types.single(i);
                res.push_back( Assertion{TypeConstraint{{r1, t}, {r2, t}} });
            }
        }
    }

    vector<Assertion> operator()(Bin ins) {
        switch (ins.op) {
            case Bin::Op::MOV:
                return {};
            case Bin::Op::ADD:
                if (std::holds_alternative<Reg>(ins.v)) {
                    Reg reg = std::get<Reg>(ins.v);
                    return {
                        Assertion{ TypeConstraint{{reg, num}, {ins.dst, ptr}} },
                        Assertion{ TypeConstraint{{ins.dst, num}, {reg, ptr}} }
                    };
                }
                return {};
            case Bin::Op::SUB:
                if (std::holds_alternative<Reg>(ins.v)) {
                    vector<Assertion> res;
                    res.push_back(type_of(ins.dst, nonfd));
                    same_type(res, maps | ctx | packet, std::get<Reg>(ins.v), ins.dst);
                    res.push_back(type_of(std::get<Reg>(ins.v), nonfd));
                    return res;
                }
                return {};
            default:
                return { type_of(ins.dst, num) };
        }
    }
};

void explicate_assertions(Cfg& cfg, program_info info) {
    for (auto const& this_label : cfg.keys()) {
        vector<Instruction>& old_insts = cfg[this_label].insts;
        vector<Instruction> insts;

        for (auto ins : old_insts) {
            for (auto a : std::visit(AssertionExtractor{info}, ins))
                insts.emplace_back(std::make_unique<Assertion>(a));
            insts.push_back(ins);
        }

        old_insts = insts;
    }
}
