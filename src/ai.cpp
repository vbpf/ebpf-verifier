#include <inttypes.h>
#include <assert.h>

#include <vector>
#include <list>
#include <string>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <optional>
#include <bitset>
#include <functional>

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

struct MemDom {
    struct Pair {
        RCP_domain dom;
        uint64_t width{};
        bool operator==(const Pair& o) const { return dom == o.dom && width == o.width; }
    };
    bool bot = true;
    std::map<int, Pair> arr;
    
    void load(const OffsetDomSet& offset, uint64_t width, RCP_domain& outval) const {
        if (offset.is_top()) {
            outval.havoc();
            return;
        }
        assert(!offset.elems.empty());
        outval.to_bot();
        for (int64_t k : offset.elems) {
            for (auto [k1, v] : arr) {
                if ((k1 <= k && k1 + v.width >  k + width)
                 || (k1 <  k && k1 + v.width >= k + width)) {
                    if (v.dom.must_be_num()) {
                        outval = outval.with_num(TOP);
                    } else {
                        outval.havoc();
                    }
                    goto next_iteration;
                }
            }
            if (arr.count(k)) {
                const auto& dom = arr.at(k).dom;
                if (arr.at(k).width == width) {
                    outval |= dom;
                } else {
                    // partial read of num havocs only num
                    if (dom.must_be_num())
                        outval = outval.with_num(TOP);
                    else
                        outval.havoc();
                    return;
                }
            } else {
                outval.havoc();
                return;
            }
        next_iteration:
            ;
        }
    }

    void store(const OffsetDomSet& offset, const NumDomSet& ws, const RCP_domain& value) {
        bot = false;
        if (offset.is_top() || !ws.is_single()) {
            arr.clear();
            return;
        }
        uint64_t width = ws.elems.front();
        assert(!offset.elems.empty());
        for (int64_t k : offset.elems) {
            std::vector<int64_t> to_remove;
            for (auto& [k1, v1] : arr) {
                if (k1 >= k) break;
                if (k1 + v1.width > k) {
                    if (v1.dom.must_be_num()) {
                        // part of num is valid num
                        v1.width = k - k1;
                        v1.dom = v1.dom.with_num(TOP);
                    } else {
                        to_remove.push_back(k1);
                    }
                }
            }
            for (auto k1 : to_remove) arr.erase(k1);
            if (arr.count(k)) {
                if (arr.at(k).width == width) {
                    arr.at(k).dom |= value;
                    if (arr.at(k).dom.is_top())
                        arr.erase(k);
                } else {
                    arr.erase(k);
                }
            } // otherwise it's already top
            for (uint64_t i=1; i<width; i++) {
                arr.erase(k + (int)i);
            }
        }

        if (offset.is_single()) {
            arr.insert_or_assign(offset.elems.front(), Pair{value, width});
        }
    };

    void operator|=(const MemDom& o) {
        //std::cerr << *this << " | " << o;
        if (o.bot)
            return;
        if (bot) {
            *this = o;
        } else {
            for (auto& [k, p] : o.arr) {
                if (arr.count(k) == 1 && arr.at(k).width == p.width) {
                    arr.at(k).dom |= p.dom;
                } else {
                    arr.erase(k);
                }
            }
        }
        //std::cerr << " = " << *this << "\n";
    }
    void operator&=(const MemDom& o) {
        // TODO
    }
    bool is_bot() { return bot; }

    bool operator==(const MemDom& o) const { return arr == o.arr; }

    friend std::ostream& operator<<(std::ostream& os, const MemDom& d) {
        if (d.bot) return os << "{BOT}";
        os << "{";
        for (auto [k, v] : d.arr) {
            os << k - STACK_SIZE << ":" << v.width << "->" << v.dom << ", ";
        }
        os << "}";
        return os;
    }
};

struct RegsDom {
    using ValDom = RCP_domain;
    std::array<std::optional<ValDom>, 16> regs;

    RegsDom(size_t nmaps) {
        for (auto& r : regs) r = {nmaps};
    }

    friend std::ostream& operator<<(std::ostream& os, const RegsDom& d) {
        os << "<<";
        for (size_t i = 0; i < 10; i++) {
            os << "r"<< i << ": ";
            if (d.regs.at(i)) os << *d.regs[i];
            else os << "*";
            os << ", ";
        }
        os << ">>";
        return os;
    }

    void init(const ValDom& ctx, const ValDom& stack_end, const ValDom& top_num) {
        for (auto& r : regs) r = {};
        regs[1] = ctx;
        regs[10] = stack_end;

        // initialized to num to be consistent with other bound checks that assume num
        // (therefore region->zero is added before checking assertion)
        regs[13] = top_num;
        regs[14] = top_num;
    }

    bool is_bot() const {
        for (size_t i=0; i < 10; i++) {
            if (regs[i] && regs[i]->is_bot())
                return true;
        }
        return false;
    }

    void operator|=(const RegsDom& o) {
        for (size_t i=0; i < regs.size(); i++) {
            if (!regs[i] || !o.regs[i])
                regs[i] = {};
            else
                *regs[i] |= *o.regs[i];
        }
    }

    void operator&=(const RegsDom& o) {
        for (size_t i=0; i < regs.size(); i++)
            if (!regs[i] || !o.regs[i])
                regs[i] = {};
            else
                *regs[i] &= *o.regs[i];
    }

    void scratch_regs() {
        for (int i=1; i < 6; i++)
            regs[i] = {};
    }

    void assign(Reg r, const ValDom& v) {
        regs[r.v] = v;
    }

    ValDom& at(Reg r) {
        if (!regs[r.v]) throw std::runtime_error{std::string("Uninitialized register r") + std::to_string(r.v)};
        return *regs[r.v];
    }

    void to_uninit(Reg r) {
        regs[r.v] = {};
    }

    bool operator==(const RegsDom& o) const { return regs == o.regs; }
};

struct Machine {
    RegsDom regs;
    MemDom stack_arr;

    program_info info;
    RCP_domain BOT;
    TypeSet types;

    Machine(program_info info) : regs{info.map_sizes.size()}, info{info}, BOT{info.map_sizes.size()}, types{info.map_sizes.size()} {
    }

    void init() {
        regs.init(BOT.with_ctx(0), BOT.with_stack(STACK_SIZE), BOT.with_num(TOP));
        stack_arr.bot = false;
    }

    bool is_bot() {
        return regs.is_bot()
            || stack_arr.is_bot();
    }

    friend std::ostream& operator<<(std::ostream& os, const Machine& d) {
        return os << d.regs << " " << d.stack_arr;
    }

    RCP_domain eval(uint64_t v) {
        return BOT.with_num(v);
    }

    RCP_domain eval(Value v) {
        if (std::holds_alternative<Imm>(v)) {
            return eval(std::get<Imm>(v).v);
        } else {
            return regs.at(std::get<Reg>(v));
        }
    }

    void operator|=(const Machine& o) {
        regs |= o.regs;
        stack_arr |= o.stack_arr;
    }

    void operator&=(const Machine& o) {
        regs &= o.regs;
        stack_arr &= o.stack_arr;
    }

    bool operator==(Machine o) const { return regs == o.regs && stack_arr == o.stack_arr; }
    bool operator!=(Machine o) const { return !(*this == o); }

    void operator()(Undefined const& a) { assert(false); }

    void operator()(LoadMapFd const& a) {
        regs.assign(a.dst, BOT.with_fd(a.mapfd));
    }

    void operator()(Un const& a) { };
    void operator()(Bin const& a) { 
        switch (a.op) {
            case Bin::Op::MOV: regs.assign(a.dst, eval(a.v)); return;
            case Bin::Op::ADD: regs.at(a.dst) += eval(a.v); return;
            case Bin::Op::SUB: regs.at(a.dst) -= eval(a.v); return;
            default: regs.at(a.dst).exec(a.op, eval(a.v)); return;
        }
        assert(false);
        return;
    }

    void operator()(Assume const& a) {
        RCP_domain::assume(regs.at(a.cond.left), a.cond.op, eval(a.cond.right));
    }

    void operator()(Assert const& a) { 
        // treat as assume
        if (std::holds_alternative<LinearConstraint>(a.p->cst)) {
            auto lc = std::get<LinearConstraint>(a.p->cst);
            assert((lc.when_types & types.num()).none()
                || (lc.when_types & types.ptr()).none());
            const RCP_domain right = regs.at(lc.reg).zero() + (eval(lc.v) - eval(lc.width) - eval(lc.offset));
            RCP_domain::assume(regs.at(lc.reg), lc.op, right, lc.when_types);
        } else {
            auto tc = std::get<TypeConstraint>(a.p->cst);
            if (tc.given) {
                RCP_domain::assume(regs.at(tc.then.reg), tc.then.types, regs.at(tc.given->reg), tc.given->types);
            } else {
                RCP_domain::assume(regs.at(tc.then.reg), tc.then.types);
            }
        }
    }

    bool satisfied(Assert const& a) { 
        if (std::holds_alternative<LinearConstraint>(a.p->cst)) {
            auto lc = std::get<LinearConstraint>(a.p->cst);
            const RCP_domain right = regs.at(lc.reg).zero() + (eval(lc.v) - eval(lc.width) - eval(lc.offset));
            return RCP_domain::satisfied(regs.at(lc.reg), lc.op, right, lc.when_types);
        }
        auto tc = std::get<TypeConstraint>(a.p->cst);
        const RCP_domain left = regs.at(tc.then.reg);
        //if (left.is_bot()) return false;
        if (tc.given) {
            return RCP_domain::satisfied(left, tc.then.types, regs.at(tc.given->reg), tc.given->types);
        }
        return RCP_domain::satisfied(left, tc.then.types);
    }

    void operator()(Exit const& a) { }

    void operator()(Jmp const& a) { }

    void operator()(Call const& call) {
        bpf_func_proto proto = get_prototype(call.func);
        uint8_t i = 0;
        std::array<Arg, 5> args = {{proto.arg1_type, proto.arg2_type, proto.arg3_type, proto.arg4_type, proto.arg5_type}};
        for (Arg t : args) {
            ++i;
            if (t == Arg::DONTCARE)
                break;
            switch (t) {
            case Arg::DONTCARE: assert(false); break;
            case Arg::ANYTHING: break;
            case Arg::CONST_MAP_PTR: break;
            case Arg::CONST_SIZE:
            case Arg::CONST_SIZE_OR_ZERO: break;
            case Arg::PTR_TO_MAP_KEY: break;
            case Arg::PTR_TO_MAP_VALUE: break;
            case Arg::PTR_TO_MEM_OR_NULL: break;
            case Arg::PTR_TO_MEM: break;
            case Arg::PTR_TO_UNINIT_MEM: {
                store(regs.at(Reg{i}), regs.at(Reg{(uint8_t)(i+1)}).get_num(), BOT.with_num(TOP));
                break;
            }
            case Arg::PTR_TO_CTX:
                break;
            }
        }
        switch (proto.ret_type) {
            case Ret::VOID: // actually noreturn - meaning < 0 when returns
            case Ret::INTEGER:
                regs.assign(Reg{0}, BOT.with_num(TOP));
                break;
            case Ret::PTR_TO_MAP_VALUE_OR_NULL:
                regs.assign(Reg{0}, regs.regs.at(1)->maps_from_fds().with_num(0));
                break;
        }
        regs.scratch_regs();
    }

    void operator()(Packet const& a) {
        // Different syntax for a function call
        regs.assign(Reg{0}, BOT.with_num(TOP));
        regs.scratch_regs();
    }

    void store(const RCP_domain& addr, const NumDomSet& width, const RCP_domain& value) {
        OffsetDomSet as_stack = addr.get_stack();
        if (!as_stack.is_bot()) {
            // make weak updates extremely weak
            if (addr.with_stack({}).is_bot())
                stack_arr.store(as_stack, width, value);
            else
                stack_arr.store(TOP, width, value);
        }
    }

    RCP_domain load_stack(const OffsetDomSet& as_stack, int width) {
        if (as_stack.is_bot()) return BOT;
        RCP_domain r = BOT;
        stack_arr.load(as_stack, width, r);
        return r;
    }

    RCP_domain load_ctx(const OffsetDomSet& as_ctx, int width) {
        if (as_ctx.is_bot()) return BOT;
        RCP_domain r = BOT;
        if (as_ctx.is_single()) {
            auto d = info.descriptor;
            auto data_start = BOT.with_packet(0);
            if (d.data > -1 && as_ctx.contains(d.data))
                r |= data_start;
            else if (d.end > -1 && as_ctx.contains(d.end))
                r |= data_start + regs.at(DATA_END_REG);
            else if (d.meta > -1 && as_ctx.contains(d.meta))
                r |= data_start + regs.at(META_REG);
            else 
                r |= BOT.with_num(TOP);
        } else {
            r.havoc(); // TODO: disallow, or at least don't havoc fd
        }
        return r;
    }

    RCP_domain load_other(const RCP_domain& addr) {
        if (addr.maybe_packet()
         || addr.maybe_map())
            return BOT.with_num(TOP);
        return BOT;
    }

    RCP_domain load(const RCP_domain& addr, int width) {
        return load_stack(addr.get_stack(), width)
             | load_ctx(addr.get_ctx(), width)
             | load_other(addr);
    }

    void operator()(Mem const& a) {
        const auto& addr = regs.at(a.access.basereg) + eval(a.access.offset);
        if (a.is_load) {
            regs.assign(std::get<Reg>(a.value), load(addr, a.access.width));
        } else {
            store(addr, a.access.width, eval(a.value));
        }
    }

    void operator()(LockAdd const& a) { }

    void visit(Instruction ins) {
        std::visit(*this, ins);
    }
};

struct Analyzer {
    std::unordered_map<Label, Machine> pre;
    std::unordered_map<Label, Machine> post;

    Analyzer(const Cfg& cfg, program_info info)  {
        for (auto l : cfg.keys()) {
            pre.emplace(l, info);
            post.emplace(l, info);
        }
        pre.at(cfg.keys().front()).init();
    }

    bool recompute(Label l, const BasicBlock& bb) {        
        Machine dom = pre.at(l);
        for (const Instruction& ins : bb.insts) {
            dom.visit(ins);
        }
        bool res = post.at(l) != dom;
        post.insert_or_assign(l, dom);
        return res;
    }

    void join(const std::vector<Label>& prevs, Label into) {
        Machine new_pre = pre.at(into);
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
                }
            }
            // std::cerr << l << "\n";
            // std::cerr << dom << "\n";
            // std::cerr << ins << "\n";
            dom.visit(ins);
            // std::cerr << dom << "\n";
        }
        // for (auto n : cfg[l].nextlist)
        //     std::cerr << n << ",";
        // std::cerr << "\n";
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
        vector<Assertion> res;
        Types previous_types;
        bpf_func_proto proto = get_prototype(call.func);
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
                auto op = t == Arg::CONST_SIZE_OR_ZERO ? Condition::Op::GE : Condition::Op::GT;
                res.push_back(type_of(reg, num));
                res.push_back(Assertion{LinearConstraint{op, reg, 0, Imm{0}, Imm{0}, num}});
                check_access(res, previous_types, Reg{(uint8_t)(i-1)}, 0, reg);
                previous_types.reset();
                break;
            }
            case Arg::PTR_TO_MEM_OR_NULL:
                res.push_back(type_of(reg, mem | num));
                res.push_back(Assertion{LinearConstraint{Condition::Op::EQ, reg, 0, Imm{0}, Imm{0}, num} });
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
