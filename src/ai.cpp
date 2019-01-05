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

struct MinSizeDom {
    int64_t size = 0xFFFFFFF;

    void operator|=(const MinSizeDom& o) {
        size = std::min(size, o.size);
    }
    void operator&=(const MinSizeDom& o) {
        size = std::max(size, o.size);
    }

    void to_bot() {
        *this = MinSizeDom{};
    }

    void havoc() {
        size = 0;
    }

    void assume_larger_than(const OffsetDomSet& ub) {
        if (ub.is_bot()) return;
        int64_t m = *std::min_element(ub.elems.begin(), ub.elems.end());
        size = std::max(size, m);
    }

    bool in_bounds(const OffsetDomSet& ub) {
        if (ub.is_bot()) return true;
        int64_t m = *std::max_element(ub.elems.begin(), ub.elems.end());
        return size >= m;
    }

    bool operator==(const MinSizeDom& o) const {
        return size == o.size;
    }
};

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
    MinSizeDom data_end;

    program_info info;
    RCP_domain BOT;
    TypeSet types;

    Machine(program_info info) : regs{info.map_defs.size()}, info{info}, BOT{info.map_defs.size()}, types{info.map_defs.size()} {
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
        data_end |= o.data_end;
    }

    void operator&=(const Machine& o) {
        regs &= o.regs;
        stack_arr &= o.stack_arr;
        data_end &= o.data_end;
    }

    bool operator==(Machine o) const { return regs == o.regs && stack_arr == o.stack_arr && data_end == o.data_end; }
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
        std::visit(overloaded{
            [this](const LinearConstraint& lc) {
                assert((lc.when_types & types.num()).none()
                    || (lc.when_types & types.ptr()).none());
                const RCP_domain right = regs.at(lc.reg).zero() + (eval(lc.v) - eval(lc.width) - eval(lc.offset));
                RCP_domain::assume(regs.at(lc.reg), lc.op, right, lc.when_types);
            },
            [this](const TypeConstraint& tc) {
                auto& r = regs.at(tc.then.reg);
                auto t = tc.then.types;
                if (tc.given) {
                    RCP_domain::assume(r, t, regs.at(tc.given->reg), tc.given->types);
                } else {
                    RCP_domain::assume(r, t);
                }
            }
        }, a.p->cst);
    }

    bool satisfied(Assert const& a) { 
        return std::visit(overloaded{
            [this](const LinearConstraint& lc) {
                const RCP_domain right = regs.at(lc.reg).zero() + (eval(lc.v) - eval(lc.width) - eval(lc.offset));
                return RCP_domain::satisfied(regs.at(lc.reg), lc.op, right, lc.when_types);
            },
            [this](const TypeConstraint& tc) {
                const RCP_domain left = regs.at(tc.then.reg);
                auto t = tc.then.types;
                //if (left.is_bot()) return false;
                if (tc.given) {
                    return RCP_domain::satisfied(left, t, regs.at(tc.given->reg), tc.given->types);
                } else {
                    return RCP_domain::satisfied(left, t);
                }
            }
        }, a.p->cst);
    }

    void operator()(Exit const& a) { }

    void operator()(Jmp const& a) { }

    void operator()(Call const& call) {
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING: break;
            case ArgSingle::Kind::MAP_FD: break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY: break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE: break;
            case ArgSingle::Kind::PTR_TO_CTX: break;
            }
        }
        for (ArgPair arg : call.pairs) {
            switch (arg.kind) {
                case ArgPair::Kind::PTR_TO_MEM_OR_NULL: break;
                case ArgPair::Kind::PTR_TO_MEM: break;
                case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
                    store(regs.at(arg.mem), regs.at(arg.size).get_num(), BOT.with_num(TOP));
                    break;
                }
            }
        }
        if (call.returns_map) {
            auto fds = regs.at(Reg{1}).get_fd();
            RCP_domain res = BOT;
            for (size_t i=0; i < fds.fds.size(); i++) {
                if (fds.fds[i]) {
                    auto def = info.map_defs.at(i);
                    if (def.type == MapType::ARRAY_OF_MAPS
                        || def.type == MapType::HASH_OF_MAPS) {
                        res = res.with_fd(def.inner_map_fd);
                    } else {
                        res = res.with_map(i, 0);
                    }
                }
            }
            regs.assign(Reg{0}, res.with_num(0));
        } else {
            regs.assign(Reg{0}, BOT.with_num(TOP));
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
            auto data_start = BOT.with_packet(3);
            if (d.data > -1 && as_ctx.contains(d.data))
                r |= data_start;
            else if (d.end > -1 && as_ctx.contains(d.end))
                r |= data_start + regs.at(DATA_END_REG);
            else if (d.meta > -1 && as_ctx.contains(d.meta))
                r |= data_start + BOT.with_packet(0);
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
        // std::cerr << "\n";
        // std::cerr << into << ":\n";
        // std::cerr << new_pre << "\n";
        for (Label l : prevs) {
            new_pre |= post.at(l);
            // std::cerr << new_pre << "\n";
        }
        // std::cerr << "\n\n";
        pre.insert_or_assign(into, new_pre);
    }
};

void worklist(const Cfg& cfg, Analyzer& analyzer) {
    // Only works with DAGs
    std::list<Label> w{cfg.keys().front()};
    std::unordered_map<Label, int> count;
    for (auto l : cfg.keys()) count[l] = 0;
    while (!w.empty()) {
        Label label = w.front();
        w.pop_front();
        const BasicBlock& bb = cfg.at(label);
        analyzer.join(bb.prevlist, label);
        if (analyzer.recompute(label, bb)) {
            for (Label next_label : bb.nextlist) {
                count[next_label]++;
                if (count[next_label] >= cfg.at(next_label).prevlist.size())
                    w.push_back(next_label);
            }
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
    const Types fd = types.fd();
    const Types mem = stack | packet | maps;
    const Types ptr = mem | ctx;
    const Types nonfd = ptr | num;
    
    auto type_of(Reg r, const Types t) {
        assert(t.size() == types.all().size());
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
            if (i < info.map_defs.size()) end = Imm{info.map_defs.at(i).value_size};
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
    AssertionExtractor(program_info info) : info{info}, types{info.map_defs.size()} { }

    template <typename T>
    vector<Assertion> operator()(T ins) { return {}; }

    vector<Assertion> operator()(Exit const& e) {
        return { type_of(Reg{0}, num) };
    }

    vector<Assertion> operator()(Call const& call) {
        vector<Assertion> res;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING: 
                // avoid pointer leakage:
                if (!is_priviledged)
                    res.push_back(type_of(arg.reg, num));
                break;
            case ArgSingle::Kind::MAP_FD:
                res.push_back(type_of(arg.reg, fd));
                break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY: 
                // what other conditions?
                // looks like packet is valid
                // TODO: maybe arg.packet_access?
                res.push_back(type_of(arg.reg, stack | packet));
                break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                res.push_back(type_of(arg.reg, stack | packet)); // strangely, looks like it means stack or packet
                break;
            case ArgSingle::Kind::PTR_TO_CTX: 
                res.push_back(type_of(arg.reg, ctx));
                // TODO: the kernel has some other conditions here - 
                // maybe offset == 0
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            Types arg_types;
            switch (arg.kind) {
                case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                    res.push_back(type_of(arg.mem, mem | num));
                    res.push_back(Assertion{LinearConstraint{Condition::Op::EQ, arg.mem, 0, Imm{0}, Imm{0}, num} });
                    break;
                case ArgPair::Kind::PTR_TO_MEM: 
                    /* LINUX: pointer to valid memory (stack, packet, map value) */
                    res.push_back(type_of(arg.mem, mem));
                    break;
                case ArgPair::Kind::PTR_TO_UNINIT_MEM:
                    // memory may be uninitialized, i.e. write only
                    res.push_back(type_of(arg.mem, mem));
                    break;
            }
            // TODO: reg is constant (or maybe it's not important)
            auto op = arg.can_be_zero ? Condition::Op::GE : Condition::Op::GT;
            res.push_back(type_of(arg.size, num));
            res.push_back(Assertion{LinearConstraint{op, arg.size, 0, Imm{0}, Imm{0}, num}});
            check_access(res, mem, arg.mem, 0, arg.size);
            break;
        }
        return res;
    }

    vector<Assertion> explicate(Condition cond) { 
        if (is_priviledged) return {};
        vector<Assertion> res;
        if (std::holds_alternative<Imm>(cond.right)) {
            if (std::get<Imm>(cond.right).v != 0) {
                res.push_back(type_of(cond.left, num));
            } else {
                // OK - fd is just another pointer
                // Everything can be compared to 0
            }
        } else if (cond.op != Condition::Op::EQ
                && cond.op != Condition::Op::NE) {
            res.push_back(type_of(cond.left, nonfd));
            same_type(res, nonfd, cond.left, std::get<Reg>(cond.right));
        }
        return res;
    }

    vector<Assertion> operator()(Assume ins) { 
        return explicate(ins.cond);
    }

    vector<Assertion> operator()(Jmp ins) { 
        if (!ins.cond) return {};
        return explicate(*ins.cond);
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
