#include <assert.h>
#include <inttypes.h>

#include <algorithm>
#include <bitset>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ai.hpp"
#include "ai_dom_mem.hpp"
#include "ai_dom_rcp.hpp"
#include "ai_dom_set.hpp"
#include "asm_cfg.hpp"
#include "asm_ostream.hpp"
#include "asm_syntax.hpp"
#include "config.hpp"
#include "spec_assertions.hpp"
#include "spec_type_descriptors.hpp"

using std::optional;
using std::string;
using std::to_string;
using std::vector;

// implement here, where Assertion is complete
Assert::~Assert() = default;
Assert::Assert(const Assert& a) : p{std::make_unique<Assertion>(*a.p)}, satisfied{a.satisfied} {}
Assert::Assert(AssertionPtr&& p) : p{std::move(p)} {}
void Assert::operator=(const Assert& a) {
    *p = *a.p;
    satisfied = a.satisfied;
}
bool operator==(const Assert& a, const Assert& b) { return *a.p == *b.p && a.satisfied == b.satisfied; }

constexpr Reg DATA_END_REG = Reg{13};
// constexpr Reg META_REG = Reg{14};

struct RegsDom {
    using ValDom = RCP_domain;
    std::array<std::optional<ValDom>, 16> regs;

    RegsDom() {
        for (auto& r : regs)
            r = ValDom{};
    }

    friend std::ostream& operator<<(std::ostream& os, const RegsDom& d) {
        os << "<<";
        for (size_t i = 0; i < 10; i++) {
            os << "r" << i << ": ";
            if (d.regs.at(i))
                os << *d.regs[i];
            else
                os << "*";
            os << ", ";
        }
        os << ">>";
        return os;
    }

    void init(const ValDom& ctx, const ValDom& stack_end, const ValDom& top_num) {
        for (auto& r : regs)
            r = {};
        regs[1] = ctx;
        regs[10] = stack_end;

        // initialized to num to be consistent with other bound checks that assume num
        // (therefore region->zero is added before checking assertion)
        regs[13] = top_num;
        regs[14] = top_num;
    }

    bool is_bot() const {
        for (size_t i = 0; i < 10; i++) {
            if (regs[i] && regs[i]->is_bot())
                return true;
        }
        return false;
    }

    void operator|=(const RegsDom& o) {
        for (size_t i = 0; i < regs.size(); i++) {
            if (!regs[i] || !o.regs[i])
                regs[i] = {};
            else
                *regs[i] |= *o.regs[i];
        }
    }

    void operator&=(const RegsDom& o) {
        for (size_t i = 0; i < regs.size(); i++)
            if (!regs[i] || !o.regs[i])
                regs[i] = {};
            else
                *regs[i] &= *o.regs[i];
    }

    void scratch_regs() {
        for (int i = 1; i < 6; i++)
            regs[i] = {};
    }

    void assign(Reg r, const ValDom& v) { regs[r.v] = v; }

    ValDom& at(Reg r) {
        if (!regs[r.v])
            throw std::runtime_error{std::string("Uninitialized register r") + std::to_string(r.v)};
        return *regs[r.v];
    }

    bool operator==(const RegsDom& o) const { return regs == o.regs; }
};

struct Machine {
    RegsDom regs;
    MemDom stack_arr;

    program_info info;
    RCP_domain BOT;

    Machine(program_info info) : info{info} {}

    static inline const RCP_domain numtop = RCP_domain{}.with_num(TOP);

    void init() {
        regs.init(BOT.with_ctx(0), BOT.with_stack(STACK_SIZE), numtop);
        stack_arr.bot = false;
    }

    bool is_bot() { return regs.is_bot() || stack_arr.is_bot(); }

    friend std::ostream& operator<<(std::ostream& os, const Machine& d) { return os << d.regs << " " << d.stack_arr; }

    RCP_domain eval(uint64_t v) { return BOT.with_num(v); }

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

    void operator()(LoadMapFd const& a) { regs.assign(a.dst, BOT.with_fd(a.mapfd)); }

    void operator()(Un const& a){};
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

    void operator()(Assume const& a) { RCP_domain::assume(regs.at(a.cond.left), a.cond.op, eval(a.cond.right)); }

    void operator()(Assert const& a) {
        // treat as assume
        std::visit(overloaded{[this](const LinearConstraint& lc) {
                                  assert((lc.when_types & TypeSet::num).none() ||
                                         (lc.when_types & TypeSet::ptr).none());
                                  const RCP_domain right =
                                      regs.at(lc.reg).zero() + (eval(lc.v) - eval(lc.width) - eval(lc.offset));
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
                              }},
                   a.p->cst);
    }

    bool satisfied(Assert const& a) {
        return std::visit(overloaded{[this](const LinearConstraint& lc) {
                                         const RCP_domain right =
                                             regs.at(lc.reg).zero() + (eval(lc.v) - eval(lc.width) - eval(lc.offset));
                                         return RCP_domain::satisfied(regs.at(lc.reg), lc.op, right, lc.when_types);
                                     },
                                     [this](const TypeConstraint& tc) {
                                         const RCP_domain left = regs.at(tc.then.reg);
                                         auto t = tc.then.types;
                                         // if (left.is_bot()) return false;
                                         if (tc.given) {
                                             return RCP_domain::satisfied(left, t, regs.at(tc.given->reg),
                                                                          tc.given->types);
                                         } else {
                                             return RCP_domain::satisfied(left, t);
                                         }
                                     }},
                          a.p->cst);
    }

    void operator()(Exit const& a) {}

    void operator()(Jmp const& a) {}

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
            RCP_domain val = numtop;
            switch (arg.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                if (regs.at(arg.mem).must_be_num())
                    break;
                if (!regs.at(arg.mem).get_num().is_bot())
                    val.havoc();
                // fallthrough
            case ArgPair::Kind::PTR_TO_MEM:
                // fallthrough
            case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
                store(regs.at(arg.mem), regs.at(arg.size).get_num(), val);
                break;
            }
            }
        }
        if (call.returns_map) {
            regs.assign(Reg{0}, regs.at(Reg{1}).map_lookup_elem(info.map_defs));
        } else {
            regs.assign(Reg{0}, numtop);
        }
        regs.scratch_regs();
    }

    void operator()(Packet const& a) {
        // Different syntax for a function call
        regs.assign(Reg{0}, numtop);
        regs.scratch_regs();
    }

    void store(const RCP_domain& addr, const NumDomSet& width, const RCP_domain& value) {
        if (addr.get_types().count() > 1)
            std::cerr << "store: " << addr << "\n";
        OffsetDomSet as_stack = addr.get_stack();
        if (!as_stack.is_bot()) {
            // make weak updates extremely weak
            if (addr.with_stack({}).is_bot()) {
                if (!width.is_single()) {
                    stack_arr.store_dynamic(as_stack, width, value);
                } else {
                    stack_arr.store(as_stack, width.elems.front(), value);
                }
            } else {
                if (!width.is_single()) {
                    stack_arr.store_dynamic(TOP, width, value);
                } else {
                    stack_arr.store(TOP, width.elems.front(), value);
                }
            }
        }
    }

    RCP_domain load_stack(const OffsetDomSet& as_stack, int width) {
        RCP_domain r;
        if (!as_stack.is_bot())
            r |= stack_arr.load(as_stack, width);
        return r;
    }

    RCP_domain load_ctx(const OffsetDomSet& as_ctx, int width) {
        if (as_ctx.is_bot())
            return {};
        RCP_domain r;
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
                r |= numtop;
        } else {
            r.havoc(); // TODO: disallow, or at least don't havoc fd
        }
        return r;
    }

    RCP_domain load_other(const RCP_domain& addr) {
        if (addr.maybe_packet() || addr.maybe_map())
            return numtop;
        return {};
    }

    RCP_domain load(const RCP_domain& addr, int width) {
        if (addr.get_types().count() > 1)
            std::cerr << "load: " << addr << "\n";
        return load_stack(addr.get_stack(), width) | load_ctx(addr.get_ctx(), width) | load_other(addr);
    }

    void operator()(Mem const& a) {
        const auto& addr = regs.at(a.access.basereg) + eval(a.access.offset);
        if (a.is_load) {
            regs.assign(std::get<Reg>(a.value), load(addr, a.access.width));
        } else {
            store(addr, a.access.width, eval(a.value));
        }
    }

    void operator()(LockAdd const& a) {}

    void visit(Instruction ins) { std::visit(*this, ins); }
};

static label_t pop(std::list<label_t>& wl) {
    label_t u = wl.front();
    wl.pop_front();
    return u;
}

static auto initialized_invs(const Cfg& cfg, program_info info) -> std::unordered_map<label_t, Machine> {
    std::unordered_map<label_t, Machine> df;
    for (auto& [l, _] : cfg) {
        df.emplace(l, info);
    }
    df.at(*cfg.label_begin()).init();
    return df;
}

static Machine transfer(const BasicBlock& bb, Machine m) {
    for (const Instruction& ins : bb) {
        m.visit(ins);
    }
    return m;
}

static auto chaotic(const Cfg& cfg, program_info info) -> std::unordered_map<label_t, Machine> {
    std::list<label_t> wl{*cfg.label_begin()};
    auto df = initialized_invs(cfg, info);
    while (!wl.empty()) {
        label_t u = pop(wl);
        const BasicBlock& bb = cfg.get_node(u);
        auto [nb, ne] = bb.next_blocks();
        for (auto v : std::vector<label_t>(nb, ne)) {
            auto old_as = df.at(v);
            auto new_as = transfer(bb, df.at(u)) | old_as;
            if (new_as != old_as) {
                df.insert_or_assign(v, new_as);
                wl.push_back(v);
                wl.sort([](auto a, auto b) { return b < a; });
                wl.erase(std::unique(wl.begin(), wl.end()), wl.end());
            }
        }
    }
    return df;
}

void analyze_rcp(Cfg& cfg, program_info info) {
    auto df = chaotic(cfg, info);

    for (auto& [l, _] : cfg) {
        auto dom = df.at(l);
        for (Instruction& ins : cfg.get_node(l)) {
            // bool unsatisfied_assertion = false;
            if (std::holds_alternative<Assert>(ins)) {
                Assert& a = std::get<Assert>(ins);
                if (!a.satisfied) { // && !dom.is_bot()
                    a.satisfied = dom.satisfied(a);
                    // unsatisfied_assertion = !a.satisfied;
                }
            }
            if (global_options.print_invariants) {
                std::cerr << l << "\n";
                std::cerr << dom << "\n";
                std::cerr << ins << "\n";
            }
            dom.visit(ins);
            if (global_options.print_invariants) {
                std::cerr << dom << "\n";
            }
        }
        if (global_options.print_invariants) {
            auto [b, e] = cfg.get_node(l).next_blocks();
            for (auto n : std::vector(b, e))
                std::cerr << n << ",";
            std::cerr << "\n";
        }
    }
}

class AssertionExtractor {
    program_info info;
    std::vector<size_t> type_indices;
    bool is_priviledged = false;

    auto type_of(Reg r, const Types t) {
        assert(t.size() == TypeSet::all.size());
        return Assertion{TypeConstraint{{r, t}}};
    };

    void check_access(vector<Assertion>& assumptions, Types t, Reg reg, int offset, Value width) {
        using Op = Condition::Op;
        assumptions.push_back(Assertion{LinearConstraint{Op::GE, reg, offset, (Value)Imm{0}, Imm{0}, t}});
        for (size_t i : type_indices) {
            if (!t[i])
                continue;
            Types s = TypeSet::single(i);
            if (s == TypeSet::num)
                continue;

            Value end;
            if (i < info.map_defs.size())
                end = Imm{info.map_defs.at(i).value_size};
            else if (s == TypeSet::packet)
                end = DATA_END_REG;
            else if (s == TypeSet::stack)
                end = Imm{STACK_SIZE};
            else if (s == TypeSet::ctx)
                end = Imm{static_cast<uint64_t>(info.descriptor.size)};
            else if (s == TypeSet::num)
                assert(false);
            else if (s == TypeSet::fd)
                assert(false);
            else
                assert(false);
            assumptions.push_back(Assertion{LinearConstraint{Op::LE, reg, offset, width, end, s}});
        }
    }

  public:
    AssertionExtractor(program_info info) : info{info} {
        for (size_t i = 0; i < info.map_defs.size(); i++) {
            type_indices.push_back(i);
        }
        type_indices.push_back(ALL_TYPES + T_CTX);
        type_indices.push_back(ALL_TYPES + T_STACK);
        type_indices.push_back(ALL_TYPES + T_DATA);
        type_indices.push_back(ALL_TYPES + T_NUM);
        type_indices.push_back(ALL_TYPES + T_FD);
    }

    template <typename T>
    vector<Assertion> operator()(T ins) {
        return {};
    }

    vector<Assertion> operator()(Exit const& e) { return {type_of(Reg{0}, TypeSet::num)}; }

    vector<Assertion> operator()(Call const& call) {
        vector<Assertion> res;
        for (ArgSingle arg : call.singles) {
            switch (arg.kind) {
            case ArgSingle::Kind::ANYTHING:
                // avoid pointer leakage:
                if (!is_priviledged)
                    res.push_back(type_of(arg.reg, TypeSet::num));
                break;
            case ArgSingle::Kind::MAP_FD: res.push_back(type_of(arg.reg, TypeSet::fd)); break;
            case ArgSingle::Kind::PTR_TO_MAP_KEY:
                // what other conditions?
                // looks like packet is valid
                // TODO: maybe arg.packet_access?
                res.push_back(type_of(arg.reg, TypeSet::stack | TypeSet::packet));
                break;
            case ArgSingle::Kind::PTR_TO_MAP_VALUE:
                res.push_back(type_of(arg.reg, TypeSet::stack |
                                                   TypeSet::packet)); // strangely, looks like it means stack or packet
                break;
            case ArgSingle::Kind::PTR_TO_CTX:
                res.push_back(type_of(arg.reg, TypeSet::ctx));
                // TODO: the kernel has some other conditions here -
                // maybe offset == 0
                break;
            }
        }
        for (ArgPair arg : call.pairs) {
            switch (arg.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                res.push_back(type_of(arg.mem, TypeSet::mem | TypeSet::num));
                res.push_back(Assertion{LinearConstraint{Condition::Op::EQ, arg.mem, 0, Imm{0}, Imm{0}, TypeSet::num}});
                break;
            case ArgPair::Kind::PTR_TO_MEM:
                /* LINUX: pointer to valid memory (stack, packet, map value) */
                res.push_back(type_of(arg.mem, TypeSet::mem));
                break;
            case ArgPair::Kind::PTR_TO_UNINIT_MEM:
                // memory may be uninitialized, i.e. write only
                res.push_back(type_of(arg.mem, TypeSet::mem));
                break;
            }
            // TODO: reg is constant (or maybe it's not important)
            auto op = arg.can_be_zero ? Condition::Op::GE : Condition::Op::GT;
            res.push_back(type_of(arg.size, TypeSet::num));
            res.push_back(Assertion{LinearConstraint{op, arg.size, 0, Imm{0}, Imm{0}, TypeSet::num}});
            check_access(res, TypeSet::mem, arg.mem, 0, arg.size);
            break;
        }
        return res;
    }

    vector<Assertion> explicate(Condition cond) {
        if (is_priviledged)
            return {};
        vector<Assertion> res;
        if (std::holds_alternative<Imm>(cond.right)) {
            if (std::get<Imm>(cond.right).v != 0) {
                res.push_back(type_of(cond.left, TypeSet::num));
            } else {
                // OK - fd is just another pointer
                // Everything can be compared to 0
            }
        } else {
            if (cond.op != Condition::Op::EQ && cond.op != Condition::Op::NE) {
                res.push_back(type_of(cond.left, TypeSet::nonfd));
            }
            same_type(res, TypeSet::all, cond.left, std::get<Reg>(cond.right));
        }
        return res;
    }

    vector<Assertion> operator()(Assume ins) { return explicate(ins.cond); }

    vector<Assertion> operator()(Jmp ins) {
        if (!ins.cond)
            return {};
        return explicate(*ins.cond);
    }

    vector<Assertion> operator()(Mem ins) {
        vector<Assertion> res;
        Reg reg = ins.access.basereg;
        Imm width{static_cast<uint32_t>(ins.access.width)};
        int offset = ins.access.offset;
        if (reg.v == 10) {
            check_access(res, TypeSet::stack, reg, offset, width);
        } else {
            res.emplace_back(type_of(reg, TypeSet::ptr));
            check_access(res, TypeSet::ptr, reg, offset, width);
            if (!is_priviledged && !ins.is_load && std::holds_alternative<Reg>(ins.value)) {
                for (auto t : {TypeSet::maps, TypeSet::ctx, TypeSet::packet}) {
                    res.push_back(Assertion{TypeConstraint{{std::get<Reg>(ins.value), TypeSet::num}, {reg, t}}});
                }
            }
        }
        return res;
    };

    vector<Assertion> operator()(LockAdd ins) {
        vector<Assertion> res;
        res.push_back(type_of(ins.access.basereg, TypeSet::maps));
        check_access(res, TypeSet::maps, ins.access.basereg, ins.access.offset,
                     Imm{static_cast<uint32_t>(ins.access.width)});
        return res;
    };

    void same_type(vector<Assertion>& res, Types ts, Reg r1, Reg r2) {
        for (size_t i : type_indices) {
            if (ts[i]) {
                Types t = TypeSet::single(i);
                res.push_back(Assertion{TypeConstraint{{r1, t}, {r2, t}}});
            }
        }
    }

    vector<Assertion> operator()(Bin ins) {
        switch (ins.op) {
        case Bin::Op::MOV: return {};
        case Bin::Op::ADD:
            if (std::holds_alternative<Reg>(ins.v)) {
                Reg reg = std::get<Reg>(ins.v);
                return {Assertion{TypeConstraint{{reg, TypeSet::num}, {ins.dst, TypeSet::ptr}}},
                        Assertion{TypeConstraint{{ins.dst, TypeSet::num}, {reg, TypeSet::ptr}}}};
            }
            return {};
        case Bin::Op::SUB:
            if (std::holds_alternative<Reg>(ins.v)) {
                vector<Assertion> res;
                // disallow map-map since same type does not mean same offset
                // Todo: map identities
                auto ptr_or_num = TypeSet::nonfd & ~TypeSet::maps;
                res.push_back(type_of(ins.dst, ptr_or_num));
                same_type(res, ptr_or_num, std::get<Reg>(ins.v), ins.dst);
                return res;
            }
            return {};
        default: return {type_of(ins.dst, TypeSet::num)};
        }
    }
};

void explicate_assertions(Cfg& cfg, program_info info) {
    for (auto& [this_label, bb] : cfg) {
        vector<Instruction> old_insts(bb.begin(), bb.end());
        vector<Instruction> insts;

        for (auto ins : old_insts) {
            for (auto a : std::visit(AssertionExtractor{info}, ins))
                bb.insert(std::make_unique<Assertion>(a));
            bb.insert(ins);
        }
    }
}
