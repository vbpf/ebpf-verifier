/**
 * Main backend. Translating eBPF CFG to CFG of constraints in Crab.
 **/
#include <algorithm>
#include <iostream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <assert.h>
#include <inttypes.h>

#include "config.hpp"
#include "spec_prototypes.hpp"
#include "spec_type_descriptors.hpp"

#include "crab/dsl_syntax.hpp"

#include "crab_common.hpp"
#include "crab_constraints.hpp"
#include "crab_verifier.hpp"

#include "asm_cfg.hpp"
#include "asm_syntax.hpp"

#include "assertions.hpp"

using namespace crab::dsl_syntax;

using std::optional;
using std::string;
using std::to_string;
using std::tuple;
using std::vector;

using crab::linear_constraint_t;
using crab::linear_expression_t;
using crab::data_kind_t;
using crab::debug_info;
using crab::variable_t;

static linear_constraint_t eq(const variable_t& a, const variable_t& b) { return {a - b, linear_constraint_t::EQUALITY}; }

static linear_constraint_t neq(const variable_t& a, const variable_t& b) { return {a - b, linear_constraint_t::DISEQUATION}; };


constexpr int MAX_PACKET_OFF = 0xffff;
constexpr int64_t MY_INT_MAX = INT_MAX;
constexpr int64_t PTR_MAX = MY_INT_MAX - MAX_PACKET_OFF;

static basic_block_t& add_common_child(cfg_t& cfg, basic_block_t& block, std::vector<label_t> labels,
                                       std::string suffix) {
    basic_block_t& child = cfg.insert(block.label() + ":" + suffix);
    for (auto label : labels)
        cfg.get_node(label) >> child;
    return child;
}

static basic_block_t& add_child(cfg_t& cfg, basic_block_t& block, std::string suffix) {
    return add_common_child(cfg, block, {block.label()}, suffix);
}

basic_block_t& join(cfg_t& cfg, basic_block_t& left, basic_block_t& right) {
    basic_block_t& bb = cfg.insert(left.label() + "+" + right.label());
    left >> bb;
    right >> bb;
    return bb;
}

/** Encoding of memory regions and types.
 *
 * The exact numbers are of importance, since convex domains (intervals, zone,
 * polyhedra...) will only track intervals of these values. We should have a way
 * of saying `is_pointer`, `is_shared` etc. See below.
 */

struct dom_t {
    variable_t value;
    variable_t offset;
    variable_t region;
    dom_t(int i)
        : value{variable_t::reg(data_kind_t::values, i)},
          offset{variable_t::reg(data_kind_t::offsets, i)},
          region{variable_t::reg(data_kind_t::regions, i)} {}
    dom_t(variable_t value, variable_t offset, variable_t region) : value(value), offset(offset), region(region){};
};

static linear_constraint_t is_pointer(dom_t v) { return v.region >= T_CTX; }
static linear_constraint_t is_init(dom_t v) { return v.region > T_UNINIT; }
static linear_constraint_t is_shared(dom_t v) { return v.region > T_SHARED; }
static linear_constraint_t is_not_num(dom_t v) { return v.region > T_NUM; }

struct machine_t final {
    ptype_descr ctx_desc;
    std::vector<dom_t> regs;

    program_info info;

    const data_kind_t values = data_kind_t::values;
    const data_kind_t offsets = data_kind_t::offsets;
    const data_kind_t regions = data_kind_t::regions;

    const variable_t meta_size{variable_t::meta_size()};
    const variable_t data_size{variable_t::data_size()};

    //basic_block_builder in(basic_block_t& bb) { return {bb, *this}; }

    std::vector<dom_t> caller_saved_registers() const {
        return {regs[1], regs[2], regs[3], regs[4], regs[5]};
    }

    dom_t reg(Value v) { return regs[std::get<Reg>(v).v]; }

    void setup_entry(basic_block_t& entry, cfg_t& cfg);

    machine_t(program_info info);

};

/** An array of triple (region, value, offset).
 *
 * Enables coordinated load/store/havoc operations.
 */

struct basic_block_builder {
    using variable_t = crab::variable_t;
    using number_t = crab::number_t;
    using linear_constraint_t = crab::linear_constraint_t;
    using linear_expression_t = crab::linear_expression_t;

    basic_block_t& bb;
    machine_t& machine;
    cfg_t& cfg;
    debug_info di;
    bool cond = true;

    basic_block_builder(basic_block_t& bb, machine_t& machine, cfg_t& cfg, debug_info di,
                        bool cond = true)
        : bb(bb), machine(machine), cfg(cfg), di(di), cond(cond) {}

    basic_block_t& operator*() { return bb; }

    template <typename T, typename... Args>
    basic_block_builder& insert(Args&&... args) {
        if (cond)
            bb.insert<T>(std::forward<Args>(args)...);
        return *this;
    }

    basic_block_builder& where(bool new_condition) {
        cond = new_condition;
        return *this;
    }

    basic_block_builder& otherwise() {
        cond = !cond;
        return *this;
    }

    basic_block_builder& done(std::string s = {}) {
        cond = true;
        return *this;
    }

    basic_block_builder& add(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::ADD, op1, op2); }
    basic_block_builder& add(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::ADD, op1, op2); }
    basic_block_builder& sub(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::SUB, op1, op2); }
    basic_block_builder& sub(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::SUB, op1, op2); }
    basic_block_builder& add_overflow(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::ADD, op1, op2, true); }
    basic_block_builder& add_overflow(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::ADD, op1, op2, true); }
    basic_block_builder& sub_overflow(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::SUB, op1, op2, true); }
    basic_block_builder& sub_overflow(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::SUB, op1, op2, true); }
    basic_block_builder& neg(variable_t lhs) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::MUL, lhs, -1, true); }
    basic_block_builder& mul(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::MUL, op1, op2, true); }
    basic_block_builder& mul(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::MUL, op1, op2, true); }
    basic_block_builder& div(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::SDIV, op1, op2, true); }
    basic_block_builder& div(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::SDIV, op1, op2, true); }
    basic_block_builder& udiv(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs,crab::arith_binop_t::UDIV, op1, op2, true); }
    basic_block_builder& udiv(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,  crab::arith_binop_t::UDIV, op1, op2, true); }
    basic_block_builder& rem(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::arith_binop_t::SREM, op1, op2, true); }
    basic_block_builder& rem(variable_t lhs, variable_t op1, number_t op2, bool mod=true) { return insert<crab::binary_op_t>(lhs,   crab::arith_binop_t::SREM, op1, op2, mod); }
    basic_block_builder& urem(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs,crab::arith_binop_t::UREM, op1, op2, true); }
    basic_block_builder& urem(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,  crab::arith_binop_t::UREM, op1, op2, true); }
    basic_block_builder& bitwise_and(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::bitwise_binop_t::AND, op1, op2); }
    basic_block_builder& bitwise_and(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::bitwise_binop_t::AND, op1, op2); }
    basic_block_builder& bitwise_or(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs,  crab::bitwise_binop_t::OR, op1, op2); }
    basic_block_builder& bitwise_or(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,    crab::bitwise_binop_t::OR, op1, op2); }
    basic_block_builder& bitwise_xor(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::bitwise_binop_t::XOR, op1, op2); }
    basic_block_builder& bitwise_xor(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,   crab::bitwise_binop_t::XOR, op1, op2); }
    basic_block_builder& shl(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs,         crab::bitwise_binop_t::SHL, op1, op2, true); }
    basic_block_builder& shl(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,           crab::bitwise_binop_t::SHL, op1, op2, true); }
    basic_block_builder& lshr(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs,        crab::bitwise_binop_t::LSHR, op1, op2); }
    basic_block_builder& lshr(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,          crab::bitwise_binop_t::LSHR, op1, op2); }
    basic_block_builder& ashr(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs,        crab::bitwise_binop_t::ASHR, op1, op2); }
    basic_block_builder& ashr(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs,          crab::bitwise_binop_t::ASHR, op1, op2); }
    basic_block_builder& assign(variable_t lhs, linear_expression_t rhs) { return insert<crab::assign_t>(lhs, rhs); }
    basic_block_builder& assume(linear_constraint_t cst) {
        if (cst.is_tautology()) return *this;
        return insert<crab::assume_t>(cst);
    }
    basic_block_builder& havoc(variable_t lhs) { return insert<crab::havoc_t>(lhs); }
    basic_block_builder& select(variable_t lhs, variable_t v, linear_expression_t e1, linear_expression_t e2) {
        linear_constraint_t cond(exp_gte(v, 1));
        return insert<crab::select_t>(lhs, cond, e1, e2);
    }
    basic_block_builder& select(variable_t lhs, linear_constraint_t cond, linear_expression_t e1, linear_expression_t e2) {
        return insert<crab::select_t>(lhs, cond, e1, e2);
    }
    basic_block_builder& assertion(linear_constraint_t cst) { di.col++; return insert<crab::assert_t>(cst, di); }
    basic_block_builder& array_store(data_kind_t arr, linear_expression_t idx, linear_expression_t v, linear_expression_t elem_size) {
        return insert<crab::array_store_t>(arr, idx, elem_size, v);
    }
    template <typename W>
    basic_block_builder& array_forget(data_kind_t arr, linear_expression_t idx, W elem_size) {
        return insert<crab::array_havoc_t>(arr, elem_size, idx);
    }
    basic_block_builder& array_store_range(linear_expression_t idx, linear_expression_t width, linear_expression_t v) {
        return insert<crab::array_store_range_t>(data_kind_t::regions, idx, width, v);
    }
    basic_block_builder& array_load(variable_t lhs, data_kind_t arr, linear_expression_t idx, linear_expression_t elem_size) {
        return insert<crab::array_load_t>(lhs, arr, elem_size, idx);
    }

    basic_block_builder& assume(std::vector<linear_constraint_t> csts) {
        if (!cond) return *this;
        for (auto cst : csts)
            if (!cst.is_tautology())
                insert<crab::assume_t>(cst);
         return *this;
    }

    basic_block_builder& assert_init(const dom_t data_reg) {
        if (!cond) return *this;
        return assertion(is_init(data_reg));
    }

    basic_block_builder& no_pointer(dom_t v) {
        if (!cond) return *this;
        return assign(v.region, T_NUM).havoc(v.offset);
    }

    basic_block_builder& scratch(std::vector<dom_t> regs) {
        if (!cond) return *this;
        for (dom_t reg : regs) {
            havoc(reg.value);
            havoc(reg.offset);
            havoc(reg.region);
        }
        return *this;
    }

    basic_block_builder& assert_no_overflow(variable_t v) {
        // p1 = data_start; p1 += huge_positive; p1 <= p2 does not imply p1 >= data_start
        if (!cond) return *this;
        assertion(v <= MAX_PACKET_OFF);
        assertion(v >= -4098);
        return *this;
    }

    basic_block_builder& assume_normal(const linear_expression_t& addr, ptype_descr desc) {
        if (!cond) return *this;
        if (desc.data >= 0) {
            assume(addr != desc.data);
            assume(addr != desc.end);
            if (desc.meta >= 0) {
                assume(addr != desc.meta);
            }
        }
        return *this;
    }

    template <typename T, typename W>
    basic_block_builder& load(dom_t data_reg, const T& offset, W width) {
        if (!cond) return *this;
        array_load(data_reg.value,  machine.values, offset, width);
        array_load(data_reg.region, machine.regions, offset, 1);
        array_load(data_reg.offset, machine.offsets, offset, width);
        assume(is_init(data_reg));
        return *this;
    }

    basic_block_builder& havoc_num_region(linear_expression_t offset, variable_t width) {
        if (!cond) return *this;
        array_store_range(offset, width, T_NUM);
        array_forget(machine.values, offset, width);
        array_forget(machine.offsets, offset, width);
        return *this;
    }

    basic_block_builder in(basic_block_t& child) { return {child, machine, cfg, di, cond}; }
    basic_block_builder fork(std::string label, linear_constraint_t constraint) {
        return in(add_child(cfg, bb, label)).assume(constraint);
    }
    basic_block_builder fork(std::string label, linear_constraint_t cst1, linear_constraint_t cst2) {
        return in(add_child(cfg, bb, label)).assume(cst1).assume(cst2);
    }

    basic_block_t& join(basic_block_t& left, basic_block_t& right) {
        basic_block_t& bb = cfg.insert(left.label() + "+" + right.label());
        left >> bb;
        right >> bb;
        return bb;
    }

    basic_block_builder store(linear_expression_t offset, dom_t data_reg, int width) {
        if (!cond) return *this;
        assert_init(data_reg);
        array_store_range(offset, width, data_reg.region);

        if (width != 8) {
            array_forget(machine.values, offset, width);
            array_forget(machine.offsets, offset, width);
            return *this;
        }

        basic_block_builder pointer_only = in(bb).fork("non_num", is_not_num(data_reg))
                            .array_store(machine.offsets, offset, data_reg.offset, width)
                            .array_store(machine.values, offset, data_reg.value, width);

        basic_block_builder num_only = in(bb).fork("num_only", data_reg.region == T_NUM)
                        .array_store(machine.values, offset, data_reg.value, width)
                        // kill the cell
                        .array_store(machine.offsets, offset, data_reg.offset, width)
                        // so that relational domains won't think it's worth keeping track of
                        .havoc(data_reg.offset);
        return in(join(*num_only, *pointer_only));
    }

    basic_block_builder store(linear_expression_t offset, int imm, int width) {
        if (!cond) return *this;
        array_store_range(offset, width, T_NUM);
        array_forget(machine.offsets, offset, width);

        if (width != 8) {
            array_forget(machine.values, offset, width);
        } else {
            array_store(machine.values, offset, imm, width);
        }
        return *this;
    }

    basic_block_builder& access_num_only(dom_t data_reg, bool is_load) {
        if (!cond) return *this;
        return where(is_load)
                    .havoc(data_reg.offset)
                    .havoc(data_reg.value)
                    .assign(data_reg.region, T_NUM)
                .done("exec_data_access");
    }
};

class instruction_builder_t final {
  public:
    basic_block_t& exec(Instruction ins);
    instruction_builder_t(machine_t& machine, basic_block_t& block, cfg_t& cfg)
        : machine(machine), block(block), cfg(cfg), di{block.label(), first_num(block.label()), 0} {}

    basic_block_t& operator()(LockAdd const& b);
    basic_block_t& operator()(Undefined const& a);
    basic_block_t& operator()(LoadMapFd const& ld);
    basic_block_t& operator()(Bin const& b);
    basic_block_t& operator()(Un const& b);
    basic_block_t& operator()(Call const& b);
    basic_block_t& operator()(Exit const& b);
    basic_block_t& operator()(Packet const& b);
    basic_block_t& operator()(Mem const& b);
    basic_block_t& operator()(Assume const& b);

    /** Never happens - Jmps are translated to Assume */
    basic_block_t& operator()(Jmp const& b) { assert(false); }

    basic_block_t& operator()(Assert const& stmt) {
        return std::visit(overloaded{
            [this](const Comparable& s) -> basic_block_t& {
                auto r1 = machine.reg(s.r1);
                auto r2 = machine.reg(s.r2);
                in(block).assertion(eq(r1.region, r2.region));
                return block;
            },
            [this](const Addable& s) -> basic_block_t& {
                auto num = machine.reg(s.num).region;
                auto ptr = machine.reg(s.ptr).region;
                return join(block, *in(block).fork(std::to_string(s.ptr.v) + " is ptr", ptr > T_NUM)
                                             .assertion(num == T_NUM));
            },
            [this](const ValidSize& s) -> basic_block_t& {
                variable_t r = machine.reg(s.reg).value;
                if (s.can_be_zero) in(block).assertion(r >= 0);
                else in(block).assertion(r > 0);
                return block;
            },
            [this](const ValidAccess& s) -> basic_block_t& {
                auto reg = machine.reg(s.reg);
                auto addr = reg.offset + s.offset;
                basic_block_builder ptr = in(block).fork("ptr", reg.region > T_NUM)
                                                   .assertion(addr >= 0);
                // This is not the check for non-num, non-map_fd etc.
                // TODO: maybe it should be? without join:
                // b.fork("num", reg.region == T_NUM).assertion(neq(reg.region, reg.region));
                // b.fork("map_fd", reg.region == T_MAP).assertion(neq(reg.region, reg.region));
                auto& ptrs = join(*ptr.fork("stack", reg.region == T_STACK).assertion(addr <= STACK_SIZE),
                             join(*ptr.fork("shared",       is_shared(reg)).assertion(addr <= reg.region),
                             join(*ptr.fork("context", reg.region == T_CTX).assertion(addr <= machine.ctx_desc.size),
                                  *ptr.fork("data", reg.region == T_PACKET).assertion(addr <= machine.data_size))));
                if (!s.or_null) return ptrs;
                return join(ptrs, *in(block).fork("is null", reg.region == T_NUM)
                                            .assertion(reg.value == 0));
            },
            [this](const ValidStore& s) -> basic_block_t& {
                return join(block, *in(block).fork("non-stack", machine.reg(s.mem).region != T_STACK)
                                             .assertion(machine.reg(s.val).region == T_NUM));
            },
            [this](const TypeConstraint& s) -> basic_block_t& {
                basic_block_builder b = in(block);
                variable_t t = machine.reg(s.reg).region;
                switch (s.types) {
                    case TypeGroup::num: b.assertion(t == T_NUM); break;
                    case TypeGroup::map_fd: b.assertion(t == T_MAP); break;
                    case TypeGroup::ctx: b.assertion(t == T_CTX); break;
                    case TypeGroup::packet: b.assertion(t == T_PACKET); break;
                    case TypeGroup::stack: b.assertion(t == T_STACK); break;
                    case TypeGroup::shared: b.assertion(t > T_SHARED); break;
                    case TypeGroup::non_map_fd: b.assertion(t >= T_NUM); break;
                    case TypeGroup::mem: b.assertion(t >= T_STACK); break;
                    case TypeGroup::mem_or_num: b.assertion(t >= T_NUM).assertion(t != T_CTX); break;
                    case TypeGroup::ptr: b.assertion(t >= T_CTX); break;
                    case TypeGroup::ptr_or_num: b.assertion(t >= T_NUM); break;
                    case TypeGroup::stack_or_packet: b.assertion(t >= T_STACK).assertion(t <= T_PACKET); break;
                }
                return block;
            },
        }, stmt.p->cst);
    };

    basic_block_t& exec_ctx_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg,
                                                        int offset, int width) {
        linear_expression_t addr = mem_reg.offset + offset;
        auto mid = in(block).fork("assume_ctx", mem_reg.region == T_CTX);

        ptype_descr desc = machine.ctx_desc;
        if (!is_load) {
            return *mid.assume_normal(addr, desc);
        } else {
            basic_block_t& normal = *mid.fork("context-not-special", eq(data_reg.region, data_reg.region)).assume_normal(addr, desc) //FIX
                        .assign(data_reg.region, T_NUM)
                        .havoc(data_reg.offset)
                        .havoc(data_reg.value);
            if (desc.data < 0)
                return normal;
            auto load_datap = [&](string suffix, int start, auto offset) -> basic_block_t& {
                return *mid.fork(suffix, addr == start)
                    .assign(data_reg.region, T_PACKET)
                    .havoc(data_reg.value)
                    .assume(4098 <= data_reg.value)
                    .assume(data_reg.value <= PTR_MAX)
                    .assign(data_reg.offset, offset);
            };
            basic_block_t& start_end = join(load_datap("context-data_start", desc.data, 0),
                                load_datap("context-data_end",   desc.end, machine.data_size));
            if (desc.meta < 0)
                return join(start_end, normal);
            basic_block_t& meta = load_datap("context-meta", desc.meta, machine.meta_size);
            return join(join(start_end, meta), normal);
        }
    }


  private:
    machine_t& machine;
    basic_block_t& block;
    cfg_t& cfg;

    // derived fields
    debug_info di;

    basic_block_builder in(basic_block_t& bb) { return {bb, machine, cfg, di}; }

    /** Decide if the program is privileged, and allowed to leak pointers */
    bool is_privileged() { return machine.info.program_type == BpfProgType::KPROBE; }

    basic_block_t& join(basic_block_t& left, basic_block_t& right) { return ::join(cfg, left, right); }
};

/** Main loop generating the Crab cfg from eBPF Cfg.
 *
 * Each instruction is translated to a tree of Crab instructions, which are then
 * joined together.
 */
cfg_t build_crab_cfg(Cfg const& simple_cfg, program_info info) {
    cfg_t cfg(entry_label(), simple_cfg.exit());
    machine_t machine(info);
    {
        basic_block_t& entry = cfg.insert(entry_label());
        machine.setup_entry(entry, cfg);
        entry >> cfg.insert(label(0));
    }
    for (auto const& [this_label, bb] : simple_cfg) {
        basic_block_t* exit = &cfg.insert(this_label);
        int iteration = 0;
        string label = this_label;
        for (auto ins : bb) {
            basic_block_t& this_block = cfg.insert(label);
            if (iteration > 0) {
                (*exit) >> this_block;
            }
            exit = &cfg.insert(exit_label(label));
            instruction_builder_t visitor(machine, this_block, cfg);
            basic_block_t& child = std::visit([&](auto const& a) -> basic_block_t& { return visitor(a); }, ins);
            child >> *exit;
            iteration++;

            label = this_label + ":" + to_string(iteration);
        }
        auto [b, e] = bb.next_blocks();
        if (b != e) {
            for (label_t label : std::vector<label_t>(b, e))
                *exit >> cfg.insert(label);
        }
    }
    if (global_options.simplify) {
        cfg.simplify();
    }
    return cfg;
}

machine_t::machine_t(program_info info)
    : ctx_desc{get_descriptor(info.program_type)}, info{info}
 {
    for (int i = 0; i <= 10; i++) {
        regs.emplace_back(i);
    }
}

/** Generate initial state:
 *
 * 1. r10 points to the stack
 * 2. r1 points to the context
 * 3. data_start points to the packet
 * 4. data_end points to the and unknown but bounded location above data_start
 * 5. meta_start points to just-before data_start
 * 6. Other registers are scratched
 */
void machine_t::setup_entry(basic_block_t& entry, cfg_t& cfg) {
    machine_t& machine = *this;
    crab::debug_info di{"entry block"};
    basic_block_builder(entry, machine, cfg, di)
             .assume(STACK_SIZE <= machine.regs[10].value)
             .assign(machine.regs[10].offset, STACK_SIZE)
             .assign(machine.regs[10].region, T_STACK)
             .assume(1 <= machine.regs[1].value)
             .assume(machine.regs[1].value <= PTR_MAX)
             .assign(machine.regs[1].offset, 0)
             .assign(machine.regs[1].region, T_CTX)
             .assume(0 <= machine.data_size)
             .assume(machine.data_size <= 1 << 30)
             .where(machine.ctx_desc.meta >= 0).assume(machine.meta_size >= 0)  // was <= 0 ????
                                   .otherwise().assign(machine.meta_size, 0)
             .done();
}

/** Linear constraint for a pointer comparison.
 */
static linear_constraint_t jmp_to_cst_offsets_reg(Condition::Op op, variable_t& dst_offset, variable_t& src_offset) {
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return eq(dst_offset, src_offset);
    case Op::NE: return neq(dst_offset, src_offset);
    case Op::GE: return dst_offset >= src_offset;
    case Op::SGE: return dst_offset >= src_offset; // pointer comparison is unsigned
    case Op::LE: return dst_offset <= src_offset;
    case Op::SLE: return dst_offset <= src_offset; // pointer comparison is unsigned
    case Op::GT: return dst_offset >= src_offset + 1;
    case Op::SGT: return dst_offset >= src_offset + 1; // pointer comparison is unsigned
    case Op::SLT: return src_offset >= dst_offset + 1;
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return src_offset >= dst_offset + 1; // FIX unsigned
    default: return dst_offset - dst_offset == 0;
    }
}

/** Linear constraints for a comparison with a constant.
 */
static vector<linear_constraint_t> jmp_to_cst_imm(Condition::Op op, variable_t& dst_value, int imm) {
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {dst_value == imm};
    case Op::NE: return {dst_value != imm};
    case Op::GE: return {dst_value >= (unsigned)imm}; // FIX unsigned
    case Op::SGE: return {dst_value >= imm};
    case Op::LE: return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= imm};
    case Op::GT: return {dst_value >= (unsigned)imm + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= imm + 1};
    case Op::LT: return {dst_value <= (unsigned)imm - 1}; // FIX unsigned
    case Op::SLT: return {dst_value <= imm - 1};
    case Op::SET: throw std::exception();
    case Op::NSET: assert(false);
    }
    assert(false);
}

/** Linear constraint for a numerical comparison between registers.
 */
static vector<linear_constraint_t> jmp_to_cst_reg(Condition::Op op, variable_t& dst_value, variable_t& src_value) {
    using Op = Condition::Op;
    switch (op) {
    case Op::EQ: return {eq(dst_value, src_value)};
    case Op::NE: return {neq(dst_value, src_value)};
    case Op::GE: return {dst_value >= src_value}; // FIX unsigned
    case Op::SGE: return {dst_value >= src_value};
    case Op::LE: return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
    case Op::SLE: return {dst_value <= src_value};
    case Op::GT: return {dst_value >= src_value + 1}; // FIX unsigned
    case Op::SGT: return {dst_value >= src_value + 1};
    // Note: reverse the test as a workaround strange lookup:
    case Op::LT: return {src_value >= dst_value + 1}; // FIX unsigned
    case Op::SLT: return {src_value >= dst_value + 1};
    case Op::SET: throw std::exception();
    case Op::NSET: assert(false);
    }
    assert(false);
}

static bool is_unsigned_cmp(Condition::Op op) {
    using Op = Condition::Op;
    switch (op) {
    case Op::GE:
    case Op::LE:
    case Op::GT:
    case Op::LT: return true;
    default: return false;
    }
    assert(false);
}

// static bool is_signed_cmp(Condition::Op op)
// {
//     using Op = Condition::Op;
//     switch (op) {
//         case Op::SGE :
//         case Op::SLE :
//         case Op::SGT :
//         case Op::SLT :
//             return true;
//         default:
//             return false;
//     }
//     assert(false);
// }

/** Should never occur */
basic_block_t& instruction_builder_t::operator()(Undefined const& a) { assert(false); }

/** Translate operation of the form `r2 = map_fd 0x5436`.
 *
 * This instruction is one of the two possible sources of map descriptors.
 * (The other one, `call 1` on a map-in-map, is not supported yet)
 */
basic_block_t& instruction_builder_t::operator()(LoadMapFd const& ld) {
    auto reg = machine.reg(ld.dst);
    return *in(block)
           .assign(reg.region, T_MAP)
           .assign(reg.value, ld.mapfd)
           .havoc(reg.offset);
}

/** load-increment-store, from shared regions only. */
basic_block_t& instruction_builder_t::operator()(LockAdd const& b) {
    return block;
}

/** Translate eBPF binary instructions to Crab.
 *
 * Binary instructions may be either of one of the two form:
 *
 * 1. dst op= src
 * 2. dst op= K
 *
 * `src` must be initialized, and, Except in plain assignment, `dst
 */
basic_block_t& instruction_builder_t::operator()(Bin const& bin) {
    dom_t dst = machine.reg(bin.dst);
    auto b = in(block)
             .where(bin.op != Bin::Op::MOV).assert_init(dst)
             .done();
    if (std::holds_alternative<Reg>(bin.v)) b.assert_init(machine.reg(bin.v));

    if (std::holds_alternative<Imm>(bin.v)) {
        // dst += K
        int imm = static_cast<int>(std::get<Imm>(bin.v).v);
        switch (bin.op) {
        case Bin::Op::MOV:
            in(block).assign(dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::ADD:
            if (imm == 0)
                return block;
            in(block).add_overflow(dst.value, dst.value, imm)
                     .add(dst.offset, dst.offset, imm);
            break;
        case Bin::Op::SUB:
            if (imm == 0)
                return block;
            in(block).sub_overflow(dst.value, dst.value, imm)
                     .sub(dst.offset, dst.offset, imm);
            break;
        case Bin::Op::MUL:
            in(block).mul(dst.value, dst.value, imm)
                     .no_pointer(dst);
        case Bin::Op::DIV:
            in(block).div(dst.value, dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::MOD:
            in(block).rem(dst.value, dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::OR:
            in(block).bitwise_or(dst.value, dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            in(block).bitwise_and(dst.value, dst.value, imm)
                     .where((int32_t)imm > 0).assume(dst.value <= imm)
                                             .assume(0 <= dst.value)
                     .done()
                     .no_pointer(dst);
            break;
        case Bin::Op::RSH:
            in(block).ashr(dst.value, dst.value, imm)
                     .assume(dst.value <= (1 << (64 - imm)))
                     .assume(dst.value >= 0)
                     .no_pointer(dst);
            break;
        case Bin::Op::LSH:
            in(block).lshr(dst.value, dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::XOR:
            in(block).bitwise_xor(dst.value, dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::ARSH:
            in(block).ashr(dst.value, dst.value, imm) // = (int64_t)dst >> imm;
                     .assume(dst.value <= (1 << (64 - imm)))
                     .assume(dst.value >= -(1 << (64 - imm)))
                     .no_pointer(dst);
            break;
        }
    } else {
        // dst op= src
        dom_t src = machine.reg(bin.v);
        switch (bin.op) {
        case Bin::Op::ADD: {
            auto ptr_dst = in(block).fork("ptr_dst", is_pointer(dst))
                           .add_overflow(dst.value, dst.value, src.value)
                           .add(dst.offset, dst.offset, src.value);

            auto ptr_src = in(block).fork("ptr_src", is_pointer(src))
                           .add(dst.offset, dst.value, src.offset)
                           .assert_no_overflow(dst.offset)
                           .assign(dst.region, src.region)
                           .havoc(dst.value)
                           .assume(4098 <= dst.value);

            auto both_num = in(block).fork("both_num", dst.region == T_NUM, src.region == T_NUM)
                            .add_overflow(dst.value, dst.value, src.value);
            return join(*both_num, join(*ptr_src, *ptr_dst));
        }
        case Bin::Op::SUB: {
            auto same = in(block).fork("ptr_src", is_pointer(src))
                        .sub(dst.value, dst.offset, src.offset)
                        .assign(dst.region, T_NUM)
                        .havoc(dst.offset);

            auto num_src = in(block).fork("num_src", src.region == T_NUM);
            {
                auto ptr_dst = num_src.fork("ptr_dst", is_pointer(dst))
                               .sub(dst.offset, dst.offset, src.value)
                               .assert_no_overflow(dst.offset);

                auto both_num = num_src.fork("both_num", dst.region == T_NUM)
                                .sub_overflow(dst.value, dst.value, src.value);

                return join(join(*both_num, *same), *ptr_dst);
            }
        }
        case Bin::Op::MUL:
            in(block).mul(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::DIV:
            // For some reason, DIV is not checked for zerodiv
            in(block).div(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::MOD:
            // See DIV comment
            in(block).rem(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::OR:
            in(block).bitwise_or(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::AND:
            in(block).bitwise_and(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::LSH:
            in(block).lshr(dst.value, dst.value, src.value)
                     .no_pointer(dst);
        case Bin::Op::RSH:
            in(block).ashr(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::XOR:
            in(block).bitwise_xor(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            break;
        case Bin::Op::MOV:
            in(block).assign(dst.value, src.value)
                     .assign(dst.offset, src.offset)
                     .assign(dst.region, src.region);
            break;
        case Bin::Op::ARSH:
            in(block).ashr(dst.value, dst.value, src.value) // = (int64_t)dst >> src;
                     .no_pointer(dst);
            break;
        }
    }
    in(block).where(!bin.is64).bitwise_and(dst.value, dst.value, UINT32_MAX)
             .done();

    return block;
}

/** Translate unary operations: either a negation, or an endianness swapping.
 */
basic_block_t& instruction_builder_t::operator()(Un const& b) {
    dom_t dst = machine.reg(b.dst);
    in(block).assert_init(dst);
    switch (b.op) {
    case Un::Op::LE16:
    case Un::Op::LE32:
    case Un::Op::LE64:
        in(block).havoc(dst.value)
                 .no_pointer(dst);
        break;
    case Un::Op::NEG:
        in(block).neg(dst.value);
    }
    return block;
}

/** Generate assertions and commands that overapproximate eBPF function call.
 *
 * Function calls has two different kinds of arguments: single and (mem, size) pair.
 * Except `call 1`, functions always return a number to register r0.
 * Registers r1-r5 are scratched.
 */
basic_block_t& instruction_builder_t::operator()(Call const& call) {
    variable_t map_value_size{variable_t::map_value_size()};
    variable_t map_key_size{variable_t::map_key_size()};
    for (ArgSingle param : call.singles) {
        dom_t arg = machine.regs[param.reg.v];
        switch (param.kind) {
        case ArgSingle::Kind::ANYTHING:
            // avoid pointer leakage:
            break;
        case ArgSingle::Kind::MAP_FD:
            in(block).lshr(map_value_size, arg.value, 14)
                     .rem(map_key_size, arg.value, 1 << 14, false)
                     .lshr(map_key_size, map_key_size, 6);
            break;
        case ArgSingle::Kind::PTR_TO_MAP_KEY:
            // TODO: move to assertions.cpp
            in(block).assertion(arg.offset <= STACK_SIZE - map_key_size);
            break;
        case ArgSingle::Kind::PTR_TO_MAP_VALUE:
            // TODO: move to assertions.cpp
            in(block).assertion(arg.offset <= STACK_SIZE - map_value_size);
            break;
        case ArgSingle::Kind::PTR_TO_CTX:
            break;
        }
    }
    basic_block_t* current = &block;
    for (ArgPair param : call.pairs) {
        dom_t arg = machine.regs[param.mem.v];
        dom_t sizereg = machine.regs[param.size.v];
        switch (param.kind) {
        case ArgPair::Kind::PTR_TO_MEM_OR_NULL: break;
        case ArgPair::Kind::PTR_TO_MEM: break;
        case ArgPair::Kind::PTR_TO_UNINIT_MEM:
            // assume it's always the stack. The following fails to work for some reason
            // current = &join(*current, *in(*current).fork("assume_stack_uninit", arg.region == T_STACK)
            //                                       .havoc_num_region(arg.offset, sizereg.value));
            in(*current).havoc_num_region(arg.offset, sizereg.value);
            break;
        }
    }
    dom_t r0 = machine.regs[0];
    in(*current).scratch(machine.caller_saved_registers());
    if (call.returns_map) {
        // no support for map-in-map yet:
        //   if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
        //    || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
        in(*current).assign(r0.region, map_value_size)
                    .havoc(r0.value)
                    // This is the only way to get a null pointer - note the `<=`:
                    .assume(0 <= r0.value)
                    .assume(r0.value <= PTR_MAX)
                    .assign(r0.offset, 0);
    } else {
        in(*current).havoc(r0.value)
                    .assign(r0.region, T_NUM)
                    .havoc(r0.offset);
        // in(*current).assume(r0.value < 0); for VOID, which is actually "no return if succeed".
    }
    return *current;
}

/** Translate `Exit` to an assertion that r0 holds a number.
 */
basic_block_t& instruction_builder_t::operator()(Exit const& b) {
    return block;
}

/** Generate Crab assertions and assumptions for a single eBPF `assume` command (extracted from a Jmp).
 */
basic_block_t& instruction_builder_t::operator()(Assume const& b) {
    Condition cond = b.cond;

    dom_t dst = machine.reg(cond.left);
    if (std::holds_alternative<Reg>(cond.right)) {
        dom_t src = machine.reg(cond.right);
        basic_block_t& same = *in(block).fork("same_type", eq(dst.region, src.region));
        basic_block_t& numbers = *in(same).fork("numbers", dst.region == T_NUM)
                                 .where(!is_unsigned_cmp(cond.op)).assume(jmp_to_cst_reg(cond.op, dst.value, src.value))
                                 .done();
        basic_block_t& pointers = *in(same).fork("pointers", is_pointer(dst))
                                  .assume(jmp_to_cst_offsets_reg(cond.op, dst.offset, src.offset));

        basic_block_t& different = *in(block).fork("different_type",neq(dst.region, src.region));

        basic_block_t& null_src = *in(different).fork("null_src", is_pointer(dst));
        basic_block_t& null_dst = *in(different).fork("null_dst", is_pointer(src));

        return join(join(numbers, pointers), join(null_src, null_dst));
    } else {
        int imm = static_cast<int>(std::get<Imm>(cond.right).v);
        return *in(block)
               .assume(jmp_to_cst_imm(cond.op, dst.value, imm));
    }
}

/** A special instruction for _checked_ read from packets.
 *
 * No bound checking happens at verification time.
 * r6 must hold a pointer to the context.
 * r0 holds some the value read from the packet.
 *
 * Since this instruction is actually a function call, callee-saved registers are scratched.
 */
basic_block_t& instruction_builder_t::operator()(Packet const& b) {
    /* From the linux verifier code:
     * verify safety of LD_ABS|LD_IND instructions:
     * - they can only appear in the programs where ctx == skb
     * - since they are wrappers of function calls, they scratch R1-R5 registers,
     *   preserve R6-R9, and store return value into R0
     *
     * Implicit input:
     *   ctx == skb == R6 == CTX
     *
     * Explicit input:
     *   SRC == any register
     *   IMM == 32-bit immediate
     *
     * Output:
     *   R0 - 8/16/32-bit skb data converted to cpu endianness
     */
    return *in(block)
           .assign(machine.regs[0].region, T_NUM)
           .havoc(machine.regs[0].offset)
           .havoc(machine.regs[0].value)
           .scratch(machine.caller_saved_registers());
}

/** Generate constraints and instructions for memory accesses.
 */
basic_block_t& instruction_builder_t::operator()(Mem const& b) {
    int width = (int)b.access.width;
    int offset = (int)b.access.offset;
    if (b.access.basereg.v == 10) {
        int start = STACK_SIZE + offset;
        if (std::holds_alternative<Reg>(b.value)) {
            dom_t data_reg = machine.reg(std::get<Reg>(b.value));
            return *in(block)
                   .where(b.is_load).load(data_reg, start, width)
                   .otherwise().store(start, data_reg, width)
                   .done();
        } else {
            return *in(block)
                   .array_forget(machine.offsets, start, width)
                   .array_store_range(start, width, T_NUM)
                   .array_store(machine.values, start, std::get<Imm>(b.value).v, width);
        }
    }

    dom_t mem_reg = machine.reg(b.access.basereg);

    if (std::holds_alternative<Imm>(b.value)) {
        // mem[offset] = immediate
        // FIX: STW stores long long immediate
        linear_expression_t addr = offset + mem_reg.offset; // negate access
        return join(block,
                    *in(block).fork("assume_stack", mem_reg.region == T_STACK)
                              .store(addr, std::get<Imm>(b.value).v, width)
                              .done());
    }
    auto data_reg = machine.reg(std::get<Reg>(b.value));
    linear_expression_t addr = offset + mem_reg.offset;
    basic_block_t& tmp =  join(
                          join(*in(block).fork("assume_stack", mem_reg.region == T_STACK)
                                         .where(b.is_load).load(data_reg, addr, width) // FIX: requires loop
                                              .otherwise().store(addr, data_reg, width)
                                         .done(),
                               *in(block).fork("assume_shared", is_shared(mem_reg))
                                          .access_num_only(data_reg, b.is_load)),
                               exec_ctx_access(   block, b.is_load, mem_reg, data_reg, offset, width));
    if (machine.ctx_desc.data >= 0) {
        return join(tmp, *in(block).fork("assume_data", mem_reg.region == T_PACKET)
                                   .access_num_only(data_reg, b.is_load));
    }
    return tmp;
}
