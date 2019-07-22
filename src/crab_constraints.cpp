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

using namespace crab::dsl_syntax;

using std::optional;
using std::string;
using std::to_string;
using std::tuple;
using std::vector;

using crab::linear_constraint_t;
using crab::linear_expression_t;
using crab::variable_factory;

constexpr int MAX_PACKET_OFF = 0xffff;
constexpr int64_t MY_INT_MIN = INT_MIN;
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
    auto& bb = cfg.insert(left.label() + "+" + right.label());
    left >> bb;
    right >> bb;
    return bb;
}

using crab::debug_info;

using crab::variable_t;

/** Encoding of memory regions and types.
 *
 * The exact numbers are of importance, since convex domains (intervals, zone,
 * polyhedra...) will only track intervals of these values. We should have a way
 * of saying `is_pointer`, `is_shared` etc. See below.
 */
enum region_t {
    T_UNINIT = -6,
    T_NUM = -5,
    T_MAP = -4,
    T_CTX = -3,
    T_STACK = -2,
    T_DATA = -1,
    T_SHARED = 0,
};

struct dom_t {
    variable_t value;
    variable_t offset;
    variable_t region;
    dom_t(variable_factory& vfac, int i)
        : value{vfac[std::string("r") + std::to_string(i)], crab::TYPE::INT, 64},
          offset{vfac[std::string("off") + std::to_string(i)], crab::TYPE::INT, 64},
          region{vfac[std::string("t") + std::to_string(i)], crab::TYPE::INT, 64} {}
    dom_t(variable_t value, variable_t offset, variable_t region) : value(value), offset(offset), region(region){};
};

static linear_constraint_t is_pointer(dom_t v) { return v.region >= T_CTX; }
static linear_constraint_t is_init(dom_t v) { return v.region > T_UNINIT; }
static linear_constraint_t is_singleton(dom_t v) { return v.region < T_SHARED; }
static linear_constraint_t is_shared(dom_t v) { return v.region > T_SHARED; }
static linear_constraint_t is_not_num(dom_t v) { return v.region > T_NUM; }

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

    basic_block_builder(basic_block_t& bb) : bb(bb) { }
    /// To build statements

    basic_block_t& operator*() { return bb; }
    basic_block_t* operator->() { return &bb; }

    template <typename T, typename... Args>
    basic_block_builder& insert(Args&&... args) {
        bb.insert<T>(std::forward<Args>(args)...);
        return *this;
    }

    basic_block_builder& add(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::ADD, op1, op2); }
    basic_block_builder& add(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::ADD, op1, op2); }
    basic_block_builder& sub(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SUB, op1, op2); }
    basic_block_builder& sub(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SUB, op1, op2); }
    basic_block_builder& mul(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::MUL, op1, op2); }
    basic_block_builder& mul(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::MUL, op1, op2); }
    basic_block_builder& div(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SDIV, op1, op2); }
    basic_block_builder& div(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SDIV, op1, op2); }
    basic_block_builder& udiv(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::UDIV, op1, op2); }
    basic_block_builder& udiv(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::UDIV, op1, op2); }
    basic_block_builder& rem(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SREM, op1, op2); }
    basic_block_builder& rem(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SREM, op1, op2); }
    basic_block_builder& urem(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::UREM, op1, op2); }
    basic_block_builder& urem(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::UREM, op1, op2); }
    basic_block_builder& bitwise_and(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::AND, op1, op2); }
    basic_block_builder& bitwise_and(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::AND, op1, op2); }
    basic_block_builder& bitwise_or(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::OR, op1, op2); }
    basic_block_builder& bitwise_or(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::OR, op1, op2); }
    basic_block_builder& bitwise_xor(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::XOR, op1, op2); }
    basic_block_builder& bitwise_xor(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::XOR, op1, op2); }
    basic_block_builder& shl(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SHL, op1, op2); }
    basic_block_builder& shl(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::SHL, op1, op2); }
    basic_block_builder& lshr(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::LSHR, op1, op2); }
    basic_block_builder& lshr(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::LSHR, op1, op2); }
    basic_block_builder& ashr(variable_t lhs, variable_t op1, variable_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::ASHR, op1, op2); }
    basic_block_builder& ashr(variable_t lhs, variable_t op1, number_t op2) { return insert<crab::binary_op_t>(lhs, crab::BINOP::ASHR, op1, op2); }
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
    basic_block_builder& assertion(linear_constraint_t cst, crab::debug_info di = {}) { return insert<crab::assert_t>(cst, di); }
    basic_block_builder& array_store(variable_t arr, linear_expression_t idx, linear_expression_t v, linear_expression_t elem_size) {
        return insert<crab::array_store_t>(arr, elem_size, idx, idx, v);
    }
    basic_block_builder& array_store_range(variable_t arr, linear_expression_t lb_idx, linear_expression_t ub_idx,
                        linear_expression_t v, linear_expression_t elem_size) {
        return insert<crab::array_store_t>(arr, elem_size, lb_idx, ub_idx, v);
    }
    basic_block_builder& array_load(variable_t lhs, variable_t arr, linear_expression_t idx, linear_expression_t elem_size) {
        return insert<crab::array_load_t>(lhs, arr, elem_size, idx);
    }

    basic_block_builder& assert_init(const dom_t data_reg, debug_info di) {
        return assertion(is_init(data_reg), di);
    }
    basic_block_builder& no_pointer(dom_t v) {
        return assign(v.region, T_NUM).havoc(v.offset);
    }
    basic_block_builder& scratch(std::vector<dom_t> regs) {
        for (dom_t& reg : regs) {
            havoc(reg.value);
            havoc(reg.offset);
            assign(reg.region, T_UNINIT);
        }
        return *this;
    }

    basic_block_builder& assert_no_overflow(variable_t v, debug_info di) {
        // p1 = data_start; p1 += huge_positive; p1 <= p2 does not imply p1 >= data_start
        assertion(v <= MAX_PACKET_OFF, di);
        assertion(v >= -4098, di);
        return *this;
    }

};

basic_block_builder in(basic_block_t& bb) { return {bb}; }

struct array_dom_t {
    variable_factory& vfac;
    variable_t values;
    variable_t offsets;
    variable_t regions;

    array_dom_t(variable_factory& vfac, std::string name)
        : vfac(vfac), values{vfac[std::string(name + "_r")], crab::TYPE::ARR, 64},
          offsets{vfac[std::string(name + "_off")], crab::TYPE::ARR, 64}, regions{vfac[std::string(name + "_t")],
                                                                                  crab::TYPE::ARR, 64} {}

    template <typename T, typename W>
    basic_block_t& load(basic_block_t& block, dom_t data_reg, const T& offset, W width, cfg_t& cfg) {
        in(block).array_load(data_reg.value, values, offset, width)
                 .array_load(data_reg.region, regions, offset, 1)
                 .array_load(data_reg.offset, offsets, offset, width);
        return block;
    }

    void mark_region(basic_block_t& block, linear_expression_t offset, const variable_t v, variable_t width) {
        variable_t lb{vfac["lb"], crab::TYPE::INT, 64};
        variable_t ub{vfac["ub"], crab::TYPE::INT, 64};
        in(block).assign(lb, offset)
                 .assign(ub, offset + width)
                 .array_store_range(regions, lb, ub, v, 1);
    }

    void mark_region(basic_block_t& block, linear_expression_t offset, const variable_t v, int width) {
        for (int i = 0; i < width; i++)
            in(block).array_store(regions, offset + i, v, 1);
    }

    void havoc_num_region(basic_block_t& block, linear_expression_t offset, variable_t width) {
        variable_t lb{vfac["lb"], crab::TYPE::INT, 64};
        variable_t ub{vfac["ub"], crab::TYPE::INT, 64};
        variable_t scratch{vfac["scratch"], crab::TYPE::INT, 64};

        in(block).assign(lb, offset)
                 .assign(ub, offset + width)
                 .array_store_range(regions, lb, ub, T_NUM, 1)
                 .havoc(scratch)
                 .array_store(values, lb, scratch, width)
                 .havoc(scratch)
                 .array_store(offsets, lb, scratch, width);
    }

    basic_block_t& store(basic_block_t& block, linear_expression_t offset, const dom_t data_reg, int width,
                         debug_info di, cfg_t& cfg) {
        mark_region(block, offset, data_reg.region, width);

        if (width == 8) {
            auto& pointer_only = in(add_child(cfg, block, "non_num"))
                                .assume(is_not_num(data_reg))
                                .array_store(offsets, offset, data_reg.offset, width)
                                .array_store(values, offset, data_reg.value, width);

            auto& num_only = in(add_child(cfg, block, "num_only"))
                            .assume(data_reg.region == T_NUM)
                            .array_store(values, offset, data_reg.value, width)
                            // kill the cell
                            .array_store(offsets, offset, data_reg.offset, width)
                            // so that relational domains won't think it's worth keeping track of
                            .havoc(data_reg.offset);

            return join(cfg, *num_only, *pointer_only);
        } else {
            variable_t scratch{vfac["scratch"], crab::TYPE::INT, (unsigned int)width};
            in(block).assertion(data_reg.region == T_NUM, di)
                     .havoc(scratch)
                     .array_store(values, offset, scratch, width)
                     .havoc(scratch)
                     .array_store(offsets, offset, scratch, width);
            return block;
        }
    }
};

struct machine_t final {
    ptype_descr ctx_desc;
    variable_factory& vfac;
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "S"};
    variable_t meta_size{vfac[std::string("meta_size")], crab::TYPE::INT, 64};
    variable_t data_size{vfac[std::string("data_size")], crab::TYPE::INT, 64};

    variable_t top{vfac[std::string("*")], crab::TYPE::INT, 64};
    variable_t num{vfac[std::string("T_NUM")], crab::TYPE::INT, 64};

    program_info info;

    std::vector<dom_t> caller_saved_registers() const {
        return {regs[1], regs[2], regs[3], regs[4], regs[5]};
    }

    dom_t& reg(Value v) { return regs[std::get<Reg>(v).v]; }

    void setup_entry(basic_block_t& entry);

    machine_t(variable_factory& vfac, program_info info);
};

class instruction_builder_t final {
  public:
    basic_block_t& exec(Instruction ins);
    instruction_builder_t(machine_t& machine, basic_block_t& block, cfg_t& cfg)
        : machine(machine), block(block), cfg(cfg), di{first_num(block.label()), 0} {}

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

    /** Unimplemented */
    basic_block_t& operator()(Assert const& b) { assert(false); };

  private:
    machine_t& machine;
    basic_block_t& block;
    cfg_t& cfg;

    // derived fields
    debug_info di;

    template <typename W>
    basic_block_t& exec_stack_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset,
                                     W width);

    template <typename W>
    basic_block_t& exec_shared_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset,
                                      W width);

    template <typename W>
    basic_block_t& exec_data_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset,
                                    W width);

    template <typename W>
    basic_block_t& exec_ctx_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset,
                                   W width);

    basic_block_t& exec_direct_stack_load(basic_block_t& block, dom_t data_reg, int _offset, int width);

    basic_block_t& exec_direct_stack_store(basic_block_t& block, dom_t data_reg, int _offset, int width);

    basic_block_t& exec_direct_stack_store_immediate(basic_block_t& block, int _offset, int width, uint64_t immediate);

    template <typename W>
    basic_block_t& exec_mem_access_indirect(basic_block_t& block, bool is_load, bool is_st, dom_t mem_reg,
                                            dom_t data_reg, int offset, W width);

    /** Decide if the program is privileged, and allowed to leak pointers */
    bool is_privileged() { return machine.info.program_type == BpfProgType::KPROBE; }

    basic_block_t& join(basic_block_t& left, basic_block_t& right) { return ::join(cfg, left, right); }
};

/** Main loop generating the Crab cfg from eBPF Cfg.
 *
 * Each instruction is translated to a tree of Crab instructions, which are then
 * joined together.
 */
cfg_t build_crab_cfg(variable_factory& vfac, Cfg const& simple_cfg, program_info info) {
    cfg_t cfg(entry_label(), simple_cfg.exit());
    machine_t machine(vfac, info);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
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

machine_t::machine_t(variable_factory& vfac, program_info info)
    : ctx_desc{get_descriptor(info.program_type)}, vfac{vfac}, info{info} {
    for (int i = 0; i < 12; i++) {
        regs.emplace_back(vfac, i);
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
void machine_t::setup_entry(basic_block_t& entry) {
    machine_t& machine = *this;
    in(entry).havoc(machine.top)
             .assign(machine.num, T_NUM)
             .assume(STACK_SIZE <= machine.regs[10].value)
             .assign(machine.regs[10].offset, 0) // XXX: Maybe start with STACK_SIZE
             .assign(machine.regs[10].region, T_STACK)
             .assume(1 <= machine.regs[1].value)
             .assume(machine.regs[1].value <= PTR_MAX)
             .assign(machine.regs[1].offset, 0)
             .assign(machine.regs[1].region, T_CTX)
             .assume(0 <= machine.data_size)
             .assume(machine.data_size <= 1 << 30);

    for (int i : {0, 2, 3, 4, 5, 6, 7, 8, 9}) {
        in(entry).assign(machine.regs[i].region, T_UNINIT);
    }
    if (machine.ctx_desc.meta >= 0) {
        in(entry).assume(machine.meta_size <= 0);
    } else {
        in(entry).assign(machine.meta_size, 0);
    }
}

static linear_constraint_t eq(variable_t& a, variable_t& b) { return {a - b, linear_constraint_t::EQUALITY}; }

static linear_constraint_t neq(variable_t& a, variable_t& b) { return {a - b, linear_constraint_t::DISEQUATION}; };

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

static void wrap32(basic_block_t& block, variable_t& dst_value) {
    in(block).bitwise_and(dst_value, dst_value, UINT32_MAX);
}

template <typename T>
static void move_into(vector<T>& dst, vector<T>&& src) {
    dst.insert(dst.end(), std::make_move_iterator(src.begin()), std::make_move_iterator(src.end()));
}

/** Translate a memory access to a location that might be the stack (but do not explicitly use r10).
 *
 * Note that addresses in the stack are reversed.
 * TODO: replace it with accesses relative to STACK_SIZE.
 */
template <typename W>
basic_block_t& instruction_builder_t::exec_stack_access(basic_block_t& block, bool is_load, dom_t mem_reg,
                                                        dom_t data_reg, int offset, W width) {
    auto& mid = add_child(cfg, block, "assume_stack");
    linear_expression_t addr = (-offset) - width - mem_reg.offset; // negate access

    in(mid).assume(mem_reg.region == T_STACK)
           .assertion(addr >= 0, di)
           .assertion(addr <= STACK_SIZE - width, di);
    if (is_load) {
        machine.stack_arr.load(mid, data_reg, addr, width, cfg);
        in(mid).assume(is_init(data_reg));
        /* FIX: requires loop
        variable_t tmp{machine.vfac["tmp"], crab::TYPE::INT, 64};
        for (int idx=1; idx < width; idx++) {
            mid.array_load(tmp, machine.stack_arr.regions, addr+idx, 1);
            in(mid).assertion(eq(tmp, data_reg.region), di);
        }*/
        return mid;
    } else {
        in(mid).assert_init(data_reg, di);
        auto& res = machine.stack_arr.store(mid, addr, data_reg, width, di, cfg);
        in(res).havoc(machine.top);
        return res;
    }
}

/** Translate a memory access to a shared location (MAP_VALUE)
 *
 * We do not and cannot track the content of this access; we do not even know
 * what region is this precisely. What we know is that the size of this region
 * is encoded in the type, so we can check that
 *
 *     `0 <= addr <= mem_reg.region - width`.
 *
 * Shared regions are externally visible, so nonprivileged programs are not
 * allowed to leak pointers there.
 */
template <typename W>
basic_block_t& instruction_builder_t::exec_shared_access(basic_block_t& block, bool is_load, dom_t mem_reg,
                                                         dom_t data_reg, int offset, W width) {
    linear_expression_t addr = mem_reg.offset + offset;
    auto& mid = in(add_child(cfg, block, "assume_shared"))
               .assume(is_shared(mem_reg))
               .assertion(addr >= 0, di)
               .assertion(addr <= mem_reg.region - width, di);
    if (is_load) {
        mid.havoc(data_reg.value)
           .assign(data_reg.region, T_NUM)
           .havoc(data_reg.offset);
    } else {
        mid.assertion(data_reg.region == T_NUM, di);
    }
    return *mid;
}

/** Translate a packet memory access
 *
 * We do not track packet contents. We just verify that only numbers are written
 * there, so as not to leak information.
 */
template <typename W>
basic_block_t& instruction_builder_t::exec_data_access(basic_block_t& block, bool is_load, dom_t mem_reg,
                                                       dom_t data_reg, int offset, W width) {
    linear_expression_t addr = mem_reg.offset + offset;

    auto& mid = in(add_child(cfg, block, "assume_data"))
               .assume(mem_reg.region == T_DATA)
               .assertion(machine.meta_size <= addr, di)
               .assertion(addr <= machine.data_size - width, di);
    if (is_load) {
        mid.havoc(data_reg.offset)
           .havoc(data_reg.value)
           .assign(data_reg.region, T_NUM);
    }
    return *mid;
}

/** Translate memory access to the context.
 *
 * We do not track the context using the memory domain (though it would be simple).
 * Instead, we nondeterministically branch on the three important cases:
 *
 * 1. read data_start
 * 2. read data_end
 * 3. read meta_start
 * 4. access some other location
 */
template <typename W>
basic_block_t& instruction_builder_t::exec_ctx_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg,
                                                      int offset, W width) {
    linear_expression_t addr = mem_reg.offset + offset;
    auto& mid = in(add_child(cfg, block, "assume_ctx"))
               .assume(mem_reg.region == T_CTX)
               .assertion(addr >= 0, di)
               .assertion(addr <= machine.ctx_desc.size - width, di);

    ptype_descr desc = machine.ctx_desc;
    auto assume_normal = [&](basic_block_t& b) {
        if (desc.data >= 0) {
            in(b).assume(addr != desc.data)
                 .assume(addr != desc.end);
            if (desc.meta >= 0) {
                in(b).assume(addr != desc.meta);
            }
        }
    };
    if (!is_load) {
        assume_normal(*mid);
        mid.assertion(data_reg.region == T_NUM, di);
        return *mid;
    } else {
        auto load_datap = [&](string suffix, int start, auto offset) -> basic_block_t& {
            return *in(add_child(cfg, *mid, suffix))
                   .assume(addr == start)
                   .assign(data_reg.region, T_DATA)
                   .havoc(data_reg.value)
                   .assume(4098 <= data_reg.value)
                   .assume(data_reg.value <= PTR_MAX)
                   .assign(data_reg.offset, offset);
        };
        auto normal = [&]() -> basic_block_t& {
            auto& normal = add_child(cfg, *mid, "assume_ctx_not_special");
            assume_normal(normal);
            in(normal).assign(data_reg.region, T_NUM)
                      .havoc(data_reg.offset)
                      .havoc(data_reg.value);
            return normal;
        };
        if (desc.data < 0)
            return normal();
        auto& start_end =
            join(load_datap("data_start", desc.data, 0), load_datap("data_end", desc.end, machine.data_size));
        if (desc.meta < 0)
            return join(start_end, normal());
        auto& meta = load_datap("meta", desc.meta, machine.meta_size);
        return join(join(start_end, meta), normal());
    }
}

static inline void assert_in_stack(basic_block_t& block, int offset, int width, debug_info di) {
    // NOP - should be done in the validator
}

int get_start(int offset, int width) { return (-offset) - width; }

/** Translate a direct load of a of data_reg, with r10 as base address (known to be a store to the stack).
 */
basic_block_t& instruction_builder_t::exec_direct_stack_load(basic_block_t& block, dom_t data_reg, int offset,
                                                             int width) {
    assert_in_stack(block, offset, width, di);
    int start = get_start(offset, width);
    auto& child = machine.stack_arr.load(block, data_reg, start, width, cfg);
    in(child).assume(is_init(data_reg));

    /* FIX
    variable_t tmp{machine.vfac["tmp"], crab::TYPE::INT, 64};
    for (int idx=1; idx < width; idx++) {
        in(*b).array_load(tmp, machine.stack_arr.regions, offset+idx, 1);
        in(*b).assertion(eq(tmp, data_reg.region), di);
    }
    */
    return child;
}

/** Translate a direct store of a of data_reg, with r10 as base address (known to be a store to the stack).
 */
basic_block_t& instruction_builder_t::exec_direct_stack_store(basic_block_t& block, dom_t data_reg, int offset,
                                                              int width) {
    assert_in_stack(block, offset, width, di);
    in(block).assert_init(data_reg, di);
    return machine.stack_arr.store(block, (-offset) - width, data_reg, width, di, cfg);
}

/** Translate a direct store of a number, with r10 as base address (known to be a store to the stack).
 */
basic_block_t& instruction_builder_t::exec_direct_stack_store_immediate(basic_block_t& block, int offset, int width,
                                                                        uint64_t immediate) {
    assert_in_stack(block, offset, width, di);
    int start = get_start(offset, width);
    in(block).havoc(machine.top);
    for (int i = start; i <= start + width; i++) {
        in(block).array_store(machine.stack_arr.regions, i, T_NUM, 1)
                 .array_store(machine.stack_arr.offsets, i, machine.top, 1);
    }
    in(block).array_store(machine.stack_arr.values, start, immediate, width);
    return block;
}

/** Translate indirect store/load operation
 *
 *  For example: *(u64*)(r1 + 5) = r3
 *
 *  Since at code-gen time we do not know what is the target region, we generate
 *  a non-deterministic branch with `assume mem_reg.type == region` on each
 *  outgoing node.
 */
template <typename W>
basic_block_t& instruction_builder_t::exec_mem_access_indirect(basic_block_t& block, bool is_load, bool is_ST,
                                                               dom_t mem_reg, dom_t data_reg, int offset, W width) {
    bool can_ctx = is_load || !is_ST;
    in(block).assertion(mem_reg.value != 0, di)
             .assertion(is_not_num(mem_reg), di);
    if (!can_ctx) {
        // "BPF_ST stores into R1 context is not allowed"
        // (This seems somewhat arbitrary)
        in(block).assertion(mem_reg.region != T_CTX, di);
    }
    basic_block_t* tmp = &join(exec_stack_access(block, is_load, mem_reg, data_reg, offset, width),
                               exec_shared_access(block, is_load, mem_reg, data_reg, offset, width));
    if (can_ctx) {
        tmp = &join(*tmp, exec_ctx_access(block, is_load, mem_reg, data_reg, offset, width));
    }
    if (machine.ctx_desc.data >= 0) {
        tmp = &join(*tmp, exec_data_access(block, is_load, mem_reg, data_reg, offset, width));
    }
    return *tmp;
}

/** Should never occur */
basic_block_t& instruction_builder_t::operator()(Undefined const& a) { assert(false); }

/** Translate operation of the form `r2 = fd 0x5436`.
 *
 * This instruction is one of the two possible sources of map descriptors.
 * (The other one, `call 1` on a map-in-map, is not supported yet)
 */
basic_block_t& instruction_builder_t::operator()(LoadMapFd const& ld) {
    auto reg = machine.reg(ld.dst);
    in(block).assign(reg.region, T_MAP)
             .assign(reg.value, ld.mapfd)
             .havoc(reg.offset);
    return block;
}

/** load-increment-store, from shared regions only. */
basic_block_t& instruction_builder_t::operator()(LockAdd const& b) {
    auto addr = machine.reg(b.access.basereg).offset + b.access.offset;
    in(block).assertion(is_shared(machine.reg(b.access.basereg)), di)
             .assertion(machine.reg(b.valreg).region == T_NUM, di)
             .assertion(addr >= 0, di)
             .assertion(addr <= machine.reg(b.access.basereg).region - b.access.width, di);
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
    dom_t& dst = machine.reg(bin.dst);

    if (std::holds_alternative<Reg>(bin.v)) {
        in(block).assert_init(machine.reg(bin.v), di);
    }

    if (bin.op != Bin::Op::MOV) {
        in(block).assert_init(dst, di);
    }

    auto underflow = [&](basic_block_t& b) -> basic_block_t& {
        return *in(add_child(cfg, b, "underflow"))
               .assume(MY_INT_MIN > dst.value)
               .havoc(dst.value);
    };

    auto overflow = [&](basic_block_t& b) -> basic_block_t& {
        return *in(add_child(cfg, b, "overflow"))
               .assume(dst.value > MY_INT_MAX)
               .havoc(dst.value);
    };

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
            in(block).add(dst.value, dst.value, imm)
                     .add(dst.offset, dst.offset, imm);
            return join(block, imm > 0
                      ? overflow(block)
                      : underflow(block));
        case Bin::Op::SUB:
            if (imm == 0)
                return block;
            in(block).sub(dst.value, dst.value, imm)
                     .sub(dst.offset, dst.offset, imm);
            if (imm < 0) {
                return join(block, overflow(block));
            } else {
                return join(block, underflow(block));
            }
            break;
        case Bin::Op::MUL:
            in(block).mul(dst.value, dst.value, imm)
                     .no_pointer(dst);
            return join(block, join(overflow(block), underflow(block)));
        case Bin::Op::DIV:
            in(block).div(dst.value, dst.value, imm)
                     .no_pointer(dst);
            if (imm == -1) {
                return join(block, overflow(block));
            } else {
                return block;
            }
            break;
        case Bin::Op::MOD:
            in(block).rem(dst.value, dst.value, imm)
                     .no_pointer(dst);
            if (imm == -1) {
                return join(block, overflow(block));
            } else {
                return block;
            }
            break;
        case Bin::Op::OR:
            in(block).bitwise_or(dst.value, dst.value, imm)
                     .no_pointer(dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            in(block).bitwise_and(dst.value, dst.value, imm);
            if ((int32_t)imm > 0) {
                in(block).assume(dst.value <= imm)
                         .assume(0 <= dst.value);
            }
            in(block).no_pointer(dst);
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
            return join(block, join(overflow(block), underflow(block)));
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
        dom_t& src = machine.reg(bin.v);
        switch (bin.op) {
        case Bin::Op::ADD: {
            auto& ptr_dst = in(add_child(cfg, block, "ptr_dst"))
                           .assume(is_pointer(dst))
                           .assertion(src.region == T_NUM, di)
                           .add(dst.offset, dst.offset, src.value)
                           .add(dst.value, dst.value, src.value)
                           .assert_no_overflow(dst.offset, di);

            auto& ptr_src = in(add_child(cfg, block, "ptr_src"))
                           .assume(is_pointer(src))
                           .assertion(dst.region == T_NUM, di)
                           .add(dst.offset, dst.value, src.offset)
                           .add(dst.value, dst.value, src.value)
                           .assert_no_overflow(dst.offset, di)
                           .assign(dst.region, src.region)
                           .havoc(machine.top)
                           .assign(dst.value, machine.top)
                           .assume(4098 <= dst.value);

            auto& both_num = in(add_child(cfg, block, "both_num"))
                            .assume(dst.region == T_NUM)
                            .assume(src.region == T_NUM)
                            .add(dst.value, dst.value, src.value);

            return join(join(*both_num, join(*ptr_src, *ptr_dst)), join(overflow(*both_num), underflow(*both_num)));
        } break;
        case Bin::Op::SUB: {
            auto& same = in(add_child(cfg, block, "ptr_src"))
                        .assume(is_pointer(src))
                        .assertion(is_singleton(src), di) // since map values of the same type can point to different maps
                        .assertion(eq(dst.region, src.region), di)
                        .sub(dst.value, dst.offset, src.offset)
                        .assign(dst.region, T_NUM)
                        .havoc(dst.offset);

            auto& num_src = in(add_child(cfg, block, "num_src"))
                           .assume(src.region == T_NUM);
            {
                auto& ptr_dst = in(add_child(cfg, *num_src, "ptr_dst"))
                               .assume(is_pointer(dst))
                               .sub(dst.offset, dst.offset, src.value)
                               .assert_no_overflow(dst.offset, di);

                auto& both_num = in(add_child(cfg, *num_src, "both_num"))
                                .assume(dst.region == T_NUM)
                                .sub(dst.value, dst.value, src.value);

                return join(join(join(*both_num, *same), *ptr_dst), join(overflow(*both_num), underflow(*both_num)));
            }
        } break;
        case Bin::Op::MUL:
            in(block).mul(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            return join(block, join(overflow(block), underflow(block)));
        case Bin::Op::DIV:
            // For some reason, DIV is not checked for zerodiv
            in(block).div(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            // overflow if INT_MIN / -1
            return join(block, overflow(block));
        case Bin::Op::MOD:
            // See DIV comment
            in(block).rem(dst.value, dst.value, src.value)
                     .no_pointer(dst);
            // overflow if INT_MIN % -1
            return join(block, overflow(block));
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
            return join(block, join(overflow(block), underflow(block)));
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

    if (!bin.is64)
        wrap32(block, dst.value);

    return block;
}

/** Translate unary operations: either a negation, or an endianness swapping.
 */
basic_block_t& instruction_builder_t::operator()(Un const& b) {
    dom_t& dst = machine.reg(b.dst);
    in(block).assert_init(dst, di);
    switch (b.op) {
    case Un::Op::LE16:
    case Un::Op::LE32:
    case Un::Op::LE64:
        in(block).havoc(dst.value)
                 .no_pointer(dst);
        break;
    case Un::Op::NEG:
        in(block).assign(dst.value, 0 - dst.value);
        auto& overflow = in(add_child(cfg, block, "overflow"))
                        .assume(dst.value > MY_INT_MAX)
                        .havoc(dst.value);
        return join(block, *overflow);
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
    variable_t map_value_size{machine.vfac["map_value_size"], crab::TYPE::INT, 64};
    variable_t map_key_size{machine.vfac["map_key_size"], crab::TYPE::INT, 64};
    for (ArgSingle param : call.singles) {
        dom_t arg = machine.regs[param.reg.v];
        switch (param.kind) {
        case ArgSingle::Kind::ANYTHING:
            // avoid pointer leakage:
            if (!is_privileged()) {
                in(block).assertion(arg.region == T_NUM, di);
            }
            break;
        case ArgSingle::Kind::MAP_FD:
            in(block).assertion(arg.region == T_MAP, di)
                     .lshr(map_value_size, arg.value, 14)
                     .rem(map_key_size, arg.value, 1 << 14)
                     .lshr(map_key_size, map_key_size, 6);
            break;
        case ArgSingle::Kind::PTR_TO_MAP_KEY:
            in(block).assertion(arg.value > 0, di)
                     .assertion(arg.region == T_STACK, di)
                     .assertion(arg.offset + map_key_size <= 0, di)
                     .assertion(arg.offset <= STACK_SIZE, di);
            break;
        case ArgSingle::Kind::PTR_TO_MAP_VALUE:
            in(block).assertion(arg.value > 0, di)
                     .assertion(arg.region == T_STACK, di)
                     .assertion(arg.offset + map_value_size <= 0, di)
                     .assertion(arg.offset <= STACK_SIZE, di);
            break;
        case ArgSingle::Kind::PTR_TO_CTX:
            // FIX: should be arg.offset == 0
            in(block).assertion(arg.value > 0, di)
                     .assertion(arg.region == T_CTX, di)
                     .assertion(arg.offset >= 0, di);
            break;
        }
    }
    basic_block_t* current = &block;
    for (ArgPair param : call.pairs) {
        dom_t arg = machine.regs[param.mem.v];
        dom_t sizereg = machine.regs[param.size.v];
        in(*current).assertion(sizereg.region == T_NUM, di)
                    .assertion(param.can_be_zero ? sizereg.value >= 0 : sizereg.value > 0, di);
        auto assert_mem = [&](basic_block_t& ptr, bool may_write, bool may_read) -> basic_block_t& {
            in(ptr).assertion(is_pointer(arg), di)
                   .assertion(arg.value > 0, di);

            variable_t width = sizereg.value;
            auto assume_stack = [&]() -> basic_block_t& {
                auto& mid = *in(add_child(cfg, ptr, "assume_stack"))
                            .assume(arg.region == T_STACK)
                            .assertion(arg.offset + width <= 0, di)
                            .assertion(arg.offset <= STACK_SIZE, di);
                if (may_write) {
                    machine.stack_arr.havoc_num_region(mid, -(width + arg.offset), width);
                }
                if (may_read) {
                    // TODO: check initialization
                }
                return mid;
            };
            auto assume_shared = [&]() -> basic_block_t& {
                return *in(add_child(cfg, ptr, "assume_shared"))
                       .assume(is_shared(arg))
                       .assertion(arg.offset >= 0, di)
                       .assertion(arg.offset <= arg.region - width, di);
            };
            auto assume_data = [&]() -> basic_block_t& {
                return *in(add_child(cfg, ptr, "assume_data"))
                       .assume(arg.region == T_DATA)
                       .assertion(machine.meta_size <= arg.offset, di)
                       .assertion(arg.offset <= machine.data_size - width, di);
            };
            auto& res = join(assume_stack(), assume_shared());
            if (machine.ctx_desc.data >= 0) {
                return join(res, assume_data());
            }
            return res;
        };
        switch (param.kind) {
        case ArgPair::Kind::PTR_TO_MEM_OR_NULL: {
            auto& null = in(add_child(cfg, *current, "null"))
                        .assume(arg.region == T_NUM)
                        .assertion(arg.value == 0, di);

            auto& ptr = in(add_child(cfg, *current, "ptr"))
                       .assume(is_not_num(arg));
            current = &join(*null, assert_mem(*ptr, false, true));
        } break;
        case ArgPair::Kind::PTR_TO_MEM: {
            current = &assert_mem(*current, false, true);
        } break;
        case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
            current = &assert_mem(*current, true, false);
        } break;
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
    // assert_init(block, machine.regs[0], di);
    in(block).assertion(machine.regs[0].region == T_NUM, di);
    return block;
}

/** Generate Crab assertions and assumptions for a single eBPF `assume` command (extracted from a Jmp).
 */
basic_block_t& instruction_builder_t::operator()(Assume const& b) {
    Condition cond = b.cond;
    if (std::holds_alternative<Reg>(cond.right)) {
        in(block).assert_init(machine.reg(cond.right), di);
    }
    in(block).assert_init(machine.reg(cond.left), di);

    dom_t& dst = machine.reg(cond.left);
    if (std::holds_alternative<Reg>(cond.right)) {
        dom_t& src = machine.reg(cond.right);
        auto same_type = [&]() -> basic_block_t& {
            auto& same = in(add_child(cfg, block, "same_type"))
                        .assume(eq(dst.region, src.region));
            auto numbers = [&]() -> basic_block_t& {
                auto& numbers = in(add_child(cfg, *same, "numbers"))
                               .assume(dst.region == T_NUM);
                if (!is_unsigned_cmp(cond.op)) {
                    for (auto c : jmp_to_cst_reg(cond.op, dst.value, src.value))
                        numbers.assume(c);
                }
                return *numbers;
            };
            auto pointers = [&]() -> basic_block_t& {
                return *in(add_child(cfg, *same, "pointers"))
                       .assume(is_pointer(dst))
                       .assertion(is_singleton(dst), di)
                       .assume(jmp_to_cst_offsets_reg(cond.op, dst.offset, src.offset));
            };
            return join(numbers(), pointers());
        };
        auto different_type = [&]() -> basic_block_t& {
            auto& different = in(add_child(cfg, block, "different_type"))
                             .assume(neq(dst.region, src.region));
            auto null_src = [&]() -> basic_block_t& {
                return *in(add_child(cfg, *different, "null_src"))
                       .assume(is_pointer(dst))
                       .assertion(src.region == T_NUM)
                       .assertion(src.value == 0, di);
            };
            auto null_dst = [&]() -> basic_block_t& {
                return *in(add_child(cfg, *different, "null_dst"))
                       .assume(is_pointer(src))
                       .assertion(dst.region == T_NUM)
                       .assertion(dst.value == 0, di);
            };
            return join(null_src(), null_dst());
        };
        return join(same_type(), different_type());
    } else {
        int imm = static_cast<int>(std::get<Imm>(cond.right).v);
        vector<linear_constraint_t> csts = jmp_to_cst_imm(cond.op, dst.value, imm);
        for (linear_constraint_t c : csts)
            in(block).assume(c);
        if (!is_privileged() && imm != 0) {
            // only null can be compared to pointers without leaking secrets
            in(block).assertion(dst.region == T_NUM, di);
        }
        return block;
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
    return *in(block).assertion(machine.regs[6].region == T_CTX, di)
           .assign(machine.regs[0].region, T_NUM)
           .havoc(machine.regs[0].offset)
           .havoc(machine.regs[0].value)
           .scratch(machine.caller_saved_registers());
}

/** Generate constraints and instructions for memory accesses.
 */
basic_block_t& instruction_builder_t::operator()(Mem const& b) {
    dom_t mem_reg = machine.reg(b.access.basereg);
    bool mem_is_fp = b.access.basereg.v == 10;
    int width = (int)b.access.width;
    int offset = (int)b.access.offset;
    if (b.is_load) {
        // data = mem[offset]
        assert(std::holds_alternative<Reg>(b.value));
        dom_t data_reg = machine.reg(std::get<Reg>(b.value));
        if (mem_is_fp) {
            return exec_direct_stack_load(block, data_reg, offset, width);
        } else {
            return exec_mem_access_indirect(block, true, false, mem_reg, data_reg, offset, width);
        }
    } else {
        if (std::holds_alternative<Reg>(b.value)) {
            // mem[offset] = data
            dom_t data_reg = machine.reg(std::get<Reg>(b.value));
            if (mem_is_fp) {
                return exec_direct_stack_store(block, data_reg, offset, width);
            } else {
                return exec_mem_access_indirect(block, false, false, mem_reg, data_reg, offset, width);
            }
        } else {
            // mem[offset] = immediate
            auto imm = std::get<Imm>(b.value).v;
            if (mem_is_fp) {
                return exec_direct_stack_store_immediate(block, offset, width, imm);
            } else {
                // FIX: STW stores long long immediate
                variable_t tmp{machine.vfac["tmp"], crab::TYPE::INT, 64};
                in(block).assign(tmp, imm);
                in(block).havoc(machine.top);
                return exec_mem_access_indirect(block, false, true, mem_reg, {tmp, machine.top, machine.num}, offset,
                                                width);
            }
        }
    }
}
