#include <iostream>
#include <vector>
#include <string>
#include <map>

#include "instructions.hpp"
#include "common.hpp"
#include "constraints.hpp"
#include "prototypes.hpp"
#include "type_descriptors.hpp"

using std::tuple;
using std::string;
using std::vector;
using std::map;

using ikos::z_number;
using debug_info = crab::cfg::debug_info;

using var_t     = ikos::variable<z_number, varname_t>;
using lin_cst_t = ikos::linear_constraint<z_number, varname_t>;

enum region_t {
    T_UNINIT,
    T_NUM,
    T_CTX,
    T_STACK,
    T_DATA,
    T_MAP,
};

struct dom_t {
    var_t value;
    var_t offset;
    var_t region;
    dom_t(variable_factory_t& vfac, int i) :
        value{vfac[std::string("r") + std::to_string(i)], crab::INT_TYPE, 64}, 
        offset{vfac[std::string("off") + std::to_string(i)], crab::INT_TYPE, 64},
        region{vfac[std::string("t") + std::to_string(i)], crab::INT_TYPE, 8}
    { }
    dom_t(var_t value, var_t offset, var_t region) : value(value), offset(offset), region(region) { };
};

static void assert_init(basic_block_t& block, const dom_t& target, debug_info di)
{
    block.assertion(target.region >= T_NUM, di);
}

struct array_dom_t {
    variable_factory_t& vfac;
    var_t values;
    var_t offsets;
    var_t regions;
    array_dom_t(variable_factory_t& vfac, std::string name) :
        vfac(vfac),
        values{vfac[std::string(name + "_vals")], crab::ARR_INT_TYPE, 64}, 
        offsets{vfac[std::string(name + "_offsets")], crab::ARR_INT_TYPE, 64},
        regions{vfac[std::string(name + "_regions")], crab::ARR_INT_TYPE, 8}
    { }
    template<typename T, typename W>
    void load(basic_block_t& block, dom_t& target, const T& offset, W width) {
        block.array_load(target.value, values, offset, width);
        block.array_load(target.region, regions, offset, width);
        block.array_load(target.offset, offsets, offset, width);
    }
    
    template<typename T, typename W>
    void store(basic_block_t& block, const T& offset, const dom_t& target, W width, debug_info di) {
        var_t lb{vfac["lb"], crab::INT_TYPE, 64};
        var_t ub{vfac["ub"], crab::INT_TYPE, 64};
        block.assign(lb, offset);
        block.assign(ub, offset + width);
        block.array_init(regions, 1, lb, ub, target.region);

        block.array_store(values, offset, target.value, width);
        block.array_store(offsets, offset, target.offset, width);
    }
};


struct machine_t final
{
    ptype_descr ctx_desc;
    variable_factory_t& vfac;
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "stack"};
    array_dom_t ctx_arr{vfac, "ctx"};
    array_dom_t data_arr{vfac, "data"};
    var_t meta_size{vfac[std::string("meta_size")], crab::INT_TYPE, 64};
    var_t total_size{vfac[std::string("total_data_size")], crab::INT_TYPE, 64};
    var_t top{vfac[std::string("*")], crab::INT_TYPE, 64};
    var_t num{vfac[std::to_string(T_NUM)], crab::INT_TYPE, 8};

    machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac);
};

class instruction_builder_t final
{
public:
    vector<basic_block_label_t> exec();
    instruction_builder_t(machine_t& machine, ebpf_inst inst, ebpf_inst next_inst, basic_block_t& block, cfg_t& cfg) :
        machine(machine), inst(inst), next_inst(next_inst), block(block), cfg(cfg), pc((unsigned int)first_num(block.label())),
        di{"pc", pc, 0}, mem(is_load(inst.opcode) ? inst.src : inst.dst), width(access_width(inst.opcode))
        {
        }
private:
    machine_t& machine;
    ebpf_inst inst;
    ebpf_inst next_inst; // for LDDW, STDW
    basic_block_t& block;
    cfg_t& cfg;

    // derived fields
    uint16_t pc;
    debug_info di;
    uint8_t mem = is_load(inst.opcode) ? inst.src : inst.dst;
    int width = access_width(inst.opcode);

    void scratch_regs(basic_block_t& block);
    static void no_pointer(basic_block_t& block, dom_t& v);

    vector<basic_block_label_t> exec_alu();
    vector<basic_block_label_t> exec_call();
};

abs_machine_t::abs_machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac)
: impl{new machine_t{prog_type, vfac}}
{
}

abs_machine_t::~abs_machine_t() = default;

machine_t::machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac)
    : ctx_desc{get_descriptor(prog_type)}, vfac{vfac}
{
    for (int i=0; i < 11; i++) {
        this->regs.emplace_back(vfac, i);
    }
}

void abs_machine_t::setup_entry(basic_block_t& entry)
{
    auto& machine = *impl;
    entry.havoc(machine.top);
    entry.assign(machine.num, T_NUM);

    entry.assume(STACK_SIZE <= machine.regs[10].value);
    entry.assign(machine.regs[10].offset, 0); // XXX: Maybe start with STACK_SIZE
    entry.assign(machine.regs[10].region, T_STACK);

    entry.assume(1 <= machine.regs[1].value);
    entry.assign(machine.regs[1].offset, 0);
    entry.assign(machine.regs[1].region, T_CTX);

    for (int i : {0, 2, 3, 4, 5, 6, 7, 8, 9}) {
        entry.assign(machine.regs[i].region, T_UNINIT);
    }

    entry.assume(0 <= machine.total_size);
    if (machine.ctx_desc.meta < 0) {
        entry.assign(machine.meta_size, 0);
    } else {
        entry.assume(0 <= machine.meta_size);
        entry.assume(machine.meta_size <= machine.total_size);
    }
}

static auto eq(var_t& a, var_t& b)
{
    return lin_cst_t(a - b, lin_cst_t::EQUALITY);
}

static auto neq(var_t& a, var_t& b)
{
    return lin_cst_t(a - b, lin_cst_t::DISEQUATION);
}

static lin_cst_t jmp_to_cst_offsets(uint8_t opcode, var_t& dst_offset, var_t& src_offset)
{
    switch (opcode) {
    case EBPF_OP_JEQ_REG:  return eq(dst_offset, src_offset);
    case EBPF_OP_JNE_REG:  return neq(dst_offset, src_offset);

    // don't leak
    case EBPF_OP_JEQ_IMM:  assert(false); break;
    case EBPF_OP_JNE_IMM:  assert(false); break;
    
    case EBPF_OP_JGE_REG:  return dst_offset >= src_offset; // FIX unsigned
    case EBPF_OP_JSGE_REG: return dst_offset >= src_offset;
    case EBPF_OP_JLE_REG:  return dst_offset <= src_offset; // FIX unsigned
    case EBPF_OP_JSLE_REG: return dst_offset <= src_offset;
    
    case EBPF_OP_JGT_REG:  return dst_offset >= src_offset + 1; // FIX unsigned
    case EBPF_OP_JSGT_REG: return dst_offset >= src_offset + 1;

    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return src_offset >= dst_offset + 1; // FIX unsigned
    case EBPF_OP_JSLT_REG: return src_offset >= dst_offset + 1;
    }
    return dst_offset - dst_offset == 0;
}


static lin_cst_t jmp_to_cst(uint8_t opcode, int imm, var_t& dst_value, var_t& src_value)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM:  return dst_value == imm;
    case EBPF_OP_JEQ_REG:  return eq(dst_value, src_value);

    case EBPF_OP_JNE_IMM:  return dst_value != imm;
    case EBPF_OP_JNE_REG:  return neq(dst_value, src_value);
    
    case EBPF_OP_JGE_IMM:  return dst_value >= imm; // FIX unsigned
    case EBPF_OP_JGE_REG:  return dst_value >= src_value; // FIX unsigned

    case EBPF_OP_JSGE_IMM: return dst_value >= imm;
    case EBPF_OP_JSGE_REG: return dst_value >= src_value;
    
    case EBPF_OP_JLE_IMM:  return dst_value <= imm; // FIX unsigned
    case EBPF_OP_JLE_REG:  return dst_value <= src_value; // FIX unsigned
    case EBPF_OP_JSLE_IMM: return dst_value <= imm;
    case EBPF_OP_JSLE_REG: return dst_value <= src_value;

    case EBPF_OP_JGT_IMM:  return dst_value >= imm + 1; // FIX unsigned
    case EBPF_OP_JGT_REG:  return dst_value >= src_value + 1; // FIX unsigned
    case EBPF_OP_JSGT_IMM: return dst_value >= imm + 1;
    case EBPF_OP_JSGT_REG: return dst_value >= src_value + 1;

    case EBPF_OP_JLT_IMM:  return dst_value <= imm - 1; // FIX unsigned
    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return src_value >= dst_value + 1; // FIX unsigned
    case EBPF_OP_JSLT_IMM: return dst_value <= imm - 1;
    case EBPF_OP_JSLT_REG: return src_value >= dst_value + 1;
    }
    assert(false);
}


void abs_machine_t::jump(ebpf_inst inst, basic_block_t& block, bool taken)
{
    auto& machine = *impl;
    uint8_t opcode = taken ? inst.opcode : reverse(inst.opcode);
    auto& dst = machine.regs[inst.dst];
    auto& src = machine.regs[inst.src];
    block.assume(jmp_to_cst(opcode, inst.imm, dst.value, src.value));

    if (opcode & EBPF_SRC_REG) {
        block.assertion(eq(dst.region, src.region), debug_info{"pc", 0, (unsigned int)first_num(block.label())});
        lin_cst_t offset_cst = jmp_to_cst_offsets(opcode, dst.offset, src.offset);
        if (!offset_cst.is_tautology()) {
            block.assume(offset_cst);
        }
    }
}

static void wrap32(basic_block_t& block, var_t& dst_value)
{
    block.bitwise_and(dst_value, dst_value, UINT32_MAX);
}


void instruction_builder_t::no_pointer(basic_block_t& block, dom_t& v)
{
    block.havoc(v.offset);
    block.assign(v.region, T_NUM);
}

vector<basic_block_label_t> abs_machine_t::exec(ebpf_inst inst, ebpf_inst next_inst, basic_block_t& block, cfg_t& cfg)
{
    return instruction_builder_t(*impl, inst, next_inst, block, cfg).exec();
}

uint64_t immediate(ebpf_inst inst, ebpf_inst next_inst)
{
    return (uint32_t)inst.imm | ((uint64_t)next_inst.imm << 32);
}

void instruction_builder_t::scratch_regs(basic_block_t& block)
{
    for (int i=1; i<=5; i++) {
        block.havoc(machine.regs[i].value);
        block.havoc(machine.regs[i].offset);
        block.assign(machine.regs[i].region, T_UNINIT);
    }
}

static vector<basic_block_label_t> exec_stack_access(basic_block_t& block, bool is_load, dom_t mem, dom_t target, int offset, var_t width, debug_info di, cfg_t& cfg,
                                                      machine_t& machine)
{
    basic_block_t& mid = add_child(cfg, block, "assume_stack");
    lin_exp_t addr = (-offset) - width - mem.offset; // negate access
    
    mid.assume(mem.region == T_STACK);
    mid.assertion(addr >= 0, di);
    mid.assertion(addr <= STACK_SIZE - width, di);
    if (is_load) {
        machine.stack_arr.load(mid, target, addr, width);
        mid.array_load(target.region, machine.stack_arr.regions, addr, 1);
        mid.assume(target.region >= 1);
        /* FIX: requires loop
        var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 8};
        for (int idx=1; idx < width; idx++) {
            mid.array_load(tmp, machine.stack_arr.regions, addr+idx, 1);
            mid.assertion(eq(tmp, target.region), di);
        }*/
    } else {
        assert_init(mid, target, di);
        machine.stack_arr.store(mid, addr, target, width, di);
    }
    return { mid.label() };
}

static vector<basic_block_label_t> exec_map_access(basic_block_t& block, bool is_load, dom_t mem, dom_t target, int offset, var_t width, debug_info di, cfg_t& cfg)
{
    basic_block_t& mid = add_child(cfg, block, "assume_map");
    lin_exp_t addr = mem.offset + offset;

    mid.assume(mem.region == T_MAP);
    mid.assertion(addr >= 0, di);
    constexpr int MAP_SIZE = 256;
    mid.assertion(addr <= MAP_SIZE - width, di);
    if (is_load) {
        mid.havoc(target.value);
        mid.assign(target.region, T_NUM);
    } else {
        mid.assertion(target.region == T_NUM, di);
    }
    return { mid.label() };
}

static vector<basic_block_label_t> exec_data_access(basic_block_t& block, bool is_load, dom_t mem, dom_t target, int offset, var_t width, debug_info di, cfg_t& cfg,
                                            machine_t& machine)
{
    basic_block_t& mid = add_child(cfg, block, "assume_data");
    lin_exp_t addr = mem.offset + offset;

    mid.assume(mem.region == T_DATA);
    mid.assertion(addr >= 0, di);
    mid.assertion(addr <= machine.total_size - width, di);
    if (is_load) {
        machine.data_arr.load(mid, target, addr, width);
        mid.assign(target.region, T_NUM);
    } else {
        machine.data_arr.store(mid, addr, target, width, di);
    }
    return { mid.label() };
}

static vector<basic_block_label_t> exec_ctx_access(basic_block_t& block, bool is_load, dom_t mem, dom_t target, int offset, var_t width, debug_info di, cfg_t& cfg,
                                            machine_t& machine)
{
    basic_block_t& mid = add_child(cfg, block, "assume_ctx");
    mid.assume(mem.region == T_CTX);
    lin_exp_t addr = mem.offset + offset;
    mid.assertion(addr >= 0, di);
    mid.assertion(addr <= machine.ctx_desc.size - width, di);

    auto desc = machine.ctx_desc;
    vector<basic_block_label_t> ret;
    if (is_load) {
        auto load_datap = [&](string suffix, int start, auto offset) {
            basic_block_t& b = add_child(cfg, mid, suffix);
            b.assume(addr == start);
            b.assign(target.region, T_DATA);
            b.havoc(target.value);
            b.assume(4098 <= target.value);
            b.assign(target.offset, offset);
            ret.push_back(b.label());
        };

        if (desc.data >= 0) {
            load_datap("data_start", desc.data, machine.meta_size);
            load_datap("data_end", desc.end, machine.total_size);
            if (desc.meta >= 0) {
                load_datap("meta", desc.meta, 0);
            }
        }

        basic_block_t& normal = add_child(cfg, mid, "assume_ctx_not_special");
        if (desc.data >= 0) {
            normal.assume(addr != desc.data);
            normal.assume(addr != desc.end);
        }
        if (desc.meta >= 0) {
            normal.assume(addr != desc.meta);
        }
        machine.ctx_arr.load(normal, target, addr, width);
        normal.assign(target.region, T_NUM);
        ret.push_back(normal.label());
    } else {
        mid.assertion(addr != desc.data, di);
        mid.assertion(addr != desc.end, di);
        mid.assertion(addr != desc.meta, di);
        mid.assertion(target.region == T_NUM, di);
        machine.ctx_arr.store(mid, addr, target, width, di);
        ret.push_back(mid.label());
    }
    return ret;
}

static void exec_direct_stack_load(basic_block_t& block, dom_t target, int _offset, var_t width, debug_info di, machine_t& machine)
{
    lin_exp_t offset = (-_offset) - width;
    block.assertion(offset >= 0, di);
    block.assertion(offset + width <= STACK_SIZE, di);
    machine.stack_arr.load(block, target, offset, width);
    block.array_load(target.region, machine.stack_arr.regions, offset+0, 1);
    block.assume(target.region >= 1);
    /* FIX: requires loop
    var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 8};
    for (int idx=1; idx < width; idx++) {
        block.array_load(tmp, machine.stack_arr.regions, offset+idx, 1);
        block.assertion(eq(tmp, target.region), di);
    }*/
}

static void exec_direct_stack_store(basic_block_t& block, dom_t target, int _offset, var_t width, debug_info di, machine_t& machine)
{
    lin_exp_t offset = (-_offset) - width;
    block.assertion(offset >= 0, di);
    block.assertion(offset + width <= STACK_SIZE, di);
    assert_init(block, target, di);
    machine.stack_arr.store(block, offset, target, width, di);
}

static void exec_direct_stack_store_immediate(basic_block_t& block, int _offset, int width, debug_info di, machine_t& machine,
                                              uint64_t immediate)
{
    std::cout << "_offset: " << _offset << " width " << width << "\n";
    int offset = (-_offset) - width;
    assert(offset >= 0);
    assert(offset + width <= STACK_SIZE);
    var_t lb{machine.vfac["lb"], crab::INT_TYPE, 64};
    var_t ub{machine.vfac["ub"], crab::INT_TYPE, 64};
    block.assign(lb, offset);
    block.assign(ub, offset + width);
    block.array_init(machine.stack_arr.regions, 1, lb, ub, T_NUM);
    block.array_store(machine.stack_arr.values, offset, immediate, width);
}

template <typename T>
static void move_into(vector<T>& dst, vector<T>&& src)
{
    dst.insert(dst.end(),
        std::make_move_iterator(src.begin()),
        std::make_move_iterator(src.end())
    );
}

static vector<basic_block_label_t> exec_mem_access_indirect(basic_block_t& block, bool is_load, dom_t mem, dom_t target, int offset, var_t width, debug_info di, cfg_t& cfg, machine_t& machine)
{
    block.assertion(mem.value != 0, di);
    block.assertion(mem.region != T_NUM, di);
    vector<basic_block_label_t> outs;
    
    move_into(outs, exec_stack_access(block, is_load, mem, target, offset, width, di, cfg, machine));
    move_into(outs, exec_ctx_access(block, is_load, mem, target, offset, width, di, cfg, machine));
    move_into(outs, exec_map_access(block, is_load, mem, target, offset, width, di, cfg));
    if (machine.ctx_desc.data >= 0) {
        move_into(outs, exec_data_access(block, is_load, mem, target, offset, width, di, cfg, machine));
    }
    return outs;
}

vector<basic_block_label_t> instruction_builder_t::exec()
{
    if (is_alu(inst.opcode)) {
        return exec_alu();
    } else if (inst.opcode == EBPF_OP_LDDW_IMM) {
        block.assign(machine.regs[inst.dst].value, immediate(inst, next_inst));
        no_pointer(block, machine.regs[inst.dst]);
        return { block.label() };
    } else if (inst.opcode == EBPF_OP_EXIT) {
        // assert_init(block, machine.regs[inst.dst], di);
        block.assertion(machine.regs[inst.dst].region == T_NUM, di);
        return { block.label() };
    } else if (inst.opcode == EBPF_OP_CALL) {
        return exec_call();
    } else if (is_jump(inst.opcode)) {
        // cfg-related action is handled in build_cfg() and instruction_builder_t::jump()
        if (inst.opcode != EBPF_OP_JA) {
            if (inst.opcode & EBPF_SRC_REG) {
                assert_init(block, machine.regs[inst.src], di);
            }
            assert_init(block, machine.regs[inst.dst], di);
        }
    } else if ((inst.opcode & 0xE0) == 0x20 || (inst.opcode & 0xE0) == 0x40) { // TODO NAME: LDABS, LDIND
        /* From the linux verifier code:
        verify safety of LD_ABS|LD_IND instructions:
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
        block.assertion(machine.regs[6].region == T_CTX);
        // TODO: There seems no offset checking at the kernel. Why?
        if ((inst.opcode & 0xE0) == 0x20)
            /* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
            machine.data_arr.load(block, machine.regs[0], inst.imm, width);
        else
            /* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */
            machine.data_arr.load(block, machine.regs[0], machine.regs[inst.src].value + inst.imm, width);
        block.assign(machine.regs[0].region, T_NUM);
        scratch_regs(block);
        return { block.label() };
    } else if (is_access(inst.opcode)) {
        if (inst.opcode == 0x7a && inst.src == 10) {
            std::cout << "pc " << pc << " inst.opcode " << (int)inst.opcode << "\n";
            exec_direct_stack_store_immediate(block, inst.offset, width, di, machine, immediate(inst, next_inst));
            return { block.label() };
        } else if ((inst.opcode & EBPF_CLS_ALU) == EBPF_MODE_IMM ) {
            std::cout << "???\n";
        }

        dom_t mem = is_load(inst.opcode) ? machine.regs.at(inst.src) : machine.regs.at(inst.dst);
        dom_t target = is_load(inst.opcode) ? machine.regs.at(inst.dst) : machine.regs.at(inst.src);
        var_t width{machine.vfac["width"], crab::INT_TYPE, 64};
        block.assign(width, access_width(inst.opcode));
        if (inst.src == 10) {
            if (is_load(inst.opcode)) {
                exec_direct_stack_load(block, target, inst.offset, width, di, machine);
            } else {
                exec_direct_stack_store(block, target, inst.offset, width, di, machine);
            }
            return { block.label() };
        } else {
            return exec_mem_access_indirect(block, is_load(inst.opcode), mem, target, inst.offset, width, di, cfg, machine);
        }
    } else {
        std::cout << "bad instruction " << (int)inst.opcode << " at " << first_num(block.label()) << "},n";
        assert(false);
    }
    return { block.label() };
}

vector<basic_block_label_t> instruction_builder_t::exec_call()
{
    bpf_func_proto proto = get_prototype(inst.imm);
    int i = 0;
    std::vector<basic_block_label_t> prevs{block.label()};
    std::array<bpf_arg_type, 5> args = {{proto.arg1_type, proto.arg2_type, proto.arg3_type, proto.arg4_type, proto.arg5_type}};
    for (bpf_arg_type t : args) {
        dom_t& arg = machine.regs[++i];
        if (t == ARG_DONTCARE)
            break;
        basic_block_t& current = add_common_child(cfg, block, prevs, "arg" + std::to_string(i));
        auto assert_pointer_or_null = [&](lin_cst_t cst) {
            basic_block_t& pointer = add_child(cfg, current, "pointer");
            pointer.assume(cst);
            basic_block_t& null = add_child(cfg, current, "null");
            null.assume(arg.region == T_NUM);
            null.assertion(arg.value == 0, di);
            prevs = {pointer.label(), null.label()};
        };
        prevs = {current.label()};
        switch (t) {
        case ARG_DONTCARE:
            assert(false);
            break;
        case ARG_ANYTHING:
            // avoid pointer leakage:
            current.assertion(arg.region == T_NUM, di);
            break;
        case ARG_CONST_SIZE:
            current.assertion(arg.region == T_NUM, di);
            current.assertion(arg.value > 0, di);
            break;
        case ARG_CONST_SIZE_OR_ZERO:
            current.assertion(arg.region == T_NUM, di);
            current.assertion(arg.value >= 0, di);
            break;
        case ARG_CONST_MAP_PTR:
            assert_pointer_or_null(arg.region == T_MAP);
            break;
        case ARG_PTR_TO_CTX:
            assert_pointer_or_null(arg.region == T_CTX);
            break;
        case ARG_PTR_TO_MAP_KEY:
            current.assertion(arg.value > 0, di);
            current.assertion(arg.region >= T_STACK, di);
            break;
        case ARG_PTR_TO_MAP_VALUE:
            current.assertion(arg.value > 0, di);
            current.assertion(arg.region == T_STACK, di);
            current.assertion(arg.offset < 0, di);
            break;
        case ARG_PTR_TO_MEM: {
                current.assertion(arg.value > 0, di);
                current.assertion(arg.region >= T_STACK, di);
                var_t width = machine.regs[i+1].value;
                exec_mem_access_indirect(current, true, arg, { machine.top, machine.top, machine.top }, 0, width, di, cfg, machine);
                exec_mem_access_indirect(current, false, arg, { machine.top, machine.top, machine.num }, 0, width, di, cfg, machine);
            }
            break;
        case ARG_PTR_TO_MEM_OR_NULL:
            assert_pointer_or_null(arg.region >= T_STACK);
            break;
        case ARG_PTR_TO_UNINIT_MEM: {
                current.assertion(arg.region >= T_STACK, di);
                current.assertion(arg.offset <= 0, di);
                var_t width = machine.regs[i+1].value;
                exec_mem_access_indirect(current, true, arg, { machine.top, machine.top, machine.top }, 0, width, di, cfg, machine);
                exec_mem_access_indirect(current, false, arg, { machine.top, machine.top, machine.num }, 0, width, di, cfg, machine);
            }
            break;
        }
    }

    basic_block_t& epilog = add_common_child(cfg, block, prevs, "epilog");
    scratch_regs(epilog);
    switch (proto.ret_type) {
    case RET_PTR_TO_MAP_VALUE_OR_NULL:
        epilog.assign(machine.regs[0].region, T_MAP);
        epilog.havoc(machine.regs[0].value);
        epilog.assume(0 <= machine.regs[0].value);
        epilog.assign(machine.regs[0].offset, 0);
        break;
    case RET_INTEGER:
        epilog.havoc(machine.regs[0].value);
        epilog.assign(machine.regs[0].region, T_NUM);
        break;
    case RET_VOID:
        epilog.assign(machine.regs[0].region, T_UNINIT);
        break;
    }
    return { epilog.label() };
}

vector<basic_block_label_t> instruction_builder_t::exec_alu()
{
    assert((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU
         ||(inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64);
    auto& dst = machine.regs[inst.dst];
    auto& src = machine.regs[inst.src];

    int imm = inst.imm;

    // TODO: add assertion for all operators that the arguments are initialized
    // TODO: or, just do dst_initialized = dst_initialized & src_initialized
    /*if (inst.opcode & EBPF_SRC_REG) {
        assert_init(block, machine.regs[inst.src], di);
    }
    assert_init(block, machine.regs[inst.dst], di);*/
    switch (inst.opcode) {
    case EBPF_OP_LE:
    case EBPF_OP_BE:
        block.havoc(dst.value);
        no_pointer(block, dst);
        break;

    case EBPF_OP_ADD_IMM:
    case EBPF_OP_ADD64_IMM:
        block.add(dst.value, dst.value, imm);
        block.add(dst.offset, dst.offset, imm);
        break;
    case EBPF_OP_ADD_REG:
    case EBPF_OP_ADD64_REG:
        block.add(dst.value, dst.value, src.value);
        // FIX: handle "offset := value + offset" 
        // and region := (pointer + value || value + pointer) ? pointer : number
        // How do we do meet? Should we assume something?
        block.add(dst.offset, dst.offset, src.value); // XXX note src.value
        break;
    case EBPF_OP_SUB_IMM:
    case EBPF_OP_SUB64_IMM:
        block.sub(dst.value, dst.value, imm);
        block.sub(dst.offset, dst.offset, imm);
        break;
    case EBPF_OP_SUB_REG:
    case EBPF_OP_SUB64_REG:
        // FIX: unsafe. check for same-pointer substraction
        // i.e.: either same region, or one is T_NUM
        block.sub(dst.value, dst.offset, src.offset);
        block.sub(dst.offset, dst.offset, src.value); // XXX note src.value
        break;
    case EBPF_OP_MUL_IMM:
    case EBPF_OP_MUL64_IMM:
        block.mul(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MUL_REG:
    case EBPF_OP_MUL64_REG:
        block.mul(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV64_IMM:
        block.div(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV_REG:
    case EBPF_OP_DIV64_REG:
        block.assertion(src.value != 0, di);
        block.div(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR_IMM:
    case EBPF_OP_OR64_IMM:
        block.bitwise_or(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR_REG:
    case EBPF_OP_OR64_REG:
        block.assertion(src.value != 0, di);
        block.bitwise_or(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND_IMM:
    case EBPF_OP_AND64_IMM:
        block.bitwise_and(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND_REG:
    case EBPF_OP_AND64_REG:
        block.bitwise_and(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH_IMM:
    case EBPF_OP_LSH64_IMM:
        block.lshr(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH_REG:
    case EBPF_OP_LSH64_REG:
        block.lshr(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH_IMM:
    case EBPF_OP_RSH64_IMM:
        block.ashr(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH_REG:
    case EBPF_OP_RSH64_REG:
        block.ashr(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_NEG64:
        block.assign(dst.value, 0-dst.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD_IMM:
    case EBPF_OP_MOD64_IMM:
        block.rem(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD_REG:
    case EBPF_OP_MOD64_REG:
        block.assertion(src.value != 0, di);
        block.rem(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR_IMM:
    case EBPF_OP_XOR64_IMM:
        block.bitwise_xor(dst.value, dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR_REG:
    case EBPF_OP_XOR64_REG:
        block.bitwise_xor(dst.value, dst.value, src.value);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV_IMM:
    case EBPF_OP_MOV64_IMM:
        block.assign(dst.value, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV_REG:
    case EBPF_OP_MOV64_REG:
        block.assign(dst.value, src.value);
        block.assign(dst.offset, src.offset);
        block.assign(dst.region, src.region);
        break;
    case EBPF_OP_ARSH_IMM:
    case EBPF_OP_ARSH64_IMM:
        block.ashr(dst.value, dst.value, imm); // = (int64_t)dst >> imm;
        no_pointer(block, dst);
        break;
    case EBPF_OP_ARSH_REG:
    case EBPF_OP_ARSH64_REG:
        block.ashr(dst.value, dst.value, src.value); // = (int64_t)dst >> src;
        no_pointer(block, dst);
        break;
    default:
        printf("%d\n", inst.opcode);
        assert(false);
        break;
    }
    if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU)
        wrap32(block, dst.value);

    return { block.label() };
}
