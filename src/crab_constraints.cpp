#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include <optional>

#include <inttypes.h>
#include <assert.h>

#include "spec_type_descriptors.hpp"
#include "spec_prototypes.hpp"

#include "crab_common.hpp"
#include "crab_constraints.hpp"
#include "crab_verifier.hpp"

#include "asm_syntax.hpp"
#include "asm_cfg.hpp"

using std::tuple;
using std::string;
using std::vector;
using std::optional;
using std::to_string;

using crab::cfg_impl::variable_factory_t;

static int first_num(const basic_block_t& block)
{
    return first_num(block.label());
}

static basic_block_t& add_common_child(cfg_t& cfg, basic_block_t& block, std::vector<basic_block_label_t> labels, std::string suffix)
{
    basic_block_t& child = cfg.insert(block.label() + ":" + suffix);
    for (auto label : labels)
        cfg.get_node(label) >> child;
    return child;
}

static basic_block_t& add_child(cfg_t& cfg, basic_block_t& block, std::string suffix)
{
    return add_common_child(cfg, block, {block.label()}, suffix);
}

using crab::cfg::debug_info;

using var_t     = ikos::variable<ikos::z_number, varname_t>;
using lin_cst_t = ikos::linear_constraint<ikos::z_number, varname_t>;

enum region_t {
    T_UNINIT = -5,
    T_NUM = -4,
    T_CTX = -3,
    T_STACK = -2,
    T_DATA = -1,
    T_MAP = 0,
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

struct array_dom_t {
    variable_factory_t& vfac;
    var_t values;
    var_t offsets;
    var_t regions;
    array_dom_t(variable_factory_t& vfac, std::string name) :
        vfac(vfac),
        values{vfac[std::string(name + "_r")], crab::ARR_INT_TYPE, 64}, 
        offsets{vfac[std::string(name + "_off")], crab::ARR_INT_TYPE, 64},
        regions{vfac[std::string(name + "_t")], crab::ARR_INT_TYPE, 8}
    { }
    template<typename T, typename W>
    vector<basic_block_t*> load(basic_block_t& block, dom_t data_reg, const T& offset, W width, cfg_t& cfg) {
        block.array_load(data_reg.value, values, offset, width);
        block.array_load(data_reg.region, regions, offset, 1);
        block.array_load(data_reg.offset, offsets, offset, width);
        return { &block };
    }
    
    template<typename T, typename W>
    vector<basic_block_t*> store(basic_block_t& block, const T& offset, const dom_t data_reg, W width, debug_info di, cfg_t& cfg) {
        var_t lb{vfac["lb"], crab::INT_TYPE, 64};
        var_t ub{vfac["ub"], crab::INT_TYPE, 64};
        block.assign(lb, offset);
        block.assign(ub, offset + width);
        block.array_init(regions, 1, lb, ub, data_reg.region);

        basic_block_t& pointer_only = add_child(cfg, block, "pointer_only");
        pointer_only.assume(data_reg.region > T_NUM);
        pointer_only.array_store(offsets, offset, data_reg.offset, width);
        pointer_only.array_store(values, offset, data_reg.value, width);

        basic_block_t& num_only = add_child(cfg, block, "num_only");
        num_only.assume(data_reg.region == T_NUM);
        num_only.array_store(values, offset, data_reg.value, width);
        // kill the cell
        num_only.array_store(offsets, offset, data_reg.offset, width);
        // so that relational domains won't think it's worth keeping track of
        num_only.havoc(data_reg.offset); 

        return {&num_only, &pointer_only};
    }
};

struct machine_t final
{
    ptype_descr ctx_desc;
    variable_factory_t& vfac;
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "S"};
    var_t meta_size{vfac[std::string("meta_size")], crab::INT_TYPE, 64};
    var_t data_size{vfac[std::string("data_size")], crab::INT_TYPE, 64};
    var_t top{vfac[std::string("*")], crab::INT_TYPE, 64};
    var_t num{vfac[std::string("T_NUM")], crab::INT_TYPE, 64};

    program_info info;

    dom_t& reg(Value v) {
        return regs[std::get<Reg>(v).v];
    }

    void setup_entry(basic_block_t& entry);

    machine_t(variable_factory_t& vfac, program_info info);
};

class instruction_builder_t final
{
public:
    vector<basic_block_t*> exec();
    instruction_builder_t(machine_t& machine, Instruction ins, basic_block_t& block, cfg_t& cfg) :
        machine(machine), ins(ins), block(block), cfg(cfg), pc(first_num(block)),
        di{"pc", (unsigned int)pc, 0}
        {
        }
private:
    machine_t& machine;
    Instruction ins;
    basic_block_t& block;
    cfg_t& cfg;

    // derived fields
    int pc;
    debug_info di;

    void scratch_regs(basic_block_t& block);
    static void no_pointer(basic_block_t& block, dom_t v);

    template<typename W>
    vector<basic_block_t*> exec_stack_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width);

    template<typename W>
    vector<basic_block_t*> exec_map_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width);

    template<typename W>
    vector<basic_block_t*> exec_data_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width);

    template<typename W>
    vector<basic_block_t*> exec_ctx_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width);

    vector<basic_block_t*> exec_direct_stack_load(basic_block_t& block, dom_t data_reg, int _offset, int width);

    vector<basic_block_t*> exec_direct_stack_store(basic_block_t& block, dom_t data_reg, int _offset, int width);
    
    vector<basic_block_t*> exec_direct_stack_store_immediate(basic_block_t& block, int _offset, int width, uint64_t immediate);

    template<typename W>
    vector<basic_block_t*> exec_mem_access_indirect(basic_block_t& block, bool is_load, bool is_st, dom_t mem_reg, dom_t data_reg, int offset, W width);

    vector<basic_block_t*> operator()(Undefined const& a);
    vector<basic_block_t*> operator()(LoadMapFd const& ld);
    vector<basic_block_t*> operator()(Bin const& b);
    vector<basic_block_t*> operator()(Un const& b);
    vector<basic_block_t*> operator()(Call const& b);
    vector<basic_block_t*> operator()(Exit const& b);
    vector<basic_block_t*> operator()(Jmp const& b) { assert(false); }
    vector<basic_block_t*> operator()(LockAdd const& b) { assert(false); }
    vector<basic_block_t*> operator()(Packet const& b);
    vector<basic_block_t*> operator()(Mem const& b);
    vector<basic_block_t*> operator()(Assume const& b);
    vector<basic_block_t*> operator()(Assert const& b) { return {}; };

    bool is_priviledged() {
        return machine.info.program_type == BpfProgType::KPROBE;
    }
};

void build_crab_cfg(cfg_t& cfg, variable_factory_t& vfac, Cfg const& simple_cfg, program_info info)
{
    machine_t machine(vfac, info);
    {
        auto& entry = cfg.insert(entry_label());
        machine.setup_entry(entry);
        entry >> cfg.insert(label(0));
    }
    for (auto const& this_label : simple_cfg.keys()) {
        auto const& bb = simple_cfg.at(this_label);
        basic_block_t* exit = &cfg.insert(this_label);
        if (bb.insts.size() > 0) {
            int iteration = 0;
            string label = this_label;
            for (auto ins : bb.insts) {
                basic_block_t& this_block = cfg.insert(label);
                if (iteration > 0) {
                    (*exit) >> this_block;
                }
                exit = &cfg.insert(exit_label(this_block.label()));
                vector<basic_block_t*> outs = instruction_builder_t(machine, ins, this_block, cfg).exec();
                for (basic_block_t* b : outs)
                    (*b) >> *exit;
                iteration++;
                
                label = this_label + ":" + to_string(iteration);
            }
        }
        if (bb.nextlist.size() == 0) {
            cfg.set_exit(exit->label());
        } else {
            for (auto label : bb.nextlist)
                *exit >> cfg.insert(label);
        }
    }
    if (global_options.simplify) {
        cfg.simplify();
    }
}


static lin_cst_t is_pointer(dom_t v) { return v.region >= T_CTX; }
static lin_cst_t is_init(dom_t v)    { return v.region >= T_NUM; }
static lin_cst_t is_map(dom_t v)     { return v.region >= T_MAP; }


static void assert_init(basic_block_t& block, const dom_t data_reg, debug_info di)
{
    block.assertion(is_init(data_reg), di);
}

machine_t::machine_t(variable_factory_t& vfac, program_info info)
    : ctx_desc{get_descriptor(info.program_type)}, vfac{vfac}, info{info}
{
    for (int i=0; i < 12; i++) {
        regs.emplace_back(vfac, i);
    }
}

void machine_t::setup_entry(basic_block_t& entry)
{
    auto& machine = *this;
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

    entry.assume(0 <= machine.data_size);
    if (machine.ctx_desc.meta >= 0) {
        entry.assume(machine.meta_size <= 0);
    } else {
        entry.assign(machine.meta_size, 0);
    }
}

static lin_cst_t eq(var_t& a, var_t& b)  { return {a - b, lin_cst_t::EQUALITY}; }

static lin_cst_t neq(var_t& a, var_t& b) { return {a - b, lin_cst_t::DISEQUATION}; };

static lin_cst_t jmp_to_cst_offsets_reg(Condition::Op op, var_t& dst_offset, var_t& src_offset)
{
    using Op = Condition::Op;
    switch (op) {
        case Op::EQ : return eq(dst_offset, src_offset);
        case Op::NE : return neq(dst_offset, src_offset);
        case Op::GE : return dst_offset >= src_offset; // FIX unsigned
        case Op::SGE: return dst_offset >= src_offset;
        case Op::LE : return dst_offset <= src_offset; // FIX unsigned
        case Op::SLE: return dst_offset <= src_offset;
        case Op::GT : return dst_offset >= src_offset + 1; // FIX unsigned
        case Op::SGT: return dst_offset >= src_offset + 1;
        case Op::SLT: return src_offset >= dst_offset + 1;
        // Note: reverse the test as a workaround strange lookup:
        case Op::LT : return src_offset >= dst_offset + 1; // FIX unsigned
        default:
            return dst_offset - dst_offset == 0;
    }
}

static vector<lin_cst_t> jmp_to_cst_imm(Condition::Op op, var_t& dst_value, int imm)
{
    using Op = Condition::Op;
    switch (op) {
        case Op::EQ : return {dst_value == imm};
        case Op::NE : return {dst_value != imm};
        case Op::GE : return {dst_value >= (unsigned)imm}; // FIX unsigned
        case Op::SGE: return {dst_value >= imm};
        case Op::LE : return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
        case Op::SLE: return {dst_value <= imm};
        case Op::GT : return {dst_value >= (unsigned)imm + 1}; // FIX unsigned
        case Op::SGT: return {dst_value >= imm + 1};
        case Op::LT : return {dst_value <= (unsigned)imm - 1}; // FIX unsigned
        case Op::SLT: return {dst_value <= imm - 1};
        case Op::SET: throw std::exception();
        case Op::NSET: assert(false);
    }
    assert(false);
}

static vector<lin_cst_t> jmp_to_cst_reg(Condition::Op op, var_t& dst_value, var_t& src_value)
{
    using Op = Condition::Op;
    switch (op) {
        case Op::EQ : return {eq(dst_value, src_value)};
        case Op::NE : return {neq(dst_value, src_value)};
        case Op::GE : return {dst_value >= src_value}; // FIX unsigned
        case Op::SGE: return {dst_value >= src_value};
        case Op::LE : return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
        case Op::SLE: return {dst_value <= src_value};
        case Op::GT : return {dst_value >= src_value + 1}; // FIX unsigned
        case Op::SGT: return {dst_value >= src_value + 1};
        // Note: reverse the test as a workaround strange lookup:
        case Op::LT : return {src_value >= dst_value + 1}; // FIX unsigned
        case Op::SLT: return {src_value >= dst_value + 1};
        case Op::SET: throw std::exception();
        case Op::NSET: assert(false);
    }
    assert(false);
}


static void wrap32(basic_block_t& block, var_t& dst_value)
{
    block.bitwise_and(dst_value, dst_value, UINT32_MAX);
}


void instruction_builder_t::no_pointer(basic_block_t& block, dom_t v)
{
    block.assign(v.region, T_NUM);
    block.havoc(v.offset);
}

template <typename T>
static void move_into(vector<T>& dst, vector<T>&& src)
{
    dst.insert(dst.end(),
        std::make_move_iterator(src.begin()),
        std::make_move_iterator(src.end())
    );
}

void instruction_builder_t::scratch_regs(basic_block_t& block)
{
    for (int i=1; i<=5; i++) {
        block.havoc(machine.regs[i].value);
        block.havoc(machine.regs[i].offset);
        block.assign(machine.regs[i].region, T_UNINIT);
    }
}

template<typename W>
vector<basic_block_t*> instruction_builder_t::exec_stack_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width)
{
    basic_block_t& mid = add_child(cfg, block, "assume_stack");
    lin_exp_t addr = (-offset) - width - mem_reg.offset; // negate access
    
    mid.assume(mem_reg.region == T_STACK);
    mid.assertion(addr >= 0, di);
    mid.assertion(addr <= STACK_SIZE - width, di);
    if (is_load) {
        machine.stack_arr.load(mid, data_reg, addr, width, cfg);
        mid.assume(is_init(data_reg));
        /* FIX: requires loop
        var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 64};
        for (int idx=1; idx < width; idx++) {
            mid.array_load(tmp, machine.stack_arr.regions, addr+idx, 1);
            mid.assertion(eq(tmp, data_reg.region), di);
        }*/
        return { &mid };
    } else {
        assert_init(mid, data_reg, di);
        auto res = machine.stack_arr.store(mid, addr, data_reg, width, di, cfg);
        mid.havoc(machine.top);
        return res;
    }
}

template<typename W>
vector<basic_block_t*> instruction_builder_t::exec_map_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width)
{
    vector<basic_block_t*> res;
    int map_index = 0;
    for (map_def def : machine.info.map_defs) {
        basic_block_t& mid = add_child(cfg, block, "assume_map" + std::to_string(map_index));
        lin_exp_t addr = mem_reg.offset + offset;

        mid.assume(mem_reg.region == map_index); //is_map(mem_reg));
        mid.assertion(addr >= 0, di);
        mid.assertion(addr <= def.value_size - width, di);
        if (is_load) {
            mid.havoc(data_reg.value);
            mid.assign(data_reg.region, T_NUM);
            mid.havoc(data_reg.offset);
        } else {
            mid.assertion(data_reg.region == T_NUM, di);
        }
        res.push_back(&mid);
        map_index++;
    }
    return res;
}

template<typename W>
vector<basic_block_t*> instruction_builder_t::exec_data_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width)
{
    basic_block_t& mid = add_child(cfg, block, "assume_data");
    lin_exp_t addr = mem_reg.offset + offset;

    mid.assume(mem_reg.region == T_DATA);
    mid.assertion(machine.meta_size <= addr, di);
    mid.assertion(addr <= machine.data_size - width, di);
    if (is_load) {
        mid.havoc(data_reg.offset);
        mid.havoc(data_reg.value);
        mid.assign(data_reg.region, T_NUM);
    }
    return { &mid };
}

template<typename W>
vector<basic_block_t*> instruction_builder_t::exec_ctx_access(basic_block_t& block, bool is_load, dom_t mem_reg, dom_t data_reg, int offset, W width)
{
    basic_block_t& mid = add_child(cfg, block, "assume_ctx");
    mid.assume(mem_reg.region == T_CTX);
    lin_exp_t addr = mem_reg.offset + offset;
    mid.assertion(addr >= 0, di);
    mid.assertion(addr <= machine.ctx_desc.size - width, di);

    ptype_descr desc = machine.ctx_desc;
    auto assume_normal = [&](basic_block_t& b) {
        if (desc.data >= 0) {
            b.assume(addr != desc.data);
            b.assume(addr != desc.end);
            if (desc.meta >= 0) {
                b.assume(addr != desc.meta);
            }
        }
    };
    if (is_load) {
        vector<basic_block_t*> ret;
        auto load_datap = [&](string suffix, int start, auto offset) {
            basic_block_t& b = add_child(cfg, mid, suffix);
            b.assume(addr == start);
            b.assign(data_reg.region, T_DATA);
            b.havoc(data_reg.value);
            b.assume(4098 <= data_reg.value);
            b.assign(data_reg.offset, offset);
            ret.push_back(&b);
        };
        if (desc.data >= 0) {
            load_datap("data_start", desc.data, 0);
            load_datap("data_end", desc.end, machine.data_size);
            if (desc.meta >= 0) {
                load_datap("meta", desc.meta, machine.meta_size);
            }
        }

        basic_block_t& normal = add_child(cfg, mid, "assume_ctx_not_special");
        assume_normal(normal);
        normal.assign(data_reg.region, T_NUM);
        normal.havoc(data_reg.offset);
        normal.havoc(data_reg.value);
        ret.push_back(&normal);
        return ret;
    } else {
        assume_normal(mid);
        mid.assertion(data_reg.region == T_NUM, di);
        return { &mid };
    }
}

static inline void assert_in_stack(basic_block_t& block, int offset, int width, debug_info di) {
    // NOP - should be done in the validator
}
/* Here for the unlikely case the width is dynamic
static void assert_in_stack(basic_block_t& block, int offset, var_t width, debug_info di) {
    auto start = (-offset) - width;
    block.assertion(start >= 0, di);
    block.assertion(start + width <= STACK_SIZE, di);
}
*/

int get_start(int offset, int width) {
    return (-offset) - width;
}

vector<basic_block_t*> instruction_builder_t::exec_direct_stack_load(basic_block_t& block, dom_t data_reg, int offset, int width)
{
    assert_in_stack(block, offset, width, di);
    int start = get_start(offset, width);
    auto blocks = machine.stack_arr.load(block, data_reg, start, width, cfg);
    for (auto b : blocks) {
        b->assume(is_init(data_reg));

        /* FIX
        var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 64};
        for (int idx=1; idx < width; idx++) {
            b->array_load(tmp, machine.stack_arr.regions, offset+idx, 1);
            b->assertion(eq(tmp, data_reg.region), di);
        }
        */
    }
    return blocks;
}

vector<basic_block_t*> instruction_builder_t::exec_direct_stack_store(basic_block_t& block, dom_t data_reg, int offset, int width)
{
    assert_in_stack(block, offset, width, di);
    assert_init(block, data_reg, di);
    return machine.stack_arr.store(block, (-offset) - width, data_reg, width, di, cfg);
}

vector<basic_block_t*> instruction_builder_t::exec_direct_stack_store_immediate(basic_block_t& block, int offset, int width, uint64_t immediate)
{
    assert_in_stack(block, offset, width, di);
    int start = get_start(offset, width);
    var_t lb{machine.vfac["lb"], crab::INT_TYPE, 64};
    var_t ub{machine.vfac["ub"], crab::INT_TYPE, 64};
    block.assign(lb, start);
    block.assign(ub, start + width);
    block.array_init(machine.stack_arr.regions, 1, lb, ub, T_NUM);

    block.havoc(machine.top);
    block.array_init(machine.stack_arr.offsets, 1, lb, ub, machine.top);

    block.array_store(machine.stack_arr.values, start, immediate, width);
    return { &block };
}


template<typename W>
vector<basic_block_t*> instruction_builder_t::exec_mem_access_indirect(basic_block_t& block, bool is_load, bool is_ST, dom_t mem_reg, dom_t data_reg, int offset, W width)
{
    block.assertion(mem_reg.value != 0, di);
    block.assertion(mem_reg.region != T_NUM, di);
    vector<basic_block_t*> outs;
    
    move_into(outs, exec_stack_access(block, is_load, mem_reg, data_reg, offset, width));
    if (is_load || !is_ST) {
        move_into(outs, exec_ctx_access(block, is_load, mem_reg, data_reg, offset, width));
    } else {
        // "BPF_ST stores into R1 context is not allowed"
        // (This seems somewhat arbitrary)
        block.assertion(mem_reg.region != T_CTX, di);
    }
    move_into(outs, exec_map_access(block, is_load, mem_reg, data_reg, offset, width));
    if (machine.ctx_desc.data >= 0) {
        move_into(outs, exec_data_access(block, is_load, mem_reg, data_reg, offset, width));
    }
    return outs;
}

void assert_no_overflow(basic_block_t& b, var_t v, debug_info di) {
    // p1 = data_start; p1 += huge_positive; p1 <= p2 does not imply p1 >= data_start
    // We assume that pointers are 32 bit so slight overflow is still sound
    b.assertion(v <= 1 << 30 , di);
    b.assertion(v >= -4098 , di);
}


vector<basic_block_t*> instruction_builder_t::operator()(Undefined const& a) {
    assert(false);
}

vector<basic_block_t*> instruction_builder_t::operator()(LoadMapFd const& ld) {
    // we're a per-process file descriptor defining the map.
    // (for details, look for BPF_PSEUDO_MAP_FD in the kernel)
    // This is what Arg::MAP_FD looks for
    // This is probably the wrong thing to do. should we add an FD type?
    // Here we (probably) need the map structure
    if (ld.mapfd >= machine.info.map_defs.size()) {
        block.assertion(neq(machine.num, machine.num), di);
    }
    auto reg = machine.reg(ld.dst);
    block.assign(reg.region, ld.mapfd);
    block.havoc(reg.value);
    block.havoc(reg.offset);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Bin const& bin) {    
    dom_t& dst = machine.reg(bin.dst);
    vector<basic_block_t*> res{ &block };

    // TODO: add assertion for all operators that the arguments are initialized
    // TODO: or, just do dst_initialized = dst_initialized & src_initialized
    /*if (inst.opcode & EBPF_SRC_REG) {
        assert_init(block, machine.regs[inst.src], di);
    }
    assert_init(block, machine.regs[inst.dst], di);*/
    if (std::holds_alternative<Imm>(bin.v)) {
        int imm = static_cast<int>(get<Imm>(bin.v).v);
        switch (bin.op) {
        case Bin::Op::MOV:
            block.assign(dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::ADD:
            block.add(dst.value, dst.value, imm);
            block.add(dst.offset, dst.offset, imm);
            break;
        case Bin::Op::SUB:
            block.sub(dst.value, dst.value, imm);
            block.sub(dst.offset, dst.offset, imm);
            break;
        case Bin::Op::MUL:
            block.mul(dst.value, dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::DIV:
            block.div(dst.value, dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::MOD:
            block.rem(dst.value, dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::OR:
            block.bitwise_or(dst.value, dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::AND:
            // FIX: what to do with ptr&-8 as in counter/simple_loop_unrolled?
            block.bitwise_and(dst.value, dst.value, imm);
            if ((int32_t)imm > 0) {
                block.assume(dst.value <= imm);
                block.assume(0 <= dst.value);
            }
            no_pointer(block, dst);
            break;
        case Bin::Op::RSH:
            block.ashr(dst.value, dst.value, imm);
            block.assume(dst.value <= (1 << (64-imm)));
            block.assume(dst.value >= 0);
            no_pointer(block, dst);
            break;
        case Bin::Op::LSH:
            block.lshr(dst.value, dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::XOR:
            block.bitwise_xor(dst.value, dst.value, imm);
            no_pointer(block, dst);
            break;
        case Bin::Op::ARSH:
            block.ashr(dst.value, dst.value, imm); // = (int64_t)dst >> imm;
            block.assume(dst.value <= (1 << (64-imm)));
            block.assume(dst.value >= -(1 << (64-imm)));
            no_pointer(block, dst);
            break;
        } 
    } else {
        dom_t& src = machine.reg(bin.v);
        switch (bin.op) {
        case Bin::Op::ADD: {
                basic_block_t& ptr_dst = add_child(cfg, block, "ptr_dst");
                ptr_dst.assume(is_pointer(dst));
                ptr_dst.assertion(src.region == T_NUM , di);
                ptr_dst.add(dst.offset, dst.offset, src.value);
                ptr_dst.add(dst.value, dst.value, src.value);
                assert_no_overflow(ptr_dst, dst.offset, di);

                basic_block_t& ptr_src = add_child(cfg, block, "ptr_src");
                ptr_src.assume(is_pointer(src));
                ptr_src.assertion(dst.region == T_NUM , di);
                ptr_src.add(dst.offset, dst.value, src.offset);
                ptr_src.add(dst.value, dst.value, src.value);
                assert_no_overflow(ptr_src, dst.offset, di);
                ptr_src.assign(dst.region, src.region);
                ptr_src.havoc(machine.top);
                ptr_src.assign(dst.value, machine.top);
                ptr_src.assume(4098 <= dst.value);
                
                basic_block_t& both_num = add_child(cfg, block, "both_num");
                both_num.assume(dst.region == T_NUM);
                both_num.assume(src.region == T_NUM);
                both_num.add(dst.value, dst.value, src.value);

                res = {&ptr_src, &ptr_dst, &both_num};
                return res;
            }
            break;
        case Bin::Op::SUB: {
                basic_block_t& same = add_child(cfg, block, "ptr_src");
                same.assume(is_pointer(src));
                same.assertion(is_pointer(dst), di);
                same.assertion(dst.region < T_MAP, di); // since map values of the same type can point to different maps
                same.assertion(eq(dst.region, src.region), di);
                same.sub(dst.value, dst.offset, src.offset);
                same.assign(dst.region, T_NUM);
                same.havoc(dst.offset);

                basic_block_t& num_src = add_child(cfg, block, "num_src");
                num_src.assume(src.region == T_NUM);
                {
                    basic_block_t& ptr_dst = add_child(cfg, num_src, "ptr_dst");
                    ptr_dst.assume(is_pointer(dst));
                    ptr_dst.sub(dst.offset, dst.offset, src.value);
                    assert_no_overflow(ptr_dst, dst.offset, di);

                    basic_block_t& both_num = add_child(cfg, num_src, "both_num");    
                    both_num.assume(dst.region == T_NUM);
                    both_num.sub(dst.value, dst.value, src.value);
                    res = {&same, &ptr_dst, &both_num};
                }
            }
            break;
        case Bin::Op::MUL:
            block.mul(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::DIV:
            // For some reason, DIV is not checked for zerodiv
            block.div(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::MOD:
            // See DIV comment
            block.rem(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::OR:
            block.bitwise_or(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::AND:
            block.bitwise_and(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::LSH:
            block.lshr(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::RSH:
            block.ashr(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::XOR:
            block.bitwise_xor(dst.value, dst.value, src.value);
            no_pointer(block, dst);
            break;
        case Bin::Op::MOV:
            block.assign(dst.value, src.value);
            block.assign(dst.offset, src.offset);
            block.assign(dst.region, src.region);
            break;
        case Bin::Op::ARSH:
            block.ashr(dst.value, dst.value, src.value); // = (int64_t)dst >> src;
            no_pointer(block, dst);
            break;
        }
    }

    if (!bin.is64)
        for (auto b : res) {
            wrap32(*b, dst.value);
        }

    return res;
}

vector<basic_block_t*> instruction_builder_t::operator()(Un const& b) {
    dom_t& dst = machine.reg(b.dst);

    switch (b.op) {
    case Un::Op::LE16:
    case Un::Op::LE32:
    case Un::Op::LE64:
        block.havoc(dst.value);
        break;
    case Un::Op::NEG:
        block.assign(dst.value, 0-dst.value);
        break;
    }
    no_pointer(block, dst);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Call const& call) {
    vector<basic_block_t*> blocks{&block};
    var_t map_type{machine.vfac["map_type"], crab::INT_TYPE, 8};
    auto assert_pointer_or_null = [&](dom_t arg, lin_cst_t cst) {
        vector<basic_block_t*> next;
        for (auto b : blocks) {
            basic_block_t& pointer = add_child(cfg, *b, "pointer");
            pointer.assume(cst);
            next.push_back(&pointer);

            basic_block_t& null = add_child(cfg, *b, "null");
            null.assume(arg.region == T_NUM);
            null.assertion(arg.value == 0, di);
            next.push_back(&null);
        }
        blocks = std::move(next);
    };
    for (ArgSingle param : call.singles) {
        dom_t arg = machine.regs[param.reg.v];
        switch (param.kind) {
        case ArgSingle::Kind::ANYTHING:
            // avoid pointer leakage:
            if (!is_priviledged()) {
                for (basic_block_t* b : blocks) {
                    b->assertion(arg.region == T_NUM, di);
                }
            }
            break;
        case ArgSingle::Kind::MAP_FD:
            //assert_pointer_or_null(is_map(arg));
            for (basic_block_t* b : blocks) {
                b->assign(map_type, arg.region);
                b->assertion(map_type < machine.info.map_defs.size(), di);
                b->assertion(map_type >= 0, di);
            }
            break;
        case ArgSingle::Kind::PTR_TO_MAP_KEY:
            for (basic_block_t* b : blocks) {
                b->assertion(arg.value > 0, di);
                b->assertion(is_pointer(arg), di);
            }
            break;
        case ArgSingle::Kind::PTR_TO_MAP_VALUE:
            for (basic_block_t* b : blocks) {
                b->assertion(arg.value > 0, di);
                b->assertion(arg.region == T_STACK, di);
                b->assertion(arg.offset < 0, di);
            }
            break;
        case ArgSingle::Kind::PTR_TO_CTX: 
            for (basic_block_t* b : blocks) {
                b->assertion(arg.value > 0, di);
                b->assertion(arg.region == T_CTX, di);
                b->assertion(arg.offset >= 0, di);
            }
            break;
        }
    }
    for (ArgPair param : call.pairs) {
        dom_t arg = machine.regs[param.mem.v];
        dom_t sizereg = machine.regs[param.size.v];
        for (basic_block_t* b : blocks) {
            b->assertion(sizereg.region == T_NUM, di);
            if (param.can_be_zero) {
                b->assertion(sizereg.value >= 0, di);
            } else {
                b->assertion(sizereg.value > 0, di);
            }
        }
        switch (param.kind) {
            case ArgPair::Kind::PTR_TO_MEM_OR_NULL:
                assert_pointer_or_null(arg, is_pointer(arg));
                // TODO: mem access when not null
                break;
            case ArgPair::Kind::PTR_TO_MEM:  {
                    vector<basic_block_t*> next;
                    for (basic_block_t* b : blocks) {
                        b->assertion(arg.value > 0, di);
                        b->assertion(is_pointer(arg), di);
                        var_t width = machine.regs[param.size.v].value;
                        b->havoc(machine.top);
                        move_into(next, exec_mem_access_indirect(*b, true, false, arg, { machine.top, machine.top, machine.top }, 0, width));
                    }
                    for (auto b: next) {
                        b->havoc(machine.top);
                    }
                    blocks = std::move(next);
                }
                break;
            case ArgPair::Kind::PTR_TO_UNINIT_MEM: {
                    vector<basic_block_t*> next;
                    for (basic_block_t* b : blocks) {
                        b->assertion(is_pointer(arg), di);
                        b->assertion(arg.offset <= 0, di);
                        var_t width = sizereg.value;
                        b->havoc(machine.top);
                        move_into(next, exec_mem_access_indirect(*b, false, false, arg, { machine.top, machine.top, machine.num }, 0, width));
                    }
                    for (auto b: next) {
                        b->havoc(machine.top);
                    }
                    blocks = std::move(next);
                }
                break;
        }
    }
    dom_t r0 = machine.regs[0];
    for (auto b: blocks) {
        scratch_regs(*b);
        if (call.returns_map) {
            //if (machine.info.map_defs.at(map_type).type == MapType::ARRAY_OF_MAPS
            // || machine.info.map_defs.at(map_type).type == MapType::HASH_OF_MAPS) { }
            b->assign(r0.region, map_type);
            b->havoc(r0.value);
            b->assume(0 <= r0.value);
            b->assign(r0.offset, 0);
        } else {
            b->havoc(r0.value);
            b->assign(r0.region, T_NUM);
            b->havoc(r0.offset);
            // b->assume(r0.value < 0); for VOID
        }
    }
    return blocks;
}

vector<basic_block_t*> instruction_builder_t::operator()(Exit const& b) {
    // assert_init(block, machine.regs[0], di);
    block.assertion(machine.regs[0].region == T_NUM, di);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Assume const& b) {
    Condition cond = b.cond;
    if (std::holds_alternative<Reg>(cond.right)) {
        assert_init(block, machine.reg(cond.right), di);
    }
    assert_init(block, machine.reg(cond.left), di);

    dom_t& dst = machine.reg(cond.left);
    if (std::holds_alternative<Reg>(cond.right)) {
        dom_t& src = machine.reg(cond.right);
        basic_block_t& same = add_child(cfg, block, "same_type");
        for (auto c : jmp_to_cst_reg(cond.op, dst.value, src.value))
            same.assume(c);
        same.assume(eq(dst.region, src.region));

        basic_block_t& null_src = add_child(cfg, block, "null_src");
        null_src.assume(src.region == T_NUM);
        null_src.assume(is_pointer(dst));
        null_src.assertion(src.value == 0, di);

        basic_block_t& null_dst = add_child(cfg, block, "null_dst");
        null_dst.assume(dst.region == T_NUM);
        null_dst.assume(is_pointer(src));
        null_dst.assertion(dst.value == 0, di);

        auto prevs = {same.label(), null_src.label(), null_dst.label()};
        basic_block_t& offset_check = add_common_child(cfg, block, prevs, "offsets_check");

        lin_cst_t offset_cst = jmp_to_cst_offsets_reg(cond.op, dst.offset, src.offset);
        if (!offset_cst.is_tautology()) {
            offset_check.assume(offset_cst);
        }
        return { &offset_check };
    } else {
        int imm = static_cast<int>(std::get<Imm>(cond.right).v);
        vector<lin_cst_t> csts = jmp_to_cst_imm(cond.op, dst.value, imm);
        for (lin_cst_t c : csts)
            block.assume(c);
        if (!is_priviledged() && imm != 0) {
            // only null can be compared to pointers without leaking secrets
            block.assertion(dst.region == T_NUM, di);
        }
        return { &block };
    }
}

vector<basic_block_t*> instruction_builder_t::operator()(Packet const& b) {
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
    block.assertion(machine.regs[6].region == T_CTX, di);
    block.assign(machine.regs[0].region, T_NUM);
    block.havoc(machine.regs[0].offset);
    block.havoc(machine.regs[0].value);
    scratch_regs(block);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Mem const& b) {
    dom_t mem_reg =  machine.reg(b.access.basereg);
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
                var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 64};
                block.assign(tmp, imm);
                block.havoc(machine.top);
                return exec_mem_access_indirect(block, false, true, mem_reg, {tmp, machine.top, machine.num}, offset, width);
            } 
        }
    }
}

vector<basic_block_t*> instruction_builder_t::exec()
{
    return std::visit([this](auto const& a) { return (*this)(a); }, ins);
}
