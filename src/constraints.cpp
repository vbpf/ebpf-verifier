#include <iostream>
#include <vector>
#include <string>
#include <type_traits>

#include "common.hpp"
#include "constraints.hpp"
#include "prototypes.hpp"
#include "type_descriptors.hpp"

#include "asm.hpp"

using std::tuple;
using std::string;
using std::vector;

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

static void assert_init(basic_block_t& block, const dom_t data_reg, debug_info di)
{
    block.assertion(data_reg.region >= T_NUM, di);
}

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
        block.array_load(data_reg.region, regions, offset, width);
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
        block.array_store(values, offset, data_reg.value, width);
        // kill the cell
        num_only.array_store(offsets, offset, data_reg.offset, width);
        // so that relational domains won't think it's worth keeping track of
        num_only.havoc(data_reg.offset); 

        return {&num_only, &pointer_only};
    }
};


struct machine_t final
{
    ebpf_prog_type prog_type;
    ptype_descr ctx_desc;
    variable_factory_t& vfac;
    std::vector<dom_t> regs;
    array_dom_t stack_arr{vfac, "S"};
    array_dom_t ctx_arr{vfac, "C"};
    array_dom_t data_arr{vfac, "D"};
    var_t meta_size{vfac[std::string("meta_size")], crab::INT_TYPE, 64};
    var_t data_size{vfac[std::string("data_size")], crab::INT_TYPE, 64};
    var_t top{vfac[std::string("*")], crab::INT_TYPE, 64};
    var_t num{vfac[std::string("T_NUM")], crab::INT_TYPE, 8};

    dom_t& reg(Value v) {
        return regs[static_cast<int>(std::get<Reg>(v))];
    }
    machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac);
};

class instruction_builder_t final
{
public:
    vector<basic_block_t*> exec();
    basic_block_t& jump(bool taken);
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
    vector<basic_block_t*> operator()(Goto const& b);
    vector<basic_block_t*> operator()(Jmp const& b);
    vector<basic_block_t*> operator()(Packet const& b);
    vector<basic_block_t*> operator()(Mem const& b);
    vector<basic_block_t*> operator()(LockAdd const& b);

    bool is_priviledged() {
        return machine.prog_type == 2;
    }
};

abs_machine_t::abs_machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac)
: impl{new machine_t{prog_type, vfac}}
{
}

abs_machine_t::~abs_machine_t() = default;

machine_t::machine_t(ebpf_prog_type prog_type, variable_factory_t& vfac)
    : prog_type(prog_type), ctx_desc{get_descriptor(prog_type)}, vfac{vfac}
{
    for (int i=0; i < 12; i++) {
        regs.emplace_back(vfac, i);
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

    entry.assume(0 <= machine.data_size);
    if (machine.ctx_desc.meta >= 0) {
        entry.assume(machine.meta_size <= 0);
    } else {
        entry.assign(machine.meta_size, 0);
    }
}

static lin_cst_t is_pointer(dom_t v)
{
    return v.region >= T_CTX;
}

static auto eq(var_t& a, var_t& b)
{
    return lin_cst_t(a - b, lin_cst_t::EQUALITY);
}

static auto neq(var_t& a, var_t& b)
{
    return lin_cst_t(a - b, lin_cst_t::DISEQUATION);
}

Jmp::Op reverse(Jmp::Op op)
{
    switch (op) {
    case Jmp::Op::EQ : return Jmp::Op::NE;
    case Jmp::Op::GE : return Jmp::Op::LT;
    case Jmp::Op::SGE: return Jmp::Op::SLT;
    case Jmp::Op::LE : return Jmp::Op::GT;
    case Jmp::Op::SLE: return Jmp::Op::SGT;
    case Jmp::Op::NE : return Jmp::Op::EQ;
    case Jmp::Op::GT : return Jmp::Op::LE;
    case Jmp::Op::SGT: return Jmp::Op::SLE;
    case Jmp::Op::LT : return Jmp::Op::GE;
    case Jmp::Op::SLT: return Jmp::Op::SGE;
    case Jmp::Op::SET: throw std::exception();
    }
}

static lin_cst_t jmp_to_cst_offsets_reg(Jmp::Op op, var_t& dst_offset, var_t& src_offset)
{
    switch (op) {
        case Jmp::Op::EQ : return eq(dst_offset, src_offset);
        case Jmp::Op::NE : return neq(dst_offset, src_offset);
        case Jmp::Op::GE : return dst_offset >= src_offset; // FIX unsigned
        case Jmp::Op::SGE: return dst_offset >= src_offset;
        case Jmp::Op::LE : return dst_offset <= src_offset; // FIX unsigned
        case Jmp::Op::SLE: return dst_offset <= src_offset;
        case Jmp::Op::GT : return dst_offset >= src_offset + 1; // FIX unsigned
        case Jmp::Op::SGT: return dst_offset >= src_offset + 1;
        case Jmp::Op::SLT: return src_offset >= dst_offset + 1;
        // Note: reverse the test as a workaround strange lookup:
        case Jmp::Op::LT : return src_offset >= dst_offset + 1; // FIX unsigned
        default:
            return dst_offset - dst_offset == 0;
    }
}

static vector<lin_cst_t> jmp_to_cst_imm(Jmp::Op op, var_t& dst_value, int imm)
{
    switch (op) {
        case Jmp::Op::EQ : return {dst_value == imm};
        case Jmp::Op::NE : return {dst_value != imm};
        case Jmp::Op::GE : return {dst_value >= (unsigned)imm}; // FIX unsigned
        case Jmp::Op::SGE: return {dst_value >= imm};
        case Jmp::Op::LE : return {dst_value <= imm, 0 <= dst_value}; // FIX unsigned
        case Jmp::Op::SLE: return {dst_value <= imm};
        case Jmp::Op::GT : return {dst_value >= (unsigned)imm + 1}; // FIX unsigned
        case Jmp::Op::SGT: return {dst_value >= imm + 1};
        case Jmp::Op::LT : return {dst_value <= (unsigned)imm - 1}; // FIX unsigned
        case Jmp::Op::SLT: return {dst_value <= imm - 1};
        case Jmp::Op::SET: throw std::exception();
    }
    assert(false);
}

static vector<lin_cst_t> jmp_to_cst_reg(Jmp::Op op, var_t& dst_value, var_t& src_value)
{
    switch (op) {
        case Jmp::Op::EQ : return {eq(dst_value, src_value)};
        case Jmp::Op::NE : return {neq(dst_value, src_value)};
        case Jmp::Op::GE : return {dst_value >= src_value}; // FIX unsigned
        case Jmp::Op::SGE: return {dst_value >= src_value};
        case Jmp::Op::LE : return {dst_value <= src_value, 0 <= dst_value}; // FIX unsigned
        case Jmp::Op::SLE: return {dst_value <= src_value};
        case Jmp::Op::GT : return {dst_value >= src_value + 1}; // FIX unsigned
        case Jmp::Op::SGT: return {dst_value >= src_value + 1};
        // Note: reverse the test as a workaround strange lookup:
        case Jmp::Op::LT : return {src_value >= dst_value + 1}; // FIX unsigned
        case Jmp::Op::SLT: return {src_value >= dst_value + 1};
        case Jmp::Op::SET: throw std::exception();
    }
    assert(false);
}


basic_block_t& instruction_builder_t::jump(bool taken)
{
    Jmp jmp = std::get<Jmp>(ins);
    auto& dst = machine.reg(jmp.left);
    Jmp::Op op = taken ? jmp.op : reverse(jmp.op);
    debug_info di{"pc", (unsigned int)first_num(block), 0}; 
    if (std::holds_alternative<Reg>(jmp.right)) {
        auto& src = machine.reg(jmp.right);
        basic_block_t& same = add_child(cfg, block, "same_type");
        for (auto c : jmp_to_cst_reg(op, dst.value, src.value))
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

        lin_cst_t offset_cst = jmp_to_cst_offsets_reg(op, dst.offset, src.offset);
        if (!offset_cst.is_tautology()) {
            offset_check.assume(offset_cst);
        }
        return offset_check;
    } else {
        int imm = static_cast<int>(std::get<Imm>(jmp.right).v);
        vector<lin_cst_t> csts = jmp_to_cst_imm(op, dst.value, imm);
        for (auto c : csts)
            block.assume(c);
        if (!is_priviledged() && imm != 0) {
            // only null can be compared to pointers without leaking secrets
            block.assertion(dst.region == T_NUM, di);
        }
        return block;
    }
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

basic_block_t& abs_machine_t::jump(Jmp ins, bool taken, basic_block_t& block, cfg_t& cfg) {
    return instruction_builder_t(*impl, ins, block, cfg).jump(taken);
}

vector<basic_block_t*> abs_machine_t::expand_lockadd(LockAdd lock, basic_block_t& block, cfg_t& cfg)
{
    Mem load_ins{
        .width = lock.width,
        .basereg = lock.basereg,
        .offset = 0,
        .value = Mem::Load{11},
    };
    vector<basic_block_t*> loaded = instruction_builder_t(*impl, load_ins, block, cfg).exec();

    Bin add_ins{
        .op = Bin::Op::ADD,
        .is64 = false,
        .dst = Reg{11},
        .v = lock.offset,
    };
    vector<basic_block_t*> added;
    for (auto b: loaded) {
        move_into(added, instruction_builder_t(*impl, add_ins, *b, cfg).exec());
    }

    Mem store_ins{
        .width = lock.width,
        .basereg = lock.basereg,
        .offset = 0,
        .value = Mem::StoreReg{11},
    };
    vector<basic_block_t*> stored;
    for (auto b: added) {
        move_into(stored, instruction_builder_t(*impl, store_ins, *b, cfg).exec());
    }
    return stored;
}

vector<basic_block_t*> abs_machine_t::exec(Instruction ins, basic_block_t& block, cfg_t& cfg)
{
    if (std::holds_alternative<LockAdd>(ins)) {
        return expand_lockadd(get<LockAdd>(ins), block, cfg);
    }
    return instruction_builder_t(*impl, ins, block, cfg).exec(); 
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
        mid.array_load(data_reg.region, machine.stack_arr.regions, addr, 1);
        mid.assume(data_reg.region >= 1);
        /* FIX: requires loop
        var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 8};
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
    basic_block_t& mid = add_child(cfg, block, "assume_map");
    lin_exp_t addr = mem_reg.offset + offset;

    mid.assume(mem_reg.region == T_MAP);
    mid.assertion(addr >= 0, di);
    constexpr int MAP_SIZE = 8192;
    mid.assertion(addr <= MAP_SIZE - width, di);
    if (is_load) {
        mid.havoc(data_reg.value);
        mid.assign(data_reg.region, T_NUM);
        mid.havoc(data_reg.offset);
    } else {
        mid.assertion(data_reg.region == T_NUM, di);
    }
    return { &mid };
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
        auto blocks = machine.data_arr.load(mid, data_reg, addr, width, cfg);
        for (auto b : blocks) {
            b->assign(data_reg.region, T_NUM);
            b->havoc(data_reg.offset);
        }
        return blocks;
    } else {
        mid.assertion(data_reg.region == T_NUM, di);
        return machine.data_arr.store(mid, addr, data_reg, width, di, cfg);
    }
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
        auto blocks = machine.ctx_arr.load(normal, data_reg, addr, width, cfg);
        for (auto b : blocks) {
            b->assign(data_reg.region, T_NUM);
            b->havoc(data_reg.offset);
            ret.push_back(b);
        }
        return ret;
    } else {
        assume_normal(mid);
        mid.assertion(data_reg.region == T_NUM, di);
        return machine.ctx_arr.store(mid, addr, data_reg, width, di, cfg);
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

template<typename W>
auto get_start(int offset, W width) {
    return (-offset) - width;
}

vector<basic_block_t*> instruction_builder_t::exec_direct_stack_load(basic_block_t& block, dom_t data_reg, int offset, int width)
{
    assert_in_stack(block, offset, width, di);
    auto start = get_start(offset, width);
    auto blocks = machine.stack_arr.load(block, data_reg, start, width, cfg);
    for (auto b : blocks) {
        b->array_load(data_reg.region, machine.stack_arr.regions, start, 1);
        b->assume(data_reg.region >= 1);

        /* FIX
        var_t tmp{machine.vfac["tmp"], crab::INT_TYPE, 8};
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
    auto start = get_start(offset, width);
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
    std::cout << "bad instruction " << a.opcode << " at " << first_num(block) << "\n";
    assert(false);
}

vector<basic_block_t*> instruction_builder_t::operator()(LoadMapFd const& ld) {
    // we're a per-process file descriptor defining the map.
    // (for details, look for BPF_PSEUDO_MAP_FD in the kernel)
    // This is what ARG_CONST_MAP_PTR looks for
    // This is probably the wrong thing to do. should we add an FD type?
    // Here we (probably) need the map structure
    block.assign(machine.regs[ld.dst].region, T_MAP);
    block.assign(machine.regs[ld.dst].offset, 0);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Bin const& bin) {
    
            
    auto& dst = machine.regs[bin.dst];

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
            no_pointer(block, dst);
            break;
        } 
    } else {
        auto& src = machine.reg(bin.v);
        switch (bin.op) {
        case Bin::Op::ADD: {
                block.add(dst.value, dst.value, src.value);
                
                basic_block_t& ptr_dst = add_child(cfg, block, "ptr_dst");
                ptr_dst.assume(is_pointer(dst));
                ptr_dst.assertion(src.region == T_NUM , di);
                ptr_dst.add(dst.offset, dst.offset, src.value);
                assert_no_overflow(ptr_dst, dst.offset, di);

                basic_block_t& ptr_src = add_child(cfg, block, "ptr_src");
                ptr_src.assume(is_pointer(src));
                ptr_src.assertion(dst.region == T_NUM , di);
                ptr_src.add(dst.offset, dst.value, src.offset);
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
                same.assume(eq(dst.region, src.region));
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
    auto& dst = machine.regs[b.dst];

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

vector<basic_block_t*> instruction_builder_t::operator()(Call const& b) {
    bpf_func_proto proto = get_prototype(b.func);
    int i = 0;
    vector<basic_block_t*> blocks{&block};
    std::array<bpf_arg_type, 5> args = {{proto.arg1_type, proto.arg2_type, proto.arg3_type, proto.arg4_type, proto.arg5_type}};
    for (bpf_arg_type t : args) {
        dom_t arg = machine.regs[++i];
        if (t == ARG_DONTCARE)
            break;
        auto assert_pointer_or_null = [&](lin_cst_t cst) {
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
        switch (t) {
        case ARG_DONTCARE:
            assert(false);
            break;
        case ARG_ANYTHING:
            // avoid pointer leakage:
            if (!is_priviledged()) {
                for (basic_block_t* b : blocks) {
                    b->assertion(arg.region == T_NUM, di);
                }
            }
            break;
        case ARG_CONST_SIZE:
            for (basic_block_t* b : blocks) {
                b->assertion(arg.region == T_NUM, di);
                b->assertion(arg.value > 0, di);
            }
            break;
        case ARG_CONST_SIZE_OR_ZERO:
            for (basic_block_t* b : blocks) {
                b->assertion(arg.region == T_NUM, di);
                b->assertion(arg.value >= 0, di);
            }
            break;
        case ARG_CONST_MAP_PTR:
            assert_pointer_or_null(arg.region == T_MAP);
            break;
        case ARG_PTR_TO_CTX:
            assert_pointer_or_null(arg.region == T_CTX);
            break;
        case ARG_PTR_TO_MEM_OR_NULL:
            assert_pointer_or_null(is_pointer(arg));
            break;
        case ARG_PTR_TO_MAP_KEY:
            for (basic_block_t* b : blocks) {
                b->assertion(arg.value > 0, di);
                b->assertion(is_pointer(arg), di);
            }
            break;
        case ARG_PTR_TO_MAP_VALUE:
            for (basic_block_t* b : blocks) {
                b->assertion(arg.value > 0, di);
                b->assertion(arg.region == T_STACK, di);
                b->assertion(arg.offset < 0, di);
            }
            break;
        case ARG_PTR_TO_MEM: {
                vector<basic_block_t*> next;
                for (basic_block_t* b : blocks) {
                    b->assertion(arg.value > 0, di);
                    b->assertion(is_pointer(arg), di);
                    var_t width = machine.regs[i+1].value;
                    b->havoc(machine.top);
                    move_into(next, exec_mem_access_indirect(*b, true, false, arg, { machine.top, machine.top, machine.top }, 0, width));
                }
                for (auto b: next) {
                    b->havoc(machine.top);
                }
                blocks = std::move(next);
            }
            break;
        case ARG_PTR_TO_UNINIT_MEM: {
                vector<basic_block_t*> next;
                for (basic_block_t* b : blocks) {
                    b->assertion(is_pointer(arg), di);
                    b->assertion(arg.offset <= 0, di);
                    var_t width = machine.regs[i+1].value;
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
        switch (proto.ret_type) {
        case RET_PTR_TO_MAP_VALUE_OR_NULL:
            b->assign(r0.region, T_MAP);
            b->havoc(r0.value);
            b->assume(0 <= r0.value);
            b->assign(r0.offset, 0);
            break;
        case RET_INTEGER:
            b->havoc(r0.value);
            b->assign(r0.region, T_NUM);
            b->havoc(r0.offset);
            break;
        case RET_VOID:
            // return from tail call - meaning the call has failed; return negative
            b->havoc(r0.value);
            b->assign(r0.region, T_NUM);
            b->havoc(r0.offset);
            b->assume(r0.value < 0);
            break;
        }
    }
    return blocks;
}

vector<basic_block_t*> instruction_builder_t::operator()(Exit const& b) {
    // assert_init(block, machine.regs[0], di);
    block.assertion(machine.regs[0].region == T_NUM, di);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Goto const& b) {
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Jmp const& b) {
    // cfg-related action is handled in build_cfg() and instruction_builder_t::jump()
    if (std::holds_alternative<Reg>(b.right)) {
        assert_init(block, machine.reg(b.right), di);
    }
    assert_init(block, machine.regs[static_cast<int>(b.left)], di);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Packet const& b) {
    int width = (int)b.width;
            
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
    if (b.regoffset) {
        /* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */
        machine.data_arr.load(block, machine.regs[0], machine.regs[*b.regoffset].value + b.offset, width, cfg);
    } else {
        /* Direct packet access, R0 = *(uint *) (skb->data + imm32) */
        machine.data_arr.load(block, machine.regs[0], b.offset, width, cfg);
    }
    block.assign(machine.regs[0].region, T_NUM);
    block.havoc(machine.regs[0].offset);
    scratch_regs(block);
    return { &block };
}

vector<basic_block_t*> instruction_builder_t::operator()(Mem const& b) {
    dom_t mem_reg =  machine.regs.at(b.basereg);
    bool mem_is_fp = (int)b.basereg == 10;
    int width = (int)b.width;
    int offset = (int)b.offset;
    return std::visit(overloaded{
        [&](Mem::Load reg) {
            // data = mem[offset]
            dom_t data_reg = machine.reg((Reg)reg);
            if (mem_is_fp) {
                return exec_direct_stack_load(block, data_reg, offset, width);
            } else {
                return exec_mem_access_indirect(block, true, false, mem_reg, data_reg, offset, width);
            }
        },
        [&](Mem::StoreReg reg) {
            // mem[offset] = data
            dom_t data_reg = machine.reg((Reg)reg);
            if (mem_is_fp) {
                return exec_direct_stack_store(block, data_reg, offset, width);
            } else {
                return exec_mem_access_indirect(block, false, false, mem_reg, data_reg, offset, width);
            }
        },
        [&](Mem::StoreImm imm)  {
            // mem[offset] = immediate  
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
    }, b.value);
}

vector<basic_block_t*> instruction_builder_t::operator()(LockAdd const& b) {
    assert(false);
}

vector<basic_block_t*> instruction_builder_t::exec()
{
    return std::visit([this](auto const& a) { return (*this)(a); }, ins);
}
