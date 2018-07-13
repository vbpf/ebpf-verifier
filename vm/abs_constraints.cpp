#include <iostream>
#include <vector>
#include <string>

#include "ebpf.h"

#include "abs_common.hpp"

#include "abs_constraints.hpp"

using std::tuple;
enum region_t {
    T_NUM,
    T_STACK,
    T_CTX,
    T_DATA,
    T_MAP,
};

constraints::constraints(basic_block_t& entry)
{
    for (int i=0; i < 16; i++) {
        regs.emplace_back(vfac, i);
    }
    entry.assume(regs[10].value != 0);
    entry.assign(regs[10].offset, 0);
    entry.assign(regs[10].region, T_STACK);
    entry.assume(regs[1].value != 0);
    entry.assign(regs[1].offset, 0);
    entry.assign(regs[1].region, T_CTX);
}

static bool is_load(uint8_t opcode)
{
    switch (opcode & EBPF_CLS_MASK) {
    case EBPF_CLS_LD:
    case EBPF_CLS_LDX:
        return true;
    default:
        return false;
    }
}

static bool is_store(uint8_t opcode)
{
    switch (opcode & EBPF_CLS_MASK) {
    case EBPF_CLS_ST:
    case EBPF_CLS_STX:
        return true;
    default:
        return false;
    }
}

static bool is_access(uint8_t opcode)
{
    return is_load(opcode) || is_store(opcode);
}


static int access_width(uint8_t opcode)
{
    if (!is_access(opcode))
        return -1;
    switch (opcode & EBPF_SIZE_MASK) {
    case EBPF_SIZE_B: return 1;
    case EBPF_SIZE_H: return 2;
    case EBPF_SIZE_W: return 4;
    case EBPF_SIZE_DW: return 8;
    default: assert(false);
    }
}

static lin_cst_t jmp_to_cst_offsets(uint8_t opcode, int imm, var_t& odst, var_t& osrc)
{
    switch (opcode) {
    case EBPF_OP_JEQ_REG:
        return lin_cst_t(odst - osrc, lin_cst_t::EQUALITY);

    case EBPF_OP_JGE_REG:  return odst >= osrc; // FIX unsigned
    case EBPF_OP_JSGE_REG: return odst >= osrc;
    case EBPF_OP_JLE_REG:  return odst <= osrc; // FIX unsigned
    case EBPF_OP_JSLE_REG: return odst <= osrc;
    case EBPF_OP_JNE_REG:
        return lin_cst_t(odst - osrc, lin_cst_t::DISEQUATION);
    
    case EBPF_OP_JGT_REG:  return odst > osrc; // FIX unsigned
    case EBPF_OP_JSGT_REG: return odst > osrc;

    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return osrc > odst; // FIX unsigned
    case EBPF_OP_JSLT_REG: return osrc > odst;
    }
    return odst - odst == 0;
}


static lin_cst_t jmp_to_cst(uint8_t opcode, int imm, var_t& vdst, var_t& vsrc)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM:  return vdst == imm;
    case EBPF_OP_JEQ_REG:
        return lin_cst_t(vdst - vsrc, lin_cst_t::EQUALITY);

    case EBPF_OP_JGE_IMM:  return vdst >= imm; // FIX unsigned
    case EBPF_OP_JGE_REG:  return vdst >= vsrc; // FIX unsigned

    case EBPF_OP_JSGE_IMM: return vdst >= imm;
    case EBPF_OP_JSGE_REG: return vdst >= vsrc;
    
    case EBPF_OP_JLE_IMM:  return vdst <= imm; // FIX unsigned
    case EBPF_OP_JLE_REG:  return vdst <= vsrc; // FIX unsigned
    case EBPF_OP_JSLE_IMM: return vdst <= imm;
    case EBPF_OP_JSLE_REG: return vdst <= vsrc;

    case EBPF_OP_JNE_IMM:  return vdst != imm;
    case EBPF_OP_JNE_REG:
        return lin_cst_t(vdst - vsrc, lin_cst_t::DISEQUATION);
    
    case EBPF_OP_JGT_IMM:  return vdst > imm; // FIX unsigned
    case EBPF_OP_JGT_REG:  return vdst > vsrc; // FIX unsigned
    case EBPF_OP_JSGT_IMM: return vdst > imm;
    case EBPF_OP_JSGT_REG: return vdst > vsrc;

    case EBPF_OP_JLT_IMM:  return vdst < imm; // FIX unsigned
    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return vsrc > vdst; // FIX unsigned
    case EBPF_OP_JSLT_IMM: return vdst < imm;
    case EBPF_OP_JSLT_REG: return vsrc > vdst;
    }
    assert(false);
}

static uint8_t reverse(uint8_t opcode)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM:  return EBPF_OP_JNE_IMM;
    case EBPF_OP_JEQ_REG:  return EBPF_OP_JNE_REG;

    case EBPF_OP_JGE_IMM:  return EBPF_OP_JLT_IMM;
    case EBPF_OP_JGE_REG:  return EBPF_OP_JLT_REG;

    case EBPF_OP_JSGE_IMM: return EBPF_OP_JSLT_IMM;
    case EBPF_OP_JSGE_REG: return EBPF_OP_JSLT_REG;
    
    case EBPF_OP_JLE_IMM:  return EBPF_OP_JGT_IMM;
    case EBPF_OP_JLE_REG:  return EBPF_OP_JGT_REG;

    case EBPF_OP_JSLE_IMM: return EBPF_OP_JSGT_IMM;
    case EBPF_OP_JSLE_REG: return EBPF_OP_JSGT_REG;

    case EBPF_OP_JNE_IMM:  return EBPF_OP_JEQ_IMM;
    case EBPF_OP_JNE_REG:  return EBPF_OP_JEQ_REG;
    
    case EBPF_OP_JGT_IMM:  return EBPF_OP_JLE_IMM;
    case EBPF_OP_JGT_REG:  return EBPF_OP_JLE_REG;
    case EBPF_OP_JSGT_IMM: return EBPF_OP_JSLE_IMM;
    case EBPF_OP_JSGT_REG: return EBPF_OP_JSLE_REG;

    case EBPF_OP_JLT_IMM:  return EBPF_OP_JGE_IMM;
    case EBPF_OP_JLT_REG:  return EBPF_OP_JGE_REG;
    case EBPF_OP_JSLT_IMM: return EBPF_OP_JSGE_IMM;
    case EBPF_OP_JSLT_REG: return EBPF_OP_JSGE_REG;
    } 
    assert(false);
}


void constraints::jump(ebpf_inst inst, basic_block_t& block, bool taken)
{
    uint8_t opcode = taken ? inst.opcode : reverse(inst.opcode);
    lin_cst_t cst = jmp_to_cst(opcode, inst.imm, regs[inst.dst].value, regs[inst.src].value);
    block.assume(cst);

    lin_cst_t offset_cst = jmp_to_cst_offsets(opcode, inst.imm, regs[inst.dst].offset, regs[inst.src].offset);
    if (!offset_cst.is_tautology()) {
        block.assume(offset_cst);
    }
}

static void wrap32(basic_block_t& block, var_t& vdst)
{
    block.bitwise_and(vdst, vdst, UINT32_MAX);
}


void constraints::no_pointer(basic_block_t& block, constraints::dom_t& v)
{
    block.havoc(v.offset);
    block.assign(v.region, T_NUM);
}

struct desc {
    int size;
    int data;
    int end;
    int meta; // data to meta is like end to data. i.e. meta <= data <= end
    constexpr desc(int _size, int _data, int _end, int _meta) : size(_size), data(_data), end(_end), meta(_meta) { }
};
static constexpr desc sk_buff = { 24*4, 15*4, 16*4, 23*4};
static constexpr desc xdp_md = { 5*4, 0, 1*4, 2*4};
static constexpr desc sk_msg_md = { 11*4, 0, 1*4, -1};
static constexpr desc ctx_desc = xdp_md;

void constraints::exec(ebpf_inst inst, basic_block_t& block, basic_block_t& exit, unsigned int _pc, cfg_t& cfg)
{
    crab::cfg::debug_info di{"", _pc, 0};
    exit.assign(pc, _pc+1);
    block.assign(pc, pc);

    auto& dst = regs[inst.dst];

    var_t& vdst = regs[inst.dst].value;
    var_t& odst = regs[inst.dst].offset;
    var_t& rdst = regs[inst.dst].region;

    var_t& src = regs[inst.src].value;
    var_t& osrc = regs[inst.src].offset;
    var_t& rsrc = regs[inst.src].region;

    int imm = inst.imm;

    bool exit_linked = false;

    switch (inst.opcode) {
    case EBPF_OP_ADD_IMM:
        block.add(vdst, vdst, imm);
        wrap32(block, vdst);
        block.add(odst, odst, imm);
        break;
    case EBPF_OP_ADD_REG:
        block.add(vdst, vdst, src);
        wrap32(block, vdst);
        block.add(odst, odst, src);
        break;
    case EBPF_OP_SUB_IMM:
        block.sub(vdst, vdst, imm);
        wrap32(block, vdst);
        block.sub(odst, odst, imm);
        break;
    case EBPF_OP_SUB_REG:
        block.sub(vdst, vdst, src);
        wrap32(block, vdst);
        // TODO: meet of this and "odst - odst" if same region
        block.sub(odst, odst, src);
        break;
    case EBPF_OP_MUL_IMM:
        block.mul(vdst, vdst, imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MUL_REG:
        block.mul(vdst, vdst, src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV_IMM:
        block.div(vdst, vdst, src); // TODO: u32(vdst) / u32(imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV_REG:
        block.div(vdst, vdst, src); // TODO: u32(vdst) / u32(src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR_IMM:
        block.bitwise_or(vdst, vdst, imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR_REG:
        block.bitwise_or(vdst, vdst, src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND_IMM:
        block.bitwise_and(vdst, vdst, imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND_REG:
        block.bitwise_and(vdst, vdst, src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH_IMM:
        block.shl(vdst, vdst, imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH_REG:
        block.shl(vdst, vdst, src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH_IMM:
        block.lshr(vdst, vdst, imm); // TODO u32(vdst) >> imm;
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH_REG:
        block.lshr(vdst, vdst, src); // TODO u32(vdst) >> src;
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_NEG:
        block.mul(vdst, vdst, -1); // ???
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD_IMM:
        block.rem(vdst, vdst, imm); // FIX: vdst = u32(vdst) % u32(imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD_REG:
        block.rem(vdst, vdst, src); // FIX: vdst = u32(vdst) % u32(src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR_IMM:
        block.bitwise_xor(vdst, vdst, imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR_REG:
        block.bitwise_xor(vdst, vdst, src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV_IMM:
        block.assign(vdst, imm);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV_REG:
        block.assign(vdst, src);
        wrap32(block, vdst);
        block.assign(odst, osrc);
        block.assign(rdst, rsrc);
        break;
    case EBPF_OP_ARSH_IMM:
        block.ashr(vdst, vdst, imm); // FIX: (int32_t)dst >> imm;
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;
    case EBPF_OP_ARSH_REG:
        block.ashr(vdst, vdst, src); // FIX = (int32_t)dst >> u32(src);
        wrap32(block, vdst);
        no_pointer(block, dst);
        break;

    case EBPF_OP_LE:
    case EBPF_OP_BE:
        block.havoc(vdst);
        no_pointer(block, dst);
        break;

    case EBPF_OP_ADD64_IMM:
        block.add(vdst, vdst, imm);
        block.add(odst, odst, imm);
        break;
    case EBPF_OP_ADD64_REG:
        block.add(vdst, vdst, src);
        block.add(odst, odst, src);
        break;
    case EBPF_OP_SUB64_IMM:
        block.sub(vdst, vdst, imm);
        block.sub(odst, odst, imm);
        break;
    case EBPF_OP_SUB64_REG:
        block.sub(odst, odst, osrc);
        block.sub(odst, odst, src);
        break;
    case EBPF_OP_MUL64_IMM:
        block.mul(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MUL64_REG:
        block.mul(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV64_IMM:
        block.div(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_DIV64_REG:
        block.div(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR64_IMM:
        block.bitwise_or(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_OR64_REG:
        block.bitwise_or(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND64_IMM:
        block.bitwise_and(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_AND64_REG:
        block.bitwise_and(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH64_IMM:
        block.lshr(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_LSH64_REG:
        block.lshr(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH64_IMM:
        block.ashr(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_RSH64_REG:
        block.ashr(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_NEG64:
        block.mul(vdst, vdst, -1); // ???
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD64_IMM:
        block.rem(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOD64_REG:
        block.rem(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR64_IMM:
        block.bitwise_xor(vdst, vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_XOR64_REG:
        block.bitwise_xor(vdst, vdst, src);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV64_IMM:
        block.assign(vdst, imm);
        no_pointer(block, dst);
        break;
    case EBPF_OP_MOV64_REG:
        block.assign(vdst, src);
        block.assign(odst, osrc);
        block.assign(rdst, rsrc);
        break;
    case EBPF_OP_ARSH64_IMM:
        block.ashr(vdst, vdst, imm); // = (int64_t)dst >> imm;
        no_pointer(block, dst);
        break;
    case EBPF_OP_ARSH64_REG:
        block.ashr(vdst, vdst, src); // = (int64_t)dst >> src;
        no_pointer(block, dst);
        break;
    case EBPF_OP_LDDW:
        block.assign(vdst, (uint32_t)inst.imm | ((uint64_t)imm << 32));
        no_pointer(block, dst);
        break;
    case EBPF_OP_JEQ_IMM:
    case EBPF_OP_JEQ_REG:
    case EBPF_OP_JGE_IMM:
    case EBPF_OP_JGE_REG:
    case EBPF_OP_JSGE_IMM:
    case EBPF_OP_JSGE_REG:
    case EBPF_OP_JLE_IMM:
    case EBPF_OP_JLE_REG:
    case EBPF_OP_JSLE_IMM:
    case EBPF_OP_JSLE_REG:
    case EBPF_OP_JNE_IMM:
    case EBPF_OP_JNE_REG:
    case EBPF_OP_JGT_IMM:
    case EBPF_OP_JGT_REG:
    case EBPF_OP_JSGT_IMM:
    case EBPF_OP_JSGT_REG:
    case EBPF_OP_JLT_IMM:
    case EBPF_OP_JLT_REG:
    case EBPF_OP_JSLT_IMM:
    case EBPF_OP_JSLT_REG:
    case EBPF_OP_JA:
    case EBPF_OP_EXIT:
        break;

    case EBPF_OP_CALL:
        for (int i=1; i<=5; i++) {
            block.havoc(regs[i].value);
            block.havoc(regs[i].region);
            block.havoc(regs[i].offset);
        }
        if (inst.imm == 0x1) {
            block.assign(regs[0].offset, 0);
            block.assign(regs[0].region, T_MAP);
            block.havoc(regs[0].value);
            block.assume(regs[0].value != 0);
        } else {
            block.havoc(regs[0].offset);
            block.havoc(regs[0].value);
            block.havoc(regs[0].region);
        }
        break;
    default:
        int width = access_width(inst.opcode);
        if (width <= 0) {
            std::cout << "bad instruction " << (int)inst.opcode << " at "<< _pc << "\n";
        } else {
            // loads and stores are handles by offsets
            uint8_t mem = is_load(inst.opcode) ? inst.src : inst.dst;
            //uint8_t target = is_load(inst.opcode) ? inst.dst : inst.src;

            block.assertion(regs[mem].value != 0, di);
            block.assertion(regs[mem].region != T_NUM, di);

            if (mem == 10) {
                auto offset = -inst.offset;
                // not dynamic
                assert(offset >= width);
                assert(offset <= STACK_SIZE);
                if (is_load(inst.opcode)) {
                    stack_arr.load(block, regs[inst.dst], offset, width);
                } else {
                    stack_arr.store(block, offset, regs[inst.src], width);
                }
            } else {
                {
                    auto& mid = cfg.insert(label(_pc)+"-assume_stack");
                    block >> mid;
                    mid >> exit;
                    auto addr = regs[mem].offset - inst.offset;
                    mid.assume(regs[mem].region == T_STACK);
                    mid.assertion(addr >= width, di);
                    mid.assertion(addr <= STACK_SIZE - width, di);
                    if (is_load(inst.opcode)) {
                        stack_arr.load(mid, regs[inst.dst], addr, width);
                    } else {
                        stack_arr.store(mid, addr, regs[inst.src], width);
                    }
                }
                {
                    auto& mid = cfg.insert(label(_pc)+"-assume_ctx");
                    block >> mid;
                    auto addr = regs[mem].offset + inst.offset;
                    mid.assume(regs[mem].region == T_CTX);
                    mid.assertion(addr >= 0, di);
                    mid.assertion(addr <= ctx_desc.size - width, di);
                    if (is_load(inst.opcode)) {
                        if (ctx_desc.data >= 0) {
                            auto& start = cfg.insert(label(_pc)+"-assume_data_start");
                            mid >> start;
                            start >> exit;
                            start.assume(addr == ctx_desc.data);
                            start.assign(regs[inst.dst].region, T_DATA);
                            start.assume(regs[inst.dst].value > ctx_desc.data);
                            start.assume(regs[inst.dst].offset <= data_end);
                            start.assign(regs[inst.dst].offset, data);
                        }
                        if (ctx_desc.data >= 0) {
                            auto& end = cfg.insert(label(_pc)+"-assume_data_end");
                            mid >> end;
                            end >> exit;
                            end.assume(addr == ctx_desc.end);
                            end.assign(regs[inst.dst].region, T_DATA);
                            end.assume(regs[inst.dst].value > ctx_desc.end);
                            end.assign(regs[inst.dst].offset, data_end);
                        }
                        if (ctx_desc.meta >= 0) {
                            auto& meta = cfg.insert(label(_pc)+"-assume_meta");
                            mid >> meta;
                            meta >> exit;
                            meta.assume(addr == ctx_desc.meta);
                            meta.assign(regs[inst.dst].region, T_DATA);
                            meta.assume(regs[inst.dst].value > ctx_desc.meta);
                            meta.assume(regs[inst.dst].offset <= data);
                        }
                        {
                            auto& normal = cfg.insert(label(_pc)+"-assume_not_data");
                            mid >> normal;
                            normal >> exit;
                            if (ctx_desc.data >= 0) {
                                normal.assume(addr != ctx_desc.data);
                                normal.assume(addr != ctx_desc.end);
                            }
                            if (ctx_desc.meta >= 0) {
                                normal.assume(addr != ctx_desc.meta);
                            }
                            ctx_arr.load(normal, regs[inst.dst], addr, width);
                        }
                    } else {
                        ctx_arr.store(mid, addr, regs[inst.src], width);
                        mid >> exit;
                    }
                }
                if (ctx_desc.data >= 0) {
                    auto& mid = cfg.insert(label(_pc)+"-assume_data");
                    block >> mid;
                    mid >> exit;
                    auto addr = regs[mem].offset + inst.offset;
                    mid.assume(regs[mem].region == T_DATA);
                    mid.assertion(addr >= 0, di);
                    mid.assertion(addr <= data_end - width, di);
                    if (is_load(inst.opcode)) {
                        data_arr.load(mid, regs[inst.dst], addr, width);
                    } else {
                        data_arr.store(mid, addr, regs[inst.src], width);
                    }
                }
                {
                    auto& mid = cfg.insert(label(_pc)+"-assume_map");
                    block >> mid;
                    mid >> exit;
                    auto addr = regs[mem].offset - inst.offset;
                    mid.assume(regs[mem].region == T_MAP);
                    mid.assertion(addr >= width, di);
                    constexpr int MAP_SIZE = 8;
                    mid.assertion(addr <= MAP_SIZE - width, di);
                }
                exit_linked = true;
            }
            /* else if (is_load(inst.opcode)) {
                block.havoc(regs[target].value);
                block.havoc(regs[target].offset);
                block.assign(regs[target].region, T_NUM);
            } */
        }
        break;
    }

    if (!exit_linked) {
        block >> exit;
    }
}
