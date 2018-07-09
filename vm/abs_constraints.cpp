
#include <vector>
#include <string>

#include "ebpf.h"

#include "abs_common.hpp"

#include "abs_constraints.hpp"

using std::tuple;

constraints::constraints(basic_block_t& entry)
{
    for (int i=0; i < 16; i++) {
        regs.emplace_back(vfac, i);
    }
    entry.assume(regs[10].value != 0);
    entry.assume(regs[10].offset == 0);
    entry.assume(regs[1].value != 0);
    entry.assume(regs[1].offset == 0);
}

static int access_width(uint8_t opcode)
{
    switch (opcode) {
    case EBPF_OP_LDXB:
    case EBPF_OP_STB:
    case EBPF_OP_STXB: return 1;
    case EBPF_OP_LDXH:
    case EBPF_OP_STH:
    case EBPF_OP_STXH: return 2;
    case EBPF_OP_LDXW:
    case EBPF_OP_STW:
    case EBPF_OP_STXW: return 4;
    case EBPF_OP_LDXDW:
    case EBPF_OP_STDW:
    case EBPF_OP_STXDW: return 8;
    default: return -1;
    }
}

static lin_cst_t jmp_to_cst_offsets(uint8_t opcode, int imm, var_t& dst, var_t& src)
{
    switch (opcode) {
    case EBPF_OP_JEQ_REG:
        return lin_cst_t(dst - src, lin_cst_t::EQUALITY);

    case EBPF_OP_JGE_REG:  return dst >= src; // FIX unsigned
    case EBPF_OP_JSGE_REG: return dst >= src;
    case EBPF_OP_JLE_REG:  return dst <= src; // FIX unsigned
    case EBPF_OP_JSLE_REG: return dst <= src;
    case EBPF_OP_JNE_REG:
        return lin_cst_t(dst - src, lin_cst_t::DISEQUATION);
    
    case EBPF_OP_JGT_REG:  return dst > src; // FIX unsigned
    case EBPF_OP_JSGT_REG: return dst > src;

    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return src > dst; // FIX unsigned
    case EBPF_OP_JSLT_REG: return src > dst;
    }
    return dst - dst == 0;
}


static lin_cst_t jmp_to_cst(uint8_t opcode, int imm, var_t& dst, var_t& src)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM:  return dst == imm;
    case EBPF_OP_JEQ_REG:
        return lin_cst_t(dst - src, lin_cst_t::EQUALITY);

    case EBPF_OP_JGE_IMM:  return dst >= imm; // FIX unsigned
    case EBPF_OP_JGE_REG:  return dst >= src; // FIX unsigned

    case EBPF_OP_JSGE_IMM: return dst >= imm;
    case EBPF_OP_JSGE_REG: return dst >= src;
    
    case EBPF_OP_JLE_IMM:  return dst <= imm; // FIX unsigned
    case EBPF_OP_JLE_REG:  return dst <= src; // FIX unsigned
    case EBPF_OP_JSLE_IMM: return dst <= imm;
    case EBPF_OP_JSLE_REG: return dst <= src;

    case EBPF_OP_JNE_IMM:  return dst != imm;
    case EBPF_OP_JNE_REG:
        return lin_cst_t(dst - src, lin_cst_t::DISEQUATION);
    
    case EBPF_OP_JGT_IMM:  return dst > imm; // FIX unsigned
    case EBPF_OP_JGT_REG:  return dst > src; // FIX unsigned
    case EBPF_OP_JSGT_IMM: return dst > imm;
    case EBPF_OP_JSGT_REG: return dst > src;

    case EBPF_OP_JLT_IMM:  return dst < imm; // FIX unsigned
    // Note: reverse the test as a workaround strange lookup:
    case EBPF_OP_JLT_REG:  return src > dst; // FIX unsigned
    case EBPF_OP_JSLT_IMM: return dst < imm;
    case EBPF_OP_JSLT_REG: return src > dst;
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

static void wrap32(basic_block_t& block, var_t& dst)
{
    block.bitwise_and(dst, dst, UINT32_MAX);
}

static bool is_load(uint8_t opcode)
{
    return ((opcode & EBPF_CLS_MASK) == EBPF_CLS_LD)
        || ((opcode & EBPF_CLS_MASK) == EBPF_CLS_LDX);
}

void constraints::exec(ebpf_inst inst, basic_block_t& block)
{
    exec_offsets(inst, block);
    exec_values(inst, block);
}

void constraints::exec_values(ebpf_inst inst, basic_block_t& block)
{
    var_t& dst = regs[inst.dst].value;
    var_t& src = regs[inst.src].value;
    int imm = inst.imm;

    switch (inst.opcode) {
    case EBPF_OP_ADD_IMM:
        block.add(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_ADD_REG:
        block.add(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_SUB_IMM:
        block.sub(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_SUB_REG:
        block.sub(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_MUL_IMM:
        block.mul(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_MUL_REG:
        block.mul(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_DIV_IMM:
        block.div(dst, dst, src); // TODO: u32(dst) / u32(imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_DIV_REG:
        block.div(dst, dst, src); // TODO: u32(dst) / u32(src);
        wrap32(block, dst);
        break;
    case EBPF_OP_OR_IMM:
        block.bitwise_or(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_OR_REG:
        block.bitwise_or(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_AND_IMM:
        block.bitwise_and(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_AND_REG:
        block.bitwise_and(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_LSH_IMM:
        block.shl(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_LSH_REG:
        block.shl(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_RSH_IMM:
        block.lshr(dst, dst, imm); // TODO u32(dst) >> imm;
        wrap32(block, dst);
        break;
    case EBPF_OP_RSH_REG:
        block.lshr(dst, dst, src); // TODO u32(dst) >> src;
        wrap32(block, dst);
        break;
    case EBPF_OP_NEG:
        block.mul(dst, dst, -1); // ???
        wrap32(block, dst);
        break;
    case EBPF_OP_MOD_IMM:
        block.rem(dst, dst, imm); // FIX: dst = u32(dst) % u32(imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_MOD_REG:
        block.rem(dst, dst, src); // FIX: dst = u32(dst) % u32(src);
        break;
    case EBPF_OP_XOR_IMM:
        block.bitwise_xor(dst, dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_XOR_REG:
        block.bitwise_xor(dst, dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_MOV_IMM:
        block.assign(dst, imm);
        wrap32(block, dst);
        break;
    case EBPF_OP_MOV_REG:
        block.assign(dst, src);
        wrap32(block, dst);
        break;
    case EBPF_OP_ARSH_IMM:
        block.ashr(dst, dst, imm); // FIX: (int32_t)dst >> imm;
        wrap32(block, dst);
        break;
    case EBPF_OP_ARSH_REG:
        block.ashr(dst, dst, src); // FIX = (int32_t)dst >> u32(src);
        wrap32(block, dst);
        break;

    case EBPF_OP_LE:
        // TODO: implement
        block.havoc(dst);
        /*
        if (imm == 16) {
            dst = htole16(dst);
        } else if (imm == 32) {
            dst = htole32(dst);
        } else if (imm == 64) {
            dst = htole64(dst);
        }*/
        break;
    case EBPF_OP_BE:
        // TODO: implement
        block.havoc(dst);
        /*
        if (imm == 16) {
            dst = htobe16(dst);
        } else if (imm == 32) {
            dst = htobe32(dst);
        } else if (imm == 64) {
            dst = htobe64(dst);
        }*/
        break;

    case EBPF_OP_ADD64_IMM:
        block.add(dst, dst, imm);
        break;
    case EBPF_OP_ADD64_REG:
        block.add(dst, dst, src);
        break;
    case EBPF_OP_SUB64_IMM:
        block.sub(dst, dst, imm);
        break;
    case EBPF_OP_SUB64_REG:
        block.sub(dst, dst, src);
        break;
    case EBPF_OP_MUL64_IMM:
        block.mul(dst, dst, imm);
        break;
    case EBPF_OP_MUL64_REG:
        block.mul(dst, dst, src);
        break;
    case EBPF_OP_DIV64_IMM:
        block.div(dst, dst, imm);
        break;
    case EBPF_OP_DIV64_REG:
        block.div(dst, dst, src);
        break;
    case EBPF_OP_OR64_IMM:
        block.bitwise_or(dst, dst, imm);
        break;
    case EBPF_OP_OR64_REG:
        block.bitwise_or(dst, dst, src);
        break;
    case EBPF_OP_AND64_IMM:
        block.bitwise_and(dst, dst, imm);
        break;
    case EBPF_OP_AND64_REG:
        block.bitwise_and(dst, dst, src);
        break;
    case EBPF_OP_LSH64_IMM:
        block.lshr(dst, dst, imm);
        break;
    case EBPF_OP_LSH64_REG:
        block.lshr(dst, dst, src);
        break;
    case EBPF_OP_RSH64_IMM:
        block.ashr(dst, dst, imm);
        break;
    case EBPF_OP_RSH64_REG:
        block.ashr(dst, dst, src);
        break;
    case EBPF_OP_NEG64:
        block.mul(dst, dst, -1); // ???
        break;
    case EBPF_OP_MOD64_IMM:
        block.rem(dst, dst, imm);
        break;
    case EBPF_OP_MOD64_REG:
        block.rem(dst, dst, src);
        break;
    case EBPF_OP_XOR64_IMM:
        block.bitwise_xor(dst, dst, imm);
        break;
    case EBPF_OP_XOR64_REG:
        block.bitwise_xor(dst, dst, src);
        break;
    case EBPF_OP_MOV64_IMM:
        block.assign(dst, imm);
        break;
    case EBPF_OP_MOV64_REG:
        block.assign(dst, src);
        break;
    case EBPF_OP_ARSH64_IMM:
        block.ashr(dst, dst, imm); // = (int64_t)dst >> imm;
        break;
    case EBPF_OP_ARSH64_REG:
        block.ashr(dst, dst, src); // = (int64_t)dst >> src;
        break;
    case EBPF_OP_LDDW:
        block.assign(dst, (uint32_t)inst.imm | ((uint64_t)imm << 32));
        break;
    case EBPF_OP_CALL:
        for (int i=1; i<=5; i++)
            block.havoc(regs[i].value);
        block.havoc(regs[0].value);
        break;
    default:
        // jumps - no op
        int width = access_width(inst.opcode);
        if (width > 0) {
            // loads and stores are handles by offsets
            auto [memreg, target] = is_load(inst.opcode) ? tuple{src, dst} : tuple{dst, src};
            block.assertion(memreg != 0);
            if (is_load(inst.opcode)) {
                block.havoc(target);
            }
        }
        break;
    }  
}

void constraints::exec_offsets(ebpf_inst inst, basic_block_t& block)
{
    var_t& dst = regs[inst.dst].offset;
    var_t& src = regs[inst.src].offset;
    int imm = inst.imm;

    switch (inst.opcode) {
    case EBPF_OP_ADD_IMM:
        block.add(dst, dst, imm);
        break;
    case EBPF_OP_ADD_REG:
        block.add(dst, dst, src);
        break;
    case EBPF_OP_SUB_IMM:
        block.sub(dst, dst, imm);
        break;
    case EBPF_OP_SUB_REG:
        // TODO: meet of this and "value - value"
        block.sub(dst, dst, src);
        break;
    case EBPF_OP_MUL_IMM:
    case EBPF_OP_MUL_REG:
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV_REG:
    case EBPF_OP_OR_IMM:
    case EBPF_OP_OR_REG:
    case EBPF_OP_AND_IMM:
    case EBPF_OP_AND_REG:
    case EBPF_OP_LSH_IMM:
    case EBPF_OP_LSH_REG:
    case EBPF_OP_RSH_IMM:
    case EBPF_OP_RSH_REG:
    case EBPF_OP_NEG:
    case EBPF_OP_MOD_IMM:
    case EBPF_OP_MOD_REG:
    case EBPF_OP_XOR_IMM:
    case EBPF_OP_XOR_REG:
        block.havoc(dst);
        break;
    case EBPF_OP_MOV_IMM: // Meaningless for offset
        block.havoc(dst);
        break;
    case EBPF_OP_MOV_REG:
        block.assign(dst, src);
        // wrap32(block, dst); TODO: verify that this is harmless
        break;
    case EBPF_OP_ARSH_IMM:
    case EBPF_OP_ARSH_REG:

    case EBPF_OP_LE:
    case EBPF_OP_BE:
        block.havoc(dst);
        break;

    case EBPF_OP_ADD64_IMM:
        block.add(dst, dst, imm);
        break;
    case EBPF_OP_ADD64_REG:
        block.add(dst, dst, src);
        break;
    case EBPF_OP_SUB64_IMM:
        block.sub(dst, dst, imm);
        break;
    case EBPF_OP_SUB64_REG:
        // TODO: meet of this and "value - value"
        block.sub(dst, dst, src);
        break;
    case EBPF_OP_MUL64_IMM:
    case EBPF_OP_MUL64_REG:
    case EBPF_OP_DIV64_IMM:
    case EBPF_OP_DIV64_REG:
    case EBPF_OP_OR64_IMM:
    case EBPF_OP_OR64_REG:
    case EBPF_OP_AND64_IMM:
    case EBPF_OP_AND64_REG:
    case EBPF_OP_LSH64_IMM:
    case EBPF_OP_LSH64_REG:
    case EBPF_OP_RSH64_IMM:
    case EBPF_OP_RSH64_REG:
    case EBPF_OP_NEG64:
    case EBPF_OP_MOD64_IMM:
    case EBPF_OP_MOD64_REG:
    case EBPF_OP_XOR64_IMM:
    case EBPF_OP_XOR64_REG:
        block.havoc(dst);
        break;
    case EBPF_OP_MOV64_IMM: // Meaningless for offsets
        block.havoc(dst);
        break;
    case EBPF_OP_MOV64_REG:
        block.assign(dst, src);
        break;
    case EBPF_OP_ARSH64_IMM:
    case EBPF_OP_ARSH64_REG:
    case EBPF_OP_LDDW:
        block.havoc(dst);
        break;
    case EBPF_OP_CALL:
        for (int i=1; i<=5; i++) {
            block.havoc(regs[i].offset);
        }
        if (inst.imm == 0x1) {
            block.assign(regs[0].offset, 0);
        } else {
            block.havoc(regs[0].offset);
        }
        break;
    default:
        // jumps - no op
        int width = access_width(inst.opcode);
        if (width > 0) {
            auto [memreg, target] = is_load(inst.opcode) ? tuple{src, dst} : tuple{dst, src};
            uint8_t r = is_load(inst.opcode) ? inst.src : inst.dst;
            if (r == 10) {
                auto offset = -inst.offset;
                // not dynamic
                assert(offset >= width);
                assert(offset <= STACK_SIZE);
                if (is_load(inst.opcode)) {
                    block.array_load(target, stack, offset, width);
                } else {
                    block.array_store(stack, offset, target, width);
                }
            } else if (r == 1) {
                auto addr = memreg + inst.offset;
                block.assertion(addr >= 0);
                block.assertion(addr <= 4096 - width);
                if (is_load(inst.opcode)) {
                    block.array_load(target, ctx, addr, width);
                } else {
                    block.array_store(ctx, addr, target, width);
                }
            } else if (is_load(inst.opcode)) {
                block.havoc(target);
            }
        }
        break;
    }  
}
