#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <assert.h>

#include "ubpf_int.h"

#include "abs_interp.h"

void logg(const char* format, ...)
{
    FILE *fp = fopen("log.txt","a");
    va_list argptr;
    va_start(argptr, format);
    vfprintf(fp, format, argptr);
    va_end(argptr);
    fclose(fp);
}

const struct abs_state abs_bottom = { { 0 }, { 0 }, true }; // second zero makes unknowns

void 
abs_initialize_state(struct abs_state *state)
{
    for (int i = 0; i < 11; i++) {
        state->known[i] = false;
    }
    state->known[1] = false;

    state->known[10] = false;
}

struct abs_state
abs_execute_assume(struct abs_state *_state, struct ebpf_inst inst, bool taken)
{
    struct abs_state res = *_state;
    struct abs_state* state = &res;

    // TODO: check feasibility; this might cause problems with pending.
    if ((taken && inst.opcode == EBPF_OP_JEQ_IMM)
    || (!taken && inst.opcode == EBPF_OP_JNE_IMM)) {
        state->known[inst.dst] = true;
        state->reg[inst.dst] = inst.imm;
    }
    if ((taken && inst.opcode == EBPF_OP_JEQ_REG)
    || (!taken && inst.opcode == EBPF_OP_JNE_REG)) {
        state->known[inst.dst] = true;
        state->reg[inst.dst] = state->reg[inst.src];
        // we don't track correlation
    }
    return res;
}

void
abs_join(struct abs_state *state, struct abs_state other)
{
    if (state->bot) {
        *state = other;
    } else {
        for (int r = 1; r < 11; r++) {
            if (!other.known[r] || state->reg[r] != other.reg[r])
                state->known[r] = false;
        }
    }
}

static int
access_width(uint8_t opcode) {
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

static uint32_t
u32(uint64_t x)
{
    return x;
}

bool
abs_bounds_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg) {
    int width = access_width(inst.opcode);
    if (width <= 0) {
        return false;
    }

    bool is_load = ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_LD)
                || ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_LDX);
    uint8_t r = is_load ? inst.src : inst.dst;
    bool fail;
    if (r == 10) {
        fail = inst.offset + width > 0 || inst.offset < -STACK_SIZE;
    } else if (r == 1) {
        // unsafely assume this is context pointer
        fail = inst.offset < 0 || inst.offset + width > 4096;
    } else {
        fail = true;
    }
    if (fail) {
        *errmsg = ubpf_error("out of bounds memory %s at PC %d [r%d%+d]",
                            is_load ? "load" : "store", pc, is_load ? inst.src : inst.dst, inst.offset);
    }
    return fail;
}

bool
abs_divzero_fail(struct abs_state *state, struct ebpf_inst inst, uint16_t pc, char** errmsg) {
    bool div = (inst.opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_DIV_REG & EBPF_ALU_OP_MASK);
    bool mod = (inst.opcode & EBPF_ALU_OP_MASK) == (EBPF_OP_MOD_REG & EBPF_ALU_OP_MASK);
    if (div || mod) {
        bool is64 = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
        if (!state->known[inst.src]
        || ( is64 &&     state->reg[inst.src]  == 0)
        || (!is64 && u32(state->reg[inst.src]) == 0)) {
            *errmsg = ubpf_error("division by zero at PC %d", pc);
            return true;
        }
    }
    return false;
}

static bool
is_mov(uint8_t opcode)
{
    return opcode == EBPF_OP_MOV64_IMM
        || opcode == EBPF_OP_MOV64_REG
        || opcode == EBPF_OP_MOV_IMM
        || opcode == EBPF_OP_MOV_REG;
}

static bool
is_alu(uint8_t opcode)
{
    return (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU
        || (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
}

struct abs_state
abs_execute(struct abs_state *_state, struct ebpf_inst inst)
{
    struct abs_state res = *_state;
    struct abs_state* state = &res;

    if (inst.opcode == EBPF_OP_CALL) {
        for (int r=1; r <= 6; r++) {
            state->known[r] = false;
        }
        // r0 depends on the particular function
        state->known[0] = false;
    }
    if (!is_alu(inst.opcode))
        return res;

    if (inst.opcode & EBPF_SRC_REG && !state->known[inst.src]) {
        state->known[inst.dst] = false;
        return res;
    }

    // if it's not mov, the dst register is also important for definedness
    if (!state->known[inst.dst] && !is_mov(inst.opcode)) {
        state->known[inst.dst] = false;
        return res;
    }

    state->known[inst.dst] = true;

    #define reg state->reg
    switch (inst.opcode) {
    case EBPF_OP_ADD_IMM:
        reg[inst.dst] += inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_ADD_REG:
        reg[inst.dst] += reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_SUB_IMM:
        reg[inst.dst] -= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_SUB_REG:
        reg[inst.dst] -= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MUL_IMM:
        reg[inst.dst] *= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MUL_REG:
        reg[inst.dst] *= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_DIV_IMM:
        reg[inst.dst] = u32(reg[inst.dst]) / u32(inst.imm);
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_DIV_REG:
        assert(reg[inst.src] != 0);
        reg[inst.dst] = u32(reg[inst.dst]) / u32(reg[inst.src]);
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_OR_IMM:
        reg[inst.dst] |= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_OR_REG:
        reg[inst.dst] |= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_AND_IMM:
        reg[inst.dst] &= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_AND_REG:
        reg[inst.dst] &= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_LSH_IMM:
        reg[inst.dst] <<= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_LSH_REG:
        reg[inst.dst] <<= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_RSH_IMM:
        reg[inst.dst] = u32(reg[inst.dst]) >> inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_RSH_REG:
        reg[inst.dst] = u32(reg[inst.dst]) >> reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_NEG:
        reg[inst.dst] = -reg[inst.dst];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOD_IMM:
        reg[inst.dst] = u32(reg[inst.dst]) % u32(inst.imm);
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOD_REG:
        assert(reg[inst.src] != 0);
        reg[inst.dst] = u32(reg[inst.dst]) % u32(reg[inst.src]);
        break;
    case EBPF_OP_XOR_IMM:
        reg[inst.dst] ^= inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_XOR_REG:
        reg[inst.dst] ^= reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOV_IMM:
        reg[inst.dst] = inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_MOV_REG:
        reg[inst.dst] = reg[inst.src];
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_ARSH_IMM:
        reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
        reg[inst.dst] &= UINT32_MAX;
        break;
    case EBPF_OP_ARSH_REG:
        reg[inst.dst] = (int32_t)reg[inst.dst] >> u32(reg[inst.src]);
        reg[inst.dst] &= UINT32_MAX;
        break;

    case EBPF_OP_LE:
        if (inst.imm == 16) {
            reg[inst.dst] = htole16(reg[inst.dst]);
        } else if (inst.imm == 32) {
            reg[inst.dst] = htole32(reg[inst.dst]);
        } else if (inst.imm == 64) {
            reg[inst.dst] = htole64(reg[inst.dst]);
        }
        break;
    case EBPF_OP_BE:
        if (inst.imm == 16) {
            reg[inst.dst] = htobe16(reg[inst.dst]);
        } else if (inst.imm == 32) {
            reg[inst.dst] = htobe32(reg[inst.dst]);
        } else if (inst.imm == 64) {
            reg[inst.dst] = htobe64(reg[inst.dst]);
        }
        break;


    case EBPF_OP_ADD64_IMM:
        reg[inst.dst] += inst.imm;
        break;
    case EBPF_OP_ADD64_REG:
        reg[inst.dst] += reg[inst.src];
        break;
    case EBPF_OP_SUB64_IMM:
        reg[inst.dst] -= inst.imm;
        break;
    case EBPF_OP_SUB64_REG:
        reg[inst.dst] -= reg[inst.src];
        break;
    case EBPF_OP_MUL64_IMM:
        reg[inst.dst] *= inst.imm;
        break;
    case EBPF_OP_MUL64_REG:
        reg[inst.dst] *= reg[inst.src];
        break;
    case EBPF_OP_DIV64_IMM:
        reg[inst.dst] /= inst.imm;
        break;
    case EBPF_OP_DIV64_REG:
        assert(reg[inst.src] != 0);
        reg[inst.dst] /= reg[inst.src];
        break;
    case EBPF_OP_OR64_IMM:
        reg[inst.dst] |= inst.imm;
        break;
    case EBPF_OP_OR64_REG:
        reg[inst.dst] |= reg[inst.src];
        break;
    case EBPF_OP_AND64_IMM:
        reg[inst.dst] &= inst.imm;
        break;
    case EBPF_OP_AND64_REG:
        reg[inst.dst] &= reg[inst.src];
        break;
    case EBPF_OP_LSH64_IMM:
        reg[inst.dst] <<= inst.imm;
        break;
    case EBPF_OP_LSH64_REG:
        reg[inst.dst] <<= reg[inst.src];
        break;
    case EBPF_OP_RSH64_IMM:
        reg[inst.dst] >>= inst.imm;
        break;
    case EBPF_OP_RSH64_REG:
        reg[inst.dst] >>= reg[inst.src];
        break;
    case EBPF_OP_NEG64:
        reg[inst.dst] = -reg[inst.dst];
        break;
    case EBPF_OP_MOD64_IMM:
        reg[inst.dst] %= inst.imm;
        break;
    case EBPF_OP_MOD64_REG:
        assert(reg[inst.src] != 0);
        reg[inst.dst] %= reg[inst.src];
        break;
    case EBPF_OP_XOR64_IMM:
        reg[inst.dst] ^= inst.imm;
        break;
    case EBPF_OP_XOR64_REG:
        reg[inst.dst] ^= reg[inst.src];
        break;
    case EBPF_OP_MOV64_IMM:
        reg[inst.dst] = inst.imm;
        break;
    case EBPF_OP_MOV64_REG:
        reg[inst.dst] = reg[inst.src];
        break;
    case EBPF_OP_ARSH64_IMM:
        reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
        break;
    case EBPF_OP_ARSH64_REG:
        reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
        break;
    
    case EBPF_OP_LDDW:
        assert(false); // already transformed
        break;

    default: break;
    }
    #undef reg
    return res;
}

void
abs_print(struct abs_state *state, const char* s)
{
    static int count = 0;
    FILE *fp = fopen("log.txt","a");
    fprintf(fp, "%15s: ", s);
    fprintf(fp, "%d) ", count);
    if (state->bot) {
        fprintf(fp, "BOT");
    } else {
        for (int r=0; r < 11; r++) {
            fprintf(fp, "r%d: ", r);
            if (state->known[r])
                fprintf(fp, "%lu; ", state->reg[r]);
            else
                fprintf(fp, "?; ");
        }
    }
    fprintf(fp, "\n");
    count++;
    fclose(fp);
}
