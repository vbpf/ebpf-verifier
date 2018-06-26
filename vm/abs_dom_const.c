/*
 * Copyright 2018 VMware, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#include <assert.h>
#include "ubpf_int.h"
#include "abs_interp.h"
#include "abs_dom.h"

const struct abs_dom_value abs_dom_top = { T_NOINIT, 0 };
const struct abs_dom_value abs_dom_unknown = (struct abs_dom_value){ T_UNKNOWN, 0 };
const struct abs_dom_value abs_dom_bot = { T_BOT, 0 };

const struct abs_dom_value abs_dom_ctx = { T_CTX, 0 };
const struct abs_dom_value abs_dom_stack = { T_STACK, 0 };

bool
abs_dom_is_bot(struct abs_dom_value v)
{
    return v.type == T_BOT;
}

bool
abs_dom_is_initialized(struct abs_dom_value v)
{
    return v.type != T_NOINIT;
}

static uint32_t
u32(uint64_t x)
{
    return x;
}

static bool
known(struct abs_dom_value t)
{
    return t.type != T_UNKNOWN && t.type != T_NOINIT;
}

struct abs_dom_value
abs_dom_join(struct abs_dom_value dst, struct abs_dom_value src)
{
    if (src.type == T_NOINIT)
        dst.type = T_NOINIT;
    else if (!known(src) || src.value != dst.value)
        dst.type = T_UNKNOWN;
    return dst;
}

struct abs_dom_value
abs_dom_fromconst(uint64_t value)
{
    return (struct abs_dom_value){ T_NUM, value };
}

struct abs_dom_value
abs_dom_call(struct ebpf_inst inst,
    struct abs_dom_value r1,
    struct abs_dom_value r2,
    struct abs_dom_value r3,
    struct abs_dom_value r4,
    struct abs_dom_value r5
)
{
    if (inst.imm == 0x1) {
        // TODO: differntiate maps
        return (struct abs_dom_value) { T_MAYBE_MAP, 0x0};
    }
    return abs_dom_top;
}

static bool
implies_eq(uint8_t opcode, bool taken)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM: case EBPF_OP_JEQ_REG:
        return taken;
                   
    case EBPF_OP_JNE_IMM: case EBPF_OP_JNE_REG:
        return !taken;
    default:
        return false;
    }
}

static bool
implies_neq(uint8_t opcode, bool taken)
{
    switch (opcode) {
    case EBPF_OP_JEQ_IMM: case EBPF_OP_JEQ_REG:
    case EBPF_OP_JGE_IMM: case EBPF_OP_JGE_REG: case EBPF_OP_JSGE_IMM: case EBPF_OP_JSGE_REG:
    case EBPF_OP_JLE_IMM: case EBPF_OP_JLE_REG: case EBPF_OP_JSLE_IMM: case EBPF_OP_JSLE_REG:
        return !taken;

    case EBPF_OP_JNE_IMM: case EBPF_OP_JNE_REG:
    case EBPF_OP_JGT_IMM: case EBPF_OP_JGT_REG: case EBPF_OP_JSGT_IMM: case EBPF_OP_JSGT_REG:
    case EBPF_OP_JLT_IMM: case EBPF_OP_JLT_REG: case EBPF_OP_JSLT_IMM: case EBPF_OP_JSLT_REG:
        return taken;
    default:
        return false;
    }
}

bool
abs_dom_maybe_zero(struct abs_dom_value v, bool is64)
{
    return !known(v) || (is64 ? v.value : u32(v.value)) == 0;
}

void
abs_dom_print(FILE* f, struct abs_dom_value v)
{
    fprintf(f, "{%2d, %2ld}", v.type, (int64_t)v.value);
}

void
abs_dom_assume(uint8_t opcode, bool taken, struct abs_dom_value *v1, struct abs_dom_value *v2)
{
    if (implies_eq(opcode, taken)) {
        // FIX and deduplicate 
        if (v1->type == T_MAYBE_MAP) {
            if (v2->type == T_NUM) {
                v1->type = T_NUM; 
            } else if (v2->type == T_MAP) {
                v1->type = T_MAP;
            }
            return;
        } else if (v2->type == T_MAYBE_MAP){
            if (v1->type == T_NUM)
                v2->type = T_NUM;
            else if (v1->type == T_MAP)
                v2->type = T_MAP;
            return;
        }

        // meet
        if (known(*v1) && known(*v2) && v1->value != v2->value) {
            *v2 = *v1 = abs_dom_bot;
            return;
        }
        if (known(*v1)) *v2 = *v1;
        else *v1 = *v2;
        return;
    }
    if (implies_neq(opcode, taken)) {
        // FIX and deduplicate 
        if (v1->type == T_MAYBE_MAP) {
            if (v2->type == T_NUM && v2->value == 0)
                v1->type = T_MAP;
            else if (v2->type == T_MAP)
                v1->type = T_UNKNOWN;
            return;
        } else if (v2->type == T_MAYBE_MAP) {
            if (v1->type == T_NUM && v1->value == 0)
                v2->type = T_MAP;
            else if (v1->type == T_MAP)
                v2->type = T_UNKNOWN;
            return;
        }
        if (known(*v1) && known(*v2) && v1->value == v2->value) {
            *v2 = *v1 = abs_dom_bot;
            return;
        }
        return;
    }
}

bool
abs_dom_out_of_bounds(struct abs_dom_value v, int16_t offset, int width)
{
    switch (v.type) {
    case T_STACK:
        return (int64_t)v.value + offset + width > 0 || (int64_t)v.value + offset < -STACK_SIZE;
    case T_CTX:
        return (int64_t)v.value + offset < 0 || (int64_t)v.value + offset + width > 4096;
    case T_MAP:
        // ARBITRARY. TODO: actual numbers
        return (int64_t)v.value + offset < 0 || (int64_t)v.value + offset + width > 4096;
    default:
        return true;
    }
}

static bool
is_reg(uint8_t opcode)
{
    return opcode & EBPF_SRC_REG;
}

static type_t
abs_dom_type_alu(uint8_t opcode, type_t dst, type_t src, int32_t imm)
{
    if (opcode == EBPF_OP_MOV_IMM || opcode == EBPF_OP_MOV64_IMM)
        return T_NUM;
    if (is_reg(opcode)) {
        if (src == T_NOINIT) {
            return T_BOT;
        }
    }
    if (opcode == EBPF_OP_MOV_REG || opcode == EBPF_OP_MOV64_REG)
        return src;
    if (dst == T_NOINIT) {
        return T_BOT;
    }
    if (dst == T_UNKNOWN)
        return T_UNKNOWN;
    switch (opcode) {
    case EBPF_OP_ADD_IMM: case EBPF_OP_ADD64_IMM:
    case EBPF_OP_SUB_IMM: case EBPF_OP_SUB64_IMM:
        return dst;
    case EBPF_OP_ADD_REG: case EBPF_OP_ADD64_REG:
        if (dst != T_NUM && src == T_NUM) return dst;
        if (src != T_NUM && dst == T_NUM) return src;
        // TODO: imprecise. In case one is a pointer and the offset is unknown, we can do better with unknown value and known type
        return T_UNKNOWN;
    case EBPF_OP_SUB_REG: case EBPF_OP_SUB64_REG:
        // unsafe for different maps
        return (src == dst) ? T_NUM : T_UNKNOWN;
    default:
        return (dst == T_NUM && ((opcode & EBPF_SRC_REG) == 0 || src == T_NUM)) ? T_NUM : T_UNKNOWN;
    }
}

struct abs_dom_value
abs_dom_alu(uint8_t opcode, int32_t imm, struct abs_dom_value dst, struct abs_dom_value src)
{
    dst.type = abs_dom_type_alu(opcode, dst.type, src.type, imm);
    if (dst.type == T_UNKNOWN || dst.type == T_NOINIT || dst.type == T_BOT) {
        return dst;
    }

    uint64_t dst_val = dst.value;
    uint64_t src_val = src.value;
    switch (opcode) {
    case EBPF_OP_ADD_IMM:
        dst_val += imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_ADD_REG:
        dst_val += src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_SUB_IMM:
        dst_val -= imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_SUB_REG:
        dst_val -= src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_MUL_IMM:
        dst_val *= imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_MUL_REG:
        dst_val *= src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_DIV_IMM:
        dst_val = u32(dst_val) / u32(imm);
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_DIV_REG:
        assert(src_val != 0);
        dst_val = u32(dst_val) / u32(src_val);
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_OR_IMM:
        dst_val |= imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_OR_REG:
        dst_val |= src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_AND_IMM:
        dst_val &= imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_AND_REG:
        dst_val &= src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_LSH_IMM:
        dst_val <<= imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_LSH_REG:
        dst_val <<= src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_RSH_IMM:
        dst_val = u32(dst_val) >> imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_RSH_REG:
        dst_val = u32(dst_val) >> src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_NEG:
        dst_val = -dst_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_MOD_IMM:
        dst_val = u32(dst_val) % u32(imm);
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_MOD_REG:
        assert(src_val != 0);
        dst_val = u32(dst_val) % u32(src_val);
        break;
    case EBPF_OP_XOR_IMM:
        dst_val ^= imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_XOR_REG:
        dst_val ^= src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_MOV_IMM:
        dst_val = imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_MOV_REG:
        dst_val = src_val;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_ARSH_IMM:
        dst_val = (int32_t)dst_val >> imm;
        dst_val &= UINT32_MAX;
        break;
    case EBPF_OP_ARSH_REG:
        dst_val = (int32_t)dst_val >> u32(src_val);
        dst_val &= UINT32_MAX;
        break;

    case EBPF_OP_LE:
        if (imm == 16) {
            dst_val = htole16(dst_val);
        } else if (imm == 32) {
            dst_val = htole32(dst_val);
        } else if (imm == 64) {
            dst_val = htole64(dst_val);
        }
        break;
    case EBPF_OP_BE:
        if (imm == 16) {
            dst_val = htobe16(dst_val);
        } else if (imm == 32) {
            dst_val = htobe32(dst_val);
        } else if (imm == 64) {
            dst_val = htobe64(dst_val);
        }
        break;

    case EBPF_OP_ADD64_IMM:
        dst_val += imm;
        break;
    case EBPF_OP_ADD64_REG:
        dst_val += src_val;
        break;
    case EBPF_OP_SUB64_IMM:
        dst_val -= imm;
        break;
    case EBPF_OP_SUB64_REG:
        dst_val -= src_val;
        break;
    case EBPF_OP_MUL64_IMM:
        dst_val *= imm;
        break;
    case EBPF_OP_MUL64_REG:
        dst_val *= src_val;
        break;
    case EBPF_OP_DIV64_IMM:
        dst_val /= imm;
        break;
    case EBPF_OP_DIV64_REG:
        assert(src_val != 0);
        dst_val /= src_val;
        break;
    case EBPF_OP_OR64_IMM:
        dst_val |= imm;
        break;
    case EBPF_OP_OR64_REG:
        dst_val |= src_val;
        break;
    case EBPF_OP_AND64_IMM:
        dst_val &= imm;
        break;
    case EBPF_OP_AND64_REG:
        dst_val &= src_val;
        break;
    case EBPF_OP_LSH64_IMM:
        dst_val <<= imm;
        break;
    case EBPF_OP_LSH64_REG:
        dst_val <<= src_val;
        break;
    case EBPF_OP_RSH64_IMM:
        dst_val >>= imm;
        break;
    case EBPF_OP_RSH64_REG:
        dst_val >>= src_val;
        break;
    case EBPF_OP_NEG64:
        dst_val = -dst_val;
        break;
    case EBPF_OP_MOD64_IMM:
        dst_val %= imm;
        break;
    case EBPF_OP_MOD64_REG:
        assert(src_val != 0);
        dst_val %= src_val;
        break;
    case EBPF_OP_XOR64_IMM:
        dst_val ^= imm;
        break;
    case EBPF_OP_XOR64_REG:
        dst_val ^= src_val;
        break;
    case EBPF_OP_MOV64_IMM:
        dst_val = imm;
        break;
    case EBPF_OP_MOV64_REG:
        dst_val = src_val;
        break;
    case EBPF_OP_ARSH64_IMM:
        dst_val = (int64_t)dst_val >> imm;
        break;
    case EBPF_OP_ARSH64_REG:
        dst_val = (int64_t)dst_val >> src_val;
        break;
    default:
        assert(false);
    }
    dst.value = dst_val;
    return dst;
}
