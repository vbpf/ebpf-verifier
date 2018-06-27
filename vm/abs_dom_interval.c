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

const struct abs_dom_value abs_dom_top = { T_NOINIT, 0, -1 };
const struct abs_dom_value abs_dom_unknown = (struct abs_dom_value){ T_NUM, 0, (uint64_t)-1 };
const struct abs_dom_value abs_dom_bot = { T_BOT, (uint64_t)-1, 0 };

const struct abs_dom_value abs_dom_ctx = { T_CTX, 0, 0 };
const struct abs_dom_value abs_dom_stack = { T_STACK, 0, 0 };

static uint64_t alu_single(uint8_t opcode, uint64_t dst_val, uint64_t src_val, int32_t imm);

static uint64_t
min(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

static uint64_t
max(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

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
issingle(struct abs_dom_value v)
{
    return v.minvalue == v.maxvalue;
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
    else {
        if (src.minvalue < dst.minvalue)
            dst.minvalue = src.minvalue;

        if (src.maxvalue > dst.maxvalue)
            dst.maxvalue = src.maxvalue;
    }
    return dst;
}

struct abs_dom_value
abs_dom_fromconst(uint64_t value)
{
    return (struct abs_dom_value){ T_NUM, value, value };
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
    return !known(v) || (is64 ? v.minvalue : u32(v.minvalue)) == 0;
}

void
abs_dom_print(FILE* f, struct abs_dom_value v)
{
    fprintf(f, "{%2d,[%2ld-%ld]}", v.type, (int64_t)v.minvalue, (int64_t)v.maxvalue);
}

static bool
implies_unsigned_lte(uint8_t opcode, bool taken, struct abs_dom_value **smaller, struct abs_dom_value **higher)
{
    switch (opcode) {
    case EBPF_OP_JGE_IMM: case EBPF_OP_JGE_REG:
    case EBPF_OP_JGT_IMM: case EBPF_OP_JGT_REG:
        if (!taken) {
            struct abs_dom_value *tmp = *smaller;
            *smaller = *higher;
            *higher = tmp;
            return true;
        }
        return false;

    case EBPF_OP_JLE_IMM: case EBPF_OP_JLE_REG:
    case EBPF_OP_JLT_IMM: case EBPF_OP_JLT_REG:
        if (taken) {
            struct abs_dom_value *tmp = *smaller;
            *smaller = *higher;
            *higher = tmp;
            return true;
        }
        return false;
    default:
        return false;
    }
}

static bool
implies_unsigned_lt(uint8_t opcode, bool taken, struct abs_dom_value **smaller, struct abs_dom_value **higher)
{
    return implies_neq(opcode, taken) && implies_unsigned_lte(opcode, taken, smaller, higher);
}

void
abs_dom_assume(uint8_t opcode, bool taken, struct abs_dom_value *v1, struct abs_dom_value *v2)
{
    if (implies_eq(opcode, taken)) {
        if (known(*v1) && !known(*v2)) {
            *v2 = *v1;
            return;
        }
        if (known(*v2) && !known(*v1)) {
            *v1 = *v2;
            return;
        }
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
        if (known(*v1) && v1->type == v2->type) { //TODO: handle when one is MAYBE
            if (v1->minvalue > v2->maxvalue || v1->maxvalue < v2->minvalue)
                *v1 = *v2 = abs_dom_bot;
            *v1 = *v2 = (struct abs_dom_value){
                v1->type,
                (v1->minvalue < v2->minvalue ? v2 : v1)->minvalue,
                (v1->maxvalue > v2->maxvalue ? v2 : v1)->maxvalue
            };
            return;
        }
        return;
    }

    if (!known(*v1) || !known(*v2) || v1->type != v2->type) {
        return;
    }

    struct abs_dom_value *smaller = v1, *higher = v2;
    if (implies_unsigned_lte(opcode, taken, &smaller, &higher)) {
        smaller->maxvalue = min(smaller->maxvalue, higher->maxvalue);
        higher->minvalue = max(smaller->minvalue, higher->minvalue);
    }
    if (implies_unsigned_lt(opcode, taken, &smaller, &higher)) {
        smaller->maxvalue = min(smaller->maxvalue, higher->maxvalue - 1);
        higher->minvalue = max(smaller->minvalue + 1, higher->minvalue);
    }

    if (implies_neq(opcode, taken)) {
        // FIX and deduplicate 
        if (v1->type == T_MAYBE_MAP) {
            if (v2->type == T_NUM && v2->maxvalue == 0)
                v1->type = T_MAP;
            else if (v2->type == T_MAP)
                v1->type = T_UNKNOWN;
            return;
        } else if (v2->type == T_MAYBE_MAP) {
            if (v1->type == T_NUM && v2->maxvalue == 0)
                v2->type = T_MAP;
            else if (v1->type == T_MAP)
                v2->type = T_UNKNOWN;
            return;
        }
        if (known(*v1) && known(*v2)) {
            if (issingle(*v1) && v1->minvalue == v2->maxvalue) v2->maxvalue--;
            if (issingle(*v1) && v1->minvalue == v2->minvalue) v2->minvalue++;
            if (issingle(*v2) && v2->minvalue == v1->maxvalue) v1->maxvalue--;
            if (issingle(*v2) && v2->minvalue == v1->minvalue) v1->minvalue++;
        }
        return;
    }

}

bool
abs_dom_out_of_bounds(struct abs_dom_value v, int16_t offset, int width)
{
    // FIX: interval is unsigned only. Should consider only signed.
    switch (v.type) {
    case T_STACK: 
        return (int64_t)v.minvalue + offset + width > 0 || (int64_t)v.maxvalue + offset < -STACK_SIZE;
    case T_CTX: // FIX too
        return v.maxvalue + offset + width > 4096;
    case T_MAP:
        // ARBITRARY. TODO: actual numbers
        return false; //v.maxvalue == 0;
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
    assert(!(opcode == EBPF_OP_MOV_REG || opcode == EBPF_OP_MOV64_REG));
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

static bool
is_imm(uint8_t opcode)
{
    return (opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU
        && opcode != EBPF_OP_NEG && opcode != EBPF_OP_NEG64
        && !(opcode & EBPF_MODE_IMM);
}

// monotone: if not overflows, maintains min and max of unsigned
// also overflows only if the min/max overflows
static bool
is_monotone(uint8_t opcode)
{
switch (opcode) {
    case EBPF_OP_ADD_IMM:    case EBPF_OP_ADD_REG:    case EBPF_OP_ADD64_IMM:  case EBPF_OP_ADD64_REG:
    case EBPF_OP_SUB_IMM:    case EBPF_OP_SUB_REG:    case EBPF_OP_SUB64_IMM:  case EBPF_OP_SUB64_REG:
    case EBPF_OP_MUL_IMM:    case EBPF_OP_MUL_REG:    case EBPF_OP_MUL64_IMM:  case EBPF_OP_MUL64_REG:
    case EBPF_OP_OR_IMM:     case EBPF_OP_OR_REG:     case EBPF_OP_OR64_IMM:   case EBPF_OP_OR64_REG:
    case EBPF_OP_AND_IMM:    case EBPF_OP_AND_REG:    case EBPF_OP_AND64_IMM:  case EBPF_OP_AND64_REG:
    case EBPF_OP_LSH_IMM:    case EBPF_OP_LSH_REG:    case EBPF_OP_LSH64_IMM:  case EBPF_OP_LSH64_REG:
    case EBPF_OP_RSH_IMM:    case EBPF_OP_RSH_REG:    case EBPF_OP_RSH64_IMM:  case EBPF_OP_RSH64_REG:
    case EBPF_OP_ARSH_IMM:   case EBPF_OP_ARSH_REG:   case EBPF_OP_ARSH64_IMM: case EBPF_OP_ARSH64_REG:
        return true;
    default:
        return false;
    }
}


struct abs_dom_value
abs_dom_alu(uint8_t opcode, int32_t imm, struct abs_dom_value dst, struct abs_dom_value src)
{
    if (opcode == EBPF_OP_MOV_REG || opcode == EBPF_OP_MOV64_REG)
        return src;
    if (opcode == EBPF_OP_MOV_IMM || opcode == EBPF_OP_MOV64_IMM)
        return abs_dom_fromconst(imm);
    dst.type = abs_dom_type_alu(opcode, dst.type, src.type, imm);
    if (dst.type == T_UNKNOWN || dst.type == T_NOINIT || dst.type == T_BOT) {
        return dst;
    }
    if (dst.maxvalue - dst.minvalue <= 1 && is_imm(opcode)) {
        uint64_t a = alu_single(opcode, dst.minvalue, src.minvalue, imm);
        uint64_t b = alu_single(opcode, dst.maxvalue, src.maxvalue, imm);
        dst.minvalue = min(a, b);
        dst.maxvalue = max(a, b);
        return dst;
    }
    if (is_monotone(opcode)) {
        uint64_t a1 = alu_single(opcode, dst.minvalue, src.minvalue, imm);
        uint64_t a2 = alu_single(opcode, dst.minvalue, src.maxvalue, imm);
        uint64_t b1 = alu_single(opcode, dst.maxvalue, src.minvalue, imm);
        uint64_t b2 = alu_single(opcode, dst.maxvalue, src.maxvalue, imm);
        if (max(a1, a2) <= min(b1, b2)) {
            dst.minvalue = min(a1, a2);
            dst.maxvalue = max(b1, b2);
            return dst;
        }
    }
    if (dst.minvalue <= dst.maxvalue && src.minvalue <= src.maxvalue
    && (dst.maxvalue - dst.minvalue <= 10 && src.maxvalue - src.minvalue <= 10)) {
        uint64_t tmin = (uint64_t)-1;
        uint64_t tmax = 0; 
        // don't overflow in loop
        for (uint64_t a = dst.minvalue; ; a++) {
            for (uint64_t b = src.minvalue; ; b++) {
                uint64_t t = alu_single(opcode, a, b, imm);
                tmin = min(tmin, t);
                tmax = max(tmin, t);
                if (b == src.maxvalue)
                    break;
            }
            if (a == dst.maxvalue)
                break;
        }
        dst.minvalue = tmin;
        dst.maxvalue = tmax;
        return dst;
    }
    dst.minvalue = 0;
    dst.maxvalue = (uint64_t)-1;
    return dst;
}


static uint64_t
alu_single(uint8_t opcode, uint64_t dst_val, uint64_t src_val, int32_t imm)
{
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
        fprintf(stderr, "%d\n", opcode);
        assert(false);
    }
    return dst_val;
}
