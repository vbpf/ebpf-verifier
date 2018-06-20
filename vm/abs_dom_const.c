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

const struct abs_dom_const abs_top = { false, 0 }; // second zero makes unknowns

static uint32_t
u32(uint64_t x)
{
    return x;
}

struct abs_dom_const
abs_const_join(struct abs_dom_const dst, struct abs_dom_const src)
{
    if (!src.known || src.value != dst.value)
        dst.known = false;
    return dst;
}

uint64_t
do_const_alu(uint8_t opcode, int32_t imm, uint64_t dst_val, uint64_t src_val)
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
        assert(false);
    }
    return dst_val;
}