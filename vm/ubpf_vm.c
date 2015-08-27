/*
 * Copyright 2015 Big Switch Networks, Inc
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
#include <stdarg.h>
#include <inttypes.h>
#include "ebpf.h"
#include "ubpf.h"

#define MAX_INSTS 65536

struct ubpf_vm {
    struct ebpf_inst *insts;
    uint16_t num_insts;
};

static bool validate(const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg);

static char *
error(const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}

struct ubpf_vm *
ubpf_create(const void *code, uint32_t code_len, char **errmsg)
{
    *errmsg = NULL;

    if (code_len % 8 != 0) {
        *errmsg = error("code_len must be a multiple of 8");
        return NULL;
    }

    if (!validate(code, code_len/8, errmsg)) {
        return NULL;
    }

    struct ubpf_vm *vm = malloc(sizeof(*vm));
    if (!vm) {
        return NULL;
    }

    vm->insts = malloc(code_len);
    if (vm->insts == NULL) {
        return NULL;
    }

    memcpy(vm->insts, code, code_len);
    vm->num_insts = code_len/sizeof(vm->insts[0]);

    return vm;
}

void
ubpf_destroy(struct ubpf_vm *vm)
{
    free(vm->insts);
    free(vm);
}

uint64_t
ubpf_exec(const struct ubpf_vm *vm, uint64_t arg)
{
    uint16_t pc = 0;
    const struct ebpf_inst *insts = vm->insts;
    uint16_t num_insts = vm->num_insts;
    uint64_t reg[16];

    /* TODO remove this when the verifier can prove uninitialized registers are
     * not read from */
    memset(reg, 0xff, sizeof(reg));

    reg[1] = arg;

    while (1) {
        const uint16_t cur_pc = pc;
        if (pc >= num_insts) {
            /* TODO validate control flow */
            fprintf(stderr, "uBPF error: reached end of instructions\n");
            return UINT64_MAX;
        }

        struct ebpf_inst inst = insts[pc++];

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
            reg[inst.dst] /= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] /= reg[inst.src];
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
            reg[inst.dst] >>= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst] >>= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst] = -reg[inst.dst];
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst] %= inst.imm;
            reg[inst.dst] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
            reg[inst.dst] %= reg[inst.src];
            reg[inst.dst] &= UINT32_MAX;
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
            reg[inst.dst] = (int32_t)reg[inst.dst] >> reg[inst.src];
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
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
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
            if (reg[inst.src] == 0) {
                fprintf(stderr, "uBPF error: division by zero at PC %u\n", cur_pc);
                return UINT64_MAX;
            }
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

        /*
         * HACK runtime bounds check
         *
         * Needed since we don't have a verifier yet.
         */
#define MEM_SIZE 1024*1024
#define BOUNDS_CHECK_LOAD(size) \
    do { \
        uint64_t addr = reg[inst.src] + inst.offset; \
        if (!arg || addr < arg || (addr + size) > (arg + MEM_SIZE)) { \
            fprintf(stderr, "uBPF error: out of bounds memory load at PC %u, addr 0x%"PRIx64", size %d\n", cur_pc, addr, size); \
            return UINT64_MAX; \
        } \
    } while (0)
#define BOUNDS_CHECK_STORE(size) \
    do { \
        uint64_t addr = reg[inst.dst] + inst.offset; \
        if (!arg || addr < arg || (addr + size) > (arg + MEM_SIZE)) { \
            fprintf(stderr, "uBPF error: out of bounds memory store at PC %u, addr 0x%"PRIx64", size %d\n", cur_pc, addr, size); \
            return UINT64_MAX; \
        } \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst] = *(uint32_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst] = *(uint16_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst] = *(uint8_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst] = *(uint64_t *)(uintptr_t)(reg[inst.src] + inst.offset);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = inst.imm;
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            *(uint32_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            *(uint16_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            *(uint8_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            *(uint64_t *)(uintptr_t)(reg[inst.dst] + inst.offset) = reg[inst.src];
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst] = inst.imm | ((uint64_t)insts[pc++].imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.offset;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst] == inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst] == reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst] > (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst] > reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst] >= (uint32_t)inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst] >= reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst] & inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst] & reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst] != inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst] != reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst] > inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst] >= inst.imm) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src]) {
                pc += inst.offset;
            }
            break;
        case EBPF_OP_EXIT:
            return reg[0];

        /* TODO CALL opcode */

        default:
            /* Should have been caught by validate() */
            fprintf(stderr, "internal uBPF error: unknown opcode 0x%02x at PC %u\n", inst.opcode, cur_pc);
            return UINT64_MAX;
        }
    }
}

static bool
validate(const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg)
{
    /* TODO validate registers */
    /* TODO validate jmp offsets */

    if (num_insts >= MAX_INSTS) {
        *errmsg = error("too many instructions (max %u)", MAX_INSTS);
        return false;
    }

    int i;
    for (i = 0; i < num_insts; i++) {
        struct ebpf_inst inst = insts[i];
        switch (inst.opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
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
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
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
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            break;

        case EBPF_OP_LDDW:
            if (i + 1 >= num_insts || insts[i+1].opcode != 0) {
                *errmsg = error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
            if (inst.offset == -1) {
                *errmsg = error("infinite loop at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            if (inst.imm == 0) {
                *errmsg = error("division by zero at PC %d", i);
                return false;
            }
            break;

        default:
            *errmsg = error("unknown opcode 0x%02x at PC %d", inst.opcode, i);
            return false;
        }
    }

    return true;
}
