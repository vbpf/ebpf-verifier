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
#include <sys/mman.h>
#include <assert.h>

#include "ubpf_int.h"
#include "ubpf_vm_ai.h"

static bool
is_jmp(struct ebpf_inst inst, uint16_t pc, uint16_t* out_target) {
    switch (inst.opcode) {
    case EBPF_OP_JA:
    case EBPF_OP_JEQ_REG:
    case EBPF_OP_JEQ_IMM:
    case EBPF_OP_JGT_REG:
    case EBPF_OP_JGT_IMM:
    case EBPF_OP_JGE_REG:
    case EBPF_OP_JGE_IMM:
    case EBPF_OP_JLT_REG:
    case EBPF_OP_JLT_IMM:
    case EBPF_OP_JLE_REG:
    case EBPF_OP_JLE_IMM:
    case EBPF_OP_JSET_REG:
    case EBPF_OP_JSET_IMM:
    case EBPF_OP_JNE_REG:
    case EBPF_OP_JNE_IMM:
    case EBPF_OP_JSGT_IMM:
    case EBPF_OP_JSGT_REG:
    case EBPF_OP_JSGE_IMM:
    case EBPF_OP_JSGE_REG:
    case EBPF_OP_JSLT_IMM:
    case EBPF_OP_JSLT_REG:
    case EBPF_OP_JSLE_IMM:
    case EBPF_OP_JSLE_REG:
        *out_target = pc + 1 + inst.offset;
        return true;
    default:
        return false;
    }
}

static bool
has_fallthrough(struct ebpf_inst inst, uint16_t pc, uint16_t* out_target) {
    if (inst.opcode != EBPF_OP_JA && inst.opcode != EBPF_OP_EXIT) {
        /* eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
        of two consecutive 'struct ebpf_inst' 8-byte blocks and interpreted as single
        instruction that loads 64-bit immediate value into a dst_reg. */
        if (inst.opcode == EBPF_OP_LDDW)
            pc++;
        *out_target = pc + 1;
        return true;
    }
    return false;
}

static int*
compute_pending(const struct ebpf_inst *insts, uint32_t num_insts)
{
    int *pending = calloc(num_insts, sizeof(*pending));
    pending[0] = 1;

    for (uint16_t pc = 0; pc < num_insts; pc++) {
        uint16_t target;
        if (is_jmp(insts[pc], pc, &target)) {
            assert(target < num_insts);
            assert(target >= 0);
            pending[target]++;
        }
        if (has_fallthrough(insts[pc], pc, &target)) {
            assert(target < num_insts);
            pending[target]++;
        }
    }
    return pending;
}

static bool
abs_step(const struct ebpf_inst* insts, struct abs_state *states, uint16_t pc, char** errmsg)
{
    struct ebpf_inst inst = insts[pc];
    uint16_t target;
    if (is_jmp(insts[pc], pc, &target)) {
        abs_join(&states[target], abs_execute_assume(&states[pc], inst, true));
        abs_join(&states[pc + 1], abs_execute_assume(&states[pc], inst, false));
    } else if (has_fallthrough(insts[pc], pc, &target)) {
        if (inst.opcode == EBPF_OP_LDDW) {
            inst.opcode = EBPF_OP_MOV64_REG;
            inst.src = 12;
            states[pc].reg[12] = (uint32_t)inst.imm | ((uint64_t)insts[pc+1].imm << 32);
        }
        abs_join(&states[target], abs_execute(&states[pc], inst));
        if (!abs_bounds_check(&states[pc], inst)) {
            char* msg = malloc(sizeof("AI failed to pass bound checks"));
            strcpy(*errmsg, msg);
            return false;
        }
        if (!abs_divzero_check(&states[pc], inst)) {
            char* msg = malloc(sizeof("AI failed to pass divzero checks"));
            strcpy(*errmsg, msg);
            return false;
        }
    }
    return true;
}

bool
ai_validate(const struct ebpf_inst *insts, uint32_t num_insts, void* ctx, char** errmsg)
{
    int *pending = compute_pending(insts, num_insts);

    uint16_t *available = malloc(num_insts * sizeof(*available));

    // states[i] contains the state just before instruction i
    struct abs_state *states = malloc(num_insts * sizeof(*states));
    for (int i = 0; i < num_insts; i++) {
       states[i] = abs_bottom;
    }

    uint64_t stack[(STACK_SIZE+7)/8];
    abs_initialize_state(&states[0], ctx, stack);
    
    bool res = true;
    uint16_t pc = 0;
    available[0] = pc;
    for (int wi = 1; wi != 0; pc = available[--wi]) {
        assert(wi > 0);

        bool ok = abs_step(insts, states, pc, errmsg);
        if (!ok) {
            res = false;
            break;
        }

        uint16_t target;
        if (is_jmp(insts[pc], pc, &target)) {
            pending[target]--;
            if (pending[target] == 0)
                available[wi++] = target;
        }

        if (has_fallthrough(insts[pc], pc, &target)) {
            pending[target]--;
            if (pending[target] == 0)
                available[wi++] = target;
        }
    }

    free(pending);
    free(available);
    free(states);

    return res;
}
/*
static void
print_pending(int* pending, const struct ebpf_inst *insts, uint32_t num_insts)
{
    for (uint16_t pc = 0; pc < num_insts; pc++) {
        fprintf(stderr, "%d: pending %d (ins 0x%x)", pc, pending[pc], insts[pc].opcode);
        
        uint16_t target;
        if (is_jmp(insts[pc], pc, &target)) {
            fprintf(stderr, " jmp to %d", target);
        }
        fprintf(stderr, "\n");
    }
}
*/