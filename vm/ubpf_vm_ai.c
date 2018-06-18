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
is_jmp(uint8_t opcode) {
    switch (opcode) {
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
        return true;
    default:
        return false;
    }
}

static bool
is_unconditional_jmp(uint8_t opcode) {
    return opcode == EBPF_OP_JA
        || opcode == EBPF_OP_EXIT;
}

static int*
compute_pending(const struct ebpf_inst *insts, uint32_t num_insts)
{
    int *pending = calloc(num_insts, sizeof(*pending));
    pending[0] = 1;

    for (uint16_t pc = 0; pc < num_insts; pc++) {
        if (is_jmp(insts[pc].opcode)) {
            pending[pc + 1 + insts[pc].offset]++;
        }
        if (!is_unconditional_jmp(insts[pc].opcode)) {
            if (insts[pc].opcode == EBPF_OP_LDDW)
                pc++;
            pending[pc + 1]++;
        }
    }
    return pending;
}

void
print_pending(int* pending, const struct ebpf_inst *insts, uint32_t num_insts)
{
    for (uint16_t pc = 0; pc < num_insts; pc++) {
        fprintf(stderr, "%d: pending %d (ins 0x%x)", pc, pending[pc], insts[pc].opcode);
        if (is_jmp(insts[pc].opcode))
            fprintf(stderr, " jmp to %d", pc + 1 + insts[pc].offset);
        fprintf(stderr, "\n");
    }
}

bool
ai_validate(const struct ebpf_inst *insts, uint32_t num_insts, void* ctx, char** errmsg)
{
    int *pending = compute_pending(insts, num_insts);
    // states[i] contains the state just before instruction i
    //struct abs_state *states = malloc(num_insts * sizeof(*states));
    //for (int i = 0; i < num_insts; i++) {
    //    states[i] = abs_bottom;
    //}
    uint16_t *worklist = malloc(num_insts * sizeof(*worklist));
    int wi = 0;
    worklist[wi++] = 0;

    //uint64_t stack[(STACK_SIZE+7)/8];
    //abs_initialize_state(&states[0], ctx, stack);
    
    while (wi != 0) {
        assert(wi > 0);
        uint16_t pc = worklist[--wi];

        /*
        struct ebpf_inst inst = insts[pc];
        if (is_jmp(inst.opcode)) {
            uint16_t target = pc + 1 + inst.offset;
            //fprintf(stderr, "push wi %d\n", wi);
            //abs_join(&states[target], abs_execute_assume(&states[cur_pc], inst, true));
            //abs_join(&states[pc], abs_execute_assume(&states[cur_pc], inst, false));
        } else {
            if (inst.opcode == EBPF_OP_LDDW) {
                inst.opcode = EBPF_OP_MOV64_REG;
                inst.src = 12;
                //states[pc].reg[12] = (uint32_t)inst.imm | ((uint64_t)insts[pc+1].imm << 32);
            }
            //abs_join(&states[pc], abs_execute(&states[cur_pc], inst));
            //if (inst.opcode & EBPF_MODE_MEM) {
            //    if (!abs_bounds_check(&states[cur_pc], inst)) {
            //        *errmsg = "AI failed to pass bound checks";
            //        return false;
            //    }
            //}
        }
        */

        if (is_jmp(insts[pc].opcode)) {
            uint16_t target = pc + 1 + insts[pc].offset;
            pending[target]--;
            if (pending[target] == 0)
                worklist[wi++] = target;
        }

        if (!is_unconditional_jmp(insts[pc].opcode)) {
            if (insts[pc].opcode == EBPF_OP_LDDW)
                pc++;
            pending[pc + 1]--;
            if (pending[pc + 1] == 0)
                worklist[wi++] = pc + 1;
        }
    }

    return true;
}
