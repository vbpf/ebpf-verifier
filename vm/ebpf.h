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

#ifndef EBPF_H
#define EBPF_H

#include <stdint.h>

/* eBPF definitions */

struct ebpf_inst {
    uint8_t opcode;
    uint8_t dst : 4;
    uint8_t src : 4;
    int16_t offset;
    int32_t imm;
};

#define EBPF_OP_ADD_IMM 0x04
#define EBPF_OP_ADD_REG 0x0c
#define EBPF_OP_MOV_IMM 0xb4
#define EBPF_OP_MOV_REG 0xbc

#define EBPF_OP_JGT_IMM 0x25
#define EBPF_OP_JGT_REG 0x2d
#define EBPF_OP_JGE_IMM 0x35
#define EBPF_OP_JGE_REG 0x3d
#define EBPF_OP_EXIT 0x95

#endif
