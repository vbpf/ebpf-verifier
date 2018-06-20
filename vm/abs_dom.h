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

#ifndef ABS_DOM_H
#define ABS_DOM_H

#include "ubpf_int.h"

struct abs_dom_const {
    bool known;
    uint64_t value;
};

extern const struct abs_dom_const abs_top;

struct abs_dom_const abs_const_join(struct abs_dom_const dst, struct abs_dom_const src);
uint64_t do_const_alu(uint8_t opcode, int32_t imm, uint64_t dst_val, uint64_t src_val);

#endif
