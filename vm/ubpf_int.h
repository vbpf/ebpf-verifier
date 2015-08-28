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

#ifndef UBPF_INT_H
#define UBPF_INT_H

#include <ubpf.h>
#include "ebpf.h"

struct ebpf_inst;

struct ubpf_vm {
    struct ebpf_inst *insts;
    uint16_t num_insts;
    ubpf_jit_fn jitted;
    size_t jitted_size;
};

char *ubpf_error(const char *fmt, ...);

#endif
