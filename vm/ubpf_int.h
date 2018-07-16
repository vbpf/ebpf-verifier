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

#define MAX_INSTS 65536
#define STACK_SIZE 128

struct ebpf_inst;

bool validate_simple(const struct ebpf_inst *insts, uint32_t num_insts, char **errmsg);

#ifdef __cplusplus
extern "C"
#endif
char *ubpf_error(const char *fmt, ...);

#endif
