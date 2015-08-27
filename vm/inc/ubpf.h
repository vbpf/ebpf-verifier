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

#ifndef UBPF_H
#define UBPF_H

#include <stdint.h>

struct ubpf_vm;

struct ubpf_vm *ubpf_create(const void *code, uint32_t code_len, char **errmsg);
void ubpf_destroy(struct ubpf_vm *vm);

uint64_t ubpf_exec(const struct ubpf_vm *vm, void *mem, size_t mem_len);

#endif
