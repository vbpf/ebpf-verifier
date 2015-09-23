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
#include "ubpf_int.h"
#include <elf.h>

struct bounds {
    const void *base;
    uint64_t size;
};

static const void *
bounds_check(struct bounds *bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}

int
ubpf_load_elf(struct ubpf_vm *vm, const void *elf, size_t elf_size, char **errmsg)
{
    struct bounds b = { .base=elf, .size=elf_size };

    const Elf64_Ehdr *ehdr = bounds_check(&b, 0, sizeof(*ehdr));
    if (!ehdr) {
        *errmsg = ubpf_error("not enough data for ELF header");
        goto error;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        *errmsg = ubpf_error("wrong magic");
        goto error;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        *errmsg = ubpf_error("wrong class");
        goto error;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        *errmsg = ubpf_error("wrong byte order");
        goto error;
    }

    if (ehdr->e_ident[EI_VERSION] != 1) {
        *errmsg = ubpf_error("wrong version");
        goto error;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        *errmsg = ubpf_error("wrong OS ABI");
        goto error;
    }

    if (ehdr->e_type != ET_REL) {
        *errmsg = ubpf_error("wrong type, expected relocatable");
        goto error;
    }

    if (ehdr->e_machine != EM_NONE) {
        *errmsg = ubpf_error("wrong machine, expected none");
        goto error;
    }

    const Elf64_Shdr *text_shdr = NULL;

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }

        if (shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shdr = shdr;
        } else if (shdr->sh_type == SHT_REL) {
            *errmsg = ubpf_error("rel section found but not supported");
            goto error;
        }
    }

    if (!text_shdr) {
        *errmsg = ubpf_error("text section not found");
        goto error;
    }

    const void *text_data = bounds_check(&b, text_shdr->sh_offset, text_shdr->sh_size);
    if (!text_data) {
        *errmsg = ubpf_error("bad text section offset or size");
        goto error;
    }

    return ubpf_load(vm, text_data, text_shdr->sh_size, errmsg);

error:
    return -1;
}
