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

#define MAX_SECTIONS 128

#ifndef EM_BPF
#define EM_BPF 247
#endif

struct bounds {
    const void *base;
    uint64_t size;
};

struct section {
    const Elf64_Shdr *shdr;
    const void *data;
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

enum ebpf_prog_type
section_name_to_prog_type(const char* section)
{
    // Heuristically assume the type based on section names
    if (strncmp(section, "socket", 6)       == 0) return EBPF_PROG_TYPE_SOCKET_FILTER;
	if (strncmp(section, "kprobe/", 7)      == 0) return EBPF_PROG_TYPE_KPROBE;
    if (strncmp(section, "kretprobe/", 10)  == 0) return EBPF_PROG_TYPE_KPROBE;
	if (strncmp(section, "tracepoint/", 11) == 0) return EBPF_PROG_TYPE_TRACEPOINT;
	if (strncmp(section, "xdp", 3)          == 0) return EBPF_PROG_TYPE_XDP;
	if (strncmp(section, "perf_event", 10)  == 0) return EBPF_PROG_TYPE_PERF_EVENT;
	if (strncmp(section, "cgroup/skb", 10)  == 0) return EBPF_PROG_TYPE_CGROUP_SKB;
	if (strncmp(section, "cgroup/sock", 11) == 0) return EBPF_PROG_TYPE_CGROUP_SOCK;
	if (strncmp(section, "sockops", 7)      == 0) return EBPF_PROG_TYPE_SOCK_OPS;
	if (strncmp(section, "sk_skb", 6)       == 0) return EBPF_PROG_TYPE_SK_SKB;
	if (strncmp(section, "len_hist", 8)     == 0) return EBPF_PROG_TYPE_SK_SKB;
	if (strncmp(section, "filter", 6)       == 0) return EBPF_PROG_TYPE_SK_SKB;
	return EBPF_PROG_TYPE_UNSPEC;
}

static inline Elf64_Shdr *
elf_sheader(const Elf64_Ehdr *hdr) {
	return (Elf64_Shdr *)((char*)hdr + hdr->e_shoff);
}
 
static inline Elf64_Shdr *
elf_section(const Elf64_Ehdr *hdr, int idx) {
	return &elf_sheader(hdr)[idx];
}

static inline char *
elf_str_table(const Elf64_Ehdr *hdr) {
	if(hdr->e_shstrndx == SHN_UNDEF) return NULL;
	return (char *)hdr + elf_section(hdr, hdr->e_shstrndx)->sh_offset;
}
 
static inline char *
elf_lookup_string(const Elf64_Ehdr *hdr, int offset) {
	char *strtab = elf_str_table(hdr);
	if(strtab == NULL) return NULL;
	return strtab + offset;
}

int
ubpf_load_elf(const void *elf, size_t elf_size, void** text_copy,
              int* prog_type, char **errmsg)
{

    *text_copy = NULL;
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

    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        *errmsg = ubpf_error("wrong machine, expected none or BPF, got %d",
                             ehdr->e_machine);
        goto error;
    }

    if (ehdr->e_shnum > MAX_SECTIONS) {
        *errmsg = ubpf_error("too many sections");
        goto error;
    }

    /* Parse section headers into an array */
    struct section sections[MAX_SECTIONS];
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = bounds_check(&b, ehdr->e_shoff + i*ehdr->e_shentsize, sizeof(*shdr));
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }

        const void *data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ubpf_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;
    }
    /* Find first text section */
    int text_shndx = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = sections[i].shdr;
        if (sections[i].size > 0 && shdr->sh_type == SHT_PROGBITS &&
                shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }
    if (!text_shndx) {
        *errmsg = ubpf_error("text section not found");
        goto error;
    }

    struct section *text = &sections[text_shndx];
    const char* name = elf_lookup_string(ehdr, text->shdr->sh_name);
    *prog_type = section_name_to_prog_type(name);
    printf("section name: %s\nprog type: %d\n", name, *prog_type);
    /* May need to modify text for relocations, so make a copy */
    *text_copy = malloc(text->size);
    if (!*text_copy) {
        *errmsg = ubpf_error("failed to allocate memory");
        goto error;
    }
    memcpy(*text_copy, text->data, text->size);

    return sections[text_shndx].size;
error:
    free(*text_copy);
    return -1;
}
