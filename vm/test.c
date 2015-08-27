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

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include "ubpf.h"

static void *readfile(const char *path, size_t maxlen, size_t *len);

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-a|--arg INT] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If --arg is given then it will be passed in r1. Otherwise r1 will be zero.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "arg", .val = 'a', .has_arg=1 },
        { .name = "mem", .val = 'm', .has_arg=1 },
    };

    uint64_t arg = 0;
    const char *mem_filename = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "ha:m:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'a': {
            char *endptr;
            arg = strtoull(optarg, &endptr, 0);
            if (*endptr) {
                fprintf(stderr, "Invalid --arg option.\n");
                return 1;
            }
            break;
        }
        case 'm':
            mem_filename = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    const char *code_filename = argv[optind];
    size_t code_len;
    void *code = readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    if (mem_filename != NULL) {
        if (arg != 0) {
            fprintf(stderr, "Can't specify both --arg and --mem\n");
            return 1;
        }

        void *mem = readfile(mem_filename, 1024*1024, NULL);
        if (mem == NULL) {
            return 1;
        }

        arg = (uintptr_t)mem;
    }

    char *errmsg;
    struct ubpf_vm *vm = ubpf_create(code, code_len, &errmsg);
    if (vm == NULL) {
        fprintf(stderr, "Failed to create VM: %s\n", errmsg);
        free(errmsg);
        return 1;
    }

    uint64_t ret = ubpf_exec(vm, arg);
    printf("0x%"PRIx64"\n", ret);

    ubpf_destroy(vm);

    return 0;
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}
