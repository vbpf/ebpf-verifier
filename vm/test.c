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
#include "ubpf.h"

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-a|--arg INT] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If ARG is given it will be passed in r1. Otherwise r1 will be zero.\n");
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "arg", .val = 'a', .has_arg=1 },
    };

    uint64_t arg = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "ha:", longopts, NULL)) != -1) {
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

    const char *filename = argv[optind];
    FILE *file;
    if (!strcmp(filename, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(filename, "r");
    }

    if (file == NULL) {
        perror("fopen");
        return 1;
    }

    int maxlen = 65536*8;
    void *code = malloc(maxlen);
    int offset = 0;
    int rv;
    while ((rv = fread(code+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        perror("fread");
        return 1;
    }

    char *errmsg;
    struct ubpf_vm *vm = ubpf_create(code, offset, &errmsg);
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
