/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <math.h>
#include <sysexits.h>
#include "ubpf.h"
#include "ubpf_int.h"
#include "abs_interp.h"

static char *readfile(const char *path, size_t maxlen, size_t *len);

static void usage(const char *name)
{
    fprintf(stdout, "usage: %s [-h] [-t TYPE] DOMAIN BINARY\n", name);
    fprintf(stdout, "\nVerifies the eBPF code in BINARY using DOMAIN assuming program type TYPE\n");
    fprintf(stdout, "Available domains:\n");
    print_domains();
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { },
        { },
        { }
    };
    longopts[0].name = "help";
    longopts[0].val = 'h';

    longopts[1].name = "type";
    longopts[1].val = 't';
    longopts[1].has_arg = 1;

    enum ebpf_prog_type prog_type = EBPF_PROG_TYPE_UNSPEC;
    int opt;
    while ((opt = getopt_long(argc, argv, "ht::", longopts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 't':
            prog_type = (ebpf_prog_type)atoi(optarg);
            break;
        default:
            usage(argv[0]);
            return EX_USAGE;
        }
    }

    if (argc != optind + 2) {
        usage(argv[0]);
        return EX_USAGE;
    }
    const char *domain_name = argv[optind++];
    const char *code_filename = argv[optind];

    if (!is_valid_domain(domain_name)) {
        fprintf(stderr, "Argument '%s' is not a valid domain\n", domain_name);
        return EX_USAGE;
    }


    size_t code_len;
    ebpf_inst* code = (ebpf_inst*)readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        return EX_DATAERR;
    }

    char *errmsg;
    int rv = 1;
    uint32_t num_insts = code_len / 8;
    if (code_len % 8 != 0) {
        fprintf(stderr, "code_len must be a multiple of 8\n");
        rv = EX_DATAERR;
    } else if (!validate_simple(code, num_insts, &errmsg)) {
        fprintf(stdout, "Trivial verification failure: %s\n", errmsg);
        free(errmsg);
    } else if (!abs_validate(code, num_insts, domain_name, prog_type, &errmsg)) {
        fprintf(stdout, "Verification failed: %s\n", errmsg);
        free(errmsg);
    } else {
        rv = 0;
    }
    free(code);
    return rv;
}

static char *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    char *data = (char*)calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
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
