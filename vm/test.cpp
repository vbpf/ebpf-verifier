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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <sysexits.h>

#include <iostream>
#include <iterator>
#include <fstream>
#include <vector>
#include <algorithm> // for std::copy

#include "ubpf.h"
#include "ubpf_int.h"
#include "abs_interp.h"

//static char *readfile(const char *path, size_t maxlen, size_t *len);

static void usage(const char *name)
{
    fprintf(stdout, "usage: %s [-h] [-t TYPE] DOMAIN BINARY\n", name);
    fprintf(stdout, "\nterifies the eBPF code in BINARY using DOMAIN assuming program type TYPE\n");
    fprintf(stdout, "tvailable domains:\n");
    print_domains();
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        usage(argv[0]);
        return EX_USAGE;
    }

    ebpf_prog_type prog_type = (ebpf_prog_type)atoi(argv[1]);
    const char *domain_name = argv[2];
    const char *code_filename = argv[3];

    if (!is_valid_domain(domain_name)) {
        fprintf(stderr, "argument '%s' is not a valid domain\n", domain_name);
        fprintf(stdout, "tvailable domains:\n");
        print_domains();
        return EX_USAGE;
    }

    std::ifstream is(code_filename, std::ifstream::ate | std::ifstream::binary);
    size_t code_len = is.tellg(); 
    if (code_len % 8 != 0) {
        fprintf(stderr, "file size must be a multiple of 8\n");
        exit(EX_DATAERR);
    }
    uint32_t num_insts = code_len / 8;
    is.seekg(0);
    std::vector<ebpf_inst> code(num_insts);
    is.read((char*)code.data(), code_len);

    char *errmsg;
    int rv = 1;
    if (!validate_simple(code.data(), num_insts, &errmsg)) {
        fprintf(stdout, "trivial verification failure: %s\n", errmsg);
        free(errmsg);
    } else if (!abs_validate(code.data(), num_insts, domain_name, prog_type, &errmsg)) {
        fprintf(stdout, "verification failed: %s\n", errmsg);
        free(errmsg);
    } else {
        rv = 0;
    }
    return rv;
}
/*
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
        exit(EX_DATAERR);
    }

    char *data = (char*)calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        exit(EX_DATAERR);
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        exit(EX_DATAERR);
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}
*/