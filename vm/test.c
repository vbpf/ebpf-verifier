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
#include "ubpf.h"

int main(int argc, char **argv)
{
    /* TODO arg parsing */

    int maxlen = 65536*8;
    void *code = malloc(maxlen);
    int offset = 0;
    int rv;
    while ((rv = read(STDIN_FILENO, code+offset, maxlen-offset)) > 0) {
        offset += rv;
    }

    if (rv < 0) {
        perror("read");
        return 1;
    }

    char *errmsg;
    struct ubpf_vm *vm = ubpf_create(code, offset, &errmsg);
    if (vm == NULL) {
        fprintf(stderr, "Failed to create VM: %s\n", errmsg);
        free(errmsg);
        return 1;
    }

    uint64_t ret = ubpf_exec(vm, 0);
    printf("0x%"PRIx64"\n", ret);

    ubpf_destroy(vm);

    return 0;
}
