# Copyright 2015 Big Switch Networks, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(COVERAGE),1)
COVERAGE_CFLAGS := -fprofile-arcs -ftest-coverage
COVERAGE_LDFLAGS := -fprofile-arcs
endif

DYNASM := ../dynasm

CFLAGS := -Wall -Werror -Iinc -I$(DYNASM) -O2 -g $(COVERAGE_CFLAGS)
LDFLAGS := $(COVERAGE_LDFLAGS)

all: libubpf.a test

%.c: %.dasm minilua
	LUA_PATH=$(DYNASM)/?.lua ./minilua $(DYNASM)/dynasm.lua -o $@ $<

libubpf.a: ubpf_vm.o ubpf_jit.o ubpf_loader.o
	ar rc $@ $^

test: test.o libubpf.a

minilua: ../luajit-2.0/src/host/minilua.c
	$(CC) -o $@ $< -lm

clean:
	rm -f test libubpf.a *.o ubpf_jit.c
