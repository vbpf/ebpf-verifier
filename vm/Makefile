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

CFLAGS := -Wall -Werror -Iinc -O2 -g3

l := /usr/local/lib/lib
LDLIBS := $lCrab.so $lldd.a $ltvpi.a $lcudd.a $lst.a $lutil.a $lmtr.a $lepd.a $lpolkaMPQ.a \
    $loctD.a $loptoct.a $llinkedlistapi.a $lapron.a $lboxMPQ.a $litvMPQ.a \
    -lmpfr -lgmpxx -lgmp -lm -lstdc++ 

ifeq ($(COVERAGE),1)
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs
endif

ifeq ($(ASAN),1)
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
endif

CXXFLAGS := -Wall -Werror -Wfatal-errors -Iinc \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I../crab/build/run/ldd/include/ldd/ \
    -I../crab/build/apron-prefix/src/apron/optoctagons/ \
    -I../crab/build/run/apron/include/ \
    -L../crab/build/run/ldd/lib/ \
    -O0 -g3 -std=c++17 -Wno-unused-local-typedefs 

all: libubpf.a test

libubpf.a: ubpf_loader.o ubpf_validator.o abs_interp.o abs_cfg.o abs_constraints.o crab_domains.o
	ar rc $@ $^ 

test: test.o libubpf.a 

clean:
	rm -f test libubpf.a *.o
