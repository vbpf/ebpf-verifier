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

CRABDIR := ../crab
LDD := $(CRABDIR)/build/run/ldd/lib
APRON := $(CRABDIR)/build/run/apron/lib

LDLIBS := \
    $(CRABDIR)/install/lib/libCrab.so \
    $(LDD)/libldd.a \
    $(LDD)/libtvpi.a \
    $(LDD)/libcudd.a \
    $(LDD)/libst.a \
    $(LDD)/libutil.a \
    $(LDD)/libmtr.a \
    $(LDD)/libepd.a \
    $(APRON)/libpolkaMPQ.a \
    $(APRON)/liboctD.a \
    $(APRON)/liboptoct.a \
    $(APRON)/liblinkedlistapi.a \
    $(APRON)/libapron.a \
    $(APRON)/libboxMPQ.a \
    $(APRON)/libitvMPQ.a \
    -lmpfr -lgmpxx -lgmp -lm -lstdc++ 

CXXFLAGS := -Wall -Werror -Wfatal-errors -Iinc \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I$(CRABDIR)/install/include/ \
    -I$(CRABDIR)/build/run/ldd/include/ldd/ \
    -I$(CRABDIR)/build/run/apron/include/ \
    -I$(CRABDIR)/build/apron-prefix/src/apron/optoctagons/ \
    -L$(CRABDIR)/build/run/ldd/lib/ \
    -O0 -g3 -std=c++17 -Wno-unused-local-typedefs 

all: libubpf.a test

libubpf.a: ubpf_loader.o ubpf_validator.o abs_interp.o abs_cfg.o abs_constraints.o crab_domains.o
	ar rc $@ $^ 

test: test.o libubpf.a 

clean:
	rm -f test libubpf.a *.o
