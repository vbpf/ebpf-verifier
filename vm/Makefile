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

z_interval_domain_t: DOM=z_interval_domain_
z_ric_domain_t: DOM=z_ric_domain_t
z_SparseDBMGraph: DOM=z_SparseDBMGraph
z_dbm_domain_t: DOM=z_dbm_domain_t
z_SplitDBMGraph: DOM=z_SplitDBMGraph
z_sdbm_domain_t: DOM=z_sdbm_domain_t
z_boxes_domain_t: DOM=z_boxes_domain_t
z_dis_interval_domain_t: DOM=z_dis_interval_domain_t
z_box_apron_domain_t: DOM=z_interval_domain_t
z_oct_apron_domain_t: DOM=z_oct_apron_domain_t
z_opt_oct_apron_domain_t: DOM=z_opt_oct_apron_domain_t
z_pk_apron_domain_t: DOM=z_pk_apron_domain_t
z_term_domain_t: DOM=z_term_domain_t
z_term_dbm_t: DOM=z_term_dbm_t
z_term_dis_int_t: DOM=z_term_dis_int_t
z_num_domain_t: DOM=z_num_domain_t

CXXFLAGS := -Wall -Werror -Wfatal-errors -Iinc \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I../../crab/build/run/ldd/include/ldd/ \
    -I../../crab/build/run/apron/include/ \
    -L../../crab/build/run/ldd/lib/ \
    -O0 -g3 -std=c++17 -Wno-unused-local-typedefs 

all: libubpf.a test

abs_interp.o:
	$(CXX) $(CXXFLAGS) -D DOM=$(DOM) -c -o $@ abs_interp.cpp

libubpf.a: abs_interp.o abs_cfg.o abs_constraints.o ubpf_vm.o ubpf_jit_x86_64.o ubpf_loader.o
	ar rc $@ $^ 

test: test.o libubpf.a 

z_interval_domain_t: test
z_ric_domain_t: test
z_SparseDBMGraph: test
z_dbm_domain_t: test
z_SplitDBMGraph: test
z_sdbm_domain_t: test
z_boxes_domain_t: test
z_dis_interval_domain_t: test
z_box_apron_domain_t: test
z_oct_apron_domain_t: test
z_opt_oct_apron_domain_t: test
z_pk_apron_domain_t: test
z_term_domain_t: test
z_term_dbm_t: test
z_term_dis_int_t: test
z_num_domain_t: test

clean:
	rm -f test libubpf.a *.o
