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

PROJECTDIR := $(CURDIR)../

CRABDIR := ../crab
INSTALL := $(CRABDIR)/install
LDD := $(CRABDIR)/build/run/ldd
LINUX := ../../linux

# Lookup path for libCrab.so
LDFLAGS := -Wl,-rpath,$(INSTALL)/lib/
UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
    LIBCRAB = $(INSTALL)/lib/libCrab.dylib
else
    LIBCRAB = $(INSTALL)/lib/libCrab.so
endif

LDLIBS := \
    $(LIBCRAB) \
    $(LDD)/lib/libldd.a \
    $(LDD)/lib/libtvpi.a \
    $(LDD)/lib/libcudd.a \
    $(LDD)/lib/libst.a \
    $(LDD)/lib/libutil.a \
    $(LDD)/lib/libmtr.a \
    $(LDD)/lib/libepd.a \
    -lmpfr -lgmpxx -lgmp -lm -lstdc++ 

CXXFLAGS := -Wall -Werror -Wfatal-errors \
    -Wno-unused-local-typedefs -Wno-inconsistent-missing-override -Wno-unused-const-variable -Wno-uninitialized -Wno-deprecated \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I inc \
    -I $(INSTALL)/include/ \
    -I $(LDD)/include/ldd/ \
    -O2 -g3 -std=c++17

all: test

SOURCES = $(wildcard *.cpp)
C_SOURCES += $(wildcard *.c)

OBJECTS = $(patsubst %.cpp,%.o,${SOURCES})
OBJECTS += $(patsubst %.c,%.o,${C_SOURCES})

%.o:  $(CXX) ${CXXFLAGS} $< -c -o $@

test: ${OBJECTS}
	$(CXX) ${CXXFLAGS} ${LDFLAGS} ${OBJECTS} ${LDLIBS} -o test 

clean:
	rm -f test *.a *.o

crab_clean:
	rm -rf $(CRABDIR)/build $(CRABDIR)/install

crab_install:
	mkdir -p $(CRABDIR)/build
	cd $(CRABDIR)/build \
	    && cmake -DCMAKE_INSTALL_PREFIX=../install/ -DUSE_LDD=ON ../ \
	    && cmake --build . --target ldd && cmake ../ \
	    && cmake --build . --target install

linux_samples:
	git clone --depth 1 https://github.com/torvalds/linux.git $(LINUX)
	cd $(LINUX); git apply $(PROJECTDIR)/linux.patch
	make -C $(LINUX) headers_install
	make -C $(LINUX) oldconfig < /dev/null
	make -C $(LINUX) samples/bpf/
