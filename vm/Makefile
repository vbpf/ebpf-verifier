PROJECTDIR := $(CURDIR)../

CRABDIR := ../crab
INSTALL := $(CRABDIR)/install/crab
LDD := $(CRABDIR)/install/ldd
ELINA := $(CRABDIR)/install/elina
LINUX := ../../linux

# Lookup path for libCrab.so
LDFLAGS := -Wl,-rpath,$(INSTALL)/lib/ # -Wl,-rpath,$(ELINA)/lib/
UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
    LIBCRAB = $(INSTALL)/lib/libCrab.dylib
else
    LIBCRAB = $(INSTALL)/lib/libCrab.so
endif

LDLIBS := \
    $(LIBCRAB) \
    $(ELINA)/lib/libelinalinearize.so \
    $(ELINA)/lib/libelinaux.so \
    $(ELINA)/lib/liboptoct.so \
    $(ELINA)/lib/liboptpoly.so \
    $(ELINA)/lib/liboptzones.so \
    $(LDD)/lib/libtvpi.a \
    $(LDD)/lib/libcudd.a \
    $(LDD)/lib/libst.a \
    $(LDD)/lib/libutil.a \
    $(LDD)/lib/libmtr.a \
    $(LDD)/lib/libepd.a \
    $(LDD)/lib/libldd.a \
    -lmpfr -lgmpxx -lgmp -lm -lstdc++ 

CXXFLAGS := -Wall -Werror -Wfatal-errors \
    -Wno-unused-local-typedefs -Wno-unused-function -Wno-inconsistent-missing-override -Wno-unused-const-variable -Wno-uninitialized -Wno-deprecated \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I inc \
    -I $(INSTALL)/include/ \
    -I $(LDD)/include/ldd/ \
    -I $(LDD)/include/ldd/include/ \
    -I $(ELINA)/include/ \
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
	rm -f test *.o

crab_clean:
	rm -rf $(CRABDIR)/build $(CRABDIR)/install

crab_install:
	mkdir -p $(CRABDIR)/build
	cd $(CRABDIR)/build \
	    && cmake -DCMAKE_INSTALL_PREFIX=../install/ -DUSE_LDD=ON -DUSE_ELINA=ON ../ \
	    && cmake --build . --target ldd && cmake ../ \
	    && cmake --build . --target elina && cmake ../ \
	    && cmake --build . --target install

linux_samples:
	git clone --depth 1 https://github.com/torvalds/linux.git $(LINUX)
	cd $(LINUX); git apply $(PROJECTDIR)/linux.patch
	make -C $(LINUX) headers_install
	make -C $(LINUX) oldconfig < /dev/null
	make -C $(LINUX) samples/bpf/
