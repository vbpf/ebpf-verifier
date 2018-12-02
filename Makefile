

BUILDDIR := build
BINDIR := bin
SRCDIR := src

SOURCES := $(wildcard ${SRCDIR}/*.cpp)
OBJECTS := $(SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)
OBJECTS := $(filter-out ${BUILDDIR}/disassemble.o,$(OBJECTS))

CRABDIR := crab
LDD := $(CRABDIR)/install/ldd
ELINA := $(CRABDIR)/install/elina
INSTALL := $(abspath ${CRABDIR})/install/crab

LINUX := $(abspath ../linux)

# Lookup path for libCrab.so
LDFLAGS := -Wl,-rpath,$(INSTALL)/lib/ -Wl,-rpath,$(INSTALL)/lib/
UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
    LIBCRAB = $(INSTALL)/lib/libCrab.dylib
else
    LIBCRAB = $(INSTALL)/lib/libCrab.so
    LDFLAGS += -Wl,--disable-new-dtags 
endif

LDLIBS := $(LIBCRAB)

LDLIBS += \
    $(ELINA)/lib/libelinalinearize.so \
    $(ELINA)/lib/libelinaux.so \
    $(ELINA)/lib/liboptoct.so \
    $(ELINA)/lib/liboptpoly.so \
    $(ELINA)/lib/liboptzones.so \
    $(ELINA)/lib/libpartitions.so

LDLIBS += \
    $(LDD)/lib/libtvpi.a \
    $(LDD)/lib/libcudd.a \
    $(LDD)/lib/libst.a \
    $(LDD)/lib/libutil.a \
    $(LDD)/lib/libmtr.a \
    $(LDD)/lib/libepd.a \
    $(LDD)/lib/libldd.a \

LDLIBS += -lmpfr -lgmpxx -lgmp -lm -lstdc++ 

CXXFLAGS := -Wall -Werror -Wfatal-errors -O0 -g3 -std=c++17

CRABFLAGS := \
    -Wno-unused-local-typedefs -Wno-unused-function -Wno-inconsistent-missing-override \
    -Wno-unused-const-variable -Wno-uninitialized -Wno-deprecated \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I $(INSTALL)/include/ \
    -I $(LDD)/include/ldd/ \
    -I $(LDD)/include/ldd/include/ \
    -I $(ELINA)/include/

all: $(BINDIR)/check $(BINDIR)/disassemble

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(BUILDDIR)
	@printf "$@ <- $^\n"
	@$(CXX) ${CXXFLAGS} ${CRABFLAGS} $< -c -o $@

$(BINDIR)/check: ${OBJECTS}
	@printf "$@ <- ${BUILDDIR}/*.o\n"
	@$(CXX) ${CXXFLAGS}  ${CRABFLAGS} ${LDFLAGS} ${OBJECTS} ${LDLIBS} -o $@

DISASM_OBJECTS := \
    ${BUILDDIR}/disassemble.o \
    ${BUILDDIR}/asm_dis.o \
    ${BUILDDIR}/asm_ostream.o \
    ${BUILDDIR}/asm_marshal.o \
    ${BUILDDIR}/asm_cfg.o \
    ${BUILDDIR}/prototypes.o

$(BINDIR)/disassemble: ${DISASM_OBJECTS} 
	@printf "$@ <- $<\n"
	$(CXX) ${CXXFLAGS} ${DISASM_OBJECTS} -o $@

clean:
	rm -f $(BINDIR)/check $(BINDIR)/disassemble $(BUILDDIR)/*.o

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
	cd $(LINUX); git apply counter/linux.patch
	make -C $(LINUX) headers_install
	make -C $(LINUX) oldconfig < /dev/null
	make -C $(LINUX) samples/bpf/

print-% :
	@echo $* = $($*)
