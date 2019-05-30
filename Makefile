
BUILDDIR := build
BINDIR := .
SRCDIR := src

SOURCES := $(wildcard ${SRCDIR}/*.cpp)
ALL_OBJECTS := $(SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)
DEPENDS := $(ALL_OBJECTS:%.o=%.d)

TEST_SOURCES := $(wildcard ${SRCDIR}/test*.cpp)
TEST_OBJECTS := $(TEST_SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)

MAIN_SOURCES := $(wildcard ${SRCDIR}/main_*.cpp)
MAIN_OBJECTS := $(MAIN_SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)

OBJECTS := $(filter-out $(MAIN_OBJECTS) $(TEST_OBJECTS),$(ALL_OBJECTS))

CRABDIR := $(abspath external/crab)
LDD := ${CRABDIR}/install/ldd
INSTALL := ${CRABDIR}/install/crab

# to use APRON, pass MOD=APRON in make invocation
MOD ?= ELINA
ifeq ($(MOD),ELINA)
    MOD := ELINA
    mod := elina
else
    MOD := APRON
    mod := apron
endif

MODINSTALL := ${CRABDIR}/install/$(mod)

LINUX := $(abspath ../linux)

# Lookup path for libCrab.so
LDFLAGS := -Wl,-rpath,${INSTALL}/lib/
LDFLAGS += -Wl,-rpath,${MODINSTALL}/lib/

UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
    LIBCRAB = $(INSTALL)/lib/libCrab.dylib
else
    LIBCRAB = $(INSTALL)/lib/libCrab.so
    LDFLAGS += -Wl,--disable-new-dtags 
endif

LDLIBS := $(LIBCRAB)

ifeq ($(MOD),ELINA)
    LDLIBS += \
        $(MODINSTALL)/lib/libelinalinearize.so \
        $(MODINSTALL)/lib/libelinaux.so \
        $(MODINSTALL)/lib/liboptoct.so \
        $(MODINSTALL)/lib/liboptpoly.so \
        $(MODINSTALL)/lib/liboptzones.so \
        $(MODINSTALL)/lib/libpartitions.so
else
    LDLIBS += \
        $(MODINSTALL)/lib/libpolkaMPQ.a \
        $(MODINSTALL)/lib/liboctD.a \
        $(MODINSTALL)/lib/liboptoct.a \
        $(MODINSTALL)/lib/liblinkedlistapi.a \
        $(MODINSTALL)/lib/libapron.a \
        $(MODINSTALL)/lib/libboxMPQ.a \
        $(MODINSTALL)/lib/libitvMPQ.a
endif

LDLIBS += \
    $(LDD)/lib/libtvpi.a \
    $(LDD)/lib/libcudd.a \
    $(LDD)/lib/libst.a \
    $(LDD)/lib/libutil.a \
    $(LDD)/lib/libmtr.a \
    $(LDD)/lib/libepd.a \
    $(LDD)/lib/libldd.a \

LDLIBS += -lmpfr -lgmpxx -lgmp -lm -lstdc++ 

CXXFLAGS := -Wall -Wfatal-errors -O2 -g3 -std=c++17 -I external -D$(MOD)_DOMAINS #  -Werror does not work well in Linux

CRABFLAGS := \
    -Wno-unused-local-typedefs -Wno-unused-function -Wno-inconsistent-missing-override \
    -Wno-unused-const-variable -Wno-uninitialized -Wno-deprecated \
    -DBSD -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 \
    -I $(INSTALL)/include/ \
    -I $(LDD)/include/ldd/ \
    -I $(LDD)/include/ldd/include/ \
    -I $(MODINSTALL)/include/

all: $(BINDIR)/check  # $(BINDIR)/unit-test

-include $(DEPENDS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(BUILDDIR)
	@printf "$@ <- $<\n"
	@$(CXX) ${CXXFLAGS} ${CRABFLAGS} $< -MMD -c -o $@ # important: use $< and not $^

$(BINDIR)/unit-test: ${BUILDDIR}/test.o ${TEST_OBJECTS} ${OBJECTS}
	@printf "$@ <- $^\n"
	@$(CXX) ${CXXFLAGS} ${CRABFLAGS} ${LDFLAGS} $^ ${LDLIBS} -o $@

$(BINDIR)/check: ${BUILDDIR}/main_check.o ${OBJECTS}
	@printf "$@ <- $^\n"
	@$(CXX) ${CXXFLAGS} ${CRABFLAGS} ${LDFLAGS} $^ ${LDLIBS} -o $@

clean:
	rm -f $(BINDIR)/check $(BINDIR)/unit-test $(BUILDDIR)/*.o $(BUILDDIR)/*.d

crab_clean:
	rm -rf $(CRABDIR)/build $(CRABDIR)/install

crab_install:
	mkdir -p $(CRABDIR)/build
	cd $(CRABDIR)/build \
	    && cmake -DCMAKE_INSTALL_PREFIX=../install/ -DUSE_LDD=ON -DUSE_$(MOD)=ON ../ \
	    && cmake --build . --target ldd && cmake ../ \
	    && cmake --build . --target $(mod) && cmake ../ \
	    && cmake --build . --target install

linux_samples:
	git clone --depth 1 https://github.com/torvalds/linux.git $(LINUX)
	cd $(LINUX); git apply counter/linux.patch
	make -C $(LINUX) headers_install
	make -C $(LINUX) oldconfig < /dev/null
	make -C $(LINUX) samples/bpf/

html: ${SRCDIR}/*.*pp
	doxygen

print-% :
	@echo $* = $($*)
