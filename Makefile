
BUILDDIR := build
BINDIR := .
SRCDIR := src

SOURCES := $(wildcard ${SRCDIR}/*.cpp) $(wildcard ${SRCDIR}/crab/*.cpp)
ALL_OBJECTS := $(SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)
DEPENDS := $(ALL_OBJECTS:%.o=%.d)

TEST_SOURCES := $(wildcard ${SRCDIR}/test*.cpp)
TEST_OBJECTS := $(TEST_SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)

MAIN_SOURCES := $(wildcard ${SRCDIR}/main_*.cpp)
MAIN_OBJECTS := $(MAIN_SOURCES:${SRCDIR}/%.cpp=${BUILDDIR}/%.o)

OBJECTS := $(filter-out $(MAIN_OBJECTS) $(TEST_OBJECTS),$(ALL_OBJECTS))

LINUX := $(abspath ../linux)

LDLIBS += -lgmp

CXXFLAGS := -Wall -Wfatal-errors -O2 -g3 -std=c++17 -flto -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8 -I $(SRCDIR) -I external #  -Werror does not work well in Linux

all: $(BINDIR)/check  # $(BINDIR)/unit-test

-include $(DEPENDS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(BUILDDIR)
	@printf "$@ <- $<\n"
	@$(CXX) ${CXXFLAGS} $< -MMD -c -o $@ # important: use $< and not $^

$(BUILDDIR)/crab/%.o: $(SRCDIR)/crab/%.cpp
	@mkdir -p $(BUILDDIR)
	@printf "$@ <- $<\n"
	@$(CXX) ${CXXFLAGS} $< -MMD -c -o $@ # important: use $< and not $^

$(BINDIR)/unit-test: ${BUILDDIR}/test.o ${TEST_OBJECTS} ${OBJECTS}
	@printf "$@ <- $^\n"
	@$(CXX) ${CXXFLAGS} ${LDFLAGS} $^ ${LDLIBS} -o $@

$(BINDIR)/check: ${BUILDDIR}/main_check.o ${OBJECTS}
	@printf "$@ <- $^\n"
	@$(CXX) ${CXXFLAGS} ${LDFLAGS} $^ ${LDLIBS} -o $@

clean:
	rm -f $(BINDIR)/check $(BINDIR)/unit-test $(BUILDDIR)/*.o $(BUILDDIR)/crab/*.o $(BUILDDIR)/*.d $(BUILDDIR)/crab/*.d

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
