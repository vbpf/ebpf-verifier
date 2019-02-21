MAKEFLAGS += --no-builtin-rules

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:src/%.c=objects/%.o)

D=-D__TARGET_ARCH_x86 -D__KERNEL__ -D__BPF_TRACING__

W=-Wno-unused-value \
  -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types \
  -Wno-gnu-variable-sized-type-not-at-end \
  -Wno-address-of-packed-member \
  -Wno-unknown-warning-option

L=/usr/src/linux-headers-$(shell uname -r)

INCLUDES=-Iinclude \
	 -I$L/include \
	 -I$L/include/uapi \
	 -I$L/include/generated/uapi \
	 -I$L/arch/x86/include \
	 -I$L/arch/x86/include/generated  \
	 -I$L/arch/x86/include/uapi \
	 -I$L/arch/x86/include/generated/uapi \
	 -I$L/samples/bpf \
	 -I$L/tools/testing/selftests/bpf \
	 -include $L/include/linux/kconfig.h

all: load_bpf $(OBJS)

objects/%.o: src/%.c
	@mkdir -p objects
	clang ${INCLUDES} ${D} ${W} -O2 -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@ 

load_bpf: load_bpf.c
	gcc bpf_load.o libbpf.a $@.c -lelf -o $@

clean:
	rm -f load_bpf objects/*.o
