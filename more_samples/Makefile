
SRCS = $(wildcard kern/*.c)
BUGS = $(wildcard bugs/*.c)

D=-D__TARGET_ARCH_x86 -D__KERNEL__ -D__BPF_TRACING__

W=-Wno-unused-value \
  -Wno-pointer-sign \
  -Wno-compare-distinct-pointer-types \
  -Wno-gnu-variable-sized-type-not-at-end \
  -Wno-address-of-packed-member \
  -Wno-unknown-warning-option

L=/home/elazarg/workspace/linux

INCLUDES=-I$L/include \
	 -I$L/include/uapi \
	 -I$L/include/generated/uapi \
	 -I$L/arch/x86/include \
	 -I$L/arch/x86/include/generated  \
	 -I$L/arch/x86/include/uapi \
	 -I$L/arch/x86/include/generated/uapi \
	 -include $L/include/linux/kconfig.h  \
	 -I$L/samples/bpf \
	 -I$L/tools/testing/selftests/bpf/

all: load_bpf kern

kern: $(SRCS:.c=.o)

kern/%.o: $(@:.o=.c)
	clang ${INCLUDES} -nostdinc ${D} ${W} -O1 -emit-llvm -c $(@:.o=.c) -o - | llc -march=bpf -filetype=obj -o $@
	llvm-objdump -S -no-show-raw-insn $@ > $(@:.o=.asm)

bugs: $(BUGS:.c=.o)

bugs/%.o: $(@:.o=.c)
	clang ${INCLUDES} -nostdinc ${D} ${W} -O2 -emit-llvm -c $(@:.o=.c) -o $(@:.o=.bc) 
	llvm-dis $(@:.o=.bc)
	llc -march=bpf -filetype=obj $(@:.o=.bc) -o $@
	llvm-objdump -S -no-show-raw-insn $@ > $(@:.o=.asm)

load_bpf: load_bpf.c
	gcc bpf_load.o libbpf.a $@.c -lelf -o $@

clean:
	rm -f load_bpf {kern,bugs}/*.{o,bc,asm,ll}
