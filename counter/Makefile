MAKEFLAGS += --no-builtin-rules

SRCS = $(wildcard kern/*.c)
BUGS = $(wildcard bugs/*.c)
OBJS = $(SRCS:.c=.o)

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
	 -I$L/samples/bpf \
	 -I$L/tools/testing/selftests/bpf/ \
	 -include $L/include/linux/kconfig.h

all: load_bpf kern

kern/%.bc: kern/%.c
	clang ${INCLUDES} ${D} ${W} -O2 -emit-llvm -c $< -o $@ 

kern/%.ll: kern/%.bc
	llvm-dis $<

kern/%.o: kern/%.bc kern/%.ll
	llc -march=bpf -filetype=obj $< -o $@
	cp $@ /tmp/$@
	./extract_sections.sh /tmp/$@ ../samples/counter/

kern/%.asm: kern/%.o
	llvm-objdump -S -no-show-raw-insn $< > $@

kern: $(SRCS:.c=.asm)

bugs: $(BUGS:.c=.o)

bugs/%.o: bugs/%.c
	clang ${INCLUDES} ${D} ${W} -O2 -emit-llvm -c $(@:.o=.c) -o $(@:.o=.bc) 
	llvm-dis $(@:.o=.bc)
	llc -march=bpf -filetype=obj -o $@ $(@:.o=.bc)
	llvm-objdump -S -no-show-raw-insn $@ > $(@:.o=.asm)

load_bpf: load_bpf.c
	gcc bpf_load.o libbpf.a $@.c -lelf -o $@

clean:
	rm -f load_bpf
	cd kern && rm -f *.o *.bc *.asm *.ll
	cd bugs && rm -f *.o *.bc *.asm *.ll

# don't try to compile c files on your own
.SUFFIXES:

# don't remove intermediate files
.SECONDARY:
