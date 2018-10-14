#!/bin/bash
for file in $@
do
	output="${file%.*}.o"
	W="-Wno-unused-value -Wno-pointer-sign -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-unknown-warning-option"
	L=~/workspace/linux
	INCLUDES="-I$L/arch/x86/include -I$L/arch/x86/include/generated  -I$L/include -I$L/arch/x86/include/uapi -I$L/arch/x86/include/generated/uapi -I$L/include/uapi -I$L/include/generated/uapi -include $L/include/linux/kconfig.h  -I/home/elazarg/workspace/linux/samples/bpf -I$L/tools/testing/selftests/bpf/"
	clang ${INCLUDES} -nostdinc -D__KERNEL__ -D__BPF_TRACING__ ${W} -O2 -emit-llvm -c ${file} -o - | llc -march=bpf -filetype=obj -o ${output}
done
