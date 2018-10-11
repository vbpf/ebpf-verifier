#!/bin/bash
file=$1
output="${file%.*}.o"
W="-Wno-unused-value -Wno-pointer-sign -D__TARGET_ARCH_x86 -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option"
clang -nostdinc -D__KERNEL__ -D__BPF_TRACING__ ${W} -O2 -emit-llvm -c ${file} -o - | llc -march=bpf -filetype=obj -o ${output}
