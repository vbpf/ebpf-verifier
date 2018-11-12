
kern/manual_memset.o:	file format ELF64-BPF

Disassembly of section sk_skb/manual-memset:
manual_memset:
       0:	r2 = *(u32 *)(r1 + 80)
       1:	r2 += -8
       2:	r1 = *(u32 *)(r1 + 76)
       3:	if r1 > r2 goto +3 <LBB0_2>
       4:	r1 = 4294967295 ll
       6:	*(u64 *)(r2 + 0) = r1

LBB0_2:
       7:	r0 = 0
       8:	exit
