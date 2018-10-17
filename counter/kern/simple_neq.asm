
kern/simple_neq.o:	file format ELF64-BPF

Disassembly of section sk_skb/simple-neq:
prog_simple_neq:
       0:	r0 = 1
       1:	r2 = *(u32 *)(r1 + 76)
       2:	r1 = *(u32 *)(r1 + 80)
       3:	r1 -= r2
       4:	if r1 != 1 goto +3 <LBB0_2>
       5:	r1 = 15
       6:	*(u8 *)(r2 + 0) = r1
       7:	r0 = 0

LBB0_2:
       8:	exit
