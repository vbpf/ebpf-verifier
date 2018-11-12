
kern/subtract_pointer_from_scalar.o:	file format ELF64-BPF

Disassembly of section sk_skb/simple-lt:
prog_simple_lt:
       0:	r2 = *(u32 *)(r1 + 76)
       1:	r3 = -392
       2:	r3 -= r2
       3:	r1 = *(u32 *)(r1 + 80)
       4:	r3 += r1
       5:	if r3 > 1200 goto +2 <LBB0_2>
       6:	r1 = 1
       7:	*(u64 *)(r2 + 0) = r1

LBB0_2:
       8:	r0 = 1
       9:	exit
