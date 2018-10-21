
kern/simple_lt.o:	file format ELF64-BPF

Disassembly of section sk_skb/simple-lt:
prog_simple_lt:
       0:	r2 = *(u32 *)(r1 + 76)
       1:	r1 = *(u32 *)(r1 + 80)
       2:	if r2 >= r1 goto +2 <LBB0_2>
       3:	r1 = 1
       4:	*(u8 *)(r2 + 0) = r1

LBB0_2:
       5:	r0 = 1
       6:	exit
