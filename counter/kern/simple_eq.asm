
kern/simple_eq.o:	file format ELF64-BPF

Disassembly of section sk_skb/simple-eq-linux:
prog_simple_eq_linux:
       0:	r0 = 1
       1:	r2 = *(u32 *)(r1 + 76)
       2:	r1 = *(u32 *)(r1 + 80)
       3:	if r2 == r1 goto +3 <LBB0_2>
       4:	r1 = 15
       5:	*(u8 *)(r2 + 0) = r1
       6:	r0 = 0

LBB0_2:
       7:	exit
