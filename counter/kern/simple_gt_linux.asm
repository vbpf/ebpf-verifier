
kern/simple_gt_linux.o:	file format ELF64-BPF

Disassembly of section sk_skb/simple-gt-linux:
prog_simple_eq_linux:
       0:	r0 = 1
       1:	r2 = *(u32 *)(r1 + 80)
       2:	r1 = *(u32 *)(r1 + 76)
       3:	r3 = r1
       4:	r3 += 8
       5:	if r3 >= r2 goto +3 <LBB0_2>
       6:	r2 = 15
       7:	*(u32 *)(r1 + 0) = r2
       8:	r0 = 0

LBB0_2:
       9:	exit
