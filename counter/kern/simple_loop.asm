
kern/simple_loop.o:	file format ELF64-BPF

Disassembly of section sk_skb/loop:
prog:
       0:	r2 = *(u32 *)(r1 + 76)
       1:	r1 = *(u32 *)(r1 + 80)
       2:	r1 -= r2
       3:	*(u64 *)(r10 - 8) = r1
       4:	r1 = *(u64 *)(r10 - 8)
       5:	r3 = r1
       6:	r3 += -1
       7:	*(u64 *)(r10 - 8) = r3
       8:	r3 = 1
       9:	if r3 s> r1 goto +10 <LBB0_2>

LBB0_1:
      10:	r1 = *(u64 *)(r10 - 8)
      11:	r3 = *(u64 *)(r10 - 8)
      12:	r4 = r2
      13:	r4 += r3
      14:	*(u8 *)(r4 + 0) = r1
      15:	r1 = *(u64 *)(r10 - 8)
      16:	r3 = r1
      17:	r3 += -1
      18:	*(u64 *)(r10 - 8) = r3
      19:	if r1 s> 0 goto -10 <LBB0_1>

LBB0_2:
      20:	r0 = 0
      21:	exit
