
kern/simple_loop.o:	file format ELF64-BPF

Disassembly of section sk_skb/loop:
prog:
       0:	r2 = *(u32 *)(r1 + 80)
       1:	r1 = *(u32 *)(r1 + 76)
       2:	r3 = r2
       3:	r3 -= r1
       4:	r4 = 1
       5:	if r4 s> r3 goto +11 <LBB0_3>
       6:	r2 += -1
       7:	r2 -= r1
       8:	r3 = r2

LBB0_2:
       9:	r4 = r1
      10:	r4 += r2
      11:	*(u8 *)(r4 + 0) = r2
      12:	r3 += -1
      13:	r4 = r2
      14:	r4 += 1
      15:	r2 = r3
      16:	if r4 s> 1 goto -8 <LBB0_2>

LBB0_3:
      17:	r0 = 0
      18:	exit
