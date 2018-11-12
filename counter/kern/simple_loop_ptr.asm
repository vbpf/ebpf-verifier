
kern/simple_loop_ptr.o:	file format ELF64-BPF

Disassembly of section sk_skb/loop-ptr:
prog:
       0:	r2 = *(u32 *)(r1 + 80)
       1:	r1 = *(u32 *)(r1 + 76)
       2:	if r1 >= r2 goto +28 <LBB0_7>
       3:	r4 = r1
       4:	r4 ^= -1
       5:	r3 = r2
       6:	r3 += r4
       7:	r4 = r3
       8:	r4 >>= 3
       9:	r4 += 1
      10:	r4 &= 7
      11:	if r4 == 0 goto +6 <LBB0_4>
      12:	r4 = -r4
      13:	r5 = 15

LBB0_3:
      14:	*(u64 *)(r1 + 0) = r5
      15:	r1 += 8
      16:	r4 += 1
      17:	if r4 != 0 goto -4 <LBB0_3>

LBB0_4:
      18:	r4 = 56
      19:	if r4 > r3 goto +11 <LBB0_7>
      20:	r3 = 15

LBB0_6:
      21:	*(u64 *)(r1 + 0) = r3
      22:	*(u64 *)(r1 + 8) = r3
      23:	*(u64 *)(r1 + 16) = r3
      24:	*(u64 *)(r1 + 24) = r3
      25:	*(u64 *)(r1 + 32) = r3
      26:	*(u64 *)(r1 + 40) = r3
      27:	*(u64 *)(r1 + 48) = r3
      28:	*(u64 *)(r1 + 56) = r3
      29:	r1 += 64
      30:	if r2 > r1 goto -10 <LBB0_6>

LBB0_7:
      31:	r0 = 0
      32:	exit
