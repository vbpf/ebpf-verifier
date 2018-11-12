
kern/simple_checksum.o:	file format ELF64-BPF

Disassembly of section sk_skb/checksum:
prog:
       0:	r7 = r1
       1:	r6 = 1
       2:	*(u32 *)(r10 - 4) = r6
       3:	r2 = r10
       4:	r2 += -4
       5:	r1 = 0 ll
       7:	call 1
       8:	if r0 == 0 goto +20 <LBB0_6>
       9:	r1 = *(u8 *)(r0 + 0)
      10:	r2 = *(u32 *)(r7 + 80)
      11:	r3 = *(u32 *)(r7 + 76)
      12:	r6 = 1
      13:	*(u64 *)(r10 - 16) = r6
      14:	r5 = r3
      15:	r5 += 8
      16:	r4 = 0
      17:	if r5 >= r2 goto +9 <LBB0_4>
      18:	r4 = 0

LBB0_3:
      19:	r5 = *(u8 *)(r3 + 0)
      20:	r0 = *(u64 *)(r10 - 16)
      21:	r3 += r0
      22:	r4 += r5
      23:	r4 &= 255
      24:	r5 = r3
      25:	r5 += 8
      26:	if r2 > r5 goto -8 <LBB0_3>

LBB0_4:
      27:	if r4 != r1 goto +1 <LBB0_6>
      28:	r6 = 0

LBB0_6:
      29:	r0 = r6
      30:	exit
