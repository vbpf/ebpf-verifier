
kern/simple_checksum_neq_fails_verification.o:	file format ELF64-BPF

Disassembly of section sk_skb/checksum:
prog:
       0:	r7 = r1
       1:	r6 = 1
       2:	*(u32 *)(r10 - 4) = r6
       3:	r2 = r10
       4:	r2 += -4
       5:	r1 = 0 ll
       7:	call 1
       8:	if r0 == 0 goto +15 <LBB0_6>
       9:	r1 = *(u8 *)(r0 + 0)
      10:	r2 = *(u32 *)(r7 + 80)
      11:	r3 = *(u32 *)(r7 + 76)
      12:	r3 += 8
      13:	r4 = 0
      14:	if r3 >= r2 goto +6 <LBB0_4>
      15:	r4 = 0

LBB0_3:
      16:	r5 = *(u8 *)(r3 - 8)
      17:	r4 += r5
      18:	r4 &= 255
      19:	r3 += 1
      20:	if r2 != r3 goto -5 <LBB0_3>

LBB0_4:
      21:	r6 = 1
      22:	if r4 != r1 goto +1 <LBB0_6>
      23:	r6 = 0

LBB0_6:
      24:	r0 = r6
      25:	exit
