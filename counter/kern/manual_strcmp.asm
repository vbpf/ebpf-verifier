
kern/manual_strcmp.o:	file format ELF64-BPF

Disassembly of section sk_skb/manual-strcmp:
manual_strcmp:
       0:	r7 = 1
       1:	*(u32 *)(r10 - 4) = r7
       2:	r1 = 2
       3:	*(u32 *)(r10 - 8) = r1
       4:	r2 = r10
       5:	r2 += -4
       6:	r1 = 0 ll
       8:	call 1
       9:	r6 = r0
      10:	r2 = r10
      11:	r2 += -8
      12:	r1 = 0 ll
      14:	call 1
      15:	if r6 == 0 goto +8 <LBB0_4>
      16:	r7 = 1
      17:	if r0 == 0 goto +6 <LBB0_4>
      18:	r1 = *(u8 *)(r6 + 0)
      19:	r2 = *(u8 *)(r0 + 0)
      20:	r7 = 0
      21:	if r1 != r2 goto +2 <LBB0_4>
      22:	r7 = 1
      23:	if r1 != 0 goto +2 <LBB0_5>

LBB0_4:
      24:	r0 = r7
      25:	exit

LBB0_5:
      26:	r1 = *(u8 *)(r6 + 1)
      27:	r2 = *(u8 *)(r0 + 1)
      28:	r7 = 0
      29:	if r1 != r2 goto -6 <LBB0_4>
      30:	r7 = 1
      31:	if r1 == 0 goto -8 <LBB0_4>
      32:	r1 = *(u8 *)(r6 + 2)
      33:	r2 = *(u8 *)(r0 + 2)
      34:	r7 = 0
      35:	if r1 != r2 goto -12 <LBB0_4>
      36:	r7 = 1
      37:	if r1 == 0 goto -14 <LBB0_4>
      38:	r1 = *(u8 *)(r6 + 3)
      39:	r2 = *(u8 *)(r0 + 3)
      40:	r7 = 0
      41:	if r1 != r2 goto -18 <LBB0_4>
      42:	r7 = 1
      43:	if r1 == 0 goto -20 <LBB0_4>
      44:	r1 = *(u8 *)(r0 + 4)
      45:	r2 = *(u8 *)(r6 + 4)
      46:	r7 = 1
      47:	if r2 == r1 goto -24 <LBB0_4>
      48:	r7 = 0
      49:	goto -26 <LBB0_4>
