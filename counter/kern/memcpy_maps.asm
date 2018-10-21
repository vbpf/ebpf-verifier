
kern/memcpy_maps.o:	file format ELF64-BPF

Disassembly of section sk_skb/memcpy-maps:
memcpy_maps:
       0:	r8 = r1
       1:	r1 = 0
       2:	*(u32 *)(r10 - 4) = r1
       3:	r2 = r10
       4:	r2 += -4
       5:	r1 = 0 ll
       7:	call 1
       8:	r6 = r0
       9:	r7 = 1
      10:	*(u32 *)(r10 - 8) = r7
      11:	r2 = r10
      12:	r2 += -8
      13:	r1 = 0 ll
      15:	call 1
      16:	if r6 == 0 goto +37 <LBB0_9>
      17:	if r0 == 0 goto +36 <LBB0_9>
      18:	r4 = *(u32 *)(r8 + 0)
      19:	r7 = 0
      20:	if r4 == 0 goto +33 <LBB0_9>
      21:	r7 = 0
      22:	r2 = r4
      23:	r2 &= 1
      24:	r1 = 0
      25:	if r4 == 1 goto +23 <LBB0_7>
      26:	r3 = r2
      27:	r3 -= r4
      28:	r1 = 0

LBB0_5:
      29:	r4 = r1
      30:	r4 /= 4098
      31:	r4 *= 4098
      32:	r5 = r1
      33:	r5 -= r4
      34:	r4 = r6
      35:	r4 += r5
      36:	r8 = r0
      37:	r8 += r5
      38:	r5 = *(u8 *)(r8 + 0)
      39:	*(u8 *)(r4 + 1) = r5
      40:	r5 = *(u8 *)(r8 + 1)
      41:	*(u8 *)(r4 + 2) = r5
      42:	r1 += 2
      43:	r3 += 2
      44:	if r3 != 0 goto -16 <LBB0_5>
      45:	r3 = r1
      46:	r3 /= 4098
      47:	r3 *= 4098
      48:	r1 -= r3

LBB0_7:
      49:	if r2 == 0 goto +4 <LBB0_9>
      50:	r6 += r1
      51:	r0 += r1
      52:	r1 = *(u8 *)(r0 + 0)
      53:	*(u8 *)(r6 + 1) = r1

LBB0_9:
      54:	r0 = r7
      55:	exit
