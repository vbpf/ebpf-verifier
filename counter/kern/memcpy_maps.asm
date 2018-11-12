
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
      16:	if r6 == 0 goto +48 <LBB0_9>
      17:	if r0 == 0 goto +47 <LBB0_9>
      18:	r3 = *(u32 *)(r8 + 0)
      19:	r7 = 0
      20:	if r3 == 0 goto +44 <LBB0_9>
      21:	r7 = 0
      22:	r1 = r3
      23:	r1 &= 3
      24:	r4 = r3
      25:	r4 += -1
      26:	r5 = 3
      27:	r2 = 0
      28:	if r5 > r4 goto +23 <LBB0_6>
      29:	r3 -= r1
      30:	r2 = 0

LBB0_5:
      31:	r4 = r2
      32:	r4 &= 4088
      33:	r5 = r6
      34:	r5 += r4
      35:	r8 = r0
      36:	r8 += r4
      37:	r9 = *(u8 *)(r8 + 0)
      38:	*(u8 *)(r5 + 0) = r9
      39:	r8 = *(u8 *)(r8 + 0)
      40:	*(u8 *)(r5 + 0) = r8
      41:	r4 |= 2
      42:	r5 = r6
      43:	r5 += r4
      44:	r8 = r0
      45:	r8 += r4
      46:	r4 = *(u8 *)(r8 + 0)
      47:	*(u8 *)(r5 + 0) = r4
      48:	r4 = *(u8 *)(r8 + 0)
      49:	*(u8 *)(r5 + 0) = r4
      50:	r2 += 4
      51:	if r3 != r2 goto -21 <LBB0_5>

LBB0_6:
      52:	if r1 == 0 goto +12 <LBB0_9>
      53:	r1 = -r1

LBB0_8:
      54:	r3 = r2
      55:	r3 &= 4090
      56:	r4 = r6
      57:	r4 += r3
      58:	r5 = r0
      59:	r5 += r3
      60:	r3 = *(u8 *)(r5 + 0)
      61:	*(u8 *)(r4 + 0) = r3
      62:	r2 += 1
      63:	r1 += 1
      64:	if r1 != 0 goto -11 <LBB0_8>

LBB0_9:
      65:	r0 = r7
      66:	exit
