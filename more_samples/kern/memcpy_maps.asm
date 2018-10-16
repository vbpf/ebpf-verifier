
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
      16:	if r6 == 0 goto +21 <LBB0_5>
      17:	if r0 == 0 goto +20 <LBB0_5>
      18:	r1 = *(u32 *)(r8 + 0)
      19:	r7 = 0
      20:	if r1 == 0 goto +17 <LBB0_5>
      21:	r7 = 0
      22:	r6 += 1
      23:	r2 = 0

LBB0_4:
      24:	r3 = r2
      25:	r3 /= 4098
      26:	r3 *= -4098
      27:	r4 = r6
      28:	r4 += r3
      29:	r5 = r0
      30:	r5 += r3
      31:	r3 = *(u8 *)(r5 + 0)
      32:	*(u8 *)(r4 + 0) = r3
      33:	r0 += 1
      34:	r6 += 1
      35:	r2 += 1
      36:	r1 += -1
      37:	if r1 != 0 goto -14 <LBB0_4>

LBB0_5:
      38:	r0 = r7
      39:	exit
