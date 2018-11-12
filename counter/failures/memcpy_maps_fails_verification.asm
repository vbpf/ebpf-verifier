
kern/memcpy_maps_fails_verification.o:	file format ELF64-BPF

Disassembly of section sk_skb/memcpy-maps:
memcpy_maps:
       0:	r7 = r1
       1:	r1 = 0
       2:	*(u32 *)(r10 - 4) = r1
       3:	r2 = r10
       4:	r2 += -4
       5:	r1 = 0 ll
       7:	call 1
       8:	r6 = r0
       9:	r8 = 1
      10:	*(u32 *)(r10 - 8) = r8
      11:	r2 = r10
      12:	r2 += -8
      13:	r1 = 0 ll
      15:	call 1
      16:	if r6 == 0 goto +43 <LBB0_10>
      17:	if r0 == 0 goto +42 <LBB0_10>
      18:	r4 = *(u32 *)(r7 + 0)
      19:	r1 = 1
      20:	*(u64 *)(r10 - 16) = r1
      21:	if r4 == 0 goto +37 <LBB0_9>
      22:	r1 = 0
      23:	r2 = r4
      24:	r2 &= 1
      25:	if r4 == 1 goto +28 <LBB0_7>
      26:	r3 = r2
      27:	r3 -= r4
      28:	r1 = 0
      29:	r4 = r0
      30:	r4 += 1
      31:	r5 = r6
      32:	r5 += 1

LBB0_5:
      33:	r7 = r1
      34:	r7 /= 4090
      35:	r7 *= -4090
      36:	r8 = r5
      37:	r8 += r7
      38:	r9 = r4
      39:	r9 += r7
      40:	r7 = *(u8 *)(r9 - 1)
      41:	*(u8 *)(r8 - 1) = r7
      42:	r7 = *(u8 *)(r9 + 0)
      43:	*(u8 *)(r8 + 0) = r7
      44:	r4 += 2
      45:	r5 += 2
      46:	r1 += 2
      47:	r3 += 2
      48:	if r3 == 0 goto +1 <LBB0_6>
      49:	goto -17 <LBB0_5>

LBB0_6:
      50:	r3 = r1
      51:	r3 /= 4090
      52:	r3 *= 4090
      53:	r1 -= r3

LBB0_7:
      54:	if r2 == 0 goto +4 <LBB0_9>
      55:	r6 += r1
      56:	r0 += r1
      57:	r1 = *(u8 *)(r0 + 0)
      58:	*(u8 *)(r6 + 0) = r1

LBB0_9:
      59:	r8 = 0

LBB0_10:
      60:	r0 = r8
      61:	exit
