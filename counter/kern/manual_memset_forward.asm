
kern/manual_memset_forward.o:	file format ELF64-BPF

Disassembly of section sk_skb/manual-memset:
manual_memset:
       0:	r2 = *(u32 *)(r1 + 80)
       1:	r1 = *(u32 *)(r1 + 76)
       2:	r3 = 1
       3:	*(u64 *)(r10 - 8) = r3
       4:	r3 = r1
       5:	r3 += 64
       6:	if r3 > r2 goto +9 <LBB0_3>
       7:	r3 = 4294967295 ll

LBB0_2:
       9:	*(u64 *)(r1 + 0) = r3
      10:	r4 = *(u64 *)(r10 - 8)
      11:	r4 <<= 3
      12:	r1 += r4
      13:	r4 = r1
      14:	r4 += 64
      15:	if r2 >= r4 goto -7 <LBB0_2>

LBB0_3:
      16:	r0 = 0
      17:	exit
