# Unofficial eBPF spec

The [official documentation for the eBPF instruction set][1] is in the
Linux repository. However, while it is concise, it isn't always easy to
use as a reference. This document lists each valid eBPF opcode.

[1]: https://www.kernel.org/doc/Documentation/networking/filter.txt

## Instruction encoding

An eBPF program is a sequence of 64-bit instructions. This project assumes each
instruction is encoded in host byte order, but the byte order is not relevant
to this spec.

All eBPF instructions have the same basic encoding:

    msb                                                        lsb
    +------------------------+----------------+----+----+--------+
    |immediate               |offset          |src |dst |opcode  |
    +------------------------+----------------+----+----+--------+

From least significant to most significant bit:

 - 8 bit opcode
 - 4 bit destination register (dst)
 - 4 bit source register (src)
 - 16 bit offset
 - 32 bit immediate (imm)

Most instructions do not use all of these fields. Unused fields should be
zeroed.

The low 3 bits of the opcode field are the "instruction class".
This groups together related opcodes.

LD/LDX/ST/STX opcode structure:

    msb      lsb
    +---+--+---+
    |mde|sz|cls|
    +---+--+---+

The `sz` field specifies the size of the memory location. The `mde` field is
the memory access mode. uBPF only supports the generic "MEM" access mode.

ALU/ALU64/JMP opcode structure:

    msb      lsb
    +----+-+---+
    |op  |s|cls|
    +----+-+---+

If the `s` bit is zero, then the source operand is `imm`. If `s` is one, then
the source operand is `src`. The `op` field specifies which ALU or branch
operation is to be performed.

## ALU Instructions

### 32-bit

These instructions zero the upper 32 bits of the destination register.

Opcode | Mnemonic              | Pseudocode
-------|-----------------------|------------------------------
0x04   | ADD dst, imm          | dst += imm; dst &= 0xffffffff
0x0c   | ADD dst, src          | dst += src; dst &= 0xffffffff
0x14   | SUB dst, imm          | dst -= imm; dst &= 0xffffffff
0x1c   | SUB dst, src          | dst -= src; dst &= 0xffffffff
0x24   | MUL dst, imm          | dst *= imm; dst &= 0xffffffff
0x2c   | MUL dst, src          | dst *= src; dst &= 0xffffffff
0x34   | DIV dst, imm          | dst /= imm; dst &= 0xffffffff
0x3c   | DIV dst, src          | dst /= src; dst &= 0xffffffff
0x44   | OR dst, imm           | dst \|= imm; dst &= 0xffffffff
0x4c   | OR dst, src           | dst \|= src; dst &= 0xffffffff
0x54   | AND dst, imm          | dst &= imm; dst &= 0xffffffff
0x5c   | AND dst, src          | dst &= src; dst &= 0xffffffff
0x64   | LSH dst, imm          | dst <<= imm; dst &= 0xffffffff
0x6c   | LSH dst, src          | dst <<= src; dst &= 0xffffffff
0x74   | RSH dst, imm          | dst >>= imm (logical); dst &= 0xffffffff
0x7c   | RSH dst, src          | dst >>= src (logical); dst &= 0xffffffff
0x84   | NEG dst               | dst = -dst; dst &= 0xffffffff
0x94   | MOD dst, imm          | dst %= imm; dst &= 0xffffffff
0x9c   | MOD dst, src          | dst %= src; dst &= 0xffffffff
0xa4   | XOR dst, imm          | dst ^= imm; dst &= 0xffffffff
0xac   | XOR dst, src          | dst ^= src; dst &= 0xffffffff
0xb4   | MOV dst, imm          | dst = imm; dst &= 0xffffffff
0xbc   | MOV dst, src          | dst = src; dst &= 0xffffffff
0xc4   | ARSH dst, imm         | dst >>= imm (arithmetic); dst &= 0xffffffff
0xcc   | ARSH dst, src         | dst >>= src (arithmetic); dst &= 0xffffffff
0xd4   | END16 dst (imm == 16) | dst = bswap16(dst); dst &= 0xffffffff
0xd4   | END32 dst (imm == 32) | dst = bswap32(dst); dst &= 0xffffffff
0xd4   | END64 dst (imm == 64) | dst = bswap64(dst); dst &= 0xffffffff

### 64-bit

Opcode | Mnemonic                 | Pseudocode
-------|--------------------------|------------------------------
0x07   | ADD64 dst, imm           | dst += imm
0x0f   | ADD64 dst, src           | dst += src
0x17   | SUB64 dst, imm           | dst -= imm
0x1f   | SUB64 dst, src           | dst -= src
0x27   | MUL64 dst, imm           | dst *= imm
0x2f   | MUL64 dst, src           | dst *= src
0x37   | DIV64 dst, imm           | dst /= imm
0x3f   | DIV64 dst, src           | dst /= src
0x47   | OR64 dst, imm            | dst \|= imm
0x4f   | OR64 dst, src            | dst \|= src
0x57   | AND64 dst, imm           | dst &= imm
0x5f   | AND64 dst, src           | dst &= src
0x67   | LSH64 dst, imm           | dst <<= imm
0x6f   | LSH64 dst, src           | dst <<= src
0x77   | RSH64 dst, imm           | dst >>= imm (logical)
0x7f   | RSH64 dst, src           | dst >>= src (logical)
0x87   | NEG64 dst                | dst = -dst
0x9f   | MOD64 dst, imm           | dst %= imm
0x97   | MOD64 dst, src           | dst %= src
0xaf   | XOR64 dst, imm           | dst ^= imm
0xa7   | XOR64 dst, src           | dst ^= src
0xbf   | MOV64 dst, imm           | dst = imm
0xb7   | MOV64 dst, src           | dst = src
0xcf   | ARSH64 dst, imm          | dst >>= imm (arithmetic)
0xc7   | ARSH64 dst, src          | dst >>= src (arithmetic)
0xd7   | END64_16 dst (imm == 16) | dst = bswap16(dst)
0xd7   | END64_32 dst (imm == 32) | dst = bswap32(dst)
0xd7   | END64_64 dst (imm == 64) | dst = bswap64(dst)

## Memory Instructions

TODO document non-MEM opcodes.

Opcode | Mnemonic                 | Pseudocode
-------|--------------------------|--------------------------------
0x61   | LDXW dst, [src+off]  | dst = *(uint32_t *) (src + off)
0x69   | LDXH dst, [src+off]  | dst = *(uint16_t *) (src + off)
0x71   | LDXB dst, [src+off]  | dst = *(uint8_t *) (src + off)
0x79   | LDXDW dst, [src+off] | dst = *(uint64_t *) (src + off)
0x62   | STW [dst+off], imm   | *(uint32_t *) (dst + off) = imm
0x6a   | STH [dst+off], imm   | *(uint16_t *) (dst + off) = imm
0x72   | STB [dst+off], imm   | *(uint8_t *) (dst + off) = imm
0x7a   | STDW [dst+off], imm  | *(uint64_t *) (dst + off) = imm
0x63   | STXW [dst+off], src  | *(uint32_t *) (dst + off) = src
0x6b   | STXH [dst+off], src  | *(uint16_t *) (dst + off) = src
0x73   | STXB [dst+off], src  | *(uint8_t *) (dst + off) = src
0x7b   | STXDW [dst+off], src | *(uint64_t *) (dst + off) = src

## Branch Instructions

Opcode | Mnemonic            | Pseudocode
-------|---------------------|------------------------
0x05   | JA +off             | PC += off
0x15   | JEQ dst, imm, +off  | PC += off if dst == imm
0x1d   | JEQ dst, src, +off  | PC += off if dst == src
0x25   | JGT dst, imm, +off  | PC += off if dst > imm
0x2d   | JGT dst, src, +off  | PC += off if dst > src
0x35   | JGE dst, imm, +off  | PC += off if dst >= imm
0x3d   | JGE dst, src, +off  | PC += off if dst >= src
0x45   | JSET dst, imm, +off | PC += off if dst & imm
0x4d   | JSET dst, src, +off | PC += off if dst & src
0x55   | JNE dst, imm, +off  | PC += off if dst != imm
0x5d   | JNE dst, src, +off  | PC += off if dst != src
0x65   | JSGT dst, imm, +off | PC += off if dst > imm (signed)
0x6d   | JSGT dst, src, +off | PC += off if dst > src (signed)
0x75   | JSGE dst, imm, +off | PC += off if dst >= imm (signed)
0x7d   | JSGE dst, src, +off | PC += off if dst >= src (signed)
0x85   | CALL imm            | PC = imm
0x95   | EXIT                | return r0
