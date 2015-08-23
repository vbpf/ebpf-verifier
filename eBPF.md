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
    +---------------------------------------------------+--------+
    |immediate               |offset          |src |dst |opcode  |
    +---------------------------------------------------+--------+

From least significant to most significant bit:

 - 8 bit opcode
 - 4 bit destination register (dst_reg)
 - 4 bit source register (src_reg)
 - 16 bit offset
 - 32 bit immediate (imm)

Most instructions do not use all of these fields. Unused fields should be
zeroed.

## Instruction classes

The low 3 bits of the opcode field are the "instruction class".
This groups together related opcodes.

### LD

TODO

### LDX

TODO

### ST

TODO

### STX

TODO

### ALU

#### Opcode structure

    msb      lsb
    +----------+
    |op  |s|100|
    +----------+

If the `s` bit is zero, then the source operand is `imm`. If `s` is one, then
the source operand is `src_reg`. The `op` field specifies which ALU operation
(add/multiply/etc) is to be performed. All opcodes in this class zero out the
high 32 bits of the destination register.

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
0x44   | OR dst, imm           | dst |= imm; dst &= 0xffffffff
0x4c   | OR dst, src           | dst |= src; dst &= 0xffffffff
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

### JMP

#### Opcode structure

    msb      lsb
    +----------+
    |op  |s|100|
    +----------+

If the `s` bit is zero, then the source operand is `imm`. If `s` is one, then
the source operand is `src_reg`. The `op` field specifies which type of branch
is to be performed.

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

### ALU64

TODO
