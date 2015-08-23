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
(add/multiply/etc) is to be performed.

#### ADD

    +----------+
    |0000|0|100| 0x04: dst_reg += imm; dst_reg &= 0xffffffff
    |0000|1|100| 0x0c: dst_reg += src_reg; dst_reg &= 0xffffffff
    +----------+

TODO remaining ALU opcodes

### JMP

#### Opcode structure

    msb      lsb
    +----------+
    |op  |s|100|
    +----------+

If the `s` bit is zero, then the source operand is `imm`. If `s` is one, then
the source operand is `src_reg`. The `op` field specifies which ALU operation
(add/multiply/etc) is to be performed.

Opcode | Mnemonic           | Pseudocode
-------|--------------------|------------------------
0x5    | JA +off            | PC += off
0x15   | JEQ dst, imm, +off | PC += off if dst == imm
0x1d   | JEQ dst, src, +off | PC += off if dst == src
0x25   | JGT dst, imm, +off | PC += off if dst >= imm
0x2d   | JGT dst, src, +off | PC += off if dst >= src

TODO remaining JMP opcodes

### ALU64

TODO
