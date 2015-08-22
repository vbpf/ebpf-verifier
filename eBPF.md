# Unofficial eBPF spec

The [official documentation for the eBPF instruction set][1] is in the
Linux repository. However, while it is concise, it isn't always easy to
use as a reference. This document lists each valid eBPF opcode.

[1]: https://www.kernel.org/doc/Documentation/networking/filter.txt

## Instruction encoding

An eBPF program is a sequence of 8-byte instructions. This project assumes each
instruction is encoded in host byte order.

All eBPF instructions have the same basic encoding:

    lsb                                                        msb
    +--------+----+----+----------------+------------------------+
    |opcode  |dst |src |offset          |immediate               |
    +--------+----+----+----------------+------------------------+

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

    +---+-+----+
    |001|s|op  |
    +---+-+----+

If the 's' bit is zero, then the source operand is `imm`. If 's' is one, then
the source operand is `src_reg`. The 'op' field specifies which ALU operation
(add/multiply/etc) is to be performed.

#### ADD

    +---+-+----+
    |001|0|0000| 0x04: dst_reg += imm; dst_reg &= 0xffffffff
    |001|1|0000| 0x0c: dst_reg += src_reg; dst_reg &= 0xffffffff
    +---+-+----+

### JMP

TODO

### ALU64

TODO
