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
0x04   | add dst, imm          | dst += imm; dst &= 0xffffffff
0x0c   | add dst, src          | dst += src; dst &= 0xffffffff
0x14   | sub dst, imm          | dst -= imm; dst &= 0xffffffff
0x1c   | sub dst, src          | dst -= src; dst &= 0xffffffff
0x24   | mul dst, imm          | dst *= imm; dst &= 0xffffffff
0x2c   | mul dst, src          | dst *= src; dst &= 0xffffffff
0x34   | div dst, imm          | dst /= imm; dst &= 0xffffffff
0x3c   | div dst, src          | dst /= src; dst &= 0xffffffff
0x44   | or dst, imm           | dst \|= imm; dst &= 0xffffffff
0x4c   | or dst, src           | dst \|= src; dst &= 0xffffffff
0x54   | and dst, imm          | dst &= imm; dst &= 0xffffffff
0x5c   | and dst, src          | dst &= src; dst &= 0xffffffff
0x64   | lsh dst, imm          | dst <<= imm; dst &= 0xffffffff
0x6c   | lsh dst, src          | dst <<= src; dst &= 0xffffffff
0x74   | rsh dst, imm          | dst >>= imm (logical); dst &= 0xffffffff
0x7c   | rsh dst, src          | dst >>= src (logical); dst &= 0xffffffff
0x84   | neg dst               | dst = -dst; dst &= 0xffffffff
0x94   | mod dst, imm          | dst %= imm; dst &= 0xffffffff
0x9c   | mod dst, src          | dst %= src; dst &= 0xffffffff
0xa4   | xor dst, imm          | dst ^= imm; dst &= 0xffffffff
0xac   | xor dst, src          | dst ^= src; dst &= 0xffffffff
0xb4   | mov dst, imm          | dst = imm; dst &= 0xffffffff
0xbc   | mov dst, src          | dst = src; dst &= 0xffffffff
0xc4   | arsh dst, imm         | dst >>= imm (arithmetic); dst &= 0xffffffff
0xcc   | arsh dst, src         | dst >>= src (arithmetic); dst &= 0xffffffff
0xd4   | le16 dst (imm == 16)  | dst = htole16(dst)
0xd4   | le32 dst (imm == 32)  | dst = htole32(dst)
0xd4   | le64 dst (imm == 64)  | dst = htole64(dst)
0xdc   | be16 dst (imm == 16)  | dst = htobe16(dst)
0xdc   | be32 dst (imm == 32)  | dst = htobe32(dst)
0xdc   | be64 dst (imm == 64)  | dst = htobe64(dst)

### 64-bit

Opcode | Mnemonic                 | Pseudocode
-------|--------------------------|------------------------------
0x07   | add64 dst, imm           | dst += imm
0x0f   | add64 dst, src           | dst += src
0x17   | sub64 dst, imm           | dst -= imm
0x1f   | sub64 dst, src           | dst -= src
0x27   | mul64 dst, imm           | dst *= imm
0x2f   | mul64 dst, src           | dst *= src
0x37   | div64 dst, imm           | dst /= imm
0x3f   | div64 dst, src           | dst /= src
0x47   | or64 dst, imm            | dst \|= imm
0x4f   | or64 dst, src            | dst \|= src
0x57   | and64 dst, imm           | dst &= imm
0x5f   | and64 dst, src           | dst &= src
0x67   | lsh64 dst, imm           | dst <<= imm
0x6f   | lsh64 dst, src           | dst <<= src
0x77   | rsh64 dst, imm           | dst >>= imm (logical)
0x7f   | rsh64 dst, src           | dst >>= src (logical)
0x87   | neg64 dst                | dst = -dst
0x9f   | mod64 dst, imm           | dst %= imm
0x97   | mod64 dst, src           | dst %= src
0xaf   | xor64 dst, imm           | dst ^= imm
0xa7   | xor64 dst, src           | dst ^= src
0xbf   | mov64 dst, imm           | dst = imm
0xb7   | mov64 dst, src           | dst = src
0xcf   | arsh64 dst, imm          | dst >>= imm (arithmetic)
0xc7   | arsh64 dst, src          | dst >>= src (arithmetic)

## Memory Instructions

TODO document non-MEM opcodes.

Opcode | Mnemonic             | Pseudocode
-------|----------------------|--------------------------------
0x18   | lddw dst, imm        | dst = imm
0x61   | ldxw dst, [src+off]  | dst = *(uint32_t *) (src + off)
0x69   | ldxh dst, [src+off]  | dst = *(uint16_t *) (src + off)
0x71   | ldxb dst, [src+off]  | dst = *(uint8_t *) (src + off)
0x79   | ldxdw dst, [src+off] | dst = *(uint64_t *) (src + off)
0x62   | stw [dst+off], imm   | *(uint32_t *) (dst + off) = imm
0x6a   | sth [dst+off], imm   | *(uint16_t *) (dst + off) = imm
0x72   | stb [dst+off], imm   | *(uint8_t *) (dst + off) = imm
0x7a   | stdw [dst+off], imm  | *(uint64_t *) (dst + off) = imm
0x63   | stxw [dst+off], src  | *(uint32_t *) (dst + off) = src
0x6b   | stxh [dst+off], src  | *(uint16_t *) (dst + off) = src
0x73   | stxb [dst+off], src  | *(uint8_t *) (dst + off) = src
0x7b   | stxdw [dst+off], src | *(uint64_t *) (dst + off) = src

## Branch Instructions

Opcode | Mnemonic            | Pseudocode
-------|---------------------|------------------------
0x05   | ja +off             | PC += off
0x15   | jeq dst, imm, +off  | PC += off if dst == imm
0x1d   | jeq dst, src, +off  | PC += off if dst == src
0x25   | jgt dst, imm, +off  | PC += off if dst > imm
0x2d   | jgt dst, src, +off  | PC += off if dst > src
0x35   | jge dst, imm, +off  | PC += off if dst >= imm
0x3d   | jge dst, src, +off  | PC += off if dst >= src
0x45   | jset dst, imm, +off | PC += off if dst & imm
0x4d   | jset dst, src, +off | PC += off if dst & src
0x55   | jne dst, imm, +off  | PC += off if dst != imm
0x5d   | jne dst, src, +off  | PC += off if dst != src
0x65   | jsgt dst, imm, +off | PC += off if dst > imm (signed)
0x6d   | jsgt dst, src, +off | PC += off if dst > src (signed)
0x75   | jsge dst, imm, +off | PC += off if dst >= imm (signed)
0x7d   | jsge dst, src, +off | PC += off if dst >= src (signed)
0x85   | call imm            | PC = imm
0x95   | exit                | return r0
