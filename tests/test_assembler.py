import unittest
import struct
import ubpf.assembler

class AssemblerTests(unittest.TestCase):
    def check(self, source, expected):
        expected_bin = struct.pack("L", expected)
        self.assertEquals(expected_bin, ubpf.assembler.assemble(source))

    def test_alu(self):
        self.check("ADD r1, $2", 0x0000000200000104)
        self.check("ADD r9, $ffffffff", 0xffffffff00000904)
        self.check("ADD r1, r2", 0x000000000000210c)
        self.check("SUB r1, r2", 0x000000000000211c)
        self.check("MUL r1, r2", 0x000000000000212c)
        self.check("DIV r1, r2", 0x000000000000213c)
        self.check("OR r1, r2", 0x000000000000214c)
        self.check("AND r1, r2", 0x000000000000215c)
        self.check("LSH r1, r2", 0x000000000000216c)
        self.check("RSH r1, r2", 0x000000000000217c)
        self.check("NEG r1", 0x0000000000000184)
        self.check("MOD r1, r2", 0x000000000000219c)
        self.check("XOR r1, r2", 0x00000000000021ac)
        self.check("MOV r1, r2", 0x00000000000021bc)
        self.check("ARSH r1, r2", 0x00000000000021cc)
        self.check("END16 r1", 0x00000010000001d4)
        self.check("END32 r1", 0x00000020000001d4)
        self.check("END64 r1", 0x00000040000001d4)

    def test_alu64(self):
        self.check("ADD64 r1, $2", 0x0000000200000107)
        self.check("ADD64 r9, $ffffffff", 0xffffffff00000907)
        self.check("ADD64 r1, r2", 0x000000000000210f)
        self.check("SUB64 r1, r2", 0x000000000000211f)
        self.check("MUL64 r1, r2", 0x000000000000212f)
        self.check("DIV64 r1, r2", 0x000000000000213f)
        self.check("OR64 r1, r2", 0x000000000000214f)
        self.check("AND64 r1, r2", 0x000000000000215f)
        self.check("LSH64 r1, r2", 0x000000000000216f)
        self.check("RSH64 r1, r2", 0x000000000000217f)
        self.check("NEG64 r1", 0x0000000000000187)
        self.check("MOD64 r1, r2", 0x000000000000219f)
        self.check("XOR64 r1, r2", 0x00000000000021af)
        self.check("MOV64 r1, r2", 0x00000000000021bf)
        self.check("ARSH64 r1, r2", 0x00000000000021cf)
        self.check("END64_16 r1", 0x00000010000001d7)
        self.check("END64_32 r1", 0x00000020000001d7)
        self.check("END64_64 r1", 0x00000040000001d7)

    def test_jmp(self):
        self.check("JA +1", 0x0000000000010005)
        self.check("JA +32767", 0x000000007fff0005)
        self.check("JA -1", 0x00000000ffff0005)
        self.check("JA -32768", 0x0000000080000005)
        self.check("JEQ r1, $33, +1", 0x0000003300010115)
        self.check("JEQ r1, r2, +1", 0x000000000001211d)
        self.check("JGT r1, r2, +1", 0x000000000001212d)
        self.check("JGE r1, r2, +1", 0x000000000001213d)
        self.check("JSET r1, r2, +1", 0x000000000001214d)
        self.check("JNE r1, r2, +1", 0x000000000001215d)
        self.check("JSGT r1, r2, +1", 0x000000000001216d)
        self.check("JSGE r1, r2, +1", 0x000000000001217d)
        self.check("CALL $1", 0x0000000100000085)
        self.check("EXIT", 0x0000000000000095)

    # TODO test ld

    def test_ldx(self):
        self.check("LDXW r1, [r2]", 0x0000000000002161)
        self.check("LDXH r1, [r2]", 0x0000000000002169)
        self.check("LDXB r1, [r2]", 0x0000000000002171)
        self.check("LDXDW r1, [r2]", 0x0000000000002179)
        self.check("LDXW r1, [r2+1]", 0x0000000000012161)
        self.check("LDXW r1, [r2+32767]", 0x000000007fff2161)
        self.check("LDXW r1, [r2-1]", 0x00000000ffff2161)
        self.check("LDXW r1, [r2-32768]", 0x0000000080002161)

    def test_st(self):
        self.check("STW [r1], $33", 0x0000003300000162)
        self.check("STW [r1+1], $33", 0x0000003300010162)
        self.check("STW [r1+32767], $33", 0x000000337fff0162)
        self.check("STW [r1-1], $33", 0x00000033ffff0162)
        self.check("STW [r1-32768], $33", 0x0000003380000162)

    def test_stx(self):
        self.check("STXW [r1], r2", 0x0000000000002163)
        self.check("STXW [r1+1], r2", 0x0000000000012163)
        self.check("STXW [r1+32767], r2", 0x000000007fff2163)
        self.check("STXW [r1-1], r2", 0x00000000ffff2163)
        self.check("STXW [r1-32768], r2", 0x0000000080002163)
