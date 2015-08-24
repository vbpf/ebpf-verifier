import unittest
import struct
import ubpf.assembler

class AssemblerTests(unittest.TestCase):
    def check(self, source, expected):
        expected_bin = struct.pack("L", expected)
        self.assertEquals(expected_bin, ubpf.assembler.assemble(source))

    def test_alu(self):
        self.check("add r1, 2", 0x0000000200000104)
        self.check("add r9, 0xffffffff", 0xffffffff00000904)
        self.check("add r1, r2", 0x000000000000210c)
        self.check("sub r1, r2", 0x000000000000211c)
        self.check("mul r1, r2", 0x000000000000212c)
        self.check("div r1, r2", 0x000000000000213c)
        self.check("or r1, r2", 0x000000000000214c)
        self.check("and r1, r2", 0x000000000000215c)
        self.check("lsh r1, r2", 0x000000000000216c)
        self.check("rsh r1, r2", 0x000000000000217c)
        self.check("neg r1", 0x0000000000000184)
        self.check("mod r1, r2", 0x000000000000219c)
        self.check("xor r1, r2", 0x00000000000021ac)
        self.check("mov r1, r2", 0x00000000000021bc)
        self.check("arsh r1, r2", 0x00000000000021cc)
        self.check("end16 r1", 0x00000010000001d4)
        self.check("end32 r1", 0x00000020000001d4)
        self.check("end64 r1", 0x00000040000001d4)

    def test_alu64(self):
        self.check("add64 r1, 2", 0x0000000200000107)
        self.check("add64 r9, 0xffffffff", 0xffffffff00000907)
        self.check("add64 r1, r2", 0x000000000000210f)
        self.check("sub64 r1, r2", 0x000000000000211f)
        self.check("mul64 r1, r2", 0x000000000000212f)
        self.check("div64 r1, r2", 0x000000000000213f)
        self.check("or64 r1, r2", 0x000000000000214f)
        self.check("and64 r1, r2", 0x000000000000215f)
        self.check("lsh64 r1, r2", 0x000000000000216f)
        self.check("rsh64 r1, r2", 0x000000000000217f)
        self.check("neg64 r1", 0x0000000000000187)
        self.check("mod64 r1, r2", 0x000000000000219f)
        self.check("xor64 r1, r2", 0x00000000000021af)
        self.check("mov64 r1, r2", 0x00000000000021bf)
        self.check("arsh64 r1, r2", 0x00000000000021cf)
        self.check("end64_16 r1", 0x00000010000001d7)
        self.check("end64_32 r1", 0x00000020000001d7)
        self.check("end64_64 r1", 0x00000040000001d7)

    def test_jmp(self):
        self.check("ja +1", 0x0000000000010005)
        self.check("ja +32767", 0x000000007fff0005)
        self.check("ja -1", 0x00000000ffff0005)
        self.check("ja -32768", 0x0000000080000005)
        self.check("jeq r1, 0x33, +1", 0x0000003300010115)
        self.check("jeq r1, r2, +1", 0x000000000001211d)
        self.check("jgt r1, r2, +1", 0x000000000001212d)
        self.check("jge r1, r2, +1", 0x000000000001213d)
        self.check("jset r1, r2, +1", 0x000000000001214d)
        self.check("jne r1, r2, +1", 0x000000000001215d)
        self.check("jsgt r1, r2, +1", 0x000000000001216d)
        self.check("jsge r1, r2, +1", 0x000000000001217d)
        self.check("call 0x1", 0x0000000100000085)
        self.check("exit", 0x0000000000000095)

    # TODO test ld

    def test_ldx(self):
        self.check("ldxw r1, [r2]", 0x0000000000002161)
        self.check("ldxh r1, [r2]", 0x0000000000002169)
        self.check("ldxb r1, [r2]", 0x0000000000002171)
        self.check("ldxdw r1, [r2]", 0x0000000000002179)
        self.check("ldxw r1, [r2+1]", 0x0000000000012161)
        self.check("ldxw r1, [r2+32767]", 0x000000007fff2161)
        self.check("ldxw r1, [r2-1]", 0x00000000ffff2161)
        self.check("ldxw r1, [r2-32768]", 0x0000000080002161)

    def test_st(self):
        self.check("stw [r1], 0x33", 0x0000003300000162)
        self.check("stw [r1+1], 0x33", 0x0000003300010162)
        self.check("stw [r1+32767], 0x33", 0x000000337fff0162)
        self.check("stw [r1-1], 0x33", 0x00000033ffff0162)
        self.check("stw [r1-32768], 0x33", 0x0000003380000162)

    def test_stx(self):
        self.check("stxw [r1], r2", 0x0000000000002163)
        self.check("stxw [r1+1], r2", 0x0000000000012163)
        self.check("stxw [r1+32767], r2", 0x000000007fff2163)
        self.check("stxw [r1-1], r2", 0x00000000ffff2163)
        self.check("stxw [r1-32768], r2", 0x0000000080002163)
