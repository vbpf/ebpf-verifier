import struct
import difflib
from nose.plugins.skip import Skip, SkipTest
import ubpf.disassembler
import testdata

def check_datafile(filename):
    """
    Verify that the result of disassembling the 'raw' section matches the
    'asm' section.
    """
    data = testdata.read(filename)
    if 'asm' not in data:
        raise SkipTest("no asm section in datafile")
    if 'raw' not in data:
        raise SkipTest("no raw section in datafile")

    binary = ''.join(struct.pack("=Q", x) for x in data['raw'])
    result = ubpf.disassembler.disassemble(binary)

    # TODO strip whitespace and comments from asm
    if result.strip() != data['asm'].strip():
        diff = difflib.unified_diff(data['asm'].splitlines(), result.splitlines(), lineterm="")
        formatted = ''.join('  %s\n' % x for x in diff)
        raise AssertionError("Assembly differs:\n%s" % formatted)

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
