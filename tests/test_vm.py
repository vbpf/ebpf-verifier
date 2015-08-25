import os
from subprocess import Popen, PIPE
from nose.plugins.skip import Skip, SkipTest
import ubpf.assembler
import testdata
VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "vm", "test")

def check_datafile(filename):
    """
    """
    data = testdata.read(filename)
    if 'asm' not in data:
        raise SkipTest("no asm section in datafile")
    if 'result' not in data:
        raise SkipTest("no result section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")


    code = ubpf.assembler.assemble(data['asm'])

    vm = Popen([VM], stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = vm.communicate(code)

    if vm.returncode != 0:
        raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr.strip()))

    expected = int(data['result'], 0)
    result = int(stdout, 0)

    if expected != result:
        raise AssertionError("Expected result 0x%x, got 0x%x, stderr=%r" % (expected, result, stderr.strip()))

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
