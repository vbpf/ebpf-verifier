import os
import tempfile
from subprocess import Popen, PIPE
from nose.plugins.skip import Skip, SkipTest
import ubpf.assembler
import testdata
VM = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "vm", "test")

def check_datafile(filename):
    """
    Given assembly source code and an expected result, run the eBPF program and
    verify that the result matches.
    """
    data = testdata.read(filename)
    if 'asm' not in data:
        raise SkipTest("no asm section in datafile")
    if 'result' not in data and 'error' not in data:
        raise SkipTest("no result or error section in datafile")
    if not os.path.exists(VM):
        raise SkipTest("VM not found")

    code = ubpf.assembler.assemble(data['asm'])
    memfile = None

    cmd = [VM]
    if 'arg' in data:
        cmd.extend(['-a', data['arg']])
    elif 'mem' in data:
        memfile = tempfile.NamedTemporaryFile()
        memfile.write(data['mem'])
        memfile.flush()
        cmd.extend(['-m', memfile.name])

    cmd.append('-')

    vm = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    stdout, stderr = vm.communicate(code)
    stderr = stderr.strip()

    if memfile:
        memfile.close()

    error = data.get('error', '')
    if error != stderr:
        raise AssertionError("Expected error %r, got %r" % (error, stderr))

    if 'result' in data:
        if vm.returncode != 0:
            raise AssertionError("VM exited with status %d, stderr=%r" % (vm.returncode, stderr))
        expected = int(data['result'], 0)
        result = int(stdout, 0)
        if expected != result:
            raise AssertionError("Expected result 0x%x, got 0x%x, stderr=%r" % (expected, result, stderr))
    else:
        if vm.returncode == 0:
            raise AssertionError("Expected VM to exit with an error code")

def test_datafiles():
    # Nose test generator
    # Creates a testcase for each datafile
    for filename in testdata.list_files():
        yield check_datafile, filename
