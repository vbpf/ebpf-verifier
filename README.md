# PREVAIL 
## a Polynomial-Runtime EBPF Verifier using an Abstract Interpretation Layer

A new eBPF verifier.

The project resides on https://github.com/vbpf/ebpf-verifier/tree/submission

The artifact contains two independent sub-artifacts: a verification tool, and a
set of real-world eBPF programs used for development and evaluation of the tool.
The source for the tool is in the `src` directory. The benchmarks are in ELF
files in the directory `ebpf-samples`. Each ELF file contains one or more
programs, in different sections of the file.

## Getting Started
Evaluation can be done either on an Ubuntu machine, or the supplied VM.
(the tool can also run on a Mac, but the memory measurements will always return 0).

### Dependencies from vanilla Ubuntu
```bash
sudo apt install build-essential git cmake libboost-dev libgmp-dev libmpfr-dev
sudo apt install python3-pip python3-tk
pip3 install matplotlib   # for plotting the graphs
```

Clone, make and run:
```
git clone --recurse-submodules https://github.com/vbpf/ebpf-verifier.git -b submission
cd ebpf-verifier
make crab_install
make
```

### VM
The VM supplied requires VMware Player:
https://www.vmware.com/il/products/workstation-player/workstation-player-evaluation.html

The user is `prevail`, password is also `prevail`.

The VM memory should be adjusted to the maximum available for the host.
The terminal is already configured to start from the right path, `~/ebpf-verifier`.

### 

Example:
```
ebpf-verifier$ ./check ebpf-samples/cilium/bpf_lxc.o 2/1 --domain=zoneCrab
1,0.062802,21792
```
The output is three comma-separated values:
* 1 or 0, for "pass" and "fail" respectively
* The runtime of the fixpoint algorithm (in seconds)
* The peak memory consumption, in kb, as reflected by the resident-set size (rss)

Usage:
```
ebpf-verifier$ ./check -h
A new eBPF verifier
Usage: ./check [OPTIONS] path [section]

Positionals:
  path FILE REQUIRED          Elf file to analyze
  section SECTION             Section to analyze

Options:
  -h,--help                   Print this help message and exit
  -l                          List sections
  -d,--dom,--domain DOMAIN    Abstract domain
  -v                          Print invariants
  --asm FILE                  Print disassembly to FILE
  --dot FILE                  Export cfg to dot FILE
```

A standard alternative to the --asm flag is `llvm-objdump -S FILE`.

The cfg can be viewed using `dot` and the standard PDF viewer:
```
ebpf-verifier$ ./check ebpf-samples/cilium/bpf_lxc.o 2/1 --domain=zoneCrab --dot cfg.dot
ebpf-verifier$ dot -Tpdf cfg.dot > cfg.pdf
```

## Step-by-Step Instructions

To get the results for described in Figures 10 and 11, run the following:
```
ebpf-verifier$ scripts/runperf.sh ebpf-samples interval zoneCrab zoneElina octElina polyElina | tee results.csv
ebpf-verifier$ python3 scripts/makeplot.py
```
The first argument to the script, `ebpf-samples`, is the root directory in which
to search for elf files. You can pass any subdirectory or file, e.g.
`ebpd-samples/linux`.

The rest of the positional arguments are the numerical domains to use. Any
subset of the above list is valid. So in order to compare the two different
implementations of the `zone` domain, one can run
```
ebpf-verifier$ scripts/runperf.sh ebpf-samples/linux zoneCrab zoneElina
ebpf-verifier$ python3 scripts/makeplot.py
```

While the paper states that the performance is quadratic, the results are
expected to be nearly linear for all the domains - except probably the domain
`octElina` which does not show consistent performance characteristics.

### Caveat
When performed on a VM without sufficient memory, some analyses of some domains
are terminated by the OS due to insufficient memory, resulting in "-1" runtime
and skewing the graph. To avoid this, the failing cases should be omitted.

4GB RAM should be enough for `zoneCrab`, our domain of choice, but other domains
may require much more than that. To reproduce the results as will be published
in the final version, it is recommended to use bare-metal Linux machine. 
