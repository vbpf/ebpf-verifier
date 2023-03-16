[![Coverage Status](https://coveralls.io/repos/github/vbpf/ebpf-verifier/badge.svg?branch=main)](https://coveralls.io/github/vbpf/ebpf-verifier?branch=main)[![CodeQL](https://github.com/vbpf/ebpf-verifier/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/vbpf/ebpf-verifier/actions/workflows/codeql-analysis.yml)

# PREVAIL
## a Polynomial-Runtime EBPF Verifier using an Abstract Interpretation Layer

A new eBPF verifier.

The version discussed in the [PLDI paper](https://vbpf.github.io/assets/prevail-paper.pdf) is available [here](https://github.com/vbpf/ebpf-verifier/tree/d29fd26345c3126bf166cf1c45233a9b2f9fb0a0).

## Getting Started

### Dependencies from vanilla Ubuntu
```bash
sudo apt install build-essential git cmake libboost-dev libyaml-cpp-dev
sudo apt install libboost-filesystem-dev libboost-program-options-dev
```

### Dependencies from vanilla Windows

* Install [git](https://git-scm.com/download/win)
* Install [Visual Studio Build Tools 2022](https://aka.ms/vs/17/release/vs_buildtools.exe) and choose the "C++ build tools" workload (Visual Studio Build Tools 2022 has support for CMake Version 3.25).
* Install [nuget.exe](https://www.nuget.org/downloads)

### Installation
Clone:
```
git clone --recurse-submodules https://github.com/vbpf/ebpf-verifier.git
cd ebpf-verifier
```

Make on Ubuntu:
```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Make on Windows (which uses a multi-configuration generator):
```
cmake -B build
cmake --build build --config Release
```

### Running with Docker
Build and run:
```bash
docker build -t verifier .
docker run -it verifier ebpf-samples/cilium/bpf_lxc.o 2/1
1,0.009812,4132
# To run the Linux verifier you'll need a privileged container:
docker run --privileged -it verifier ebpf-samples/linux/cpustat_kern.o --domain=linux
```

### Example:
```
ebpf-verifier$ ./check ebpf-samples/cilium/bpf_lxc.o 2/1
1,0.008288,4064
```
The output is three comma-separated values:
* 1 or 0, for "pass" and "fail" respectively
* The runtime of the fixpoint algorithm (in seconds)
* The peak memory consumption, in kb, as reflected by the resident-set size (rss)

## Usage:
```
A new eBPF verifier
Usage: ./check [OPTIONS] path [section]

Positionals:
  path FILE REQUIRED          Elf file to analyze
  section SECTION             Section to analyze

Options:
  -h,--help                   Print this help message and exit
  -l                          List sections
  -d,--dom,--domain DOMAIN:{cfg,linux,stats,zoneCrab}
                              Abstract domain
  --termination               Verify termination
  --assume-assert             Assume assertions
  -i                          Print invariants
  -f                          Print verifier's failure logs
  -s                          Apply additional checks that would cause runtime failures
  -v                          Print both invariants and failures
  --no-division-by-zero       Do not allow division by zero
  --no-simplify               Do not simplify
  --line-info                 Print line information
  --asm FILE                  Print disassembly to FILE
  --dot FILE                  Export control-flow graph to dot FILE

You can use @headers as the path to instead just show the output field headers.
```

A standard alternative to the --asm flag is `llvm-objdump -S FILE`.

The cfg can be viewed using `dot` and the standard PDF viewer:
```
sudo apt install graphviz
./check ebpf-samples/cilium/bpf_lxc.o 2/1 --dot cfg.dot
dot -Tpdf cfg.dot > cfg.pdf
```

## Testing the Linux verifier

To run the Linux verifier, you must use `sudo`:
```
sudo ./check ebpf-samples/linux/cpustat_kern.o tracepoint/power/cpu_idle --domain=linux
```
