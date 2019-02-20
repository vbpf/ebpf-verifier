# PREVAIL 
## a Polynomial-Runtime EBPF Verifier using an Abstract Interpretation Layer

A new eBPF verifier.

## Getting Started

Dependencies from vanilla Ubuntu:
```bash
sudo apt install build-essential git cmake libboost-dev libgmp-dev libmpfr-devsudo apt install python3-pip
sudo apt install python3-pip
pip3 install matplotlib
```

Clone, make and run:
```
git clone --recurse-submodules https://github.com/elazarg/ebpf-verifier.git -b submission
cd ebpf-verifier
make crab_install
make
```

Example:
```
./check ebpf-samples/cilium/bpf_lxc.o 2/1 --domain=zoneCrab
```

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
