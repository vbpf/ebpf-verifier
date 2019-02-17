# PREVAIL 
## a Polynomial-Runtime EBPF Verifier using an Abstract Interpretation Layer

A new eBPF verifier.

## Building

Dependencies from vanilla Ubuntu:
```bash
sudo apt install build-essential git cmake libboost-dev libgmp-dev libmpfr-dev
```

Clone, make and run:
```
git clone --recurse-submodules https://github.com/elazarg/ebpf-verifier.git
make crab_install
make

bin/check ebpf-samples/linux/cpustat_kern.o
```
