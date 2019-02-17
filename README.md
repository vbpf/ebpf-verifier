# PREVAIL 
## a Polynomial-Runtime EBPF Verfier using an Abstract Interpretation Layer

A new eBPF verifier.

## Building

Dependencies from vanilla Ubuntu:
```bash
sudo apt install build-essential git cmake libboost1.65-all-dev libgmp-dev libmpfr-dev
```

Clone and make:
```
git clone --recurse-submodules https://github.com/elazarg/ebpf-verifier.git
make crab_install
make
bin/check -h
```

## Running

```bash
bin/check ebpf-samples/linux/cpustat_kern.o
```
