# PREVAIL 
## a Polynomially-Runtime EBPF Verfier using an Abstract Interpretation Layer

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
Disassembler:
```bash
bin/disassemble samples/linux/accept_tc_l2_redirect-drop_non_tun_vip.14
```

Verifier:

```bash
bin/check samples/linux/accept_tc_l2_redirect-drop_non_tun_vip.14 14 sdbm-arr
```

## Testing

```bash
bin/test
```

## Benchmark

```bash
bin/benchmark.sh samples sdbm-arr
```

