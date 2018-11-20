# uBPF-verifier

A new eBPF verifier

## Building

Dependencies from vanilla Ubuntu:
```bash
sudo apt install build-essential git cmake libboost1.65-all-dev libgmp-dev libmpfr-dev
```

Clone and make:
```
git clone --recurse-submodules https://github.com/elazarg/ubpf.git
make crab_install
make
bin/check -h
```

## Running

For example

```bash
bin/check samples/linux/accept_tc_l2_redirect-drop_non_tun_vip.14 14 sdbm-arr
```
