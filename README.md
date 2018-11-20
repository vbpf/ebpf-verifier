# uBPF-verifier

A new eBPF verifier

## Building

Dependencies from vanilla Ubuntu:
```bash
sudo apt install build-essential git cmake libboost1.65-all-dev libgmp-dev libmpfr-dev
```

Clone:
```
git clone --recurse-submodules https://github.com/elazarg/ubpf.git
make -C ubpf/src crab_install
```

Then from the `vm` folder
```bash
make -C ubpf/src
./check -h
```

and then, for example

```bash
./check samples/linux/accept_tc_l2_redirect-drop_non_tun_vip.14 14 sdbm-arr
```
