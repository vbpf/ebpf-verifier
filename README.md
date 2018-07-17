# uBPF-verifier

A new eBPF verifier

## About

This project is a fork of the uBPF project, but focuses only on the verifier.

[Linux documentation for the eBPF instruction set](https://www.kernel.org/doc/Documentation/networking/filter.txt)

[Instruction set reference](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)

This project includes an eBPF assembler, disassembler, interpreter,
and JIT compiler for x86-64.

## Building

From vanilla Ubuntu:
```bash
sudo apt install build-essential git cmake libboost1.65-all-dev libgmp-dev libmpfr-dev python-pip
pip install parcon nose pyelftools

git clone --recurse-submodules https://github.com/elazarg/ubpf.git
cd ubpf/vm
make crab_install
```

Then from the `vm` folder
```bash
make
./test -h
```

To play with Linux samples:
```bash
sudo apt install bison flex libssl-dev clang llvm libelf-dev
make linux_samples
sudo updatedb && source completion.sh
```

and then, for example

```bash
./test num ../linux/samples/bpf/xdp2skb_meta_kern.o
```

## Compiling C to eBPF

You'll need [Clang 3.7](http://llvm.org/releases/download.html#3.7.0).

    clang-3.7 -O2 -target bpf -c prog.c -o prog.o

You can then pass the contents of `prog.o` to `ubpf_load_elf`, or to the stdin of
the `vm/test` binary.

## Contributing

Please fork the project on GitHub and open a pull request. You can run all the
tests with `nosetests`.

## License

Copyright 2015, Big Switch Networks, Inc. Licensed under the Apache License, Version 2.0
<LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>.
