
## Performance Evaluation

To do performance tests, run the following:
```
scripts/runperf.sh ebpf-samples stats zoneCrab | tee results.csv
```
The first argument to the script, `ebpf-samples`, is the root directory in which
to search for elf files. You can pass any subdirectory or file, e.g.
`ebpd-samples/linux`.

The rest of the positional arguments are the numerical domains to use.

The output is a large `csv` file. The first line is a header:
```
suite,project,file,section,hash,instructions,loads,stores,jumps,joins,zoneCrab?,zoneCrab_sec,zoneCrab_kb
ebpf-samples,cilium,bpf_lxc.o,2/1,69a5e4fc57ca1c94,41,6,10,1,1,1,0.057409,21796
```
* _suite_ in our case will be "ebpf-samples"
* _project_ is one of the directories in the suite. We currently have `bpf_cilium_test`, `cilium` `linux`, `ovs`,  `prototype-kernel` and  `suricata`
* _file_ is the elf file containing the programs. The compiled version of a C file
* _section_ is the elf section containing the program checked
* _hash_ is a unique hash of the eBPF code. There are duplicate programs in the benchmark (since we use files from projects "as-is"). To count the real number of programs these duplicates should be removed
* _instructions_, _loads_, _stores_, _jumps_ and _joins_ show the number of these features
* For each domain DOM, there are 3 consecutive columns:
    * "DOM?" is 0 for rejected program, 1 for accepted program
    * "DOM_sec" is the number of seconds that the fixpoint operation took
    * "DOM_kb" is the peak memory resident set size consumed by the analysis, and is an estimate for the amount of additional memory needed by the analysis
