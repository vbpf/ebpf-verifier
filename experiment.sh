#!/bin/bash
reset; for f in ebpf-samples/*/*.o; do bin/check elf=$f crab domain=oct_elina-arr --simplify -qq | grep '^1,\|^0,'; done

