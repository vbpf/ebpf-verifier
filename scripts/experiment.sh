#!/bin/bash

# double-strncmp loop experiment
# generate increasingly long unrolled versions of the function
# 
# Usage:
#    scripts/experiments.sh | double_strncmp.csv 
#    python3 scripts/makeplot.py double_strncmp.csv iterations
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

cd counter
# scripts/experiment.sh templates/tree.fmt
TEMPLATE=$1
echo -n iterations,
echo -n $(../check @headers --domain=stats),
echo -n $(../check @headers --domain=zoneCrab),
echo -n $(../check @headers --domain=linux)
echo
for i in $(seq 5 20)
do
	BASE=$(basename $TEMPLATE)
	sed "s/VALUE_SIZE/$i/g" < $TEMPLATE > src/$BASE_$i.c
	make objects/$BASE_$i.o > /dev/null
	echo -n $i,$(../check objects/$BASE_$i.o --domain=stats),
	echo -n $(../check objects/$BASE_$i.o --domain=zoneCrab),
	echo -n $(./load_bpf objects/$BASE_$i.o)
	rm -f objects/$BASE_$i.o src/$BASE_$i.c
	echo
done
