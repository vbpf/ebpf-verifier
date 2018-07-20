#!/bin/bash

OBJ=$1
OUTDIR=$2

function progtype()
{
	shopt -s extglob
	case "$1" in
		socket*) echo 1;;
		kprobe*) echo 2;;
		kretprobe/*) echo 2;;
		tracepoint/*) echo 5;;
		raw_tracepoint/*) echo 17;;
		xdp*)        echo 6;;
		perf_event*) echo 7;;
		cgroup/skb*) echo 8;;
		cgroup/sock*) echo 9;;
		sockops*)    echo 13;;
		sk_skb*)     echo 14;;
		len_hist*)   echo 14;;
		filter*)     echo 14;;
		sk_msg*)     echo 14;;
	esac
}

sections=($(readelf --section-headers -W $OBJ | grep 'AX  0   0  8' | grep -oP '[^ ]*(?= +PROGBITS)'))
for name in ${sections[@]}
do
	echo $OBJ_$name
	type=$(progtype $name)
	objcopy -I elf64-little --dump-section "$name=${OUTDIR}/$(basename ${OBJ%_kern.o})-${name}-$type.bin" $OBJ
done
