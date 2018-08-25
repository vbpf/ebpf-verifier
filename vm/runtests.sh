#!/bin/bash

test -d $1 || (echo "first argument should be a directory"; exit 1)

dir=$1
files=($(ls -S ${dir}))
shift

if [[ "$1" == "header" ]]
then
	shift
	for f in "${files[@]}"; do echo -n ",$f"; done
fi

mkdir -p ../logs
for dom in "$@"
do
	echo -n ",$dom"
done
echo
for f in "${files[@]}";
do
	echo -n "$f"
	for dom in "$@"
	do
		base=$(basename $f)
		err=../logs/${base}.err
		log=../logs/${base}.log
		CMD="./test --simplify $dom ${dir}/$base ${base##*.}"
		echo $CMD > ${err}
		echo $CMD > ${log}
		$CMD >> ${log} 2>> ${err}
		case "$?_${base}" in
		0_accept_*) echo -n ",1"  ;;
		1_accept_*) echo -n ",0"  ;;
		0_reject_*) echo -n ",0"  ;;
		1_reject_*) echo -n ",1"  ;;
		*) echo -n ",(Error: $?)" ;;
		esac
	done
	echo
done

