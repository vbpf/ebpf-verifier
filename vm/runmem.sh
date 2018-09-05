#!/bin/bash

test -d $1 || (echo "first argument should be a directory"; exit 1)

dir=$1
files=($(find ${dir} -name 'accept_*' | grep -v self))
shift

function get_mem() { /usr/bin/time -l $@ --no-print-invariants 2>&1 | grep maximum | python3 -c 'print(input().split()[0])'; }

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
	base=$(basename $f)
	s=$(./test --no-print-invariants none ${dir}/$base ${base##*.} 2>> /dev/null | grep -E "instructions|loads|stores|jumps|joins" | cut -f2 -d: | paste -s -d"," -)
	echo -n ",$s"
	baseline=$(get_mem ./test --simplify none ${dir}/$base ${base##*.})
	for dom in "$@"
	do
		s=$(get_mem ./test --simplify $dom ${dir}/$base ${base##*.})
		echo -n ",$(( (s - baseline) / 1000 ))"
	done
	echo
done

