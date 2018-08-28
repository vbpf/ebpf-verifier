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
	base=$(basename $f)
	s=$(./test --no-print-invariants none ${dir}/$base ${base##*.} 2>> /dev/null | grep -E "instructions|loads|stores|jumps" | cut -f2 -d: | paste -s -d"," -)
	echo -n ",$s"
	for dom in "$@"
	do
		s=$(./test --simplify --no-print-invariants $dom ${dir}/$base ${base##*.} 2>> /dev/null | grep seconds | cut -f2 -d:)
		echo -n ",$s"
	done
	echo
done

