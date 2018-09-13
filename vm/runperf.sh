#!/bin/bash

test -d $1 || (echo "first argument should be a directory"; exit 1)

dir=$1
files=($(find ${dir} -name 'accept_*' | grep -v self))
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
	echo -n "$(basename $(dirname $f)),$(basename $f)"
	base=$(basename $f)
	s=$(./test --no-print-invariants $f ${base##*.} none 2>> /dev/null | grep -E "instructions|loads|stores|jumps|joins" | cut -f2 -d: | paste -s -d"," -)
	echo -n ",$s"
	for dom in "$@"
	do
		s=$(./test --simplify --no-print-invariants $f ${base##*.} $dom 2>> /dev/null | grep seconds | cut -f2 -d:)
		echo -n ",$s"
	done
	echo
done

