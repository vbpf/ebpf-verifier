#!/bin/bash

test -d $1 || (echo "first argument should be a directory"; exit 1)

with_timeout() {
    if hash gtimeout 2>/dev/null; then
        gtimeout "$@"
    else
        timeout "$@"
    fi
}

dir=$1
files=($(find ${dir} -name 'accept_*'  -exec ls -Sd {} + ))
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
	s=$(bin/check -q $f ${base##*.} none 2>/dev/null | grep -E "instructions|loads|stores|jumps|joins" | cut -f2 -d: | paste -s -d"," -)
	echo -n ",$s"
	for dom in "$@"
	do
		s=$(with_timeout 10m bin/check --simplify -q $f ${base##*.} $dom 2>/dev/null | grep seconds | cut -f2 -d:)
		echo -n ",$s"
	done
	echo
done

