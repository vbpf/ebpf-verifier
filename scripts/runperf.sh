#!/bin/bash

test -d $1 || (echo "first argument should be a directory"; exit 1)

with_timeout() {
    if hash gtimeout 2>/dev/null; then gtimeout "$@"; else timeout "$@"; fi
}

dir=$1
files=($(find ${dir} -name '*.o'  -exec ls -Sd {} + ))
shift

if [[ "$1" == "header" ]]
then
	shift
	for f in "${files[@]}"; do echo -n ",$f"; done
fi

for dom in "$@"
do
	echo -n ",$dom"
done
echo

for f in "${files[@]}"
do
	sections=($(./check $f -l))
	for s in "${sections[@]}"
	do
		echo -n $(./check $f $s --domain=stats)
		for dom in "$@"
		do
			k=$(with_timeout 10m ./check $f $s --domain=$dom)
			echo -n ",$k"
		done
		echo
	done
done

