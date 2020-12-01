#!/bin/bash

# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT

dir=$1
test -d $dir || (echo "first argument should be a directory"; exit 1)
shift

with_timeout() {
    if hash gtimeout 2>/dev/null; then gtimeout "$@"; else timeout "$@"; fi
}

files=($(find ${dir} -name '*.o'  -exec ls -Sd {} + ))

echo -n suite,project,file,section
for dom in "$@"
do
	echo -n ,
	./check @headers --domain=${dom} | tr -d '\n'
done
echo

rm -f errors.log
for f in "${files[@]}"
do
	sections=($(./check $f -l))
	for s in "${sections[@]}"
	do
		echo -n $f | tr / ,
		echo -n ,$s
		for dom in "$@"
		do
			rkm=$(with_timeout 10m ./check $f $s --domain=$dom 2> /dev/null)
			echo -n ",${rkm:=0,-1,-1}"
		done
		echo
	done
done
