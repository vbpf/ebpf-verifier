#!/bin/bash

dir=$1
test -d $dir || (echo "first argument should be a directory"; exit 1)
shift

with_timeout() {
    if hash gtimeout 2>/dev/null; then gtimeout "$@"; else timeout "$@"; fi
}

files=($(find ${dir} -name '*.o'  -exec ls -Sd {} + ))

echo -n "suite,project,file,section,hash,instructions,loads,stores,jumps,joins"
for dom in "$@"; do echo -n ",$dom?,$dom-sec,$dom-kb"; done
echo

for f in "${files[@]}"
do
	sections=($(./check $f -l))
	for s in "${sections[@]}"
	do
		echo -n $f | tr / ,
		echo -n ,$s,
		echo -n $(./check $f $s --domain=stats)
		for dom in "$@"
		do
			rkm=$(with_timeout 10m ./check $f $s --domain=$dom 2>errors.log)
			echo -n ",$rkm"
		done
		echo
	done
done

