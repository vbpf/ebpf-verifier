#!/bin/bash

dir=$1
test -d $dir || (echo "first argument should be a directory"; exit 1)
shift

with_timeout() {
    if hash gtimeout 2>/dev/null; then gtimeout "$@"; else timeout "$@"; fi
}

function readmem() { 
	k=$(grep maximum $1 | python3 -c 'print(input().split()[0])');
	echo $((k / 1000))
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
			tmp=$(mktemp /tmp/mem.XXXXXX)

			k=$(with_timeout 10m /usr/bin/time -l ./check $f $s --domain=$dom 2>$tmp)
			m=$(readmem $tmp); rm "$tmp"
			echo -n ",$k,$m"

		done
		echo
	done
done

