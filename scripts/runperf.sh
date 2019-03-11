#!/bin/bash

dir=$1
test -d $dir || (echo "first argument should be a directory"; exit 1)
shift

with_timeout() {
    if hash gtimeout 2>/dev/null; then gtimeout "$@"; else timeout "$@"; fi
}

files=($(find ${dir} -name '*.o'  -exec ls -Sd {} + ))

echo -n suite,project,file,section,
echo -n $(./check @headers --domain=stats)
for dom in "$@"
do
	echo -n ,$(./check @headers --domain=${dom})
done
echo

rm -f errors.log
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
			echo >> errors.log
			echo "with_timeout 10m ./check $f $s --domain=$dom" >> errors.log
			rkm=$(with_timeout 10m ./check $f $s --domain=$dom 2>>errors.log)
			echo -n ",${rkm:=0,-1,-1}"
		done
		echo
	done
done
