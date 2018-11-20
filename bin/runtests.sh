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
files=($(ls -S ${dir}))
shift

if [[ "$1" == "header" ]]
then
	shift
	for f in "${files[@]}"; do echo -n ",$f"; done
fi

mkdir -p logs
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
		err=logs/${base}.err
		log=logs/${base}.log
		CMD="with_timeout 10m bin/check --simplify -q ${dir}/$base ${base##*.} $dom"
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

