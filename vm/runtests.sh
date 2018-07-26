#!/bin/bash
dir=../samples/linux
files=($(ls -S ${dir}))

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
	for dom in "$@"
	do
		base=$(basename $f)
		err=../logs/${base}.err
		log=../logs/${base}.log
		CMD="./test $dom ${dir}/$base ${base##*.}"
		echo $CMD > ${err}
		echo $CMD > ${log}
		$CMD >> ${log} 2>> ${err}
		case "$?" in
		0) echo -n ",1"  ;;
		1) echo -n ",0"  ;;
		*) echo -n ",$?" ;;
		esac
	done
	echo
done

