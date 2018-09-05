function run() {
	# reset;
	./test $@; x=$?; ./test $@ 2>/dev/null | grep -A8 -E 'ERROR|WARNING'; ../bin/ubpf-disassembler $2;
	return $x
}

