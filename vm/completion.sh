#!/bin/bash

function f() {
    case $COMP_CWORD in
        1)
            COMPREPLY=($($1 -h | grep -Po "\b$2[a-z_]*(?= - )"));
            ;;
        2)
            if [[ -z "$2"  ]]
            then
                COMPREPLY=($(realpath --relative-to . $(locate -l1 -r 'linux/samples/bpf$'))/*_kern.o)
            else
                COMPREPLY=($2*_kern.o)
            fi
            ;;
    esac
}

complete -F f ./test
