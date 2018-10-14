#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
//#include "bpf_load.h"

int load_bpf_file(char* filename);

int main(int argc, char **argv)
{
	if (argc <= 1) {
		printf("usage: %s filename_kern.o\n", argv[0]);
		return 1;
	}
	char* filename = argv[1];
	printf("loading %s\n", filename);
	if (load_bpf_file(filename)) {
		printf("not loaded; err=%d\n", errno);
		return 1;
	}
	printf("loaded\n");
	return 0;
}
