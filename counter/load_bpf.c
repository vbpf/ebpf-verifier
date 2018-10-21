#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
//#include "bpf_load.h"

int load_bpf_file(char* filename);

int main(int argc, char **argv)
{
	if (argc <= 1) {
		printf("usage: %s kern/filename.o\n", argv[0]);
		return 1;
	}
	int res = 0;
	for (int i=1; i < argc; i++) {
		char* filename = argv[i];
		printf("loading %s\n", filename);
		if (load_bpf_file(filename)) {
			printf("not loaded; err=%d\n", errno);
			res = 1;
		} else {
			printf("loaded\n");
		}
	}
	return res;
}
