#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/resource.h>
#include "bpf_load.h"

#include <time.h>

int load_bpf_file(char* filename);

void setrlimit_inf()
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		exit(64);
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("usage: %s filename.o\n", argv[0]);
		return 1;
	}
	setrlimit_inf();
	clock_t t = clock();
	int res = load_bpf_file(argv[1]);
	t = clock() - t; 
	double time_taken = ((double)t)/CLOCKS_PER_SEC;
	if (res != 0) {
		printf("0,%lf,0\n", time_taken);
		return 1;
	} else {
		printf("1,%lf,0\n", time_taken);
		return 0;
	}
}
