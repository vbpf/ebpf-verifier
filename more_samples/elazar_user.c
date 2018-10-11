#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "bpf_load.h"

int main(int argc, char **argv)
{
	char filename[256] = "elazar_kern.o";
	if (load_bpf_file(filename)) {
		printf("not loaded\n");
		return 1;
	}
	printf("loaded\n");
	return 0;
}
