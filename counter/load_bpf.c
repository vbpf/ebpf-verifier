#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/resource.h>
#include "bpf_load.h"

int load_bpf_file(char* filename);

void fixup_map(struct bpf_map_data *map, int idx) {
	map->fd = idx;
}

int main(int argc, char **argv)
{
	if (argc <= 1) {
		printf("usage: %s kern/filename.o\n", argv[0]);
		return 1;
	}
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
 	const char *optstr = "SN";
 	char filename[256];
 	int ret, opt, key = 0;
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}
	int res = 0;
	for (int i=1; i < argc; i++) {
		char* filename = argv[i];
		printf("loading %s with fixup map\n", filename);
		if (load_bpf_file_fixup_map(filename, fixup_map) != 0) {
			printf("not loaded; err=%d\n", errno);
			res = 1;
		} else {
			printf("loaded\n");
		}
	}
	return res;
}
