#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include "comp_header.h"

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

#define MAX_NODES 100  // Adjust this value based on your tree size

long childrenLeft[MAX_NODES];
long childrenRight[MAX_NODES];
long feature[MAX_NODES];
long threshold[MAX_NODES];
long value[MAX_NODES];
struct event es[66];

void read_from_file(const char *filename, void *arr, size_t size, size_t count) {
    FILE *file = fopen(filename, "rb");
    fread(arr, size, count, file);
    fclose(file);
}


// cat /sys/kernel/debug/tracing/trace_pipe
int main(int argc, char **argv)
{
    struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int j = 0;
	int trace_fd;
	
	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0) {
		printf("cannot open trace_pipe %d\n", trace_fd);
		return trace_fd;
	}

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}


	bpf_object__for_each_program(prog, obj) {
		links[j] = bpf_program__attach(prog);
		if (libbpf_get_error(links[j])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[j] = NULL;
			goto cleanup;
		}
		j++;
	}

	int fd_childrenLeft = bpf_object__find_map_fd_by_name(obj, "childrenLeft");
    int fd_childrenRight = bpf_object__find_map_fd_by_name(obj, "childrenRight");
    int fd_value = bpf_object__find_map_fd_by_name(obj, "value");
    int fd_feature = bpf_object__find_map_fd_by_name(obj, "features");
    int fd_threshold = bpf_object__find_map_fd_by_name(obj, "threshold");
    int fd_l1pool = bpf_object__find_map_fd_by_name(obj, "l1pool");
    int fd_l2pool = bpf_object__find_map_fd_by_name(obj, "l2pool");

	// read_from_file("/home/ppw/Documents/on-the-fly-compartment/ml-project/sample/res/childrenLeft", childrenLeft, sizeof(long), MAX_NODES);
    // read_from_file("/home/ppw/Documents/on-the-fly-compartment/ml-project/sample/res/childrenRight", childrenRight, sizeof(long), MAX_NODES);
    // read_from_file("/home/ppw/Documents/on-the-fly-compartment/ml-project/sample/res/feature", feature, sizeof(long), MAX_NODES);
    // read_from_file("/home/ppw/Documents/on-the-fly-compartment/ml-project/sample/res/threshold", threshold, sizeof(long), MAX_NODES);
    // read_from_file("/home/ppw/Documents/on-the-fly-compartment/ml-project/sample/res/value", value, sizeof(long), MAX_NODES);

	// for (int i = 0; i < MAX_NODES; ++i) {
    //     bpf_map_update_elem(fd_childrenLeft, &i, &childrenLeft[i], BPF_ANY);
    //     bpf_map_update_elem(fd_childrenRight, &i, &childrenRight[i], BPF_ANY);
    //     bpf_map_update_elem(fd_value, &i, &value[i], BPF_ANY);
    //     bpf_map_update_elem(fd_feature, &i, &feature[i], BPF_ANY);
    //     bpf_map_update_elem(fd_threshold, &i, &threshold[i], BPF_ANY);
    // }

	for (int i = 0;i < 66;i++) {
		bpf_map_update_elem(fd_l1pool, &i, &es[i], BPF_ANY);
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	
	printf("start tracing\n");
    while (!stop) {
        // fprintf(stderr, ".");
        // sleep(1);
		static char buf[4096];
		ssize_t sz;
		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = '\0';
			// printf("trace: %s\n", buf);
			puts(buf);
		}
    }


    cleanup:
        // bpf_link__destroy(link);
		// for (j--; j >= 0; j--)
		// 	bpf_link__destroy(links[j]);
	    // bpf_object__close(obj);
		// close(trace_fd);
        return 0;




    return 0;
}