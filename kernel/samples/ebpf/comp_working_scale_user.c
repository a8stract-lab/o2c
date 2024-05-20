#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <sys/resource.h>
#include "comp_header.h"
#include "trace_helpers.h"
#include <linux/bpf.h>

static volatile sig_atomic_t stop;

FILE *f_train;
FILE *f_sample;
FILE *f_policy;
int trace_fd;

static void sig_int(int signo)
{
	stop = 1;
}

static int handle_rb(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct ksym *sym;
	char call_site[32];
	
	if (e->cache_addr == 0) {
		// buddy
		strcpy(call_site, e->cache);
		snprintf(call_site + 6, 20, "%lu", e->call_site);
		// printf("====%s====\n", call_site);
		// memmove(e->cache + 6, call_site, 20);
		// strcat(e->cache, call_site);
		printf("%s,%ld,%s,%u,", call_site, e->sz, "buddy", e->isCompartment);
	} else {
		// slab
		sym = ksym_search(e->call_site);
		if (!sym) {
			printf("ksym not found. Is kallsyms loaded?\n");
			return -1;
		}
		printf("%s,%ld,%s,%u,", sym->name, e->sz, e->cache, e->isCompartment);
	}
	for (int i = 0;i < e->sz/8;i++) {
		printf("%016lx", e->content[i]);
	}
	printf("\n");
	return 0;
}



void* poll_file(void* arg) {
    char buf[4096];

    while (!stop) {
        ssize_t sz;
		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = '\0';
			// printf("trace: %s\n", buf);
			puts(buf);
		}
    }

    return NULL;
}


// cat /sys/kernel/debug/tracing/trace_pipe
int main(int argc, char **argv)
{
    struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct ring_buffer *rb = NULL;
	int rb_fd = 0;
	int i2t_fd = 0;
	char filename[256];
	int j = 0;
	
	int err = 0;
	struct rlimit limit;
  
	limit.rlim_cur = 65535;
	limit.rlim_max = 65535;
	if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
		printf("setrlimit() failed with errno=%d\n", errno);
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_train.csv", argv[0]);
	f_train = fopen(filename, "w");
	if (f_train == NULL) {
		printf("Could not open the file for writing.\n");
        return 1;
	}

	snprintf(filename, sizeof(filename), "%s_sample.csv", argv[0]);
	f_sample = fopen(filename, "w");
	if (f_sample == NULL) {
		printf("Could not open the file for writing.\n");
        return 1;
	}

	snprintf(filename, sizeof(filename), "%s_policy.csv", argv[0]);
	f_policy = fopen(filename, "w");
	if (f_policy == NULL) {
		printf("Could not open the file for writing.\n");
        return 1;
	}
	
	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0) {
		printf("cannot open trace_pipe %d\n", trace_fd);
		return trace_fd;
	}
	load_kallsyms();

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
			// goto cleanup;
		} else {
			if (j % 200 == 0)
				printf("installed: %d\n", j);
		}
		j++;
	}
	
	rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
	rb = ring_buffer__new(rb_fd, handle_rb, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	i2t_fd = bpf_object__find_map_fd_by_name(obj, "check_types");

	pthread_t thread;

    // Create a new thread to poll the file
    if (pthread_create(&thread, NULL, poll_file, NULL) != 0) {
        perror("Failed to create thread");
        return 1;
    }

    pthread_detach(thread, NULL);


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
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
 			err = 0;
 			break;
 		}
 		if (err < 0) {
 			printf("Error polling ring buffer: %d\n", err);
 			break;
 		}
		// static char buf[4096];
		// ssize_t sz;
		// sz = read(trace_fd, buf, sizeof(buf) - 1);
		// if (sz > 0) {
		// 	buf[sz] = '\0';
		// 	// printf("trace: %s\n", buf);
		// 	puts(buf);
		// }
    }


    cleanup:
        // bpf_link__destroy(link);
		// for (j; j >= 0; j--)
		// 	bpf_link__destroy(links[j]);
		// Wait for the thread to finish
    	// pthread_join(thread, NULL);
		// fhandle_i2t(i2t_fd);
	    bpf_object__close(obj);
		close(trace_fd);
		fclose(f_train);
		fclose(f_sample);
		fclose(f_policy);
        return 0;




    return 0;
}