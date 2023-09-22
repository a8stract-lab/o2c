// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "ksample.skel.h"
#include "ksample.h"
#include "trace_helpers.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int cnt = 0;
static volatile bool exiting = false;
#define MAX_ITEMS 600000

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct ksym *sym;
	sym = ksym_search(e->call_site);
	if (!sym) {
		printf("ksym not found. Is kallsyms loaded?\n");
		return -1;
	}

	printf("%s,%d,", sym->name, ALLOC_SZ);
	for (int i = 0;i < ALLOC_SZ/8;i++) {
		printf("%016lx", e->content[i]);
	}
	printf("\n");

	if (++cnt >= MAX_ITEMS) {
		exiting = true;
	}
	return 0;
}



static void sig_handler(int sig)
{
	exiting = true;
}


int main(int argc, char **argv)
{
	struct ksample_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	load_kallsyms();

	/* Open BPF application */
	skel = ksample_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = ksample_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = ksample_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");

	// for (;;) {
	// 	/* trigger our BPF program */
	// 	fprintf(stderr, ".");
	// 	sleep(1);
	// }

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ksample_bpf__destroy(skel);
	return -err;
}
