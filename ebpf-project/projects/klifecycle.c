// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "klifecycle.skel.h"
#include "klifecycle.h"
#include "trace_helpers.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct ksym *sym;
	sym = ksym_search(e->call_site);
	if (!sym) {
		printf("ksym not found. Is kallsyms loaded?\n");
		return -1;
	}

	printf("%s,%lu,%s,%lu,%lu,%lu\n", e->cache, e->sz, sym->name, e->life_ns, e->alloc_ns, e->free_ns);
	
	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}


int main(int argc, char **argv)
{
	struct klifecycle_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	load_kallsyms();

	/* Open BPF application */
	skel = klifecycle_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = klifecycle_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = klifecycle_bpf__attach(skel);
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

	// print objects are not freed, not sure if they necessary 
	// unsigned long prev_key = 0, key;
	// struct event v;
	// printf("\n\n\n");
	// while (bpf_map__get_next_key(skel->maps.record, &prev_key, &key, sizeof(key)) == 0) {
	// 	bpf_map__lookup_and_delete_elem(skel->maps.record, &key, sizeof(key), &v, sizeof(v), 0);
	// 	handle_event(NULL, &v, sizeof(v));
	// 	prev_key = key;
	// }

cleanup:
	klifecycle_bpf__destroy(skel);
	return -err;
}
