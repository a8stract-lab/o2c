// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "klifecycle.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct event);
} record SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");




int cnt = 0;
int CNT = 0;


SEC("tp/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
	u64 k = (u64) ctx->ptr;
	// u64 v = (u64) ctx->call_site;
	struct event v = {
		.call_site = ctx->call_site,
		.alloc_ns = bpf_ktime_get_ns(),
		.sz = ctx->bytes_alloc,
	};
	// 1. all memory is allocated from kmalloc-xxx, not kmalloc-cg/kmalloc-dma
	if ((ctx->gfp_flags & KMALLOC_NOT_NORMAL_BITS) == 0 /*&& ctx->bytes_alloc == ALLOC_SZ*/) {
		bpf_map_update_elem(&record, &k, &v, BPF_ANY);
	}
	return 0;
}

SEC("kprobe/__kmem_cache_free")
int BPF_KPROBE(do_kfree, struct kmem_cache *s, void *x)
{
	struct event *e;
	u64 k = (u64) x;

	struct event *pv = bpf_map_lookup_elem(&record, &k);
	if (pv) {
		// 2. calculate time consuming
		pv->free_ns = bpf_ktime_get_ns();
		u64 lifecycle = pv->free_ns - pv->alloc_ns; 

		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e)
			return 0;

		const char *s_name_addr = BPF_CORE_READ(s, name);
		bpf_core_read_str(e->cache, 32, s_name_addr);
		e->sz = pv->sz;
		e->call_site = pv->call_site;
		e->life_ns = lifecycle;
		e->alloc_ns = pv->alloc_ns;
		e->free_ns = pv->free_ns;
		

		bpf_map_delete_elem(&record, &k);
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}
