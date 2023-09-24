// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ksample.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
} record SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 81920);
	__type(key, u64);
	__type(value, u64);
} slab_access SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 81920);
	__type(key, u64);
	__type(value, u64);
} buddy_access SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 81920);
	__type(key, u64);
	__type(value, u64);
} vmalloc_access SEC(".maps");







// SEC("tp/kmem/kmalloc")
// int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
// {
// 	u64 k = (u64) ctx->ptr;
// 	u64 v = (u64) ctx->call_site;
// 	// 1. all memory is allocated from kmalloc-xxx, not kmalloc-cg/kmalloc-dma
// 	// if ((ctx->gfp_flags & KMALLOC_NOT_NORMAL_BITS) == 0 && ctx->bytes_alloc == ALLOC_SZ) {
// 	// 	bpf_map_update_elem(&record, &k, &v, BPF_ANY);
// 	// }
// 	return 0;
// }

// SEC("kprobe/__kmem_cache_free")
// int BPF_KPROBE(do_kfree, struct kmem_cache *s, void *x)
// {
// 	struct event *e;
// 	u64 k = (u64) x;
// 	u64 s_size = BPF_CORE_READ(s, size);
// 	const char *s_name_addr = BPF_CORE_READ(s, name);

// 	u64 *pv = bpf_map_lookup_elem(&record, &k);
// 	if (pv) {
// 		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 		if (!e)
// 			return 0;
		
// 		bpf_core_read_str(e->cache, 32, s_name_addr);
// 		e->sz = s_size;
// 		e->call_site = *pv;
// 		bpf_core_read(e->content, ALLOC_SZ, k);

// 		bpf_map_delete_elem(&record, &k);
// 		bpf_ringbuf_submit(e, 0);
// 	}

// 	return 0;
// }

// bool classify(unsigned long addr) 
// {

// }



SEC("tp/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
	u64 k = (u64) ctx->ptr;
	u64 v = (u64) ctx->call_site;
	// if (ctx->bytes_alloc == 96) {
		bpf_printk("%016lx\n", k);
	// }
	// 1. all memory is allocated from kmalloc-xxx, not kmalloc-cg/kmalloc-dma
	// if ((ctx->gfp_flags & KMALLOC_NOT_NORMAL_BITS) == 0 && ctx->bytes_alloc == ALLOC_SZ) {
	// 	bpf_map_update_elem(&record, &k, &v, BPF_ANY);
	// }
	return 0;
}


// tracepoint:kmem:kfree
// tracepoint:kmem:kmem_cache_free