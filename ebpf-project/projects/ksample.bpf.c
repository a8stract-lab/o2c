// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
} record SEC(".maps");

// SEC("tp/syscalls/sys_enter_write")
// int handle_tp(void *ctx)
// {
// 	int pid = bpf_get_current_pid_tgid() >> 32;

// 	if (pid != my_pid)
// 		return 0;

// 	bpf_printk("BPF triggered from PID %d.\n", pid);

// 	return 0;
// }
#define STRNCMP_STR_SZ 32
	const char cache32[STRNCMP_STR_SZ] = "kmalloc-cg-32";
	char filename[STRNCMP_STR_SZ];

int cnt = 0;
int CNT = 0;

int strncmp(char *s1, u32 sz, char *s2)
{
	for (int i = 0;i < sz;i++) {
		if (s1[i] != s2[i]) {
			return i;
		}
	}
	// bpf_printk("%s:%s", s1, s2);
	return 0;
}

// seq_open(struct file *file, const struct seq_operations *op)
SEC("kprobe/seq_open")
int BPF_KPROBE(handle0, struct file *file, struct seq_operations *op)
{
	u64 k = (u64) op;
	u64 v = 0;
	bpf_map_update_elem(&record, &k, &v, BPF_ANY);
	return 0;
}

SEC("kprobe/__kmem_cache_free")
int BPF_KPROBE(do_kfree, struct kmem_cache *s, void *x)
{
	u64 k = (u64) x;

	u64 *addr = BPF_CORE_READ(s, name);
	

	bpf_core_read_str(filename, STRNCMP_STR_SZ, addr);

	// bpf_printk("%016lx:%s\n", addr, filename);
	// filename = BPF_CORE_READ(s, name);
	// if (bpf_strncmp(cache32, 32, filename) == 0) 
	// 	bpf_printk("%s\n", filename);
	if (strncmp(cache32, 32, filename) == 0) 
	{
		++CNT;
		// bpf_printk("%s\n", filename);
		u64 *pv = bpf_map_lookup_elem(&record, &k);
		if (pv) {
			++cnt;
			bpf_map_delete_elem(&record, &k);
			bpf_printk("%ld/%ld\n", cnt, CNT);
		}
	}
	return 0;
}