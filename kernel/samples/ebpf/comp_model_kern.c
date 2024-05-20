
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "comp_header.h"

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

int count = 0;

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, u64); // addr
// 	__type(value, u64); // value
// 	__uint(max_entries, 10000000);
// } map SEC(".maps");

struct visited {
	unsigned long call_site;  // call_site in slab, used ip in buddy.
	unsigned long times;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct visited);
} slab_objs SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct visited);
} buddy_objs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct ip2type);
} check_types SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 8192);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 6 * sizeof(u64));
	__uint(max_entries, 10000);
} stackmap SEC(".maps");

struct trace_event_raw_kmalloc {
	u64 pad;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	char __data[0];
};

struct trace_event_raw_kfree {
	u64 pad;
	long unsigned int call_site;
	const void *ptr;
	char __data[0];
};

struct trace_event_raw_mm_page_free {
	u64 pad;
	long unsigned int pfn;
	unsigned int order;
	char __data[0];
};


struct trace_event_raw_mm_page_alloc {
	u64 pad;
	long unsigned int pfn;
	unsigned int order;
	long unsigned int gfp_flags;
	int migratetype;
	char __data[0];
};


struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab;
	/* Used for retrieving partial slabs, etc. */
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;	/* The size of an object including metadata */
	unsigned int object_size;/* The size of an object without metadata */
	unsigned long reciprocal_size;
	unsigned int offset;	/* Free pointer offset */
	/* Number of per cpu partial objects to keep around */
	unsigned int cpu_partial;
	/* Number of per cpu partial slabs to keep around */
	unsigned int cpu_partial_slabs;

	unsigned int oo;

	/* Allocation and freeing of slabs */
	unsigned int min;
	unsigned int allocflags;	/* gfp flags to use on each alloc */
	int refcount;		/* Refcount for slab cache destroy */
	void (*ctor)(void *);
	unsigned int inuse;		/* Offset to metadata */
	unsigned int align;		/* Alignment */
	unsigned int red_left_pad;	/* Left redzone padding size */
	const char *name;	/* Name (only for display!) */
	struct list_head list;	/* List of slab caches */

};
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// take 128 cache as example, 128 / 16 = 8

// static int func_callback(__u32 index, void *data)
// {
//     u64 *c = (u64 *)data;
//     *c = *c + index * 16;
//     unsigned long buf[2];
//     // u64 addr = (u64) *data;
//     bpf_core_read(buf, 16, *c);
//     bpf_printk("\t\t%lu%lu\n", *c, buf[0], buf[1]);
//     return 0;
// }


u32 getsize(u32 sz) {
	return sz <= 4096 ? 4096 : 8192;
}
u64 cnt_slab = 0;
u64 cnt_buddy = 0;
#define FREQ 100000

// SEC("tp/kmem/kmalloc")
// int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
// {
// 	u64 k = (u64) ctx->ptr;
// 	u64 call_site = (u64) ctx->call_site;
// 	struct visited v = {call_site, 0};
// 	// if (cnt_slab % 10000 == 0)
// 	// 	bpf_printk("----%lu----\n", cnt_slab);
// 	// ++cnt_slab;
	
// 	bpf_map_update_elem(&slab_objs, &k, &v, BPF_ANY);
// 	return 0;
// }
// u64 cnt_free = 0;
// SEC("tp/kmem/kfree")
// int handle_mm_kfree(struct trace_event_raw_kfree *ctx)
// {
// 	struct event *e;
// 	u64 k = (u64) ctx->ptr;
// 	++cnt_free;
// 	struct visited *pv = bpf_map_lookup_elem(&slab_objs, &k);
// 	if (pv) {
// 		// ++cnt_slab;
// 		if (++cnt_slab % FREQ == 0)
// 			bpf_printk("slab: %lu/%lu allocated\n", cnt_slab, cnt_free);

// 		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
// 		if (!e)
// 			return 0;
// 		e->alloc_addr = k;
// 		e->call_site = pv->call_site;
// 		e->isCompartment = pv->times > 0 ? 1 : 0;
// 		e->alloc_addr = (u64) ctx->ptr;
// 		struct kmem_cache *s = NULL;

// 		if (e->alloc_addr >= 0xffff888000000000 && e->alloc_addr < 0xffffc87fffffffff) {
// 			struct page *page = (struct page *)bpf_virt_to_page(e->alloc_addr);
// 			u32 flags = BPF_CORE_READ(page, flags);
// 			if (flags & 0x200) {
// 				// slab objects
// 				u64 slab_addr = (u64) page;
// 				slab_addr += 24;
// 				bpf_core_read(&s, 8, slab_addr);
// 			}
// 		}
// 		e->cache_addr = (u64) s;
// 		u64 name_addr = (u64)BPF_CORE_READ(s, name);
// 		e->sz = BPF_CORE_READ(s, size);
// 		bpf_core_read(e->cache, 32, name_addr);
// 		bpf_core_read(e->content, getsize(e->sz), k);
		

// 		bpf_ringbuf_submit(e, 0);
// 		bpf_map_delete_elem(&slab_objs, &k);
// 	}

// 	return 0;
// }

// struct page *start_page = (struct page *) 0xffffea0000000000;
// SEC("tp/kmem/mm_page_alloc")
// int handle_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
// // SEC("kretprobe/__alloc_pages")
// // int BPF_KRETPROBE(handle___alloc_pages)
// {
// 	struct page *curr = start_page + ctx->pfn;
// 	u64 k = (u64) bpf_page_to_virt((u64) curr);
// 	u64 stkid = (u64) bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
// 	struct visited v = {stkid, 0};
	
// 	bpf_map_update_elem(&buddy_objs, &k, &v, BPF_ANY);
// 	return 0;
// }


// // SEC("kprobe/__free_pages")
// // int BPF_KPROBE(handle__free_pages)
// SEC("tp/kmem/mm_page_free")
// int handle_mm_page_free(struct trace_event_raw_mm_page_free *ctx)
// {
// 	struct event *e;
// 	char *cache_name = "buddy-stackid";
// 	struct page *curr = (struct page *) start_page + ctx->pfn;
// 	u64 k = (u64) bpf_page_to_virt((u64) curr);
// 	// char str[10] = {'\0'};    // Character array to store the string representation
    
// 	struct visited *pv = bpf_map_lookup_elem(&buddy_objs, &k);
// 	if (pv) {
// 		// if (++cnt_buddy % FREQ == 0)
// 		// 	bpf_printk("buddy: %lu allocated\n", cnt_buddy);
		
// 		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
// 		if (!e)
// 			return 0;

// 		e->cache_addr = 0;
// 		e->alloc_addr = k;
// 		u64 times = pv->times;
// 		e->isCompartment = times;
// 		e->call_site = pv->call_site;
// 		bpf_core_read(e->cache, 32, cache_name);
// 		e->sz = ((u64) 1 << ctx->order) * (u64) 4096;

// 		bpf_core_read(e->content, getsize(e->sz), k);
		

// 		bpf_ringbuf_submit(e, 0);
// 		bpf_map_delete_elem(&buddy_objs, &k);
// 	}

// 	return 0;
// }



// tracepoint:kmem:kfree
//     unsigned long call_site
//     const void * ptr
// SEC("tp/kmem/kfree")
// int handle_kfree(struct trace_event_raw_kfree *ctx)
// {
// 	struct event *e;
// 	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
// 	if (!e) 
// 		return 0;
// 	e->call_site = ctx->call_site;
// 	// e->type = 1;
// 	e->alloc_addr = (u64) ctx->ptr;
// 	struct kmem_cache *s = NULL;

// 	if (e->alloc_addr >= 0xffff888000000000 && e->alloc_addr < 0xffffc87fffffffff) {
// 		struct page *page = bpf_virt_to_page(e->alloc_addr);
// 		u32 flags = BPF_CORE_READ(page, flags);
// 		bpf_printk("page: %016lx, flags:%lx\n", page, flags);
// 		if (flags & 0x200) {
// 			// slab objects
// 			u64 slab_addr = page;
// 			slab_addr += 24;
// 			bpf_core_read(&s, 8, slab_addr);

// 			// return cache;
// 		}
// 	}

// 	u64 name_addr = BPF_CORE_READ(s, name);
// 	e->sz = BPF_CORE_READ(s, size);
// 	bpf_core_read(e->cache, 32, name_addr);
// 	// if (e->sz > 0) {
// 	// 	e->sz = 0;
// 	// }
// 	const u64 k = e->alloc_addr;
// 	bpf_core_read(e->content, getsize(e->sz), k);

// 	bpf_ringbuf_submit(e, 0);

// 	return 0;

// }


// SEC("kprobe/__kmem_cache_free")
// int BPF_KPROBE(do_kfree, struct kmem_cache *s, void *x)
// {
//     u64 s_size = BPF_CORE_READ(s, size);
//     u64 addr = (u64) x;

// 	struct page *page = (struct page *)bpf_virt_to_page((u64)x);
// 	u64 page_flags = BPF_CORE_READ(page, flags);
// 	if (page_flags & 0x200) {
// 		// bpf_printk("slab page: %016lx: flag: %016lx\n", page, page_flags);
// 	}
//     return 0;
// }


// SEC("kprobe/vfree")
// int BPF_KPROBE(do_vfree, void *x)
// {
// 	u64 addr = (u64)x;
// 	struct vm_struct *vms = (struct vm_struct *)bpf_get_vm_struct(addr);
// 	if (!vms)
// 		bpf_printk("addr:%016lx, nr_pages:%d, caller:%016lx", BPF_CORE_READ(vms, addr), BPF_CORE_READ(vms, nr_pages), BPF_CORE_READ(vms, caller));
// 	return 0;
// }

// bool check(u64 addr) {
// 	const char name[32];
// 	const char *kmallocstr = "kmalloc-";
// 	if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {
// 		struct page *page = (struct page *)bpf_virt_to_page(addr);
// 		u32 flags = BPF_CORE_READ(page, flags);
// 		if (flags & 0x200) {
// 			// slab objects
// 			u64 slab_addr = (u64) page;
// 			slab_addr += 24;
// 			struct kmem_cache *cache;
// 			bpf_core_read(&cache, 8, slab_addr);
// 			const char *xaddr = BPF_CORE_READ(cache, name);
// 			bpf_core_read((void *)name, 32, xaddr);
// 			// u64 *pv = bpf_map_lookup_elem(&map, &slab_addr);
// 			// if (pv) return true;
// 			u64 naddr = bpf_get_slab_start(addr);
// 			int cmp = bpf_strncmp(name, 8, kmallocstr);
// 			bpf_printk("slab: %016lx, %016lx, %s\n", cache, bpf_get_slab_cache(addr), name);
// 			bpf_printk("slab: %d\n", cmp);
// 		} else {
// 			// page adddr
// 			// u64 *pv = bpf_map_lookup_elem(&map, &addr);
// 			// if (pv) return true;
// 			u64 naddr = bpf_page_to_virt((u64)page);
// 			bpf_printk("buddy: %016lx, %016lx\n", addr, naddr);
// 		}
// 	} else if (addr >= 0xffffc90000000000 && addr <= 0xffffe8ffffffffff) {
// 		struct vm_struct *vms = (struct vm_struct *)bpf_get_vm_struct(addr);
// 		// u64 caller = vms->caller;
// 		u64 naddr = (u64)BPF_CORE_READ(vms, addr);
// 		bpf_printk("vmalloc: %016lx, %016lx\n", addr, naddr);
// 		// u64 *pv = bpf_map_lookup_elem(&map, &caller);
// 		// if (pv) return true;
// 	} else if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {
// 		// struct page / folios
// 		bpf_printk("page: %016lx\n", addr);
// 	} else {
// 		bpf_printk("unmatched: %016lx\n", addr);
// 	}
// 	return false;
// }
// const char *kmallocstr = "kmalloc-";
// // SEC("sampling")
// bool sampling(u64 addr, u64 pip) {
// 	const char name[32];
	
// 	u64 ip = pip;
// 	if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {
// 		struct kmem_cache *s = bpf_get_slab_cache(addr);
// 		if (s) {
// 			// slab
// 			struct ip2type i2t = {
// 				.ip = ip,
// 				.identifier = (u64) s,
// 				.type = 1,
// 			};
// 			// bpf_printk("type:1, identifier:%016lx\n", s);
// 			u64 obj_addr = bpf_get_slab_start(addr);
// 			struct visited *pv = (struct visited *) bpf_map_lookup_elem(&slab_objs, &obj_addr);
// 			if (pv) {
// 				pv->times = 1;
// 				i2t.type = 0;
// 			}			
			
// 			// const char *xaddr = BPF_CORE_READ(s, name);
// 			// bpf_core_read((void *)name, 32, xaddr);
// 			// int cmp = bpf_strncmp(name, 8, kmallocstr);
// 			// if (cmp == 0) {
// 			// 	
// 			// }
// 			bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
// 		} else {
// 			// buddy
// 			struct page *page = (struct page *) bpf_virt_to_page(addr);
// 			u64 obj_addr = bpf_page_to_virt((u64) page);
// 			struct visited *pv = (struct visited *) bpf_map_lookup_elem(&buddy_objs, &obj_addr);
// 			if (pv) {
// 				pv->times = 1;
// 				struct ip2type i2t = {
// 					.ip = ip,
// 					.identifier = pv->call_site,
// 					.type = 2,
// 				};
// 				bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
// 			}
			
// 		}
// 	} else if (addr >= 0xffffc90000000000 && addr <= 0xffffe8ffffffffff) {
// 		struct vm_struct *vms = (struct vm_struct *)bpf_get_vm_struct(addr);
// 		u64 caller = BPF_CORE_READ(vms, caller);
// 		struct ip2type i2t = {
// 			.ip = ip,
// 			.identifier = caller,
// 			.type = 3
// 		};
// 		bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
// 	} else if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {
// 		struct ip2type i2t = {
// 			.ip = ip,
// 			.identifier = 0,
// 			.type = 4,
// 		};
// 		bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
// 	} else {
// 		struct ip2type i2t = {
// 			.ip = ip,
// 			.identifier = 0,
// 			.type = 5,
// 		};
// 		bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
// 	}
// 	return false;
// }


// // #define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

SEC("kretprobe/single_open")
int BPF_KRETPROBE(do_bio_kmalloc0)
{
	// if (check(ctx->ax)) {
	// 	bpf_printK("-\n");
	// }
	u64 addr = ctx->di + 0x14;

	// u32 stkid = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP);
	u32 stkid = bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
	bpf_printk("bio0: ip: %016lx, stackid:%d\n", ctx->ip, stkid);

	// sampling(addr, ctx->ip);
	return 0;
}

// SEC("kprobe/bio_kmalloc+5")
SEC("kprobe/mroute_clean_tables+0x35a")
int BPF_KPROBE(do_bio_kmalloc1)
{
	// if (check(ctx->ax)) {
	// 	bpf_printK("-\n");
	// }
	bpf_printk("bio + 5: ip: %016lx\n", ctx->ip);
	bpf_printk("bio + 5: ip: %016lx\n", ctx->ip-1);
	return 0;
}

SEC("kprobe/single_open+0xb")
int BPF_KPROBE(do_bio_kmalloc2)
{
	// if (check(ctx->ax)) {
	// 	bpf_printK("-\n");
	// }
	bpf_printk("bio + b: ip: %016lx\n", ctx->ip);
}

SEC("kprobe/single_open+0xe")
int BPF_KPROBE(do_bio_kmalloc3)
{
	// if (check(ctx->ax)) {
	// 	bpf_printK("-\n");
	// }
	bpf_printk("bio + e: ip: %016lx\n", ctx->ip);
}

// SEC("kprobe/__bio_clone+0x21")
// int BPF_KPROBE(do__bio_clone0)
// {
// 	u64 addr = ctx->di + 0x14;
// 	sampling(addr, ctx->ip);
// 	return 0;
// }

// SEC("kprobe/__bio_clone+0x29")
// int BPF_KPROBE(do__bio_clone1)
// {
// 	u64 addr = ctx->di + 0x16;
// 	sampling(addr, ctx->ip);
// 	return 0;
// }

// SEC("kprobe/__bio_clone+0x31")
// int BPF_KPROBE(do__bio_clone2)
// {
// 	u64 addr = ctx->di + 0x20;
// 	sampling(addr, ctx->ip);
// 	return 0;
// }

// SEC("kprobe/__bio_clone+0x39")
// int BPF_KPROBE(do__bio_clone3)
// {
// 	u64 addr = ctx->di + 0x28;
// 	sampling(addr, ctx->ip);
// 	return 0;
// }

// SEC("kprobe/__bio_clone+0x40")
// int BPF_KPROBE(do__bio_clone4)
// {
// 	u64 addr = ctx->di + 0x30;
// 	sampling(addr, ctx->ip);
// 	return 0;
// }

// SEC("kprobe/__bio_clone+0x9c")
// int BPF_KPROBE(do__bio_clone5)
// {
// 	u64 addr = ctx->di + 0x14;
// 	sampling(addr, ctx->ip);
// 	return 0;
// }




// 128:ffff8881030d4580
// ffff8881030d45800000000000000000
// ffff8881030d4590ffff8881030d45d8
// ffff8881030d45b0dead000000000122
// ffff8881030d45e000000000000bb30d
// ffff8881030d4620ffff8881030b3780
// ffff8881030d46700000000000000000
// ffff8881030d46d00000000000000000
// ffff8881030d47400000000200000103


// 128:ffff8885a3c38d00
// ffff8885a3c38d000000000100000001
// ffff8885a3c38d10ffff8885a3c38d08
// ffff8885a3c38d30ffff88811dbe1e00
// ffff8885a3c38d600000000100000000
// ffff8885a3c38da0ffff8885a3c38d98
// ffff8885a3c38df00000000000000000
// ffff8885a3c38e50ffff88811f6802c0
// ffff8885a3c38ec02eb8920082b6fabe

// Xorg-2496    [014] d..31 24260.022779: bpf_trace_printk: 128:ffff88810389d300
// 184466126864243637760
// 1844661268642436379218446612686424363864
// 1844661268642436382416045481047390945570
// 18446612686424363872819203
// 184466126864243639360
// 184466126864243640160
// 1844661268642436411218446612686891587904
// 184466126864243642243378500870021621182