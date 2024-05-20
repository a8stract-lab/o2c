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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)

int count = 0;

struct visited {
	unsigned long call_site;  // call_site in slab, used ip in buddy.
	unsigned long times;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819200);
	__type(key, u64);
	__type(value, struct visited);
} slab_objs SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819200);
	__type(key, u64);
	__type(value, struct visited);
} buddy_objs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192000);
	__type(key, u64);
	__type(value, struct ip2type);
} check_types SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 102400);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 6 * sizeof(u64));
	__uint(max_entries, 100000);
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


u32 getsize(u32 sz) {
	return sz <= 4096 ? 4096 : 8192;
}


u64 cnt_slab = 0;
u64 cnt_buddy = 0;

SEC("tp/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
	u64 k = (u64) ctx->ptr;
	u64 call_site = (u64) ctx->call_site;
	struct visited v = {call_site, 0};
	
	bpf_map_update_elem(&slab_objs, &k, &v, BPF_ANY);
	return 0;
}

SEC("tp/kmem/kfree")
int handle_mm_kfree(struct trace_event_raw_kfree *ctx)
{
	struct event *e;
	u64 k = (u64) ctx->ptr;
	struct visited *pv = bpf_map_lookup_elem(&slab_objs, &k);
	if (pv) {
		if (++cnt_slab % 1000000 == 0)
			bpf_printk("slab: %lu allocated\n", cnt_slab);

		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
		if (!e)
			return 0;
		e->alloc_addr = k;
		e->call_site = pv->call_site;
		e->isCompartment = pv->times > 0 ? 1 : 0;
		e->alloc_addr = (u64) ctx->ptr;
		struct kmem_cache *s = NULL;

		if (e->alloc_addr >= 0xffff888000000000 && e->alloc_addr < 0xffffc87fffffffff) {
			struct page *page = (struct page *)bpf_virt_to_page(e->alloc_addr);
			u32 flags = BPF_CORE_READ(page, flags);
			if (flags & 0x200) {
				// slab objects
				u64 slab_addr = (u64) page;
				slab_addr += 24;
				bpf_core_read(&s, 8, slab_addr);
			}
		}
		e->cache_addr = (u64) s;
		u64 name_addr = (u64)BPF_CORE_READ(s, name);
		e->sz = BPF_CORE_READ(s, size);
		bpf_core_read(e->cache, 32, name_addr);
		bpf_core_read(e->content, getsize(e->sz), k);
		

		bpf_ringbuf_submit(e, 0);
		bpf_map_delete_elem(&slab_objs, &k);
	}

	return 0;
}

struct page *start_page = (struct page *) 0xffffea0000000000;
SEC("tp/kmem/mm_page_alloc")
int handle_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
// SEC("kretprobe/__alloc_pages")
// int BPF_KRETPROBE(handle___alloc_pages)
{
	struct page *curr = start_page+ctx->pfn;
	u64 k = (u64) bpf_page_to_virt((u64) curr);
	u64 stkid = (u64) bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
	struct visited v = {stkid, 0};
	
	bpf_map_update_elem(&buddy_objs, &k, &v, BPF_ANY);
	return 0;
}


// SEC("kprobe/__free_pages")
// int BPF_KPROBE(handle__free_pages)
SEC("tp/kmem/mm_page_free")
int handle_mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	struct event *e;
	char *cache_name = "buddy-stackid";
	struct page *curr = (struct page *) start_page+ctx->pfn;
	u64 k = (u64) bpf_page_to_virt((u64) curr);
	// char str[10] = {'\0'};    // Character array to store the string representation
    
	struct visited *pv = bpf_map_lookup_elem(&buddy_objs, &k);
	if (pv) {
		if (++cnt_buddy % 1000000 == 0)
			bpf_printk("buddy: %lu allocated\n", cnt_buddy);
		
		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
		if (!e)
			return 0;

		e->cache_addr = 0;
		e->alloc_addr = k;
		u64 times = pv->times;
		e->isCompartment = times;
		e->call_site = pv->call_site;
		bpf_core_read(e->cache, 32, cache_name);
		e->sz = ((u64) 1 << ctx->order) * (u64) 4096;

		bpf_core_read(e->content, getsize(e->sz), k);
		

		bpf_ringbuf_submit(e, 0);
		bpf_map_delete_elem(&buddy_objs, &k);
	}

	return 0;
}


const char *kmallocstr = "kmalloc-";
bool sampling(u64 addr, u64 pip) {
	const char name[32];
	
	u64 ip = pip;
    // bpf_printk("addr: %016lx, ip: %016lx\n", addr, ip);
	if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {
		struct kmem_cache *s = bpf_get_slab_cache(addr);
		if (s) {
			// slab
			struct ip2type i2t = {
				.ip = ip,
				.identifier = (u64) s,
				.type = 1,
			};
			// bpf_printk("type:1, identifier:%016lx\n", s);
			u64 obj_addr = bpf_get_slab_start(addr);
			struct visited *pv = (struct visited *) bpf_map_lookup_elem(&slab_objs, &obj_addr);
			if (pv) {
				pv->times = 1;
				i2t.type = 0;
			}			
			
			bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
		} else {
			// buddy
			struct page *page = (struct page *) bpf_virt_to_page(addr);
			u64 obj_addr = bpf_page_to_virt((u64) page);
			struct visited *pv = (struct visited *) bpf_map_lookup_elem(&buddy_objs, &obj_addr);
			if (pv) {
				pv->times = 1;
				struct ip2type i2t = {
					.ip = ip,
					.identifier = pv->call_site,
					.type = 2,
				};
				bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
			}
			
		}
	} else if (addr >= 0xffffc90000000000 && addr <= 0xffffe8ffffffffff) {
		struct vm_struct *vms = (struct vm_struct *)bpf_get_vm_struct(addr);
		u64 caller = BPF_CORE_READ(vms, caller);
		struct ip2type i2t = {
			.ip = ip,
			.identifier = caller,
			.type = 3
		};
		bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
	} else if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {
		struct ip2type i2t = {
			.ip = ip,
			.identifier = 0,
			.type = 4,
		};
		bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
	} else {
		struct ip2type i2t = {
			.ip = ip,
			.identifier = 0,
			.type = 5,
		};
		bpf_map_update_elem(&check_types, &ip, &i2t, BPF_ANY);
	}
	return false;
}




// SEC("kprobe/copy_group_source_from_sockptr+0x80")
// int BPF_KPROBE(do_mov_0)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xbd")
// int BPF_KPROBE(do_mov_1)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xc4")
// int BPF_KPROBE(do_mov_2)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xcd")
// int BPF_KPROBE(do_mov_3)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xd7")
// int BPF_KPROBE(do_mov_4)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xe1")
// int BPF_KPROBE(do_mov_5)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xeb")
// int BPF_KPROBE(do_mov_6)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xf5")
// int BPF_KPROBE(do_mov_7)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xff")
// int BPF_KPROBE(do_mov_8)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x109")
// int BPF_KPROBE(do_mov_9)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x113")
// int BPF_KPROBE(do_mov_10)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x11d")
// int BPF_KPROBE(do_mov_11)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x127")
// int BPF_KPROBE(do_mov_12)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x131")
// int BPF_KPROBE(do_mov_13)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x13b")
// int BPF_KPROBE(do_mov_14)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x145")
// int BPF_KPROBE(do_mov_15)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x14f")
// int BPF_KPROBE(do_mov_16)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x159")
// int BPF_KPROBE(do_mov_17)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x166")
// int BPF_KPROBE(do_mov_18)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x176")
// int BPF_KPROBE(do_mov_19)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x186")
// int BPF_KPROBE(do_mov_20)
// {
//     u64 addr = ctx->r12+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x196")
// int BPF_KPROBE(do_mov_21)
// {
//     u64 addr = ctx->r12+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1a6")
// int BPF_KPROBE(do_mov_22)
// {
//     u64 addr = ctx->r12+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1b6")
// int BPF_KPROBE(do_mov_23)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1c6")
// int BPF_KPROBE(do_mov_24)
// {
//     u64 addr = ctx->r12+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1d6")
// int BPF_KPROBE(do_mov_25)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1e6")
// int BPF_KPROBE(do_mov_26)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1f6")
// int BPF_KPROBE(do_mov_27)
// {
//     u64 addr = ctx->r12+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x206")
// int BPF_KPROBE(do_mov_28)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x216")
// int BPF_KPROBE(do_mov_29)
// {
//     u64 addr = ctx->r12+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x226")
// int BPF_KPROBE(do_mov_30)
// {
//     u64 addr = ctx->r12+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x236")
// int BPF_KPROBE(do_mov_31)
// {
//     u64 addr = ctx->r12+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x246")
// int BPF_KPROBE(do_mov_32)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x256")
// int BPF_KPROBE(do_mov_33)
// {
//     u64 addr = ctx->r12+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x266")
// int BPF_KPROBE(do_mov_34)
// {
//     u64 addr = ctx->r12+0x100;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_markstate+0x2b")
// int BPF_KPROBE(do_mov_35)
// {
//     u64 addr = ctx->ax+0x1d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_markstate+0x47")
// int BPF_KPROBE(do_mov_36)
// {
//     u64 addr = ctx->ax+0x1d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x95")
// int BPF_KPROBE(do_mov_37)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x9d")
// int BPF_KPROBE(do_mov_38)
// {
//     u64 addr = ctx->bx+0x1e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0xbb")
// int BPF_KPROBE(do_mov_39)
// {
//     u64 addr = ctx->bx+0x1e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0xdb")
// int BPF_KPROBE(do_mov_40)
// {
//     u64 addr = ctx->ax+0x1e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x11e")
// int BPF_KPROBE(do_mov_41)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x125")
// int BPF_KPROBE(do_mov_42)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x12d")
// int BPF_KPROBE(do_mov_43)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x135")
// int BPF_KPROBE(do_mov_44)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x13e")
// int BPF_KPROBE(do_mov_45)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x143")
// int BPF_KPROBE(do_mov_46)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x146")
// int BPF_KPROBE(do_mov_47)
// {
//     u64 addr = ctx->ax+0x1e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0x14f")
// int BPF_KPROBE(do_mov_48)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grhead+0x36")
// int BPF_KPROBE(do_mov_49)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grhead+0x39")
// int BPF_KPROBE(do_mov_50)
// {
//     u64 addr = ctx->ax+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grhead+0x3d")
// int BPF_KPROBE(do_mov_51)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grhead+0x45")
// int BPF_KPROBE(do_mov_52)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grhead+0x65")
// int BPF_KPROBE(do_mov_53)
// {
//     u64 addr = ctx->cx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grhead+0x69")
// int BPF_KPROBE(do_mov_54)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x1c2")
// int BPF_KPROBE(do_mov_55)
// {
//     u64 addr = ctx->r14+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x22e")
// int BPF_KPROBE(do_mov_56)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x2a4")
// int BPF_KPROBE(do_mov_57)
// {
//     u64 addr = ctx->r14+0x1e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x2d5")
// int BPF_KPROBE(do_mov_58)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x326")
// int BPF_KPROBE(do_mov_59)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x38b")
// int BPF_KPROBE(do_mov_60)
// {
//     u64 addr = ctx->r14+0x1e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x3b1")
// int BPF_KPROBE(do_mov_61)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x3e8")
// int BPF_KPROBE(do_mov_62)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/add_grec+0x4af")
// int BPF_KPROBE(do_mov_63)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x16")
// int BPF_KPROBE(do_mov_64)
// {
//     u64 addr = ctx->di+0x128;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x20")
// int BPF_KPROBE(do_mov_65)
// {
//     u64 addr = ctx->di+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x2b")
// int BPF_KPROBE(do_mov_66)
// {
//     u64 addr = ctx->di+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x35")
// int BPF_KPROBE(do_mov_67)
// {
//     u64 addr = ctx->di+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x40")
// int BPF_KPROBE(do_mov_68)
// {
//     u64 addr = ctx->di+0x524;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_mfc_seq_start+0x37")
// int BPF_KPROBE(do_mov_69)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_mfc_seq_start+0x40")
// int BPF_KPROBE(do_mov_70)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_mfc_seq_start+0x48")
// int BPF_KPROBE(do_mov_71)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_expire_process+0x7c")
// int BPF_KPROBE(do_mov_72)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_expire_process+0x80")
// int BPF_KPROBE(do_mov_73)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_expire_process+0x92")
// int BPF_KPROBE(do_mov_74)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_expire_process+0x9b")
// int BPF_KPROBE(do_mov_75)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x15d")
// int BPF_KPROBE(do_mov_76)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x161")
// int BPF_KPROBE(do_mov_77)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x16e")
// int BPF_KPROBE(do_mov_78)
// {
//     u64 addr = ctx->r14+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x340")
// int BPF_KPROBE(do_mov_79)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x344")
// int BPF_KPROBE(do_mov_80)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x34c")
// int BPF_KPROBE(do_mov_81)
// {
//     u64 addr = ctx->r13+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mroute_clean_tables+0x350")
// int BPF_KPROBE(do_mov_82)
// {
//     u64 addr = ctx->r13+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x3e")
// int BPF_KPROBE(do_mov_83)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x4a")
// int BPF_KPROBE(do_mov_84)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x4d")
// int BPF_KPROBE(do_mov_85)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x8b")
// int BPF_KPROBE(do_mov_86)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x99")
// int BPF_KPROBE(do_mov_87)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x9d")
// int BPF_KPROBE(do_mov_88)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0xac")
// int BPF_KPROBE(do_mov_89)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0xc6")
// int BPF_KPROBE(do_mov_90)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x11c")
// int BPF_KPROBE(do_mov_91)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x120")
// int BPF_KPROBE(do_mov_92)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x12d")
// int BPF_KPROBE(do_mov_93)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x159")
// int BPF_KPROBE(do_mov_94)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_getname+0x15d")
// int BPF_KPROBE(do_mov_95)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_recvmsg+0x49")
// int BPF_KPROBE(do_mov_96)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_register_protosw+0x6a")
// int BPF_KPROBE(do_mov_97)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_register_protosw+0x6e")
// int BPF_KPROBE(do_mov_98)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_register_protosw+0x71")
// int BPF_KPROBE(do_mov_99)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_register_protosw+0x77")
// int BPF_KPROBE(do_mov_100)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x9c")
// int BPF_KPROBE(do_mov_101)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x108")
// int BPF_KPROBE(do_mov_102)
// {
//     u64 addr = ctx->r8+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x124")
// int BPF_KPROBE(do_mov_103)
// {
//     u64 addr = ctx->r8+0x328;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x13d")
// int BPF_KPROBE(do_mov_104)
// {
//     u64 addr = ctx->r8+0x204;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x14a")
// int BPF_KPROBE(do_mov_105)
// {
//     u64 addr = ctx->r8+0x2d0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x155")
// int BPF_KPROBE(do_mov_106)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x165")
// int BPF_KPROBE(do_mov_107)
// {
//     u64 addr = ctx->r8+0x2c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x180")
// int BPF_KPROBE(do_mov_108)
// {
//     u64 addr = ctx->r8+0x308;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x196")
// int BPF_KPROBE(do_mov_109)
// {
//     u64 addr = ctx->ax+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x1a7")
// int BPF_KPROBE(do_mov_110)
// {
//     u64 addr = ctx->ax+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x1c2")
// int BPF_KPROBE(do_mov_111)
// {
//     u64 addr = ctx->ax+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x1dd")
// int BPF_KPROBE(do_mov_112)
// {
//     u64 addr = ctx->r8+0x314;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x1eb")
// int BPF_KPROBE(do_mov_113)
// {
//     u64 addr = ctx->r8+0x326;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x1f5")
// int BPF_KPROBE(do_mov_114)
// {
//     u64 addr = ctx->r8+0x32a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x1fd")
// int BPF_KPROBE(do_mov_115)
// {
//     u64 addr = ctx->r8+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x201")
// int BPF_KPROBE(do_mov_116)
// {
//     u64 addr = ctx->r8+0x330;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x20c")
// int BPF_KPROBE(do_mov_117)
// {
//     u64 addr = ctx->r8+0x338;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x23e")
// int BPF_KPROBE(do_mov_118)
// {
//     u64 addr = ctx->r8+0x320;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x3bb")
// int BPF_KPROBE(do_mov_119)
// {
//     u64 addr = ctx->r8+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_create+0x3d0")
// int BPF_KPROBE(do_mov_120)
// {
//     u64 addr = ctx->r8+0x328;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rebuild_header+0x195")
// int BPF_KPROBE(do_mov_121)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rebuild_header+0x1a4")
// int BPF_KPROBE(do_mov_122)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rebuild_header+0x1ae")
// int BPF_KPROBE(do_mov_123)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rebuild_header+0x1bb")
// int BPF_KPROBE(do_mov_124)
// {
//     u64 addr = ctx->r12+0x1e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rebuild_header+0x1c9")
// int BPF_KPROBE(do_mov_125)
// {
//     u64 addr = ctx->r12+0x224;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x11")
// int BPF_KPROBE(do_mov_126)
// {
//     u64 addr = ctx->di+0x6d4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x1f")
// int BPF_KPROBE(do_mov_127)
// {
//     u64 addr = ctx->di+0x6cd;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x26")
// int BPF_KPROBE(do_mov_128)
// {
//     u64 addr = ctx->di+0x6d0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x30")
// int BPF_KPROBE(do_mov_129)
// {
//     u64 addr = ctx->di+0x6d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x37")
// int BPF_KPROBE(do_mov_130)
// {
//     u64 addr = ctx->di+0x6d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x42")
// int BPF_KPROBE(do_mov_131)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x4f")
// int BPF_KPROBE(do_mov_132)
// {
//     u64 addr = ctx->di+0x6f8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x6a")
// int BPF_KPROBE(do_mov_133)
// {
//     u64 addr = ctx->di+0x703;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x7b")
// int BPF_KPROBE(do_mov_134)
// {
//     u64 addr = ctx->di+0x710;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x8c")
// int BPF_KPROBE(do_mov_135)
// {
//     u64 addr = ctx->di+0x718;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x9d")
// int BPF_KPROBE(do_mov_136)
// {
//     u64 addr = ctx->di+0x6ce;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xa4")
// int BPF_KPROBE(do_mov_137)
// {
//     u64 addr = ctx->di+0x70b;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xab")
// int BPF_KPROBE(do_mov_138)
// {
//     u64 addr = ctx->di+0x731;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xb2")
// int BPF_KPROBE(do_mov_139)
// {
//     u64 addr = ctx->di+0x8a4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xbc")
// int BPF_KPROBE(do_mov_140)
// {
//     u64 addr = ctx->di+0x724;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xc6")
// int BPF_KPROBE(do_mov_141)
// {
//     u64 addr = ctx->di+0x728;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xd7")
// int BPF_KPROBE(do_mov_142)
// {
//     u64 addr = ctx->bx+0x1a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0xf6")
// int BPF_KPROBE(do_mov_143)
// {
//     u64 addr = ctx->bx+0x1c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x115")
// int BPF_KPROBE(do_mov_144)
// {
//     u64 addr = ctx->bx+0x180;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x15a")
// int BPF_KPROBE(do_mov_145)
// {
//     u64 addr = ctx->bx+0x1e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_net_init+0x180")
// int BPF_KPROBE(do_mov_146)
// {
//     u64 addr = ctx->bx+0x1e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_unregister_protosw+0x31")
// int BPF_KPROBE(do_mov_147)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_unregister_protosw+0x35")
// int BPF_KPROBE(do_mov_148)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_unregister_protosw+0x42")
// int BPF_KPROBE(do_mov_149)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0xce")
// int BPF_KPROBE(do_mov_150)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0xd3")
// int BPF_KPROBE(do_mov_151)
// {
//     u64 addr = ctx->r12+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0xe3")
// int BPF_KPROBE(do_mov_152)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0xec")
// int BPF_KPROBE(do_mov_153)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x17e")
// int BPF_KPROBE(do_mov_154)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x189")
// int BPF_KPROBE(do_mov_155)
// {
//     u64 addr = ctx->r12+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x193")
// int BPF_KPROBE(do_mov_156)
// {
//     u64 addr = ctx->r12+0x320;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x38f")
// int BPF_KPROBE(do_mov_157)
// {
//     u64 addr = ctx->r12+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x440")
// int BPF_KPROBE(do_mov_158)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x449")
// int BPF_KPROBE(do_mov_159)
// {
//     u64 addr = ctx->r12+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x462")
// int BPF_KPROBE(do_mov_160)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x467")
// int BPF_KPROBE(do_mov_161)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x474")
// int BPF_KPROBE(do_mov_162)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x477")
// int BPF_KPROBE(do_mov_163)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x4ee")
// int BPF_KPROBE(do_mov_164)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x4f7")
// int BPF_KPROBE(do_mov_165)
// {
//     u64 addr = ctx->r12+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x515")
// int BPF_KPROBE(do_mov_166)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x51e")
// int BPF_KPROBE(do_mov_167)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x5ee")
// int BPF_KPROBE(do_mov_168)
// {
//     u64 addr = ctx->r12+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x5fa")
// int BPF_KPROBE(do_mov_169)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x61d")
// int BPF_KPROBE(do_mov_170)
// {
//     u64 addr = ctx->r12+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x646")
// int BPF_KPROBE(do_mov_171)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x653")
// int BPF_KPROBE(do_mov_172)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x65b")
// int BPF_KPROBE(do_mov_173)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_bind+0x664")
// int BPF_KPROBE(do_mov_174)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_seq_stop+0x23")
// int BPF_KPROBE(do_mov_175)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_get_next.isra.0+0x20")
// int BPF_KPROBE(do_mov_176)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_get_next.isra.0+0x30")
// int BPF_KPROBE(do_mov_177)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_get_next.isra.0+0x80")
// int BPF_KPROBE(do_mov_178)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_get_next.isra.0+0x88")
// int BPF_KPROBE(do_mov_179)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_seq_start+0x2b")
// int BPF_KPROBE(do_mov_180)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_seq_start+0x49")
// int BPF_KPROBE(do_mov_181)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_seq_start+0x8d")
// int BPF_KPROBE(do_mov_182)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ac6_seq_start+0xa8")
// int BPF_KPROBE(do_mov_183)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x102")
// int BPF_KPROBE(do_mov_184)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x10a")
// int BPF_KPROBE(do_mov_185)
// {
//     u64 addr = ctx->r8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x12e")
// int BPF_KPROBE(do_mov_186)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x136")
// int BPF_KPROBE(do_mov_187)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x13e")
// int BPF_KPROBE(do_mov_188)
// {
//     u64 addr = ctx->r8+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x142")
// int BPF_KPROBE(do_mov_189)
// {
//     u64 addr = ctx->r8+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x14d")
// int BPF_KPROBE(do_mov_190)
// {
//     u64 addr = ctx->r8+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x155")
// int BPF_KPROBE(do_mov_191)
// {
//     u64 addr = ctx->r8+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x15e")
// int BPF_KPROBE(do_mov_192)
// {
//     u64 addr = ctx->r8+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x166")
// int BPF_KPROBE(do_mov_193)
// {
//     u64 addr = ctx->r8+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x16e")
// int BPF_KPROBE(do_mov_194)
// {
//     u64 addr = ctx->bx+0x260;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x1ea")
// int BPF_KPROBE(do_mov_195)
// {
//     u64 addr = ctx->r8+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x1ee")
// int BPF_KPROBE(do_mov_196)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x1f2")
// int BPF_KPROBE(do_mov_197)
// {
//     u64 addr =  - 0x7c90e820+ctx->r12 * 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_inc+0x1ff")
// int BPF_KPROBE(do_mov_198)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_join+0xdc")
// int BPF_KPROBE(do_mov_199)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_join+0xf3")
// int BPF_KPROBE(do_mov_200)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_join+0xf6")
// int BPF_KPROBE(do_mov_201)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_join+0x129")
// int BPF_KPROBE(do_mov_202)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_join+0x1de")
// int BPF_KPROBE(do_mov_203)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_join+0x1e2")
// int BPF_KPROBE(do_mov_204)
// {
//     u64 addr = ctx->cx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_dec+0x7e")
// int BPF_KPROBE(do_mov_205)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_dec+0x99")
// int BPF_KPROBE(do_mov_206)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_dec+0xc0")
// int BPF_KPROBE(do_mov_207)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_dec+0xc8")
// int BPF_KPROBE(do_mov_208)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_dec+0xcc")
// int BPF_KPROBE(do_mov_209)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_ac_dec+0x128")
// int BPF_KPROBE(do_mov_210)
// {
//     u64 addr = ctx->bx+0x260;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_drop+0x9f")
// int BPF_KPROBE(do_mov_211)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_ac_drop+0xfe")
// int BPF_KPROBE(do_mov_212)
// {
//     u64 addr = ctx->r15+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_ac_close+0x4b")
// int BPF_KPROBE(do_mov_213)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_ac_destroy_dev+0x22")
// int BPF_KPROBE(do_mov_214)
// {
//     u64 addr = ctx->bx+0x260;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_ac_destroy_dev+0x49")
// int BPF_KPROBE(do_mov_215)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_ac_destroy_dev+0x51")
// int BPF_KPROBE(do_mov_216)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_ac_destroy_dev+0x55")
// int BPF_KPROBE(do_mov_217)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x10")
// int BPF_KPROBE(do_mov_218)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x17")
// int BPF_KPROBE(do_mov_219)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x1a")
// int BPF_KPROBE(do_mov_220)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x22")
// int BPF_KPROBE(do_mov_221)
// {
//     u64 addr = ctx->ax+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x25")
// int BPF_KPROBE(do_mov_222)
// {
//     u64 addr = ctx->ax+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x2c")
// int BPF_KPROBE(do_mov_223)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x31")
// int BPF_KPROBE(do_mov_224)
// {
//     u64 addr = ctx->ax+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x35")
// int BPF_KPROBE(do_mov_225)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x38")
// int BPF_KPROBE(do_mov_226)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_init+0x3b")
// int BPF_KPROBE(do_mov_227)
// {
//     u64 addr = ctx->ax+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_cork_release+0x4c")
// int BPF_KPROBE(do_mov_228)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_cork_release+0x65")
// int BPF_KPROBE(do_mov_229)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_flush_pending_frames+0x30")
// int BPF_KPROBE(do_mov_230)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_flush_pending_frames+0x3a")
// int BPF_KPROBE(do_mov_231)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_flush_pending_frames+0x42")
// int BPF_KPROBE(do_mov_232)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_flush_pending_frames+0x49")
// int BPF_KPROBE(do_mov_233)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_flush_pending_frames+0x4d")
// int BPF_KPROBE(do_mov_234)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tunnel+0x12f")
// int BPF_KPROBE(do_mov_235)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tunnel+0x133")
// int BPF_KPROBE(do_mov_236)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xac")
// int BPF_KPROBE(do_mov_237)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xde")
// int BPF_KPROBE(do_mov_238)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x145")
// int BPF_KPROBE(do_mov_239)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x149")
// int BPF_KPROBE(do_mov_240)
// {
//     u64 addr = ctx->bx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x181")
// int BPF_KPROBE(do_mov_241)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x201")
// int BPF_KPROBE(do_mov_242)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x229")
// int BPF_KPROBE(do_mov_243)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_flow+0x53")
// int BPF_KPROBE(do_mov_244)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup_flow+0x58")
// int BPF_KPROBE(do_mov_245)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_lookup+0x6")
// int BPF_KPROBE(do_mov_246)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x2b")
// int BPF_KPROBE(do_mov_247)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x4a")
// int BPF_KPROBE(do_mov_248)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x6c")
// int BPF_KPROBE(do_mov_249)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x7d")
// int BPF_KPROBE(do_mov_250)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x86")
// int BPF_KPROBE(do_mov_251)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x8e")
// int BPF_KPROBE(do_mov_252)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x92")
// int BPF_KPROBE(do_mov_253)
// {
//     u64 addr = ctx->r14+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x96")
// int BPF_KPROBE(do_mov_254)
// {
//     u64 addr = ctx->r14+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0xb5")
// int BPF_KPROBE(do_mov_255)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0xc3")
// int BPF_KPROBE(do_mov_256)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0xd1")
// int BPF_KPROBE(do_mov_257)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0xf2")
// int BPF_KPROBE(do_mov_258)
// {
//     u64 addr = ctx->r15 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0xf6")
// int BPF_KPROBE(do_mov_259)
// {
//     u64 addr = ctx->r15 - 0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0xfb")
// int BPF_KPROBE(do_mov_260)
// {
//     u64 addr = ctx->r15 - 0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x100")
// int BPF_KPROBE(do_mov_261)
// {
//     u64 addr = ctx->r15 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x146")
// int BPF_KPROBE(do_mov_262)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x157")
// int BPF_KPROBE(do_mov_263)
// {
//     u64 addr = ctx->bx+0x74;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_init+0x15b")
// int BPF_KPROBE(do_mov_264)
// {
//     u64 addr = ctx->r9+ctx->ax * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x132")
// int BPF_KPROBE(do_mov_265)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1a8")
// int BPF_KPROBE(do_mov_266)
// {
//     u64 addr = ctx->dx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1af")
// int BPF_KPROBE(do_mov_267)
// {
//     u64 addr = ctx->dx+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1be")
// int BPF_KPROBE(do_mov_268)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1c5")
// int BPF_KPROBE(do_mov_269)
// {
//     u64 addr = ctx->dx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1d5")
// int BPF_KPROBE(do_mov_270)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1d9")
// int BPF_KPROBE(do_mov_271)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1e7")
// int BPF_KPROBE(do_mov_272)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1eb")
// int BPF_KPROBE(do_mov_273)
// {
//     u64 addr = ctx->dx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x1f4")
// int BPF_KPROBE(do_mov_274)
// {
//     u64 addr = ctx->r12+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x200")
// int BPF_KPROBE(do_mov_275)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x209")
// int BPF_KPROBE(do_mov_276)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x505")
// int BPF_KPROBE(do_mov_277)
// {
//     u64 addr = ctx->r12+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x518")
// int BPF_KPROBE(do_mov_278)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x549")
// int BPF_KPROBE(do_mov_279)
// {
//     u64 addr = ctx->ax+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x556")
// int BPF_KPROBE(do_mov_280)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x55a")
// int BPF_KPROBE(do_mov_281)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x55e")
// int BPF_KPROBE(do_mov_282)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_xmit+0x5ca")
// int BPF_KPROBE(do_mov_283)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_finish_output2+0x1b1")
// int BPF_KPROBE(do_mov_284)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_finish_output2+0x269")
// int BPF_KPROBE(do_mov_285)
// {
//     u64 addr = ctx->cx - 0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_finish_output2+0x26d")
// int BPF_KPROBE(do_mov_286)
// {
//     u64 addr = ctx->cx - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_finish_output2+0x2a5")
// int BPF_KPROBE(do_mov_287)
// {
//     u64 addr = ctx->r13+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_finish_output2+0x369")
// int BPF_KPROBE(do_mov_288)
// {
//     u64 addr = ctx->ax+0x188;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x54")
// int BPF_KPROBE(do_mov_289)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0xb5")
// int BPF_KPROBE(do_mov_290)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0xc1")
// int BPF_KPROBE(do_mov_291)
// {
//     u64 addr = ctx->r10+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0xd5")
// int BPF_KPROBE(do_mov_292)
// {
//     u64 addr = ctx->r10+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0xdf")
// int BPF_KPROBE(do_mov_293)
// {
//     u64 addr = ctx->r10+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x10a")
// int BPF_KPROBE(do_mov_294)
// {
//     u64 addr = ctx->r10+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x14b")
// int BPF_KPROBE(do_mov_295)
// {
//     u64 addr = ctx->r10+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x18c")
// int BPF_KPROBE(do_mov_296)
// {
//     u64 addr = ctx->r10+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x1cd")
// int BPF_KPROBE(do_mov_297)
// {
//     u64 addr = ctx->r10+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x1eb")
// int BPF_KPROBE(do_mov_298)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x1f4")
// int BPF_KPROBE(do_mov_299)
// {
//     u64 addr = ctx->cx+0x9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x23f")
// int BPF_KPROBE(do_mov_300)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x248")
// int BPF_KPROBE(do_mov_301)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x24c")
// int BPF_KPROBE(do_mov_302)
// {
//     u64 addr = ctx->bx+0x26;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x255")
// int BPF_KPROBE(do_mov_303)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x2a1")
// int BPF_KPROBE(do_mov_304)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x2ac")
// int BPF_KPROBE(do_mov_305)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x301")
// int BPF_KPROBE(do_mov_306)
// {
//     u64 addr = ctx->r10+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x367")
// int BPF_KPROBE(do_mov_307)
// {
//     u64 addr = ctx->r10+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x37b")
// int BPF_KPROBE(do_mov_308)
// {
//     u64 addr = ctx->r10+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_setup_cork+0x38f")
// int BPF_KPROBE(do_mov_309)
// {
//     u64 addr = ctx->r10+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x2a")
// int BPF_KPROBE(do_mov_310)
// {
//     u64 addr = ctx->di+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x36")
// int BPF_KPROBE(do_mov_311)
// {
//     u64 addr = ctx->di+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x43")
// int BPF_KPROBE(do_mov_312)
// {
//     u64 addr = ctx->di+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x82")
// int BPF_KPROBE(do_mov_313)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x9f")
// int BPF_KPROBE(do_mov_314)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0xaa")
// int BPF_KPROBE(do_mov_315)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0xb6")
// int BPF_KPROBE(do_mov_316)
// {
//     u64 addr = ctx->bx+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0xc4")
// int BPF_KPROBE(do_mov_317)
// {
//     u64 addr = ctx->bx+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0xe2")
// int BPF_KPROBE(do_mov_318)
// {
//     u64 addr = ctx->bx+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0xf9")
// int BPF_KPROBE(do_mov_319)
// {
//     u64 addr = ctx->bx+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x108")
// int BPF_KPROBE(do_mov_320)
// {
//     u64 addr = ctx->bx+0x86;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x147")
// int BPF_KPROBE(do_mov_321)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x152")
// int BPF_KPROBE(do_mov_322)
// {
//     u64 addr = ctx->bx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x194")
// int BPF_KPROBE(do_mov_323)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x1a2")
// int BPF_KPROBE(do_mov_324)
// {
//     u64 addr = ctx->bx+0x7f;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x1b1")
// int BPF_KPROBE(do_mov_325)
// {
//     u64 addr = ctx->bx+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x1c4")
// int BPF_KPROBE(do_mov_326)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_copy_metadata+0x1ef")
// int BPF_KPROBE(do_mov_327)
// {
//     u64 addr = ctx->bx+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0x46")
// int BPF_KPROBE(do_mov_328)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0x59")
// int BPF_KPROBE(do_mov_329)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0x69")
// int BPF_KPROBE(do_mov_330)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0x96")
// int BPF_KPROBE(do_mov_331)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0x9d")
// int BPF_KPROBE(do_mov_332)
// {
//     u64 addr = ctx->r13 - 0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0xa2")
// int BPF_KPROBE(do_mov_333)
// {
//     u64 addr = ctx->r13 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0xae")
// int BPF_KPROBE(do_mov_334)
// {
//     u64 addr = ctx->r13 - 0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0xbd")
// int BPF_KPROBE(do_mov_335)
// {
//     u64 addr = ctx->r13 - 0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0xcb")
// int BPF_KPROBE(do_mov_336)
// {
//     u64 addr = ctx->r13 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fraglist_prepare+0xed")
// int BPF_KPROBE(do_mov_337)
// {
//     u64 addr = ctx->cx+ctx->dx * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0xa9")
// int BPF_KPROBE(do_mov_338)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0xc6")
// int BPF_KPROBE(do_mov_339)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x13c")
// int BPF_KPROBE(do_mov_340)
// {
//     u64 addr = ctx->r15+ctx->ax * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x145")
// int BPF_KPROBE(do_mov_341)
// {
//     u64 addr = ctx->r8+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x14a")
// int BPF_KPROBE(do_mov_342)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x150")
// int BPF_KPROBE(do_mov_343)
// {
//     u64 addr = ctx->r8+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x181")
// int BPF_KPROBE(do_mov_344)
// {
//     u64 addr = ctx->r8+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x1ab")
// int BPF_KPROBE(do_mov_345)
// {
//     u64 addr = ctx->cx+ctx->dx * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_next+0x1cd")
// int BPF_KPROBE(do_mov_346)
// {
//     u64 addr = ctx->r8+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x248")
// int BPF_KPROBE(do_mov_347)
// {
//     u64 addr = ctx->si+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x3d9")
// int BPF_KPROBE(do_mov_348)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x3dd")
// int BPF_KPROBE(do_mov_349)
// {
//     u64 addr = ctx->si+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x3e0")
// int BPF_KPROBE(do_mov_350)
// {
//     u64 addr = ctx->si+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x41c")
// int BPF_KPROBE(do_mov_351)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x8da")
// int BPF_KPROBE(do_mov_352)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x8e2")
// int BPF_KPROBE(do_mov_353)
// {
//     u64 addr = ctx->r12+0xbc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xa96")
// int BPF_KPROBE(do_mov_354)
// {
//     u64 addr = ctx->si+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xc4a")
// int BPF_KPROBE(do_mov_355)
// {
//     u64 addr = ctx->r9+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xc55")
// int BPF_KPROBE(do_mov_356)
// {
//     u64 addr = ctx->r9+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xc87")
// int BPF_KPROBE(do_mov_357)
// {
//     u64 addr = ctx->r9+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xceb")
// int BPF_KPROBE(do_mov_358)
// {
//     u64 addr = ctx->r9+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xcf8")
// int BPF_KPROBE(do_mov_359)
// {
//     u64 addr = ctx->r9+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xd75")
// int BPF_KPROBE(do_mov_360)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xd79")
// int BPF_KPROBE(do_mov_361)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xd91")
// int BPF_KPROBE(do_mov_362)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xdf9")
// int BPF_KPROBE(do_mov_363)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xe4e")
// int BPF_KPROBE(do_mov_364)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xe5b")
// int BPF_KPROBE(do_mov_365)
// {
//     u64 addr = ctx->r9+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xe5f")
// int BPF_KPROBE(do_mov_366)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xe63")
// int BPF_KPROBE(do_mov_367)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xe79")
// int BPF_KPROBE(do_mov_368)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xede")
// int BPF_KPROBE(do_mov_369)
// {
//     u64 addr = ctx->r9+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xefc")
// int BPF_KPROBE(do_mov_370)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xf2c")
// int BPF_KPROBE(do_mov_371)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xf31")
// int BPF_KPROBE(do_mov_372)
// {
//     u64 addr = ctx->r12+0xbc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xfd1")
// int BPF_KPROBE(do_mov_373)
// {
//     u64 addr = ctx->r9+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0xfdc")
// int BPF_KPROBE(do_mov_374)
// {
//     u64 addr = ctx->r9+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x1076")
// int BPF_KPROBE(do_mov_375)
// {
//     u64 addr = ctx->cx+ctx->ax * 0x1+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_append_data.isra.0+0x10b3")
// int BPF_KPROBE(do_mov_376)
// {
//     u64 addr = ctx->si+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x120")
// int BPF_KPROBE(do_mov_377)
// {
//     u64 addr = ctx->di+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x12b")
// int BPF_KPROBE(do_mov_378)
// {
//     u64 addr = ctx->di+0x380;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x136")
// int BPF_KPROBE(do_mov_379)
// {
//     u64 addr = ctx->di+0x388;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x141")
// int BPF_KPROBE(do_mov_380)
// {
//     u64 addr = ctx->di+0x390;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x14c")
// int BPF_KPROBE(do_mov_381)
// {
//     u64 addr = ctx->di+0x398;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x157")
// int BPF_KPROBE(do_mov_382)
// {
//     u64 addr = ctx->di+0x3a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x162")
// int BPF_KPROBE(do_mov_383)
// {
//     u64 addr = ctx->di+0x3a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x16d")
// int BPF_KPROBE(do_mov_384)
// {
//     u64 addr = ctx->di+0x3b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x178")
// int BPF_KPROBE(do_mov_385)
// {
//     u64 addr = ctx->di+0x3b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x183")
// int BPF_KPROBE(do_mov_386)
// {
//     u64 addr = ctx->di+0x3c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x18e")
// int BPF_KPROBE(do_mov_387)
// {
//     u64 addr = ctx->di+0x3c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_append_data+0x199")
// int BPF_KPROBE(do_mov_388)
// {
//     u64 addr = ctx->di+0x3d0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_forward+0x328")
// int BPF_KPROBE(do_mov_389)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_forward+0x47b")
// int BPF_KPROBE(do_mov_390)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x3e3")
// int BPF_KPROBE(do_mov_391)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x402")
// int BPF_KPROBE(do_mov_392)
// {
//     u64 addr = ctx->dx+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x4d1")
// int BPF_KPROBE(do_mov_393)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x4d5")
// int BPF_KPROBE(do_mov_394)
// {
//     u64 addr = ctx->di+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x5d3")
// int BPF_KPROBE(do_mov_395)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x5e1")
// int BPF_KPROBE(do_mov_396)
// {
//     u64 addr = ctx->ax+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x6a3")
// int BPF_KPROBE(do_mov_397)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x6b4")
// int BPF_KPROBE(do_mov_398)
// {
//     u64 addr = ctx->r15+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fragment+0x75f")
// int BPF_KPROBE(do_mov_399)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_finish_output+0x2b2")
// int BPF_KPROBE(do_mov_400)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_output+0x44")
// int BPF_KPROBE(do_mov_401)
// {
//     u64 addr = ctx->dx+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_output+0x4b")
// int BPF_KPROBE(do_mov_402)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x89")
// int BPF_KPROBE(do_mov_403)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x95")
// int BPF_KPROBE(do_mov_404)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x9d")
// int BPF_KPROBE(do_mov_405)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0xa6")
// int BPF_KPROBE(do_mov_406)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0xaa")
// int BPF_KPROBE(do_mov_407)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x105")
// int BPF_KPROBE(do_mov_408)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x10f")
// int BPF_KPROBE(do_mov_409)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x116")
// int BPF_KPROBE(do_mov_410)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x11e")
// int BPF_KPROBE(do_mov_411)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x122")
// int BPF_KPROBE(do_mov_412)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x13e")
// int BPF_KPROBE(do_mov_413)
// {
//     u64 addr = ctx->dx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x151")
// int BPF_KPROBE(do_mov_414)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x175")
// int BPF_KPROBE(do_mov_415)
// {
//     u64 addr = ctx->si+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x17d")
// int BPF_KPROBE(do_mov_416)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x20b")
// int BPF_KPROBE(do_mov_417)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x220")
// int BPF_KPROBE(do_mov_418)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x2a4")
// int BPF_KPROBE(do_mov_419)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x30d")
// int BPF_KPROBE(do_mov_420)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x314")
// int BPF_KPROBE(do_mov_421)
// {
//     u64 addr = ctx->dx+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x31c")
// int BPF_KPROBE(do_mov_422)
// {
//     u64 addr = ctx->dx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x32f")
// int BPF_KPROBE(do_mov_423)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x333")
// int BPF_KPROBE(do_mov_424)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x33e")
// int BPF_KPROBE(do_mov_425)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x342")
// int BPF_KPROBE(do_mov_426)
// {
//     u64 addr = ctx->dx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x34c")
// int BPF_KPROBE(do_mov_427)
// {
//     u64 addr = ctx->r12+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x358")
// int BPF_KPROBE(do_mov_428)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x364")
// int BPF_KPROBE(do_mov_429)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x372")
// int BPF_KPROBE(do_mov_430)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x383")
// int BPF_KPROBE(do_mov_431)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x3a1")
// int BPF_KPROBE(do_mov_432)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x408")
// int BPF_KPROBE(do_mov_433)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x41d")
// int BPF_KPROBE(do_mov_434)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x58a")
// int BPF_KPROBE(do_mov_435)
// {
//     u64 addr = ctx->r12+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_make_skb+0x59d")
// int BPF_KPROBE(do_mov_436)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_make_skb+0x7a")
// int BPF_KPROBE(do_mov_437)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_make_skb+0x81")
// int BPF_KPROBE(do_mov_438)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_make_skb+0x171")
// int BPF_KPROBE(do_mov_439)
// {
//     u64 addr = ctx->bx+0x16;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv_finish+0x1e")
// int BPF_KPROBE(do_mov_440)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv_finish+0x22")
// int BPF_KPROBE(do_mov_441)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv_finish+0x29")
// int BPF_KPROBE(do_mov_442)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0xec")
// int BPF_KPROBE(do_mov_443)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x108")
// int BPF_KPROBE(do_mov_444)
// {
//     u64 addr = ctx->r14+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x192")
// int BPF_KPROBE(do_mov_445)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x195")
// int BPF_KPROBE(do_mov_446)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x199")
// int BPF_KPROBE(do_mov_447)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x1b0")
// int BPF_KPROBE(do_mov_448)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x1b4")
// int BPF_KPROBE(do_mov_449)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sublist_rcv+0x1bb")
// int BPF_KPROBE(do_mov_450)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0xa0")
// int BPF_KPROBE(do_mov_451)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0xae")
// int BPF_KPROBE(do_mov_452)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0xb7")
// int BPF_KPROBE(do_mov_453)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0xe9")
// int BPF_KPROBE(do_mov_454)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0x271")
// int BPF_KPROBE(do_mov_455)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0x27f")
// int BPF_KPROBE(do_mov_456)
// {
//     u64 addr = ctx->r12+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0x2d9")
// int BPF_KPROBE(do_mov_457)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rcv_core+0x2e2")
// int BPF_KPROBE(do_mov_458)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_list_rcv+0x60")
// int BPF_KPROBE(do_mov_459)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_list_rcv+0x63")
// int BPF_KPROBE(do_mov_460)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_list_rcv+0x67")
// int BPF_KPROBE(do_mov_461)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_list_rcv+0x88")
// int BPF_KPROBE(do_mov_462)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_list_rcv+0x8f")
// int BPF_KPROBE(do_mov_463)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_list_rcv+0x92")
// int BPF_KPROBE(do_mov_464)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_protocol_deliver_rcu+0xe5")
// int BPF_KPROBE(do_mov_465)
// {
//     u64 addr = ctx->r15+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_protocol_deliver_rcu+0x209")
// int BPF_KPROBE(do_mov_466)
// {
//     u64 addr = ctx->r15+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_protocol_deliver_rcu+0x296")
// int BPF_KPROBE(do_mov_467)
// {
//     u64 addr = ctx->r15+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_protocol_deliver_rcu+0x30b")
// int BPF_KPROBE(do_mov_468)
// {
//     u64 addr = ctx->r15+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_protocol_deliver_rcu+0x30f")
// int BPF_KPROBE(do_mov_469)
// {
//     u64 addr = ctx->r15+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_input_finish+0x21")
// int BPF_KPROBE(do_mov_470)
// {
//     u64 addr = ctx->dx+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_input_finish+0x29")
// int BPF_KPROBE(do_mov_471)
// {
//     u64 addr = ctx->dx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_isatap_ifid+0x9d")
// int BPF_KPROBE(do_mov_472)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_isatap_ifid+0xa4")
// int BPF_KPROBE(do_mov_473)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_isatap_ifid+0xa9")
// int BPF_KPROBE(do_mov_474)
// {
//     u64 addr = ctx->cx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_isatap_ifid+0xad")
// int BPF_KPROBE(do_mov_475)
// {
//     u64 addr = ctx->cx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x52")
// int BPF_KPROBE(do_mov_476)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x58")
// int BPF_KPROBE(do_mov_477)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x8f")
// int BPF_KPROBE(do_mov_478)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x95")
// int BPF_KPROBE(do_mov_479)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xab")
// int BPF_KPROBE(do_mov_480)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xb5")
// int BPF_KPROBE(do_mov_481)
// {
//     u64 addr = ctx->di+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xbf")
// int BPF_KPROBE(do_mov_482)
// {
//     u64 addr = ctx->di+0x5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xca")
// int BPF_KPROBE(do_mov_483)
// {
//     u64 addr = ctx->di+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xd2")
// int BPF_KPROBE(do_mov_484)
// {
//     u64 addr = ctx->di+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xf4")
// int BPF_KPROBE(do_mov_485)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xfb")
// int BPF_KPROBE(do_mov_486)
// {
//     u64 addr = ctx->di+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0xff")
// int BPF_KPROBE(do_mov_487)
// {
//     u64 addr = ctx->di+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x10d")
// int BPF_KPROBE(do_mov_488)
// {
//     u64 addr = ctx->di+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x160")
// int BPF_KPROBE(do_mov_489)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x167")
// int BPF_KPROBE(do_mov_490)
// {
//     u64 addr = ctx->di+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x16c")
// int BPF_KPROBE(do_mov_491)
// {
//     u64 addr = ctx->di+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x173")
// int BPF_KPROBE(do_mov_492)
// {
//     u64 addr = ctx->di+0x5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x17b")
// int BPF_KPROBE(do_mov_493)
// {
//     u64 addr = ctx->di+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x18e")
// int BPF_KPROBE(do_mov_494)
// {
//     u64 addr = ctx->di+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x199")
// int BPF_KPROBE(do_mov_495)
// {
//     u64 addr = ctx->di+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x1b9")
// int BPF_KPROBE(do_mov_496)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x1c5")
// int BPF_KPROBE(do_mov_497)
// {
//     u64 addr = ctx->di+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x1c9")
// int BPF_KPROBE(do_mov_498)
// {
//     u64 addr = ctx->di+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x1d7")
// int BPF_KPROBE(do_mov_499)
// {
//     u64 addr = ctx->di+0x5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_eui64+0x1df")
// int BPF_KPROBE(do_mov_500)
// {
//     u64 addr = ctx->di+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_leave_anycast+0x72")
// int BPF_KPROBE(do_mov_501)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_leave_anycast+0x85")
// int BPF_KPROBE(do_mov_502)
// {
//     u64 addr = ctx->r8+ctx->si * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_leave_anycast+0x98")
// int BPF_KPROBE(do_mov_503)
// {
//     u64 addr = ctx->r8+ctx->si * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_saddr_eval+0x8c")
// int BPF_KPROBE(do_mov_504)
// {
//     u64 addr = ctx->r12+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_saddr_eval+0x104")
// int BPF_KPROBE(do_mov_505)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_saddr_eval+0x1e9")
// int BPF_KPROBE(do_mov_506)
// {
//     u64 addr = ctx->r12+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_get_saddr+0x54")
// int BPF_KPROBE(do_mov_507)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_get_saddr+0x75")
// int BPF_KPROBE(do_mov_508)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_get_saddr+0x86")
// int BPF_KPROBE(do_mov_509)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_get_saddr+0x91")
// int BPF_KPROBE(do_mov_510)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_get_saddr+0xe2")
// int BPF_KPROBE(do_mov_511)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_get_saddr+0x160")
// int BPF_KPROBE(do_mov_512)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dev_get_saddr+0xc9")
// int BPF_KPROBE(do_mov_513)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dev_get_saddr+0xcc")
// int BPF_KPROBE(do_mov_514)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x119")
// int BPF_KPROBE(do_mov_515)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x124")
// int BPF_KPROBE(do_mov_516)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x12f")
// int BPF_KPROBE(do_mov_517)
// {
//     u64 addr = ctx->r12+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x13a")
// int BPF_KPROBE(do_mov_518)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x145")
// int BPF_KPROBE(do_mov_519)
// {
//     u64 addr = ctx->r12+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x150")
// int BPF_KPROBE(do_mov_520)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x15b")
// int BPF_KPROBE(do_mov_521)
// {
//     u64 addr = ctx->r12+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x166")
// int BPF_KPROBE(do_mov_522)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x177")
// int BPF_KPROBE(do_mov_523)
// {
//     u64 addr = ctx->r12+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x188")
// int BPF_KPROBE(do_mov_524)
// {
//     u64 addr = ctx->r12+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x19c")
// int BPF_KPROBE(do_mov_525)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1a7")
// int BPF_KPROBE(do_mov_526)
// {
//     u64 addr = ctx->r12+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1b8")
// int BPF_KPROBE(do_mov_527)
// {
//     u64 addr = ctx->r12+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1c9")
// int BPF_KPROBE(do_mov_528)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1d7")
// int BPF_KPROBE(do_mov_529)
// {
//     u64 addr = ctx->r12+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1e2")
// int BPF_KPROBE(do_mov_530)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1ed")
// int BPF_KPROBE(do_mov_531)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x1f8")
// int BPF_KPROBE(do_mov_532)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x203")
// int BPF_KPROBE(do_mov_533)
// {
//     u64 addr = ctx->r12+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x20e")
// int BPF_KPROBE(do_mov_534)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x219")
// int BPF_KPROBE(do_mov_535)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x224")
// int BPF_KPROBE(do_mov_536)
// {
//     u64 addr = ctx->r12+0xd4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x232")
// int BPF_KPROBE(do_mov_537)
// {
//     u64 addr = ctx->r12+0x9c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x240")
// int BPF_KPROBE(do_mov_538)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x24b")
// int BPF_KPROBE(do_mov_539)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x260")
// int BPF_KPROBE(do_mov_540)
// {
//     u64 addr = ctx->r12+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x26b")
// int BPF_KPROBE(do_mov_541)
// {
//     u64 addr = ctx->r12+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x279")
// int BPF_KPROBE(do_mov_542)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x284")
// int BPF_KPROBE(do_mov_543)
// {
//     u64 addr = ctx->r12+0x5c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x28f")
// int BPF_KPROBE(do_mov_544)
// {
//     u64 addr = ctx->r12+0x64;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x29a")
// int BPF_KPROBE(do_mov_545)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2a5")
// int BPF_KPROBE(do_mov_546)
// {
//     u64 addr = ctx->r12+0x6c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2b0")
// int BPF_KPROBE(do_mov_547)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2bb")
// int BPF_KPROBE(do_mov_548)
// {
//     u64 addr = ctx->r12+0x74;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2c6")
// int BPF_KPROBE(do_mov_549)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2d1")
// int BPF_KPROBE(do_mov_550)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2df")
// int BPF_KPROBE(do_mov_551)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2ed")
// int BPF_KPROBE(do_mov_552)
// {
//     u64 addr = ctx->r12+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x2fb")
// int BPF_KPROBE(do_mov_553)
// {
//     u64 addr = ctx->r12+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x309")
// int BPF_KPROBE(do_mov_554)
// {
//     u64 addr = ctx->r12+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x317")
// int BPF_KPROBE(do_mov_555)
// {
//     u64 addr = ctx->r12+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x325")
// int BPF_KPROBE(do_mov_556)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x333")
// int BPF_KPROBE(do_mov_557)
// {
//     u64 addr = ctx->r12+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x341")
// int BPF_KPROBE(do_mov_558)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x34f")
// int BPF_KPROBE(do_mov_559)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x35d")
// int BPF_KPROBE(do_mov_560)
// {
//     u64 addr = ctx->r12+0xbc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x36b")
// int BPF_KPROBE(do_mov_561)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x379")
// int BPF_KPROBE(do_mov_562)
// {
//     u64 addr = ctx->r12+0xc4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x387")
// int BPF_KPROBE(do_mov_563)
// {
//     u64 addr = ctx->r12+0xcc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x395")
// int BPF_KPROBE(do_mov_564)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x3a4")
// int BPF_KPROBE(do_mov_565)
// {
//     u64 addr = ctx->r12+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x3b2")
// int BPF_KPROBE(do_mov_566)
// {
//     u64 addr = ctx->r12+0xdc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x3c0")
// int BPF_KPROBE(do_mov_567)
// {
//     u64 addr = ctx->r12+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x3cf")
// int BPF_KPROBE(do_mov_568)
// {
//     u64 addr = ctx->r12+0xe4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x3dd")
// int BPF_KPROBE(do_mov_569)
// {
//     u64 addr = ctx->r12+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x46b")
// int BPF_KPROBE(do_mov_570)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifla6_attrs+0x480")
// int BPF_KPROBE(do_mov_571)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/if6_seq_next+0x2e")
// int BPF_KPROBE(do_mov_572)
// {
//     u64 addr = ctx->cx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/if6_seq_next+0x3b")
// int BPF_KPROBE(do_mov_573)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/if6_seq_next+0x68")
// int BPF_KPROBE(do_mov_574)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/if6_seq_start+0x25")
// int BPF_KPROBE(do_mov_575)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/if6_seq_start+0x84")
// int BPF_KPROBE(do_mov_576)
// {
//     u64 addr = ctx->dx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/if6_seq_start+0x8b")
// int BPF_KPROBE(do_mov_577)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_stable_address+0x164")
// int BPF_KPROBE(do_mov_578)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_stable_address+0x167")
// int BPF_KPROBE(do_mov_579)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_stable_address+0x1c4")
// int BPF_KPROBE(do_mov_580)
// {
//     u64 addr = ctx->ax - 0x7c90dfd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_stable_address+0x1d5")
// int BPF_KPROBE(do_mov_581)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_stable_address+0x26c")
// int BPF_KPROBE(do_mov_582)
// {
//     u64 addr = ctx->ax - 0x7c90dfcc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_generate_stable_address+0x27c")
// int BPF_KPROBE(do_mov_583)
// {
//     u64 addr = ctx->ax - 0x7c90dfca;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/check_cleanup_prefix_route+0x20")
// int BPF_KPROBE(do_mov_584)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/check_cleanup_prefix_route+0xcd")
// int BPF_KPROBE(do_mov_585)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_disable_policy_idev+0xa4")
// int BPF_KPROBE(do_mov_586)
// {
//     u64 addr = ctx->si+0x89;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_disable_policy_idev+0xee")
// int BPF_KPROBE(do_mov_587)
// {
//     u64 addr = ctx->di+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cleanup_prefix_route+0x63")
// int BPF_KPROBE(do_mov_588)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cleanup_prefix_route+0x67")
// int BPF_KPROBE(do_mov_589)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/modify_prefix_route+0x77")
// int BPF_KPROBE(do_mov_590)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/modify_prefix_route+0x7b")
// int BPF_KPROBE(do_mov_591)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/modify_prefix_route+0xb1")
// int BPF_KPROBE(do_mov_592)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/modify_prefix_route+0xb9")
// int BPF_KPROBE(do_mov_593)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x58")
// int BPF_KPROBE(do_mov_594)
// {
//     u64 addr = ctx->si+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0xc9")
// int BPF_KPROBE(do_mov_595)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x130")
// int BPF_KPROBE(do_mov_596)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x14f")
// int BPF_KPROBE(do_mov_597)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x171")
// int BPF_KPROBE(do_mov_598)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x193")
// int BPF_KPROBE(do_mov_599)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x1aa")
// int BPF_KPROBE(do_mov_600)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x1b3")
// int BPF_KPROBE(do_mov_601)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x1de")
// int BPF_KPROBE(do_mov_602)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0x74")
// int BPF_KPROBE(do_mov_603)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0x80")
// int BPF_KPROBE(do_mov_604)
// {
//     u64 addr = ctx->r13+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0x8b")
// int BPF_KPROBE(do_mov_605)
// {
//     u64 addr = ctx->r13+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0x94")
// int BPF_KPROBE(do_mov_606)
// {
//     u64 addr = ctx->r13+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0xa4")
// int BPF_KPROBE(do_mov_607)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0x1a9")
// int BPF_KPROBE(do_mov_608)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifinfo+0x1bf")
// int BPF_KPROBE(do_mov_609)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_ifinfo+0x130")
// int BPF_KPROBE(do_mov_610)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_ifinfo+0x134")
// int BPF_KPROBE(do_mov_611)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_ifinfo+0x15c")
// int BPF_KPROBE(do_mov_612)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_ifinfo+0x17b")
// int BPF_KPROBE(do_mov_613)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_ifinfo+0x19e")
// int BPF_KPROBE(do_mov_614)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifaddr+0xa9")
// int BPF_KPROBE(do_mov_615)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifaddr+0xae")
// int BPF_KPROBE(do_mov_616)
// {
//     u64 addr = ctx->r13+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifaddr+0xb2")
// int BPF_KPROBE(do_mov_617)
// {
//     u64 addr = ctx->r13+0x11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifaddr+0xb6")
// int BPF_KPROBE(do_mov_618)
// {
//     u64 addr = ctx->r13+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifaddr+0xba")
// int BPF_KPROBE(do_mov_619)
// {
//     u64 addr = ctx->r13+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_fill_ifaddr+0x279")
// int BPF_KPROBE(do_mov_620)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_ifa_notify+0x157")
// int BPF_KPROBE(do_mov_621)
// {
//     u64 addr = ctx->bx+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_ifa_notify+0x30d")
// int BPF_KPROBE(do_mov_622)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_ifa_notify+0x320")
// int BPF_KPROBE(do_mov_623)
// {
//     u64 addr = ctx->r8+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_ifa_notify+0x333")
// int BPF_KPROBE(do_mov_624)
// {
//     u64 addr = ctx->r8+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_stable_secret+0x182")
// int BPF_KPROBE(do_mov_625)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_stable_secret+0x190")
// int BPF_KPROBE(do_mov_626)
// {
//     u64 addr = ctx->r14+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_stable_secret+0x194")
// int BPF_KPROBE(do_mov_627)
// {
//     u64 addr = ctx->r14+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_stable_secret+0x1af")
// int BPF_KPROBE(do_mov_628)
// {
//     u64 addr = ctx->ax+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_stable_secret+0x208")
// int BPF_KPROBE(do_mov_629)
// {
//     u64 addr = ctx->dx+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_fill_devconf+0x75")
// int BPF_KPROBE(do_mov_630)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_fill_devconf+0x103")
// int BPF_KPROBE(do_mov_631)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_dump_devconf+0x93")
// int BPF_KPROBE(do_mov_632)
// {
//     u64 addr = ctx->r15+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_dump_devconf+0x11a")
// int BPF_KPROBE(do_mov_633)
// {
//     u64 addr = ctx->r15+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_dump_devconf+0x1df")
// int BPF_KPROBE(do_mov_634)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_dump_devconf+0x1e3")
// int BPF_KPROBE(do_mov_635)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_dump_devconf+0x228")
// int BPF_KPROBE(do_mov_636)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_dump_devconf+0x247")
// int BPF_KPROBE(do_mov_637)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_disable_policy+0x95")
// int BPF_KPROBE(do_mov_638)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_disable_policy+0xc4")
// int BPF_KPROBE(do_mov_639)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x79")
// int BPF_KPROBE(do_mov_640)
// {
//     u64 addr = ctx->ax+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0xab")
// int BPF_KPROBE(do_mov_641)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x14f")
// int BPF_KPROBE(do_mov_642)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x15f")
// int BPF_KPROBE(do_mov_643)
// {
//     u64 addr = ctx->r12+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x165")
// int BPF_KPROBE(do_mov_644)
// {
//     u64 addr = ctx->r12+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x16a")
// int BPF_KPROBE(do_mov_645)
// {
//     u64 addr = ctx->r12+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x211")
// int BPF_KPROBE(do_mov_646)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x28b")
// int BPF_KPROBE(do_mov_647)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x2f5")
// int BPF_KPROBE(do_mov_648)
// {
//     u64 addr = ctx->r13+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x319")
// int BPF_KPROBE(do_mov_649)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x3b5")
// int BPF_KPROBE(do_mov_650)
// {
//     u64 addr = ctx->r14+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x3c0")
// int BPF_KPROBE(do_mov_651)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x3d2")
// int BPF_KPROBE(do_mov_652)
// {
//     u64 addr = ctx->r14+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x3d6")
// int BPF_KPROBE(do_mov_653)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/in6_dump_addrs+0x478")
// int BPF_KPROBE(do_mov_654)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_addr+0xd5")
// int BPF_KPROBE(do_mov_655)
// {
//     u64 addr = ctx->r13+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_addr+0x1c8")
// int BPF_KPROBE(do_mov_656)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_addr+0x1cc")
// int BPF_KPROBE(do_mov_657)
// {
//     u64 addr = ctx->r13+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_get_devconf+0x26d")
// int BPF_KPROBE(do_mov_658)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_get_devconf+0x2fd")
// int BPF_KPROBE(do_mov_659)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_netconf_get_devconf+0x3ab")
// int BPF_KPROBE(do_mov_660)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x122")
// int BPF_KPROBE(do_mov_661)
// {
//     u64 addr = ctx->ax+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x137")
// int BPF_KPROBE(do_mov_662)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x13f")
// int BPF_KPROBE(do_mov_663)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x150")
// int BPF_KPROBE(do_mov_664)
// {
//     u64 addr = ctx->r12+0x120;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x158")
// int BPF_KPROBE(do_mov_665)
// {
//     u64 addr = ctx->r12+0x118;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x16f")
// int BPF_KPROBE(do_mov_666)
// {
//     u64 addr = ctx->r12+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x189")
// int BPF_KPROBE(do_mov_667)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x193")
// int BPF_KPROBE(do_mov_668)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x198")
// int BPF_KPROBE(do_mov_669)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1a1")
// int BPF_KPROBE(do_mov_670)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1b4")
// int BPF_KPROBE(do_mov_671)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1c0")
// int BPF_KPROBE(do_mov_672)
// {
//     u64 addr = ctx->r12+0x104;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1d0")
// int BPF_KPROBE(do_mov_673)
// {
//     u64 addr = ctx->r12+0x32;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1da")
// int BPF_KPROBE(do_mov_674)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1e6")
// int BPF_KPROBE(do_mov_675)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1ef")
// int BPF_KPROBE(do_mov_676)
// {
//     u64 addr = ctx->r12+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x1f7")
// int BPF_KPROBE(do_mov_677)
// {
//     u64 addr = ctx->r12+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x201")
// int BPF_KPROBE(do_mov_678)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x209")
// int BPF_KPROBE(do_mov_679)
// {
//     u64 addr = ctx->r12+0x105;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x21c")
// int BPF_KPROBE(do_mov_680)
// {
//     u64 addr = ctx->r12+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x225")
// int BPF_KPROBE(do_mov_681)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x22e")
// int BPF_KPROBE(do_mov_682)
// {
//     u64 addr = ctx->r12+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x23a")
// int BPF_KPROBE(do_mov_683)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x23f")
// int BPF_KPROBE(do_mov_684)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x264")
// int BPF_KPROBE(do_mov_685)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x330")
// int BPF_KPROBE(do_mov_686)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x340")
// int BPF_KPROBE(do_mov_687)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x348")
// int BPF_KPROBE(do_mov_688)
// {
//     u64 addr = ctx->r10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x354")
// int BPF_KPROBE(do_mov_689)
// {
//     u64 addr = ctx->r9+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x3cd")
// int BPF_KPROBE(do_mov_690)
// {
//     u64 addr = ctx->r12+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x3d5")
// int BPF_KPROBE(do_mov_691)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x3dd")
// int BPF_KPROBE(do_mov_692)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x3e5")
// int BPF_KPROBE(do_mov_693)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x5a6")
// int BPF_KPROBE(do_mov_694)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x5aa")
// int BPF_KPROBE(do_mov_695)
// {
//     u64 addr = ctx->r12+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x5b9")
// int BPF_KPROBE(do_mov_696)
// {
//     u64 addr = ctx->bx+0x280;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_addr+0x5c5")
// int BPF_KPROBE(do_mov_697)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__addrconf_sysctl_register+0x88")
// int BPF_KPROBE(do_mov_698)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__addrconf_sysctl_register+0x95")
// int BPF_KPROBE(do_mov_699)
// {
//     u64 addr = ctx->ax+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__addrconf_sysctl_register+0x99")
// int BPF_KPROBE(do_mov_700)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__addrconf_sysctl_register+0xc6")
// int BPF_KPROBE(do_mov_701)
// {
//     u64 addr = ctx->bx+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x66")
// int BPF_KPROBE(do_mov_702)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x71")
// int BPF_KPROBE(do_mov_703)
// {
//     u64 addr = ctx->ax+0x260;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x8e")
// int BPF_KPROBE(do_mov_704)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x93")
// int BPF_KPROBE(do_mov_705)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0xbb")
// int BPF_KPROBE(do_mov_706)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0xdd")
// int BPF_KPROBE(do_mov_707)
// {
//     u64 addr = ctx->r12+0x408;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0xe9")
// int BPF_KPROBE(do_mov_708)
// {
//     u64 addr = ctx->r12+0x2b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0xf6")
// int BPF_KPROBE(do_mov_709)
// {
//     u64 addr = ctx->r12+0x2a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x13a")
// int BPF_KPROBE(do_mov_710)
// {
//     u64 addr = ctx->r12+0x3a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x187")
// int BPF_KPROBE(do_mov_711)
// {
//     u64 addr = ctx->r12+0x3b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x1ae")
// int BPF_KPROBE(do_mov_712)
// {
//     u64 addr = ctx->r12+0x3b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x1de")
// int BPF_KPROBE(do_mov_713)
// {
//     u64 addr = ctx->r12+0x270;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x1ee")
// int BPF_KPROBE(do_mov_714)
// {
//     u64 addr = ctx->r12+0x334;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x211")
// int BPF_KPROBE(do_mov_715)
// {
//     u64 addr = ctx->r12+0x27c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x21d")
// int BPF_KPROBE(do_mov_716)
// {
//     u64 addr = ctx->r12+0x280;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x225")
// int BPF_KPROBE(do_mov_717)
// {
//     u64 addr = ctx->r12+0x288;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x235")
// int BPF_KPROBE(do_mov_718)
// {
//     u64 addr = ctx->r12+0x2e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x24f")
// int BPF_KPROBE(do_mov_719)
// {
//     u64 addr = ctx->r12+0x290;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x25b")
// int BPF_KPROBE(do_mov_720)
// {
//     u64 addr = ctx->r12+0x298;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x281")
// int BPF_KPROBE(do_mov_721)
// {
//     u64 addr = ctx->r12+0x3f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x2a6")
// int BPF_KPROBE(do_mov_722)
// {
//     u64 addr = ctx->bx+0x2f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x302")
// int BPF_KPROBE(do_mov_723)
// {
//     u64 addr = ctx->r12+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_add_dev+0x4bd")
// int BPF_KPROBE(do_mov_724)
// {
//     u64 addr = ctx->r12+0x278;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x30")
// int BPF_KPROBE(do_mov_725)
// {
//     u64 addr = ctx->di+0x830;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x45")
// int BPF_KPROBE(do_mov_726)
// {
//     u64 addr = ctx->di - 0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x49")
// int BPF_KPROBE(do_mov_727)
// {
//     u64 addr = ctx->di - 0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x50")
// int BPF_KPROBE(do_mov_728)
// {
//     u64 addr = ctx->di - 0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x54")
// int BPF_KPROBE(do_mov_729)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x77")
// int BPF_KPROBE(do_mov_730)
// {
//     u64 addr = ctx->bx+0x820;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x11d")
// int BPF_KPROBE(do_mov_731)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x134")
// int BPF_KPROBE(do_mov_732)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x13c")
// int BPF_KPROBE(do_mov_733)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x162")
// int BPF_KPROBE(do_mov_734)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x175")
// int BPF_KPROBE(do_mov_735)
// {
//     u64 addr = ctx->r14+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x17f")
// int BPF_KPROBE(do_mov_736)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x190")
// int BPF_KPROBE(do_mov_737)
// {
//     u64 addr = ctx->r14+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x19f")
// int BPF_KPROBE(do_mov_738)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x1a9")
// int BPF_KPROBE(do_mov_739)
// {
//     u64 addr = ctx->r14+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x1b0")
// int BPF_KPROBE(do_mov_740)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x1b9")
// int BPF_KPROBE(do_mov_741)
// {
//     u64 addr = ctx->bx+0x738;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x1c0")
// int BPF_KPROBE(do_mov_742)
// {
//     u64 addr = ctx->bx+0x740;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x215")
// int BPF_KPROBE(do_mov_743)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x248")
// int BPF_KPROBE(do_mov_744)
// {
//     u64 addr = ctx->bx+0x740;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x25b")
// int BPF_KPROBE(do_mov_745)
// {
//     u64 addr = ctx->bx+0x738;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x2a1")
// int BPF_KPROBE(do_mov_746)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x2b8")
// int BPF_KPROBE(do_mov_747)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_init_net+0x2c0")
// int BPF_KPROBE(do_mov_748)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown+0xce")
// int BPF_KPROBE(do_mov_749)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown+0xfb")
// int BPF_KPROBE(do_mov_750)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown+0x136")
// int BPF_KPROBE(do_mov_751)
// {
//     u64 addr = ctx->r8+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown+0x16a")
// int BPF_KPROBE(do_mov_752)
// {
//     u64 addr = ctx->ax+0x308;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x97")
// int BPF_KPROBE(do_mov_753)
// {
//     u64 addr = ctx->ax+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0xa3")
// int BPF_KPROBE(do_mov_754)
// {
//     u64 addr = ctx->ax+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0xaa")
// int BPF_KPROBE(do_mov_755)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x13b")
// int BPF_KPROBE(do_mov_756)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x14e")
// int BPF_KPROBE(do_mov_757)
// {
//     u64 addr = ctx->r9+ctx->ax * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x161")
// int BPF_KPROBE(do_mov_758)
// {
//     u64 addr = ctx->r9+ctx->ax * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x1ac")
// int BPF_KPROBE(do_mov_759)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x1b0")
// int BPF_KPROBE(do_mov_760)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x1b3")
// int BPF_KPROBE(do_mov_761)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/dev_forward_change+0x1b6")
// int BPF_KPROBE(do_mov_762)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_forward+0xcd")
// int BPF_KPROBE(do_mov_763)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_forward+0x12d")
// int BPF_KPROBE(do_mov_764)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_forward+0x138")
// int BPF_KPROBE(do_mov_765)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_forward+0x171")
// int BPF_KPROBE(do_mov_766)
// {
//     u64 addr = ctx->di+0x2a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_unregister+0x3c")
// int BPF_KPROBE(do_mov_767)
// {
//     u64 addr = ctx->bx+0x398;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_exit_net+0x2e")
// int BPF_KPROBE(do_mov_768)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_exit_net+0x76")
// int BPF_KPROBE(do_mov_769)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_exit_net+0xb4")
// int BPF_KPROBE(do_mov_770)
// {
//     u64 addr = ctx->bx+0x740;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_exit_net+0xcb")
// int BPF_KPROBE(do_mov_771)
// {
//     u64 addr = ctx->bx+0x738;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_exit_net+0x10f")
// int BPF_KPROBE(do_mov_772)
// {
//     u64 addr = ctx->bx+0x820;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_kick+0x8c")
// int BPF_KPROBE(do_mov_773)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_kick+0xa1")
// int BPF_KPROBE(do_mov_774)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_run+0x53")
// int BPF_KPROBE(do_mov_775)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x159")
// int BPF_KPROBE(do_mov_776)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x161")
// int BPF_KPROBE(do_mov_777)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x165")
// int BPF_KPROBE(do_mov_778)
// {
//     u64 addr = ctx->r13+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x24d")
// int BPF_KPROBE(do_mov_779)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x251")
// int BPF_KPROBE(do_mov_780)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x254")
// int BPF_KPROBE(do_mov_781)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x258")
// int BPF_KPROBE(do_mov_782)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x28d")
// int BPF_KPROBE(do_mov_783)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x336")
// int BPF_KPROBE(do_mov_784)
// {
//     u64 addr = ctx->ax+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x33d")
// int BPF_KPROBE(do_mov_785)
// {
//     u64 addr = ctx->ax+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x349")
// int BPF_KPROBE(do_mov_786)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x39c")
// int BPF_KPROBE(do_mov_787)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x3a0")
// int BPF_KPROBE(do_mov_788)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x3ad")
// int BPF_KPROBE(do_mov_789)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x3b5")
// int BPF_KPROBE(do_mov_790)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x3f1")
// int BPF_KPROBE(do_mov_791)
// {
//     u64 addr = ctx->r13 - 0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x43d")
// int BPF_KPROBE(do_mov_792)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x441")
// int BPF_KPROBE(do_mov_793)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x44e")
// int BPF_KPROBE(do_mov_794)
// {
//     u64 addr = ctx->r13 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x4bd")
// int BPF_KPROBE(do_mov_795)
// {
//     u64 addr = ctx->r15+0x408;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x4c8")
// int BPF_KPROBE(do_mov_796)
// {
//     u64 addr = ctx->r15+0x3f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x53e")
// int BPF_KPROBE(do_mov_797)
// {
//     u64 addr = ctx->r13 - 0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x550")
// int BPF_KPROBE(do_mov_798)
// {
//     u64 addr = ctx->r13 - 0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x55b")
// int BPF_KPROBE(do_mov_799)
// {
//     u64 addr = ctx->r13 - 0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x603")
// int BPF_KPROBE(do_mov_800)
// {
//     u64 addr = ctx->r15+0x274;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x646")
// int BPF_KPROBE(do_mov_801)
// {
//     u64 addr = ctx->r15+0x278;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x651")
// int BPF_KPROBE(do_mov_802)
// {
//     u64 addr = ctx->ax+0x2f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x680")
// int BPF_KPROBE(do_mov_803)
// {
//     u64 addr = ctx->r15+0x408;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_ifdown.isra.0+0x68b")
// int BPF_KPROBE(do_mov_804)
// {
//     u64 addr = ctx->r15+0x3f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_start+0x24")
// int BPF_KPROBE(do_mov_805)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x57")
// int BPF_KPROBE(do_mov_806)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x97")
// int BPF_KPROBE(do_mov_807)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x9f")
// int BPF_KPROBE(do_mov_808)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0xa3")
// int BPF_KPROBE(do_mov_809)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0xfb")
// int BPF_KPROBE(do_mov_810)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0xff")
// int BPF_KPROBE(do_mov_811)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x10c")
// int BPF_KPROBE(do_mov_812)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x1cf")
// int BPF_KPROBE(do_mov_813)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x1d3")
// int BPF_KPROBE(do_mov_814)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x1e8")
// int BPF_KPROBE(do_mov_815)
// {
//     u64 addr = ctx->r12+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x1f4")
// int BPF_KPROBE(do_mov_816)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_del_addr+0x220")
// int BPF_KPROBE(do_mov_817)
// {
//     u64 addr = ctx->r12+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_add_linklocal+0xc0")
// int BPF_KPROBE(do_mov_818)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_addr_gen+0xae")
// int BPF_KPROBE(do_mov_819)
// {
//     u64 addr = ctx->r12+0x350;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dev_config+0xca")
// int BPF_KPROBE(do_mov_820)
// {
//     u64 addr = ctx->di+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_addr_gen_mode+0xd2")
// int BPF_KPROBE(do_mov_821)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_addr_gen_mode+0xfe")
// int BPF_KPROBE(do_mov_822)
// {
//     u64 addr = ctx->r14+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_addr_gen_mode+0x114")
// int BPF_KPROBE(do_mov_823)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_addr_gen_mode+0x17c")
// int BPF_KPROBE(do_mov_824)
// {
//     u64 addr = ctx->dx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_addr_gen_mode+0x1aa")
// int BPF_KPROBE(do_mov_825)
// {
//     u64 addr = ctx->dx+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0xaa")
// int BPF_KPROBE(do_mov_826)
// {
//     u64 addr = ctx->r12+0x100;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0x2ad")
// int BPF_KPROBE(do_mov_827)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0x2b1")
// int BPF_KPROBE(do_mov_828)
// {
//     u64 addr = ctx->r14+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0x2bd")
// int BPF_KPROBE(do_mov_829)
// {
//     u64 addr = ctx->r14+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0x393")
// int BPF_KPROBE(do_mov_830)
// {
//     u64 addr = ctx->r13+0x27c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0x45a")
// int BPF_KPROBE(do_mov_831)
// {
//     u64 addr = ctx->r13+0x27c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_create_tempaddr.isra.0+0x4da")
// int BPF_KPROBE(do_mov_832)
// {
//     u64 addr = ctx->r13+0x2e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/manage_tempaddrs+0xe3")
// int BPF_KPROBE(do_mov_833)
// {
//     u64 addr = ctx->r14+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/manage_tempaddrs+0xf1")
// int BPF_KPROBE(do_mov_834)
// {
//     u64 addr = ctx->r14+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/manage_tempaddrs+0xf5")
// int BPF_KPROBE(do_mov_835)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/manage_tempaddrs+0x100")
// int BPF_KPROBE(do_mov_836)
// {
//     u64 addr = ctx->r14+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_verify_rtnl+0x213")
// int BPF_KPROBE(do_mov_837)
// {
//     u64 addr = ctx->r12+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_verify_rtnl+0x3ea")
// int BPF_KPROBE(do_mov_838)
// {
//     u64 addr = ctx->r12+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_verify_rtnl+0x415")
// int BPF_KPROBE(do_mov_839)
// {
//     u64 addr = ctx->r12+0x100;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_verify_rtnl+0x47f")
// int BPF_KPROBE(do_mov_840)
// {
//     u64 addr = ctx->bx+0x100;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_deladdr+0xfe")
// int BPF_KPROBE(do_mov_841)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_addr_add+0xb2")
// int BPF_KPROBE(do_mov_842)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_addr_add+0xdd")
// int BPF_KPROBE(do_mov_843)
// {
//     u64 addr = ctx->r15+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_addr_add+0xf3")
// int BPF_KPROBE(do_mov_844)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_stop+0x21")
// int BPF_KPROBE(do_mov_845)
// {
//     u64 addr = ctx->di+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_stop+0xb3")
// int BPF_KPROBE(do_mov_846)
// {
//     u64 addr = ctx->r12+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_stop+0x1bb")
// int BPF_KPROBE(do_mov_847)
// {
//     u64 addr = ctx->r12+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_lladdr+0x7a")
// int BPF_KPROBE(do_mov_848)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_lladdr+0x7f")
// int BPF_KPROBE(do_mov_849)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_rs_timer+0x91")
// int BPF_KPROBE(do_mov_850)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_rs_timer+0x121")
// int BPF_KPROBE(do_mov_851)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_completed+0x177")
// int BPF_KPROBE(do_mov_852)
// {
//     u64 addr = ctx->cx+0x3e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_completed+0x184")
// int BPF_KPROBE(do_mov_853)
// {
//     u64 addr = ctx->ax+0x3ec;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_work+0x5b")
// int BPF_KPROBE(do_mov_854)
// {
//     u64 addr = ctx->r14 - 0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_work+0x140")
// int BPF_KPROBE(do_mov_855)
// {
//     u64 addr = ctx->r14 - 0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_work+0x1f1")
// int BPF_KPROBE(do_mov_856)
// {
//     u64 addr = ctx->r14 - 0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_work+0x274")
// int BPF_KPROBE(do_mov_857)
// {
//     u64 addr = ctx->r14 - 0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_work+0x2a8")
// int BPF_KPROBE(do_mov_858)
// {
//     u64 addr = ctx->r14 - 0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_work+0x34b")
// int BPF_KPROBE(do_mov_859)
// {
//     u64 addr = ctx->r14 - 0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getaddr+0x117")
// int BPF_KPROBE(do_mov_860)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getaddr+0x3b1")
// int BPF_KPROBE(do_mov_861)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getaddr+0x3d9")
// int BPF_KPROBE(do_mov_862)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getaddr+0x408")
// int BPF_KPROBE(do_mov_863)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv_add_addr+0x107")
// int BPF_KPROBE(do_mov_864)
// {
//     u64 addr = ctx->r13+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv_add_addr+0x10f")
// int BPF_KPROBE(do_mov_865)
// {
//     u64 addr = ctx->r13+0x104;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv_add_addr+0x210")
// int BPF_KPROBE(do_mov_866)
// {
//     u64 addr = ctx->r13+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv_add_addr+0x226")
// int BPF_KPROBE(do_mov_867)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv_add_addr+0x22d")
// int BPF_KPROBE(do_mov_868)
// {
//     u64 addr = ctx->r13+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv_add_addr+0x23d")
// int BPF_KPROBE(do_mov_869)
// {
//     u64 addr = ctx->r13+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x351")
// int BPF_KPROBE(do_mov_870)
// {
//     u64 addr = ctx->r15+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x36f")
// int BPF_KPROBE(do_mov_871)
// {
//     u64 addr = ctx->r15+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x379")
// int BPF_KPROBE(do_mov_872)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x383")
// int BPF_KPROBE(do_mov_873)
// {
//     u64 addr = ctx->r15+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x38e")
// int BPF_KPROBE(do_mov_874)
// {
//     u64 addr = ctx->r15+0x105;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x3a5")
// int BPF_KPROBE(do_mov_875)
// {
//     u64 addr = ctx->r15+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x4f2")
// int BPF_KPROBE(do_mov_876)
// {
//     u64 addr = ctx->r15+0x120;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x4f9")
// int BPF_KPROBE(do_mov_877)
// {
//     u64 addr = ctx->r15+0x118;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_newaddr+0x627")
// int BPF_KPROBE(do_mov_878)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_dad_failure+0x64")
// int BPF_KPROBE(do_mov_879)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x303")
// int BPF_KPROBE(do_mov_880)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x314")
// int BPF_KPROBE(do_mov_881)
// {
//     u64 addr = ctx->r15+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x31c")
// int BPF_KPROBE(do_mov_882)
// {
//     u64 addr = ctx->r15+0x19;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x323")
// int BPF_KPROBE(do_mov_883)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x329")
// int BPF_KPROBE(do_mov_884)
// {
//     u64 addr = ctx->r15+0x1a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x335")
// int BPF_KPROBE(do_mov_885)
// {
//     u64 addr = ctx->r15+0x1a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x342")
// int BPF_KPROBE(do_mov_886)
// {
//     u64 addr = ctx->r15+0x1a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x3b9")
// int BPF_KPROBE(do_mov_887)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x47a")
// int BPF_KPROBE(do_mov_888)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_prefix_rcv+0x5ee")
// int BPF_KPROBE(do_mov_889)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_set_dstaddr+0xae")
// int BPF_KPROBE(do_mov_890)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_notify+0x134")
// int BPF_KPROBE(do_mov_891)
// {
//     u64 addr = ctx->r13+0x2b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_disable+0x8c")
// int BPF_KPROBE(do_mov_892)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_disable+0xca")
// int BPF_KPROBE(do_mov_893)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_disable+0x120")
// int BPF_KPROBE(do_mov_894)
// {
//     u64 addr = ctx->cx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/addrconf_sysctl_disable+0x151")
// int BPF_KPROBE(do_mov_895)
// {
//     u64 addr = ctx->di+0x32c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x109")
// int BPF_KPROBE(do_mov_896)
// {
//     u64 addr = ctx->r12+0x298;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x163")
// int BPF_KPROBE(do_mov_897)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x1be")
// int BPF_KPROBE(do_mov_898)
// {
//     u64 addr = ctx->r12+0x378;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x20f")
// int BPF_KPROBE(do_mov_899)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x290")
// int BPF_KPROBE(do_mov_900)
// {
//     u64 addr = ctx->r12+0x3ec;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x2c3")
// int BPF_KPROBE(do_mov_901)
// {
//     u64 addr = ctx->r12+0x3e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x37f")
// int BPF_KPROBE(do_mov_902)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x3a2")
// int BPF_KPROBE(do_mov_903)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_set_link_af+0x3c5")
// int BPF_KPROBE(do_mov_904)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_exit+0x3e")
// int BPF_KPROBE(do_mov_905)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_exit+0x47")
// int BPF_KPROBE(do_mov_906)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_exit+0x65")
// int BPF_KPROBE(do_mov_907)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_exit+0x7c")
// int BPF_KPROBE(do_mov_908)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x88")
// int BPF_KPROBE(do_mov_909)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x94")
// int BPF_KPROBE(do_mov_910)
// {
//     u64 addr = ctx->si+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x9c")
// int BPF_KPROBE(do_mov_911)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0xa8")
// int BPF_KPROBE(do_mov_912)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0xbf")
// int BPF_KPROBE(do_mov_913)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0xdd")
// int BPF_KPROBE(do_mov_914)
// {
//     u64 addr = ctx->si+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0xe5")
// int BPF_KPROBE(do_mov_915)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0xed")
// int BPF_KPROBE(do_mov_916)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0xf0")
// int BPF_KPROBE(do_mov_917)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x103")
// int BPF_KPROBE(do_mov_918)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x10f")
// int BPF_KPROBE(do_mov_919)
// {
//     u64 addr = ctx->si+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x113")
// int BPF_KPROBE(do_mov_920)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x120")
// int BPF_KPROBE(do_mov_921)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x12d")
// int BPF_KPROBE(do_mov_922)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x135")
// int BPF_KPROBE(do_mov_923)
// {
//     u64 addr = ctx->si+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x139")
// int BPF_KPROBE(do_mov_924)
// {
//     u64 addr = ctx->bx+0x8c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6addrlbl_add+0x145")
// int BPF_KPROBE(do_mov_925)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_fill.constprop.0+0x7f")
// int BPF_KPROBE(do_mov_926)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_fill.constprop.0+0x8b")
// int BPF_KPROBE(do_mov_927)
// {
//     u64 addr = ctx->bx+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_fill.constprop.0+0x93")
// int BPF_KPROBE(do_mov_928)
// {
//     u64 addr = ctx->bx+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_fill.constprop.0+0x97")
// int BPF_KPROBE(do_mov_929)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_fill.constprop.0+0x9a")
// int BPF_KPROBE(do_mov_930)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_fill.constprop.0+0xdb")
// int BPF_KPROBE(do_mov_931)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_dump+0xc2")
// int BPF_KPROBE(do_mov_932)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_dump+0x11e")
// int BPF_KPROBE(do_mov_933)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_dump+0x13d")
// int BPF_KPROBE(do_mov_934)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_dump+0x15f")
// int BPF_KPROBE(do_mov_935)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_get+0x1d9")
// int BPF_KPROBE(do_mov_936)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_get+0x251")
// int BPF_KPROBE(do_mov_937)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_get+0x278")
// int BPF_KPROBE(do_mov_938)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_get+0x29f")
// int BPF_KPROBE(do_mov_939)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0x78")
// int BPF_KPROBE(do_mov_940)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0x82")
// int BPF_KPROBE(do_mov_941)
// {
//     u64 addr = ctx->r8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xb6")
// int BPF_KPROBE(do_mov_942)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xba")
// int BPF_KPROBE(do_mov_943)
// {
//     u64 addr = ctx->r8+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xbe")
// int BPF_KPROBE(do_mov_944)
// {
//     u64 addr = ctx->r8+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xc2")
// int BPF_KPROBE(do_mov_945)
// {
//     u64 addr = ctx->r8+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xc6")
// int BPF_KPROBE(do_mov_946)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xce")
// int BPF_KPROBE(do_mov_947)
// {
//     u64 addr = ctx->r8+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_alloc+0xf7")
// int BPF_KPROBE(do_mov_948)
// {
//     u64 addr = ctx->r8+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x135")
// int BPF_KPROBE(do_mov_949)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x148")
// int BPF_KPROBE(do_mov_950)
// {
//     u64 addr = ctx->r8+ctx->di * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x15b")
// int BPF_KPROBE(do_mov_951)
// {
//     u64 addr = ctx->r8+ctx->di * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x1e1")
// int BPF_KPROBE(do_mov_952)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x1e9")
// int BPF_KPROBE(do_mov_953)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x203")
// int BPF_KPROBE(do_mov_954)
// {
//     u64 addr = ctx->dx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_newdel+0x30d")
// int BPF_KPROBE(do_mov_955)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_init+0x2a")
// int BPF_KPROBE(do_mov_956)
// {
//     u64 addr = ctx->di+0x8d0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_init+0x34")
// int BPF_KPROBE(do_mov_957)
// {
//     u64 addr = ctx->di+0x8c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_init+0xc9")
// int BPF_KPROBE(do_mov_958)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_init+0xd2")
// int BPF_KPROBE(do_mov_959)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_init+0xf0")
// int BPF_KPROBE(do_mov_960)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6addrlbl_net_init+0x107")
// int BPF_KPROBE(do_mov_961)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_find_match+0x3f")
// int BPF_KPROBE(do_mov_962)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_remove_prefsrc+0x64")
// int BPF_KPROBE(do_mov_963)
// {
//     u64 addr = ctx->bx+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_info_init+0xd")
// int BPF_KPROBE(do_mov_964)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_info_init+0x17")
// int BPF_KPROBE(do_mov_965)
// {
//     u64 addr = ctx->di+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_info_init+0x3d")
// int BPF_KPROBE(do_mov_966)
// {
//     u64 addr = ctx->dx+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_info_init+0x45")
// int BPF_KPROBE(do_mov_967)
// {
//     u64 addr = ctx->dx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pkt_drop+0x18a")
// int BPF_KPROBE(do_mov_968)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pkt_discard_out+0x19")
// int BPF_KPROBE(do_mov_969)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pkt_prohibit_out+0x1c")
// int BPF_KPROBE(do_mov_970)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_output_flags_noref+0x36")
// int BPF_KPROBE(do_mov_971)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_nh_nlmsg_size+0x24")
// int BPF_KPROBE(do_mov_972)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_gc+0xb5")
// int BPF_KPROBE(do_mov_973)
// {
//     u64 addr = ctx->bx+0x204;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_gc+0xcb")
// int BPF_KPROBE(do_mov_974)
// {
//     u64 addr = ctx->bx+0x204;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_inetpeer_exit+0x12")
// int BPF_KPROBE(do_mov_975)
// {
//     u64 addr = ctx->di+0x748;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_inetpeer_init+0x35")
// int BPF_KPROBE(do_mov_976)
// {
//     u64 addr = ctx->r12+0x748;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x37")
// int BPF_KPROBE(do_mov_977)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x49")
// int BPF_KPROBE(do_mov_978)
// {
//     u64 addr = ctx->di+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x63")
// int BPF_KPROBE(do_mov_979)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x8e")
// int BPF_KPROBE(do_mov_980)
// {
//     u64 addr = ctx->bx+0x758;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0xb4")
// int BPF_KPROBE(do_mov_981)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0xbe")
// int BPF_KPROBE(do_mov_982)
// {
//     u64 addr = ctx->ax+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0xda")
// int BPF_KPROBE(do_mov_983)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0xee")
// int BPF_KPROBE(do_mov_984)
// {
//     u64 addr = ctx->bx+0x760;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0xfe")
// int BPF_KPROBE(do_mov_985)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x120")
// int BPF_KPROBE(do_mov_986)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x132")
// int BPF_KPROBE(do_mov_987)
// {
//     u64 addr = ctx->ax+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x139")
// int BPF_KPROBE(do_mov_988)
// {
//     u64 addr = ctx->ax+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x145")
// int BPF_KPROBE(do_mov_989)
// {
//     u64 addr = ctx->bx+0x7d1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x151")
// int BPF_KPROBE(do_mov_990)
// {
//     u64 addr = ctx->bx+0x7e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x161")
// int BPF_KPROBE(do_mov_991)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x178")
// int BPF_KPROBE(do_mov_992)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x18a")
// int BPF_KPROBE(do_mov_993)
// {
//     u64 addr = ctx->ax+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x191")
// int BPF_KPROBE(do_mov_994)
// {
//     u64 addr = ctx->ax+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1a2")
// int BPF_KPROBE(do_mov_995)
// {
//     u64 addr = ctx->bx+0x7e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1b2")
// int BPF_KPROBE(do_mov_996)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1bd")
// int BPF_KPROBE(do_mov_997)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1cf")
// int BPF_KPROBE(do_mov_998)
// {
//     u64 addr = ctx->ax+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1d6")
// int BPF_KPROBE(do_mov_999)
// {
//     u64 addr = ctx->ax+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1e7")
// int BPF_KPROBE(do_mov_1000)
// {
//     u64 addr = ctx->bx+0x6a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x1f8")
// int BPF_KPROBE(do_mov_1001)
// {
//     u64 addr = ctx->bx+0x6b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x209")
// int BPF_KPROBE(do_mov_1002)
// {
//     u64 addr = ctx->bx+0x7d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x213")
// int BPF_KPROBE(do_mov_1003)
// {
//     u64 addr = ctx->bx+0x730;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x21a")
// int BPF_KPROBE(do_mov_1004)
// {
//     u64 addr = ctx->bx+0x7c4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x224")
// int BPF_KPROBE(do_mov_1005)
// {
//     u64 addr = ctx->bx+0x6b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_net_init+0x235")
// int BPF_KPROBE(do_mov_1006)
// {
//     u64 addr = ctx->bx+0x6c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__rt6_nh_dev_match+0x5")
// int BPF_KPROBE(do_mov_1007)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__rt6_find_exception_spinlock+0x40")
// int BPF_KPROBE(do_mov_1008)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__rt6_find_exception_rcu+0x40")
// int BPF_KPROBE(do_mov_1009)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x52")
// int BPF_KPROBE(do_mov_1010)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x56")
// int BPF_KPROBE(do_mov_1011)
// {
//     u64 addr = ctx->bx+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x64")
// int BPF_KPROBE(do_mov_1012)
// {
//     u64 addr = ctx->bx+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x68")
// int BPF_KPROBE(do_mov_1013)
// {
//     u64 addr = ctx->bx+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x71")
// int BPF_KPROBE(do_mov_1014)
// {
//     u64 addr = ctx->bx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x7a")
// int BPF_KPROBE(do_mov_1015)
// {
//     u64 addr = ctx->bx+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x11c")
// int BPF_KPROBE(do_mov_1016)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x120")
// int BPF_KPROBE(do_mov_1017)
// {
//     u64 addr = ctx->bx+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x12c")
// int BPF_KPROBE(do_mov_1018)
// {
//     u64 addr = ctx->bx+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x130")
// int BPF_KPROBE(do_mov_1019)
// {
//     u64 addr = ctx->bx+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x13d")
// int BPF_KPROBE(do_mov_1020)
// {
//     u64 addr = ctx->bx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_mtu_change+0x101")
// int BPF_KPROBE(do_mov_1021)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_mtu_change_route+0x20")
// int BPF_KPROBE(do_mov_1022)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_redirect_nh_match+0x8c")
// int BPF_KPROBE(do_mov_1023)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_redirect_match+0xc")
// int BPF_KPROBE(do_mov_1024)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_update_pmtu+0x44")
// int BPF_KPROBE(do_mov_1025)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_update_pmtu+0x53")
// int BPF_KPROBE(do_mov_1026)
// {
//     u64 addr = ctx->bx+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_update_pmtu+0x86")
// int BPF_KPROBE(do_mov_1027)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_update_pmtu+0x90")
// int BPF_KPROBE(do_mov_1028)
// {
//     u64 addr = ctx->bx+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_update_pmtu+0xb6")
// int BPF_KPROBE(do_mov_1029)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xbc")
// int BPF_KPROBE(do_mov_1030)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xc3")
// int BPF_KPROBE(do_mov_1031)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xc6")
// int BPF_KPROBE(do_mov_1032)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xca")
// int BPF_KPROBE(do_mov_1033)
// {
//     u64 addr = ctx->bx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xce")
// int BPF_KPROBE(do_mov_1034)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xd2")
// int BPF_KPROBE(do_mov_1035)
// {
//     u64 addr = ctx->bx+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xd6")
// int BPF_KPROBE(do_mov_1036)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xdd")
// int BPF_KPROBE(do_mov_1037)
// {
//     u64 addr = ctx->bx+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0xe4")
// int BPF_KPROBE(do_mov_1038)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x100")
// int BPF_KPROBE(do_mov_1039)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x12d")
// int BPF_KPROBE(do_mov_1040)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x16c")
// int BPF_KPROBE(do_mov_1041)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x206")
// int BPF_KPROBE(do_mov_1042)
// {
//     u64 addr = ctx->bx+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x20a")
// int BPF_KPROBE(do_mov_1043)
// {
//     u64 addr = ctx->bx+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x21d")
// int BPF_KPROBE(do_mov_1044)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x22f")
// int BPF_KPROBE(do_mov_1045)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x242")
// int BPF_KPROBE(do_mov_1046)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x24c")
// int BPF_KPROBE(do_mov_1047)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x25e")
// int BPF_KPROBE(do_mov_1048)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x273")
// int BPF_KPROBE(do_mov_1049)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x280")
// int BPF_KPROBE(do_mov_1050)
// {
//     u64 addr = ctx->bx+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x2bf")
// int BPF_KPROBE(do_mov_1051)
// {
//     u64 addr = ctx->bx+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x2d9")
// int BPF_KPROBE(do_mov_1052)
// {
//     u64 addr = ctx->bx+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x311")
// int BPF_KPROBE(do_mov_1053)
// {
//     u64 addr = ctx->bx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x342")
// int BPF_KPROBE(do_mov_1054)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x354")
// int BPF_KPROBE(do_mov_1055)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x393")
// int BPF_KPROBE(do_mov_1056)
// {
//     u64 addr = ctx->bx+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x397")
// int BPF_KPROBE(do_mov_1057)
// {
//     u64 addr = ctx->bx+0x5c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x3b1")
// int BPF_KPROBE(do_mov_1058)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x3d4")
// int BPF_KPROBE(do_mov_1059)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x3fe")
// int BPF_KPROBE(do_mov_1060)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rtm_to_fib6_config+0x421")
// int BPF_KPROBE(do_mov_1061)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_hold_safe+0x49")
// int BPF_KPROBE(do_mov_1062)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_ifdown+0x60")
// int BPF_KPROBE(do_mov_1063)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1c6")
// int BPF_KPROBE(do_mov_1064)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1ce")
// int BPF_KPROBE(do_mov_1065)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1d5")
// int BPF_KPROBE(do_mov_1066)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1d9")
// int BPF_KPROBE(do_mov_1067)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1e1")
// int BPF_KPROBE(do_mov_1068)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1e5")
// int BPF_KPROBE(do_mov_1069)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_probe+0x1f8")
// int BPF_KPROBE(do_mov_1070)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_nh_find_match+0x1e")
// int BPF_KPROBE(do_mov_1071)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_nh_find_match+0x81")
// int BPF_KPROBE(do_mov_1072)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_nh_find_match+0x8a")
// int BPF_KPROBE(do_mov_1073)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_confirm_neigh+0x10d")
// int BPF_KPROBE(do_mov_1074)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_flush_exceptions+0xaf")
// int BPF_KPROBE(do_mov_1075)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x101")
// int BPF_KPROBE(do_mov_1076)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x105")
// int BPF_KPROBE(do_mov_1077)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x110")
// int BPF_KPROBE(do_mov_1078)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x114")
// int BPF_KPROBE(do_mov_1079)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x117")
// int BPF_KPROBE(do_mov_1080)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x11f")
// int BPF_KPROBE(do_mov_1081)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_insert_exception+0x246")
// int BPF_KPROBE(do_mov_1082)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_link_failure+0x67")
// int BPF_KPROBE(do_mov_1083)
// {
//     u64 addr = ctx->dx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x2e")
// int BPF_KPROBE(do_mov_1084)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x3d")
// int BPF_KPROBE(do_mov_1085)
// {
//     u64 addr = ctx->di+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x50")
// int BPF_KPROBE(do_mov_1086)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x65")
// int BPF_KPROBE(do_mov_1087)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x86")
// int BPF_KPROBE(do_mov_1088)
// {
//     u64 addr = ctx->bx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x8f")
// int BPF_KPROBE(do_mov_1089)
// {
//     u64 addr = ctx->bx+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x98")
// int BPF_KPROBE(do_mov_1090)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0xa4")
// int BPF_KPROBE(do_mov_1091)
// {
//     u64 addr = ctx->bx+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0xed")
// int BPF_KPROBE(do_mov_1092)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0xf8")
// int BPF_KPROBE(do_mov_1093)
// {
//     u64 addr = ctx->bx+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x110")
// int BPF_KPROBE(do_mov_1094)
// {
//     u64 addr = ctx->bx+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x117")
// int BPF_KPROBE(do_mov_1095)
// {
//     u64 addr = ctx->bx+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x124")
// int BPF_KPROBE(do_mov_1096)
// {
//     u64 addr = ctx->bx+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x12a")
// int BPF_KPROBE(do_mov_1097)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x146")
// int BPF_KPROBE(do_mov_1098)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x16c")
// int BPF_KPROBE(do_mov_1099)
// {
//     u64 addr = ctx->bx+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x178")
// int BPF_KPROBE(do_mov_1100)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x184")
// int BPF_KPROBE(do_mov_1101)
// {
//     u64 addr = ctx->bx+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x199")
// int BPF_KPROBE(do_mov_1102)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x1d0")
// int BPF_KPROBE(do_mov_1103)
// {
//     u64 addr = ctx->di+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x1dc")
// int BPF_KPROBE(do_mov_1104)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x1e4")
// int BPF_KPROBE(do_mov_1105)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x1f5")
// int BPF_KPROBE(do_mov_1106)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x1f9")
// int BPF_KPROBE(do_mov_1107)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x206")
// int BPF_KPROBE(do_mov_1108)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x20e")
// int BPF_KPROBE(do_mov_1109)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x21b")
// int BPF_KPROBE(do_mov_1110)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x223")
// int BPF_KPROBE(do_mov_1111)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x243")
// int BPF_KPROBE(do_mov_1112)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_copy_init+0x24b")
// int BPF_KPROBE(do_mov_1113)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_destroy+0x74")
// int BPF_KPROBE(do_mov_1114)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_destroy+0x78")
// int BPF_KPROBE(do_mov_1115)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_destroy+0x7b")
// int BPF_KPROBE(do_mov_1116)
// {
//     u64 addr = ctx->bx+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_destroy+0x82")
// int BPF_KPROBE(do_mov_1117)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_dst_destroy+0x9a")
// int BPF_KPROBE(do_mov_1118)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0xf0")
// int BPF_KPROBE(do_mov_1119)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0xf2")
// int BPF_KPROBE(do_mov_1120)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0xf4")
// int BPF_KPROBE(do_mov_1121)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0xf8")
// int BPF_KPROBE(do_mov_1122)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0xff")
// int BPF_KPROBE(do_mov_1123)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0x10b")
// int BPF_KPROBE(do_mov_1124)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0x200")
// int BPF_KPROBE(do_mov_1125)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0x238")
// int BPF_KPROBE(do_mov_1126)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0x243")
// int BPF_KPROBE(do_mov_1127)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0x248")
// int BPF_KPROBE(do_mov_1128)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__find_rr_leaf+0x283")
// int BPF_KPROBE(do_mov_1129)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x83")
// int BPF_KPROBE(do_mov_1130)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0xc7")
// int BPF_KPROBE(do_mov_1131)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x10f")
// int BPF_KPROBE(do_mov_1132)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x127")
// int BPF_KPROBE(do_mov_1133)
// {
//     u64 addr = ctx->ax+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x136")
// int BPF_KPROBE(do_mov_1134)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x17f")
// int BPF_KPROBE(do_mov_1135)
// {
//     u64 addr = ctx->r14+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x18e")
// int BPF_KPROBE(do_mov_1136)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x1d7")
// int BPF_KPROBE(do_mov_1137)
// {
//     u64 addr = ctx->r14+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x1e6")
// int BPF_KPROBE(do_mov_1138)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_dev_notify+0x22a")
// int BPF_KPROBE(do_mov_1139)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0xb5")
// int BPF_KPROBE(do_mov_1140)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0xbd")
// int BPF_KPROBE(do_mov_1141)
// {
//     u64 addr = ctx->bx+0x11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0xc8")
// int BPF_KPROBE(do_mov_1142)
// {
//     u64 addr = ctx->bx+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0xcc")
// int BPF_KPROBE(do_mov_1143)
// {
//     u64 addr = ctx->bx+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0xec")
// int BPF_KPROBE(do_mov_1144)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x11b")
// int BPF_KPROBE(do_mov_1145)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x122")
// int BPF_KPROBE(do_mov_1146)
// {
//     u64 addr = ctx->bx+0x16;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x12b")
// int BPF_KPROBE(do_mov_1147)
// {
//     u64 addr = ctx->bx+0x17;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x137")
// int BPF_KPROBE(do_mov_1148)
// {
//     u64 addr = ctx->bx+0x15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x146")
// int BPF_KPROBE(do_mov_1149)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x16c")
// int BPF_KPROBE(do_mov_1150)
// {
//     u64 addr = ctx->bx+0x11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x198")
// int BPF_KPROBE(do_mov_1151)
// {
//     u64 addr = ctx->bx+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x319")
// int BPF_KPROBE(do_mov_1152)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x714")
// int BPF_KPROBE(do_mov_1153)
// {
//     u64 addr = ctx->bx+0x17;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x78c")
// int BPF_KPROBE(do_mov_1154)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_fill_node+0x867")
// int BPF_KPROBE(do_mov_1155)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_nh_dump_exceptions+0x4c")
// int BPF_KPROBE(do_mov_1156)
// {
//     u64 addr = ctx->r15+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_info_hw_flags_set+0x24")
// int BPF_KPROBE(do_mov_1157)
// {
//     u64 addr = ctx->r12+0x86;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_info_hw_flags_set+0x2c")
// int BPF_KPROBE(do_mov_1158)
// {
//     u64 addr = ctx->r12+0x87;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_info_hw_flags_set+0x42")
// int BPF_KPROBE(do_mov_1159)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x12b")
// int BPF_KPROBE(do_mov_1160)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x37b")
// int BPF_KPROBE(do_mov_1161)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x397")
// int BPF_KPROBE(do_mov_1162)
// {
//     u64 addr = ctx->r13+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x564")
// int BPF_KPROBE(do_mov_1163)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x596")
// int BPF_KPROBE(do_mov_1164)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x5b9")
// int BPF_KPROBE(do_mov_1165)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x5dc")
// int BPF_KPROBE(do_mov_1166)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_getroute+0x603")
// int BPF_KPROBE(do_mov_1167)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0xb1")
// int BPF_KPROBE(do_mov_1168)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0xc1")
// int BPF_KPROBE(do_mov_1169)
// {
//     u64 addr = ctx->r12+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0xcd")
// int BPF_KPROBE(do_mov_1170)
// {
//     u64 addr = ctx->r12+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0xd2")
// int BPF_KPROBE(do_mov_1171)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0x15c")
// int BPF_KPROBE(do_mov_1172)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0x189")
// int BPF_KPROBE(do_mov_1173)
// {
//     u64 addr = ctx->r12+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0x195")
// int BPF_KPROBE(do_mov_1174)
// {
//     u64 addr = ctx->r12+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_rt_cache_alloc+0x19d")
// int BPF_KPROBE(do_mov_1175)
// {
//     u64 addr = ctx->r12+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_rt_update_pmtu+0x280")
// int BPF_KPROBE(do_mov_1176)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_redirect+0x309")
// int BPF_KPROBE(do_mov_1177)
// {
//     u64 addr = ctx->r13+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_redirect+0x320")
// int BPF_KPROBE(do_mov_1178)
// {
//     u64 addr = ctx->r13+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_do_redirect+0x327")
// int BPF_KPROBE(do_mov_1179)
// {
//     u64 addr = ctx->r13+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_del+0x5ef")
// int BPF_KPROBE(do_mov_1180)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_del+0x92")
// int BPF_KPROBE(do_mov_1181)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_del+0x149")
// int BPF_KPROBE(do_mov_1182)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_rtm_delroute+0x99")
// int BPF_KPROBE(do_mov_1183)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_add+0x1e")
// int BPF_KPROBE(do_mov_1184)
// {
//     u64 addr = ctx->di+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_add+0x41")
// int BPF_KPROBE(do_mov_1185)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_add+0x46")
// int BPF_KPROBE(do_mov_1186)
// {
//     u64 addr = ctx->bx+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_add+0x4d")
// int BPF_KPROBE(do_mov_1187)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_add+0x54")
// int BPF_KPROBE(do_mov_1188)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_del+0x44")
// int BPF_KPROBE(do_mov_1189)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_del+0x48")
// int BPF_KPROBE(do_mov_1190)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_del+0x4b")
// int BPF_KPROBE(do_mov_1191)
// {
//     u64 addr = ctx->bx+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_uncached_list_del+0x52")
// int BPF_KPROBE(do_mov_1192)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_table_lookup+0x69")
// int BPF_KPROBE(do_mov_1193)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_table_lookup+0xa8")
// int BPF_KPROBE(do_mov_1194)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_table_lookup+0xac")
// int BPF_KPROBE(do_mov_1195)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_table_lookup+0xb3")
// int BPF_KPROBE(do_mov_1196)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_table_lookup+0xbe")
// int BPF_KPROBE(do_mov_1197)
// {
//     u64 addr = ctx->r13+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_table_lookup+0x1d4")
// int BPF_KPROBE(do_mov_1198)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_select_path+0x60")
// int BPF_KPROBE(do_mov_1199)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_select_path+0x10e")
// int BPF_KPROBE(do_mov_1200)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_select_path+0x114")
// int BPF_KPROBE(do_mov_1201)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_select_path+0x149")
// int BPF_KPROBE(do_mov_1202)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_select_path+0x177")
// int BPF_KPROBE(do_mov_1203)
// {
//     u64 addr = ctx->r12+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_select_path+0x1ad")
// int BPF_KPROBE(do_mov_1204)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route_lookup+0x38a")
// int BPF_KPROBE(do_mov_1205)
// {
//     u64 addr = ctx->ax+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route+0x247")
// int BPF_KPROBE(do_mov_1206)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route+0x353")
// int BPF_KPROBE(do_mov_1207)
// {
//     u64 addr = ctx->ax+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route+0x37a")
// int BPF_KPROBE(do_mov_1208)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route+0x37f")
// int BPF_KPROBE(do_mov_1209)
// {
//     u64 addr = ctx->ax+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route+0x386")
// int BPF_KPROBE(do_mov_1210)
// {
//     u64 addr = ctx->ax+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_pol_route+0x38d")
// int BPF_KPROBE(do_mov_1211)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_check_nh+0x18e")
// int BPF_KPROBE(do_mov_1212)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_check_nh+0x1dd")
// int BPF_KPROBE(do_mov_1213)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_input+0x1be")
// int BPF_KPROBE(do_mov_1214)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_input+0x1c7")
// int BPF_KPROBE(do_mov_1215)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_input+0x1f1")
// int BPF_KPROBE(do_mov_1216)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x5c")
// int BPF_KPROBE(do_mov_1217)
// {
//     u64 addr = ctx->bx+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x66")
// int BPF_KPROBE(do_mov_1218)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x6e")
// int BPF_KPROBE(do_mov_1219)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xa1")
// int BPF_KPROBE(do_mov_1220)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xa8")
// int BPF_KPROBE(do_mov_1221)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xb0")
// int BPF_KPROBE(do_mov_1222)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xb8")
// int BPF_KPROBE(do_mov_1223)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xc0")
// int BPF_KPROBE(do_mov_1224)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xc8")
// int BPF_KPROBE(do_mov_1225)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xd0")
// int BPF_KPROBE(do_mov_1226)
// {
//     u64 addr = ctx->ax+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xd8")
// int BPF_KPROBE(do_mov_1227)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0xdf")
// int BPF_KPROBE(do_mov_1228)
// {
//     u64 addr = ctx->ax+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x120")
// int BPF_KPROBE(do_mov_1229)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x13a")
// int BPF_KPROBE(do_mov_1230)
// {
//     u64 addr = ctx->bx+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x141")
// int BPF_KPROBE(do_mov_1231)
// {
//     u64 addr = ctx->bx+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x155")
// int BPF_KPROBE(do_mov_1232)
// {
//     u64 addr = ctx->bx+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x160")
// int BPF_KPROBE(do_mov_1233)
// {
//     u64 addr = ctx->bx+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x16c")
// int BPF_KPROBE(do_mov_1234)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x17b")
// int BPF_KPROBE(do_mov_1235)
// {
//     u64 addr = ctx->bx+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x189")
// int BPF_KPROBE(do_mov_1236)
// {
//     u64 addr = ctx->bx+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x198")
// int BPF_KPROBE(do_mov_1237)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_blackhole_route+0x1a7")
// int BPF_KPROBE(do_mov_1238)
// {
//     u64 addr = ctx->bx+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sk_dst_store_flow+0xa0")
// int BPF_KPROBE(do_mov_1239)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sk_dst_store_flow+0xb3")
// int BPF_KPROBE(do_mov_1240)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_sk_dst_store_flow+0xb7")
// int BPF_KPROBE(do_mov_1241)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xa1")
// int BPF_KPROBE(do_mov_1242)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xaf")
// int BPF_KPROBE(do_mov_1243)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xc0")
// int BPF_KPROBE(do_mov_1244)
// {
//     u64 addr = ctx->r12+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xc8")
// int BPF_KPROBE(do_mov_1245)
// {
//     u64 addr = ctx->r12+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xd8")
// int BPF_KPROBE(do_mov_1246)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xe0")
// int BPF_KPROBE(do_mov_1247)
// {
//     u64 addr = ctx->r12+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xe5")
// int BPF_KPROBE(do_mov_1248)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0xed")
// int BPF_KPROBE(do_mov_1249)
// {
//     u64 addr = ctx->r12+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0x11f")
// int BPF_KPROBE(do_mov_1250)
// {
//     u64 addr = ctx->ax+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0x135")
// int BPF_KPROBE(do_mov_1251)
// {
//     u64 addr = ctx->r12+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0x158")
// int BPF_KPROBE(do_mov_1252)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0x15c")
// int BPF_KPROBE(do_mov_1253)
// {
//     u64 addr = ctx->r12+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0x164")
// int BPF_KPROBE(do_mov_1254)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_dst_alloc+0x16c")
// int BPF_KPROBE(do_mov_1255)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x3e")
// int BPF_KPROBE(do_mov_1256)
// {
//     u64 addr = ctx->si+0xd;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x59")
// int BPF_KPROBE(do_mov_1257)
// {
//     u64 addr = ctx->si+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x85")
// int BPF_KPROBE(do_mov_1258)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x123")
// int BPF_KPROBE(do_mov_1259)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x134")
// int BPF_KPROBE(do_mov_1260)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x13d")
// int BPF_KPROBE(do_mov_1261)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x1ff")
// int BPF_KPROBE(do_mov_1262)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x2c7")
// int BPF_KPROBE(do_mov_1263)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x2d8")
// int BPF_KPROBE(do_mov_1264)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x2e1")
// int BPF_KPROBE(do_mov_1265)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x305")
// int BPF_KPROBE(do_mov_1266)
// {
//     u64 addr = ctx->si+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x309")
// int BPF_KPROBE(do_mov_1267)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x30d")
// int BPF_KPROBE(do_mov_1268)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x33b")
// int BPF_KPROBE(do_mov_1269)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x3bc")
// int BPF_KPROBE(do_mov_1270)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x45d")
// int BPF_KPROBE(do_mov_1271)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x531")
// int BPF_KPROBE(do_mov_1272)
// {
//     u64 addr = ctx->bx+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x535")
// int BPF_KPROBE(do_mov_1273)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x539")
// int BPF_KPROBE(do_mov_1274)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x66e")
// int BPF_KPROBE(do_mov_1275)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x6a1")
// int BPF_KPROBE(do_mov_1276)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x6d4")
// int BPF_KPROBE(do_mov_1277)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x7f5")
// int BPF_KPROBE(do_mov_1278)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x87f")
// int BPF_KPROBE(do_mov_1279)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x8b4")
// int BPF_KPROBE(do_mov_1280)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x8de")
// int BPF_KPROBE(do_mov_1281)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x90d")
// int BPF_KPROBE(do_mov_1282)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_init+0x945")
// int BPF_KPROBE(do_mov_1283)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_info_create+0x2e5")
// int BPF_KPROBE(do_mov_1284)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_info_create+0x313")
// int BPF_KPROBE(do_mov_1285)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_info_create+0x34c")
// int BPF_KPROBE(do_mov_1286)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_info_create+0x37e")
// int BPF_KPROBE(do_mov_1287)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_info_create+0x3d7")
// int BPF_KPROBE(do_mov_1288)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_info_create+0x576")
// int BPF_KPROBE(do_mov_1289)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_nh_release+0x2d")
// int BPF_KPROBE(do_mov_1290)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x1f9")
// int BPF_KPROBE(do_mov_1291)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x218")
// int BPF_KPROBE(do_mov_1292)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x21f")
// int BPF_KPROBE(do_mov_1293)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x280")
// int BPF_KPROBE(do_mov_1294)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x288")
// int BPF_KPROBE(do_mov_1295)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x2b6")
// int BPF_KPROBE(do_mov_1296)
// {
//     u64 addr = ctx->r8+ctx->r11 * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x2cc")
// int BPF_KPROBE(do_mov_1297)
// {
//     u64 addr = ctx->r8+ctx->r11 * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_route_rcv+0x2e4")
// int BPF_KPROBE(do_mov_1298)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x12d")
// int BPF_KPROBE(do_mov_1299)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x15c")
// int BPF_KPROBE(do_mov_1300)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x160")
// int BPF_KPROBE(do_mov_1301)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x167")
// int BPF_KPROBE(do_mov_1302)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x16b")
// int BPF_KPROBE(do_mov_1303)
// {
//     u64 addr = ctx->bx+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x176")
// int BPF_KPROBE(do_mov_1304)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x17d")
// int BPF_KPROBE(do_mov_1305)
// {
//     u64 addr = ctx->r14+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rt6_disable_ip+0x1f9")
// int BPF_KPROBE(do_mov_1306)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0xc4")
// int BPF_KPROBE(do_mov_1307)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x203")
// int BPF_KPROBE(do_mov_1308)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x2e2")
// int BPF_KPROBE(do_mov_1309)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x2e6")
// int BPF_KPROBE(do_mov_1310)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x2f3")
// int BPF_KPROBE(do_mov_1311)
// {
//     u64 addr = ctx->r13+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x2fa")
// int BPF_KPROBE(do_mov_1312)
// {
//     u64 addr = ctx->r13+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x371")
// int BPF_KPROBE(do_mov_1313)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x4c3")
// int BPF_KPROBE(do_mov_1314)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x50f")
// int BPF_KPROBE(do_mov_1315)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x676")
// int BPF_KPROBE(do_mov_1316)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x775")
// int BPF_KPROBE(do_mov_1317)
// {
//     u64 addr = ctx->cx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x8ae")
// int BPF_KPROBE(do_mov_1318)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x8ca")
// int BPF_KPROBE(do_mov_1319)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x8d4")
// int BPF_KPROBE(do_mov_1320)
// {
//     u64 addr = ctx->ax+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x8e0")
// int BPF_KPROBE(do_mov_1321)
// {
//     u64 addr = ctx->ax+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x8e7")
// int BPF_KPROBE(do_mov_1322)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_multipath_add+0x93c")
// int BPF_KPROBE(do_mov_1323)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x3a")
// int BPF_KPROBE(do_mov_1324)
// {
//     u64 addr = ctx->ax+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x41")
// int BPF_KPROBE(do_mov_1325)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x4c")
// int BPF_KPROBE(do_mov_1326)
// {
//     u64 addr = ctx->ax+0x108;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x5a")
// int BPF_KPROBE(do_mov_1327)
// {
//     u64 addr = ctx->ax+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x65")
// int BPF_KPROBE(do_mov_1328)
// {
//     u64 addr = ctx->ax+0x148;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x73")
// int BPF_KPROBE(do_mov_1329)
// {
//     u64 addr = ctx->ax+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x81")
// int BPF_KPROBE(do_mov_1330)
// {
//     u64 addr = ctx->ax+0x188;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x8f")
// int BPF_KPROBE(do_mov_1331)
// {
//     u64 addr = ctx->ax+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0x96")
// int BPF_KPROBE(do_mov_1332)
// {
//     u64 addr = ctx->ax+0x1c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0xa4")
// int BPF_KPROBE(do_mov_1333)
// {
//     u64 addr = ctx->ax+0x248;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0xb2")
// int BPF_KPROBE(do_mov_1334)
// {
//     u64 addr = ctx->ax+0x208;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0xb9")
// int BPF_KPROBE(do_mov_1335)
// {
//     u64 addr = ctx->ax+0x288;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_sysctl_init+0xca")
// int BPF_KPROBE(do_mov_1336)
// {
//     u64 addr = ctx->ax+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_yield+0x27")
// int BPF_KPROBE(do_mov_1337)
// {
//     u64 addr = ctx->cx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_yield+0x2b")
// int BPF_KPROBE(do_mov_1338)
// {
//     u64 addr = ctx->cx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x3b")
// int BPF_KPROBE(do_mov_1339)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x3e")
// int BPF_KPROBE(do_mov_1340)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x5a")
// int BPF_KPROBE(do_mov_1341)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x7e")
// int BPF_KPROBE(do_mov_1342)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x8e")
// int BPF_KPROBE(do_mov_1343)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x9e")
// int BPF_KPROBE(do_mov_1344)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0xa2")
// int BPF_KPROBE(do_mov_1345)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0xb7")
// int BPF_KPROBE(do_mov_1346)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0xf2")
// int BPF_KPROBE(do_mov_1347)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0xfd")
// int BPF_KPROBE(do_mov_1348)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x109")
// int BPF_KPROBE(do_mov_1349)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x115")
// int BPF_KPROBE(do_mov_1350)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x121")
// int BPF_KPROBE(do_mov_1351)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_walk_continue+0x12c")
// int BPF_KPROBE(do_mov_1352)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_node+0x1d")
// int BPF_KPROBE(do_mov_1353)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_node+0x5b")
// int BPF_KPROBE(do_mov_1354)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_node+0x65")
// int BPF_KPROBE(do_mov_1355)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_exit+0x52")
// int BPF_KPROBE(do_mov_1356)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_exit+0x56")
// int BPF_KPROBE(do_mov_1357)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_exit+0x5a")
// int BPF_KPROBE(do_mov_1358)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_exit+0x7d")
// int BPF_KPROBE(do_mov_1359)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_exit+0x85")
// int BPF_KPROBE(do_mov_1360)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_exit+0x89")
// int BPF_KPROBE(do_mov_1361)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_show+0x5e")
// int BPF_KPROBE(do_mov_1362)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_show+0x14e")
// int BPF_KPROBE(do_mov_1363)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x2a")
// int BPF_KPROBE(do_mov_1364)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x32")
// int BPF_KPROBE(do_mov_1365)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x4a")
// int BPF_KPROBE(do_mov_1366)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x55")
// int BPF_KPROBE(do_mov_1367)
// {
//     u64 addr = ctx->bx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x61")
// int BPF_KPROBE(do_mov_1368)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x65")
// int BPF_KPROBE(do_mov_1369)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x6c")
// int BPF_KPROBE(do_mov_1370)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x70")
// int BPF_KPROBE(do_mov_1371)
// {
//     u64 addr = ctx->bx+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x73")
// int BPF_KPROBE(do_mov_1372)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x87")
// int BPF_KPROBE(do_mov_1373)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x8b")
// int BPF_KPROBE(do_mov_1374)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x97")
// int BPF_KPROBE(do_mov_1375)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_setup_walk+0x9b")
// int BPF_KPROBE(do_mov_1376)
// {
//     u64 addr = ctx->r12+0x7a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_node_dump+0x70")
// int BPF_KPROBE(do_mov_1377)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x4f")
// int BPF_KPROBE(do_mov_1378)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x5a")
// int BPF_KPROBE(do_mov_1379)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x67")
// int BPF_KPROBE(do_mov_1380)
// {
//     u64 addr = ctx->ax+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x84")
// int BPF_KPROBE(do_mov_1381)
// {
//     u64 addr = ctx->ax+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x92")
// int BPF_KPROBE(do_mov_1382)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x96")
// int BPF_KPROBE(do_mov_1383)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0x99")
// int BPF_KPROBE(do_mov_1384)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_new_table+0xa1")
// int BPF_KPROBE(do_mov_1385)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_stop+0x5b")
// int BPF_KPROBE(do_mov_1386)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_stop+0x5f")
// int BPF_KPROBE(do_mov_1387)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_stop+0x6c")
// int BPF_KPROBE(do_mov_1388)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_stop+0x74")
// int BPF_KPROBE(do_mov_1389)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_tree+0x77")
// int BPF_KPROBE(do_mov_1390)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_tree+0x7b")
// int BPF_KPROBE(do_mov_1391)
// {
//     u64 addr = ctx->bx+0x7a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_tree+0xdb")
// int BPF_KPROBE(do_mov_1392)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_tree+0xdf")
// int BPF_KPROBE(do_mov_1393)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x34")
// int BPF_KPROBE(do_mov_1394)
// {
//     u64 addr = ctx->r12+0x7a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x4b")
// int BPF_KPROBE(do_mov_1395)
// {
//     u64 addr = ctx->r12+0x7b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x53")
// int BPF_KPROBE(do_mov_1396)
// {
//     u64 addr = ctx->r12+0x6c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x5f")
// int BPF_KPROBE(do_mov_1397)
// {
//     u64 addr = ctx->r12+0x7b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x6b")
// int BPF_KPROBE(do_mov_1398)
// {
//     u64 addr = ctx->r12+0x7c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x92")
// int BPF_KPROBE(do_mov_1399)
// {
//     u64 addr = ctx->r12+0x768;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0xb9")
// int BPF_KPROBE(do_mov_1400)
// {
//     u64 addr = ctx->r12+0x798;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0xe0")
// int BPF_KPROBE(do_mov_1401)
// {
//     u64 addr = ctx->r12+0x7a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0xf1")
// int BPF_KPROBE(do_mov_1402)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x10d")
// int BPF_KPROBE(do_mov_1403)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x119")
// int BPF_KPROBE(do_mov_1404)
// {
//     u64 addr = ctx->ax+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x144")
// int BPF_KPROBE(do_mov_1405)
// {
//     u64 addr = ctx->r12+0x7f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x155")
// int BPF_KPROBE(do_mov_1406)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x16c")
// int BPF_KPROBE(do_mov_1407)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x17d")
// int BPF_KPROBE(do_mov_1408)
// {
//     u64 addr = ctx->ax+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x19a")
// int BPF_KPROBE(do_mov_1409)
// {
//     u64 addr = ctx->ax+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1b4")
// int BPF_KPROBE(do_mov_1410)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1b8")
// int BPF_KPROBE(do_mov_1411)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1bb")
// int BPF_KPROBE(do_mov_1412)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1c3")
// int BPF_KPROBE(do_mov_1413)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1cf")
// int BPF_KPROBE(do_mov_1414)
// {
//     u64 addr = ctx->ax+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1e9")
// int BPF_KPROBE(do_mov_1415)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1ed")
// int BPF_KPROBE(do_mov_1416)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1f0")
// int BPF_KPROBE(do_mov_1417)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_net_init+0x1fc")
// int BPF_KPROBE(do_mov_1418)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x22")
// int BPF_KPROBE(do_mov_1419)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x33")
// int BPF_KPROBE(do_mov_1420)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x43")
// int BPF_KPROBE(do_mov_1421)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x65")
// int BPF_KPROBE(do_mov_1422)
// {
//     u64 addr = ctx->di+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x87")
// int BPF_KPROBE(do_mov_1423)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x8b")
// int BPF_KPROBE(do_mov_1424)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0x98")
// int BPF_KPROBE(do_mov_1425)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_done+0xa0")
// int BPF_KPROBE(do_mov_1426)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x51")
// int BPF_KPROBE(do_mov_1427)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x59")
// int BPF_KPROBE(do_mov_1428)
// {
//     u64 addr = ctx->r14+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x5d")
// int BPF_KPROBE(do_mov_1429)
// {
//     u64 addr = ctx->r14+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x71")
// int BPF_KPROBE(do_mov_1430)
// {
//     u64 addr = ctx->r14+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0xbc")
// int BPF_KPROBE(do_mov_1431)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0xc0")
// int BPF_KPROBE(do_mov_1432)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0xcd")
// int BPF_KPROBE(do_mov_1433)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0xd5")
// int BPF_KPROBE(do_mov_1434)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x125")
// int BPF_KPROBE(do_mov_1435)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x13d")
// int BPF_KPROBE(do_mov_1436)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x17c")
// int BPF_KPROBE(do_mov_1437)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x180")
// int BPF_KPROBE(do_mov_1438)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x18d")
// int BPF_KPROBE(do_mov_1439)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_next+0x195")
// int BPF_KPROBE(do_mov_1440)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_start+0x58")
// int BPF_KPROBE(do_mov_1441)
// {
//     u64 addr = ctx->di+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_start+0x63")
// int BPF_KPROBE(do_mov_1442)
// {
//     u64 addr = ctx->di+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_start+0x69")
// int BPF_KPROBE(do_mov_1443)
// {
//     u64 addr = ctx->di+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_route_seq_start+0x7b")
// int BPF_KPROBE(do_mov_1444)
// {
//     u64 addr = ctx->di+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x29")
// int BPF_KPROBE(do_mov_1445)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x3e")
// int BPF_KPROBE(do_mov_1446)
// {
//     u64 addr = ctx->dx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x46")
// int BPF_KPROBE(do_mov_1447)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x4d")
// int BPF_KPROBE(do_mov_1448)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x54")
// int BPF_KPROBE(do_mov_1449)
// {
//     u64 addr = ctx->bx+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x5b")
// int BPF_KPROBE(do_mov_1450)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x94")
// int BPF_KPROBE(do_mov_1451)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x9d")
// int BPF_KPROBE(do_mov_1452)
// {
//     u64 addr = ctx->bx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xa7")
// int BPF_KPROBE(do_mov_1453)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xb8")
// int BPF_KPROBE(do_mov_1454)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xcd")
// int BPF_KPROBE(do_mov_1455)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xe1")
// int BPF_KPROBE(do_mov_1456)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xe5")
// int BPF_KPROBE(do_mov_1457)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xef")
// int BPF_KPROBE(do_mov_1458)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0xf3")
// int BPF_KPROBE(do_mov_1459)
// {
//     u64 addr = ctx->r14+0x7a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x11a")
// int BPF_KPROBE(do_mov_1460)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x12b")
// int BPF_KPROBE(do_mov_1461)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x14e")
// int BPF_KPROBE(do_mov_1462)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x152")
// int BPF_KPROBE(do_mov_1463)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x15f")
// int BPF_KPROBE(do_mov_1464)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x166")
// int BPF_KPROBE(do_mov_1465)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x16f")
// int BPF_KPROBE(do_mov_1466)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x190")
// int BPF_KPROBE(do_mov_1467)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x194")
// int BPF_KPROBE(do_mov_1468)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x1a1")
// int BPF_KPROBE(do_mov_1469)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_dump_table.isra.0+0x1a8")
// int BPF_KPROBE(do_mov_1470)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x8a")
// int BPF_KPROBE(do_mov_1471)
// {
//     u64 addr = ctx->ax+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x194")
// int BPF_KPROBE(do_mov_1472)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x1a3")
// int BPF_KPROBE(do_mov_1473)
// {
//     u64 addr = ctx->r15+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x1b5")
// int BPF_KPROBE(do_mov_1474)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x1bd")
// int BPF_KPROBE(do_mov_1475)
// {
//     u64 addr = ctx->r15+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x1d3")
// int BPF_KPROBE(do_mov_1476)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x1da")
// int BPF_KPROBE(do_mov_1477)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x1fd")
// int BPF_KPROBE(do_mov_1478)
// {
//     u64 addr = ctx->r15+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x217")
// int BPF_KPROBE(do_mov_1479)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x21f")
// int BPF_KPROBE(do_mov_1480)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x274")
// int BPF_KPROBE(do_mov_1481)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x29c")
// int BPF_KPROBE(do_mov_1482)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x2b7")
// int BPF_KPROBE(do_mov_1483)
// {
//     u64 addr = ctx->r15+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x2e4")
// int BPF_KPROBE(do_mov_1484)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x2e8")
// int BPF_KPROBE(do_mov_1485)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x2eb")
// int BPF_KPROBE(do_mov_1486)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x2f3")
// int BPF_KPROBE(do_mov_1487)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x30e")
// int BPF_KPROBE(do_mov_1488)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_dump_fib+0x316")
// int BPF_KPROBE(do_mov_1489)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_purge_rt+0x88")
// int BPF_KPROBE(do_mov_1490)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_purge_rt+0x8c")
// int BPF_KPROBE(do_mov_1491)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_purge_rt+0x8f")
// int BPF_KPROBE(do_mov_1492)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_purge_rt+0x93")
// int BPF_KPROBE(do_mov_1493)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_purge_rt+0x122")
// int BPF_KPROBE(do_mov_1494)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x20b")
// int BPF_KPROBE(do_mov_1495)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x212")
// int BPF_KPROBE(do_mov_1496)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x21f")
// int BPF_KPROBE(do_mov_1497)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x223")
// int BPF_KPROBE(do_mov_1498)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x22f")
// int BPF_KPROBE(do_mov_1499)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x24f")
// int BPF_KPROBE(do_mov_1500)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x2ca")
// int BPF_KPROBE(do_mov_1501)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x2cf")
// int BPF_KPROBE(do_mov_1502)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x2db")
// int BPF_KPROBE(do_mov_1503)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x2e4")
// int BPF_KPROBE(do_mov_1504)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x2e8")
// int BPF_KPROBE(do_mov_1505)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x2f4")
// int BPF_KPROBE(do_mov_1506)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x31d")
// int BPF_KPROBE(do_mov_1507)
// {
//     u64 addr = ctx->r8+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x322")
// int BPF_KPROBE(do_mov_1508)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x329")
// int BPF_KPROBE(do_mov_1509)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x34e")
// int BPF_KPROBE(do_mov_1510)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x352")
// int BPF_KPROBE(do_mov_1511)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x357")
// int BPF_KPROBE(do_mov_1512)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x364")
// int BPF_KPROBE(do_mov_1513)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x376")
// int BPF_KPROBE(do_mov_1514)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x37a")
// int BPF_KPROBE(do_mov_1515)
// {
//     u64 addr = ctx->r8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x3a4")
// int BPF_KPROBE(do_mov_1516)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x3b1")
// int BPF_KPROBE(do_mov_1517)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x3ba")
// int BPF_KPROBE(do_mov_1518)
// {
//     u64 addr = ctx->r8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x3be")
// int BPF_KPROBE(do_mov_1519)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add_1.constprop.0+0x3c7")
// int BPF_KPROBE(do_mov_1520)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_update_sernum+0x3c")
// int BPF_KPROBE(do_mov_1521)
// {
//     u64 addr = ctx->r9+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_info_alloc+0x35")
// int BPF_KPROBE(do_mov_1522)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_info_alloc+0x39")
// int BPF_KPROBE(do_mov_1523)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_info_alloc+0x3d")
// int BPF_KPROBE(do_mov_1524)
// {
//     u64 addr = ctx->ax+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0x51")
// int BPF_KPROBE(do_mov_1525)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0x68")
// int BPF_KPROBE(do_mov_1526)
// {
//     u64 addr = ctx->r15+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xaf")
// int BPF_KPROBE(do_mov_1527)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xbf")
// int BPF_KPROBE(do_mov_1528)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xca")
// int BPF_KPROBE(do_mov_1529)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xe1")
// int BPF_KPROBE(do_mov_1530)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xe5")
// int BPF_KPROBE(do_mov_1531)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xec")
// int BPF_KPROBE(do_mov_1532)
// {
//     u64 addr = ctx->dx+0x7a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0xf3")
// int BPF_KPROBE(do_mov_1533)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0x162")
// int BPF_KPROBE(do_mov_1534)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0x166")
// int BPF_KPROBE(do_mov_1535)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0x169")
// int BPF_KPROBE(do_mov_1536)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_tables_dump+0x170")
// int BPF_KPROBE(do_mov_1537)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_metric_set+0x2d")
// int BPF_KPROBE(do_mov_1538)
// {
//     u64 addr = ctx->ax+ctx->si * 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_metric_set+0x54")
// int BPF_KPROBE(do_mov_1539)
// {
//     u64 addr = ctx->ax+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_metric_set+0x5b")
// int BPF_KPROBE(do_mov_1540)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_update_sernum_upto_root+0x3d")
// int BPF_KPROBE(do_mov_1541)
// {
//     u64 addr = ctx->ax+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_update_sernum_stub+0x52")
// int BPF_KPROBE(do_mov_1542)
// {
//     u64 addr = ctx->ax+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x276")
// int BPF_KPROBE(do_mov_1543)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x27a")
// int BPF_KPROBE(do_mov_1544)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x27f")
// int BPF_KPROBE(do_mov_1545)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x284")
// int BPF_KPROBE(do_mov_1546)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x2c6")
// int BPF_KPROBE(do_mov_1547)
// {
//     u64 addr = ctx->dx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x36c")
// int BPF_KPROBE(do_mov_1548)
// {
//     u64 addr = ctx->r8+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x631")
// int BPF_KPROBE(do_mov_1549)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x63a")
// int BPF_KPROBE(do_mov_1550)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x63f")
// int BPF_KPROBE(do_mov_1551)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x677")
// int BPF_KPROBE(do_mov_1552)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x72f")
// int BPF_KPROBE(do_mov_1553)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x732")
// int BPF_KPROBE(do_mov_1554)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x896")
// int BPF_KPROBE(do_mov_1555)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x89d")
// int BPF_KPROBE(do_mov_1556)
// {
//     u64 addr = ctx->r13+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x8d3")
// int BPF_KPROBE(do_mov_1557)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x8d7")
// int BPF_KPROBE(do_mov_1558)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0x905")
// int BPF_KPROBE(do_mov_1559)
// {
//     u64 addr = ctx->di+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xb2f")
// int BPF_KPROBE(do_mov_1560)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xc81")
// int BPF_KPROBE(do_mov_1561)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xcac")
// int BPF_KPROBE(do_mov_1562)
// {
//     u64 addr = ctx->r8+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xcce")
// int BPF_KPROBE(do_mov_1563)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xcf6")
// int BPF_KPROBE(do_mov_1564)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xcfe")
// int BPF_KPROBE(do_mov_1565)
// {
//     u64 addr = ctx->bx+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xd23")
// int BPF_KPROBE(do_mov_1566)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xe7f")
// int BPF_KPROBE(do_mov_1567)
// {
//     u64 addr = ctx->bx+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xe82")
// int BPF_KPROBE(do_mov_1568)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xf0e")
// int BPF_KPROBE(do_mov_1569)
// {
//     u64 addr = ctx->ax+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_add+0xf15")
// int BPF_KPROBE(do_mov_1570)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0xd2")
// int BPF_KPROBE(do_mov_1571)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0xd5")
// int BPF_KPROBE(do_mov_1572)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x14d")
// int BPF_KPROBE(do_mov_1573)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x154")
// int BPF_KPROBE(do_mov_1574)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x158")
// int BPF_KPROBE(do_mov_1575)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x15b")
// int BPF_KPROBE(do_mov_1576)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x15f")
// int BPF_KPROBE(do_mov_1577)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x1ab")
// int BPF_KPROBE(do_mov_1578)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x1b4")
// int BPF_KPROBE(do_mov_1579)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x316")
// int BPF_KPROBE(do_mov_1580)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x31f")
// int BPF_KPROBE(do_mov_1581)
// {
//     u64 addr = ctx->r14+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_del+0x360")
// int BPF_KPROBE(do_mov_1582)
// {
//     u64 addr = ctx->r14+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_node+0x5e")
// int BPF_KPROBE(do_mov_1583)
// {
//     u64 addr = ctx->dx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_node+0xbc")
// int BPF_KPROBE(do_mov_1584)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_node+0xee")
// int BPF_KPROBE(do_mov_1585)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_clean_node+0x151")
// int BPF_KPROBE(do_mov_1586)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_run_gc+0x79")
// int BPF_KPROBE(do_mov_1587)
// {
//     u64 addr = ctx->bx+0x7c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/compat_ipv6_mcast_join_leave+0x6c")
// int BPF_KPROBE(do_mov_1588)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mcast_join_leave+0x47")
// int BPF_KPROBE(do_mov_1589)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x80")
// int BPF_KPROBE(do_mov_1590)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xbd")
// int BPF_KPROBE(do_mov_1591)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xc4")
// int BPF_KPROBE(do_mov_1592)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xcd")
// int BPF_KPROBE(do_mov_1593)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xd7")
// int BPF_KPROBE(do_mov_1594)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xe1")
// int BPF_KPROBE(do_mov_1595)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xeb")
// int BPF_KPROBE(do_mov_1596)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xf5")
// int BPF_KPROBE(do_mov_1597)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0xff")
// int BPF_KPROBE(do_mov_1598)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x109")
// int BPF_KPROBE(do_mov_1599)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x113")
// int BPF_KPROBE(do_mov_1600)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x11d")
// int BPF_KPROBE(do_mov_1601)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x127")
// int BPF_KPROBE(do_mov_1602)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x131")
// int BPF_KPROBE(do_mov_1603)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x13b")
// int BPF_KPROBE(do_mov_1604)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x145")
// int BPF_KPROBE(do_mov_1605)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x14f")
// int BPF_KPROBE(do_mov_1606)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x159")
// int BPF_KPROBE(do_mov_1607)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x166")
// int BPF_KPROBE(do_mov_1608)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x176")
// int BPF_KPROBE(do_mov_1609)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x186")
// int BPF_KPROBE(do_mov_1610)
// {
//     u64 addr = ctx->r12+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x196")
// int BPF_KPROBE(do_mov_1611)
// {
//     u64 addr = ctx->r12+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1a6")
// int BPF_KPROBE(do_mov_1612)
// {
//     u64 addr = ctx->r12+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1b6")
// int BPF_KPROBE(do_mov_1613)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1c6")
// int BPF_KPROBE(do_mov_1614)
// {
//     u64 addr = ctx->r12+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1d6")
// int BPF_KPROBE(do_mov_1615)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1e6")
// int BPF_KPROBE(do_mov_1616)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x1f6")
// int BPF_KPROBE(do_mov_1617)
// {
//     u64 addr = ctx->r12+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x206")
// int BPF_KPROBE(do_mov_1618)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x216")
// int BPF_KPROBE(do_mov_1619)
// {
//     u64 addr = ctx->r12+0xd8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x226")
// int BPF_KPROBE(do_mov_1620)
// {
//     u64 addr = ctx->r12+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x236")
// int BPF_KPROBE(do_mov_1621)
// {
//     u64 addr = ctx->r12+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x246")
// int BPF_KPROBE(do_mov_1622)
// {
//     u64 addr = ctx->r12+0xf0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x256")
// int BPF_KPROBE(do_mov_1623)
// {
//     u64 addr = ctx->r12+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/copy_group_source_from_sockptr+0x266")
// int BPF_KPROBE(do_mov_1624)
// {
//     u64 addr = ctx->r12+0x100;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/compat_ipv6_get_msfilter+0x8c")
// int BPF_KPROBE(do_mov_1625)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/compat_ipv6_get_msfilter+0x21e")
// int BPF_KPROBE(do_mov_1626)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/compat_ipv6_get_msfilter+0x22c")
// int BPF_KPROBE(do_mov_1627)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_msfilter+0x68")
// int BPF_KPROBE(do_mov_1628)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_msfilter+0x115")
// int BPF_KPROBE(do_mov_1629)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_msfilter+0x12f")
// int BPF_KPROBE(do_mov_1630)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_msfilter+0x13b")
// int BPF_KPROBE(do_mov_1631)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_get_msfilter+0x157")
// int BPF_KPROBE(do_mov_1632)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_ra_control+0x85")
// int BPF_KPROBE(do_mov_1633)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_ra_control+0xcf")
// int BPF_KPROBE(do_mov_1634)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_ra_control+0xdf")
// int BPF_KPROBE(do_mov_1635)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_ra_control+0xe3")
// int BPF_KPROBE(do_mov_1636)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_ra_control+0xea")
// int BPF_KPROBE(do_mov_1637)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_update_options+0x57")
// int BPF_KPROBE(do_mov_1638)
// {
//     u64 addr = ctx->bx+0x188;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_update_options+0x61")
// int BPF_KPROBE(do_mov_1639)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_update_options+0x89")
// int BPF_KPROBE(do_mov_1640)
// {
//     u64 addr = ctx->di+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x32c")
// int BPF_KPROBE(do_mov_1641)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x5ac")
// int BPF_KPROBE(do_mov_1642)
// {
//     u64 addr = ctx->r9+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x5fa")
// int BPF_KPROBE(do_mov_1643)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x640")
// int BPF_KPROBE(do_mov_1644)
// {
//     u64 addr = ctx->r9+0x4f;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x66b")
// int BPF_KPROBE(do_mov_1645)
// {
//     u64 addr = ctx->r9+0x4f;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x6a1")
// int BPF_KPROBE(do_mov_1646)
// {
//     u64 addr = ctx->r9+0x4f;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x6d7")
// int BPF_KPROBE(do_mov_1647)
// {
//     u64 addr = ctx->r9+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x6fd")
// int BPF_KPROBE(do_mov_1648)
// {
//     u64 addr = ctx->r9+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x72a")
// int BPF_KPROBE(do_mov_1649)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x7bb")
// int BPF_KPROBE(do_mov_1650)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x7d9")
// int BPF_KPROBE(do_mov_1651)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x7f4")
// int BPF_KPROBE(do_mov_1652)
// {
//     u64 addr = ctx->r13+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x8c3")
// int BPF_KPROBE(do_mov_1653)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x8f1")
// int BPF_KPROBE(do_mov_1654)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x929")
// int BPF_KPROBE(do_mov_1655)
// {
//     u64 addr = ctx->r9+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x959")
// int BPF_KPROBE(do_mov_1656)
// {
//     u64 addr = ctx->r9+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x9ad")
// int BPF_KPROBE(do_mov_1657)
// {
//     u64 addr = ctx->r9+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x9df")
// int BPF_KPROBE(do_mov_1658)
// {
//     u64 addr = ctx->r9+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xa5d")
// int BPF_KPROBE(do_mov_1659)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xa85")
// int BPF_KPROBE(do_mov_1660)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xab2")
// int BPF_KPROBE(do_mov_1661)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xae1")
// int BPF_KPROBE(do_mov_1662)
// {
//     u64 addr = ctx->r12+0x328;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xb06")
// int BPF_KPROBE(do_mov_1663)
// {
//     u64 addr = ctx->r9+0x4f;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xb31")
// int BPF_KPROBE(do_mov_1664)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xb8e")
// int BPF_KPROBE(do_mov_1665)
// {
//     u64 addr = ctx->r9+0x51;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xb94")
// int BPF_KPROBE(do_mov_1666)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xb9a")
// int BPF_KPROBE(do_mov_1667)
// {
//     u64 addr = ctx->r12+0x188;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xbd6")
// int BPF_KPROBE(do_mov_1668)
// {
//     u64 addr = ctx->r9+0x4f;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xc61")
// int BPF_KPROBE(do_mov_1669)
// {
//     u64 addr = ctx->r9+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xc88")
// int BPF_KPROBE(do_mov_1670)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xcb2")
// int BPF_KPROBE(do_mov_1671)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xd02")
// int BPF_KPROBE(do_mov_1672)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xd29")
// int BPF_KPROBE(do_mov_1673)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xd4a")
// int BPF_KPROBE(do_mov_1674)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xd72")
// int BPF_KPROBE(do_mov_1675)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xd99")
// int BPF_KPROBE(do_mov_1676)
// {
//     u64 addr = ctx->r9+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xdbb")
// int BPF_KPROBE(do_mov_1677)
// {
//     u64 addr = ctx->r9+0x4d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xde2")
// int BPF_KPROBE(do_mov_1678)
// {
//     u64 addr = ctx->r9+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xe2e")
// int BPF_KPROBE(do_mov_1679)
// {
//     u64 addr = ctx->r12+0x13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0xe67")
// int BPF_KPROBE(do_mov_1680)
// {
//     u64 addr = ctx->r12+0x328;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x1077")
// int BPF_KPROBE(do_mov_1681)
// {
//     u64 addr = ctx->cx+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x10ce")
// int BPF_KPROBE(do_mov_1682)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x10d9")
// int BPF_KPROBE(do_mov_1683)
// {
//     u64 addr = ctx->r15+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x10ee")
// int BPF_KPROBE(do_mov_1684)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x1195")
// int BPF_KPROBE(do_mov_1685)
// {
//     u64 addr = ctx->r9+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x11ac")
// int BPF_KPROBE(do_mov_1686)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x11b0")
// int BPF_KPROBE(do_mov_1687)
// {
//     u64 addr = ctx->r9+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x11fb")
// int BPF_KPROBE(do_mov_1688)
// {
//     u64 addr = ctx->r9+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x14b9")
// int BPF_KPROBE(do_mov_1689)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x14c4")
// int BPF_KPROBE(do_mov_1690)
// {
//     u64 addr = ctx->r15+ctx->ax * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x14e1")
// int BPF_KPROBE(do_mov_1691)
// {
//     u64 addr = ctx->r15+ctx->ax * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x1572")
// int BPF_KPROBE(do_mov_1692)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x157f")
// int BPF_KPROBE(do_mov_1693)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x1587")
// int BPF_KPROBE(do_mov_1694)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x158f")
// int BPF_KPROBE(do_mov_1695)
// {
//     u64 addr = ctx->r9+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x15f1")
// int BPF_KPROBE(do_mov_1696)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x15fa")
// int BPF_KPROBE(do_mov_1697)
// {
//     u64 addr = ctx->r12+0x4a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x1606")
// int BPF_KPROBE(do_mov_1698)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_setsockopt+0x1616")
// int BPF_KPROBE(do_mov_1699)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0x1ac")
// int BPF_KPROBE(do_mov_1700)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0x1e6")
// int BPF_KPROBE(do_mov_1701)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0x22e")
// int BPF_KPROBE(do_mov_1702)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0x59c")
// int BPF_KPROBE(do_mov_1703)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0x7ce")
// int BPF_KPROBE(do_mov_1704)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0xa0d")
// int BPF_KPROBE(do_mov_1705)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0xa15")
// int BPF_KPROBE(do_mov_1706)
// {
//     u64 addr = ctx->r14+ctx->r10 * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0xa27")
// int BPF_KPROBE(do_mov_1707)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0xcf2")
// int BPF_KPROBE(do_mov_1708)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0xcfa")
// int BPF_KPROBE(do_mov_1709)
// {
//     u64 addr = ctx->r14+ctx->r10 * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/do_ipv6_getsockopt+0xd0a")
// int BPF_KPROBE(do_mov_1710)
// {
//     u64 addr = ctx->r14+ctx->r10 * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x61")
// int BPF_KPROBE(do_mov_1711)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x6d")
// int BPF_KPROBE(do_mov_1712)
// {
//     u64 addr = ctx->r8+ctx->ax * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0xbb")
// int BPF_KPROBE(do_mov_1713)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0xd6")
// int BPF_KPROBE(do_mov_1714)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0xdd")
// int BPF_KPROBE(do_mov_1715)
// {
//     u64 addr = ctx->r8+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0xe5")
// int BPF_KPROBE(do_mov_1716)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0xf3")
// int BPF_KPROBE(do_mov_1717)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0xf9")
// int BPF_KPROBE(do_mov_1718)
// {
//     u64 addr = ctx->si+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x103")
// int BPF_KPROBE(do_mov_1719)
// {
//     u64 addr = ctx->si+0x5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x10b")
// int BPF_KPROBE(do_mov_1720)
// {
//     u64 addr = ctx->si+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x116")
// int BPF_KPROBE(do_mov_1721)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x120")
// int BPF_KPROBE(do_mov_1722)
// {
//     u64 addr = ctx->si+0x9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x127")
// int BPF_KPROBE(do_mov_1723)
// {
//     u64 addr = ctx->si+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x12f")
// int BPF_KPROBE(do_mov_1724)
// {
//     u64 addr = ctx->si+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x13d")
// int BPF_KPROBE(do_mov_1725)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x152")
// int BPF_KPROBE(do_mov_1726)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x15a")
// int BPF_KPROBE(do_mov_1727)
// {
//     u64 addr = ctx->r8+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x172")
// int BPF_KPROBE(do_mov_1728)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x187")
// int BPF_KPROBE(do_mov_1729)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_mc_map+0x18e")
// int BPF_KPROBE(do_mov_1730)
// {
//     u64 addr = ctx->r8+ctx->ax * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ndisc_fill_addr_option+0x47")
// int BPF_KPROBE(do_mov_1731)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ndisc_fill_addr_option+0x54")
// int BPF_KPROBE(do_mov_1732)
// {
//     u64 addr = ctx->bx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_alloc_skb+0x61")
// int BPF_KPROBE(do_mov_1733)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_alloc_skb+0x6c")
// int BPF_KPROBE(do_mov_1734)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_alloc_skb+0x8b")
// int BPF_KPROBE(do_mov_1735)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_alloc_skb+0x9b")
// int BPF_KPROBE(do_mov_1736)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_net_init+0x4c")
// int BPF_KPROBE(do_mov_1737)
// {
//     u64 addr = ctx->bx+0x800;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_net_init+0x77")
// int BPF_KPROBE(do_mov_1738)
// {
//     u64 addr = ctx->dx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_allow_add+0x46")
// int BPF_KPROBE(do_mov_1739)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0xb4")
// int BPF_KPROBE(do_mov_1740)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0xcd")
// int BPF_KPROBE(do_mov_1741)
// {
//     u64 addr = ctx->r15+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x108")
// int BPF_KPROBE(do_mov_1742)
// {
//     u64 addr = ctx->r11+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x192")
// int BPF_KPROBE(do_mov_1743)
// {
//     u64 addr = ctx->r15+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1a4")
// int BPF_KPROBE(do_mov_1744)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1aa")
// int BPF_KPROBE(do_mov_1745)
// {
//     u64 addr = ctx->ax+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1b2")
// int BPF_KPROBE(do_mov_1746)
// {
//     u64 addr = ctx->ax+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1b5")
// int BPF_KPROBE(do_mov_1747)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1c1")
// int BPF_KPROBE(do_mov_1748)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1c5")
// int BPF_KPROBE(do_mov_1749)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1d2")
// int BPF_KPROBE(do_mov_1750)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_skb+0x1d6")
// int BPF_KPROBE(do_mov_1751)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0x8b")
// int BPF_KPROBE(do_mov_1752)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0x92")
// int BPF_KPROBE(do_mov_1753)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0x95")
// int BPF_KPROBE(do_mov_1754)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0x99")
// int BPF_KPROBE(do_mov_1755)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0xcb")
// int BPF_KPROBE(do_mov_1756)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0xd2")
// int BPF_KPROBE(do_mov_1757)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_ns_create+0xda")
// int BPF_KPROBE(do_mov_1758)
// {
//     u64 addr = ctx->ax+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0xb4")
// int BPF_KPROBE(do_mov_1759)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0xc5")
// int BPF_KPROBE(do_mov_1760)
// {
//     u64 addr = ctx->bx+0x85;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0xec")
// int BPF_KPROBE(do_mov_1761)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x12f")
// int BPF_KPROBE(do_mov_1762)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x154")
// int BPF_KPROBE(do_mov_1763)
// {
//     u64 addr = ctx->bx+0x85;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x16a")
// int BPF_KPROBE(do_mov_1764)
// {
//     u64 addr = ctx->bx+0x85;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x17f")
// int BPF_KPROBE(do_mov_1765)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x18d")
// int BPF_KPROBE(do_mov_1766)
// {
//     u64 addr = ctx->bx+0x150;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x198")
// int BPF_KPROBE(do_mov_1767)
// {
//     u64 addr = ctx->bx+0x148;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x1e2")
// int BPF_KPROBE(do_mov_1768)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x22a")
// int BPF_KPROBE(do_mov_1769)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x23c")
// int BPF_KPROBE(do_mov_1770)
// {
//     u64 addr = ctx->ax+ctx->r13 * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x26a")
// int BPF_KPROBE(do_mov_1771)
// {
//     u64 addr = ctx->bx+0x150;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x27e")
// int BPF_KPROBE(do_mov_1772)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x2b2")
// int BPF_KPROBE(do_mov_1773)
// {
//     u64 addr = ctx->bx+0x150;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x2d8")
// int BPF_KPROBE(do_mov_1774)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x2e4")
// int BPF_KPROBE(do_mov_1775)
// {
//     u64 addr = ctx->r15+ctx->r13 * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x2f7")
// int BPF_KPROBE(do_mov_1776)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x377")
// int BPF_KPROBE(do_mov_1777)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x383")
// int BPF_KPROBE(do_mov_1778)
// {
//     u64 addr = ctx->ax+ctx->r13 * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x396")
// int BPF_KPROBE(do_mov_1779)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x3d4")
// int BPF_KPROBE(do_mov_1780)
// {
//     u64 addr = ctx->bx+0x150;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x42b")
// int BPF_KPROBE(do_mov_1781)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x436")
// int BPF_KPROBE(do_mov_1782)
// {
//     u64 addr = ctx->r15+ctx->r13 * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x457")
// int BPF_KPROBE(do_mov_1783)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x462")
// int BPF_KPROBE(do_mov_1784)
// {
//     u64 addr = ctx->ax+ctx->r13 * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_constructor+0x472")
// int BPF_KPROBE(do_mov_1785)
// {
//     u64 addr = ctx->r15+ctx->r13 * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x39")
// int BPF_KPROBE(do_mov_1786)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x49")
// int BPF_KPROBE(do_mov_1787)
// {
//     u64 addr = ctx->cx+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x137")
// int BPF_KPROBE(do_mov_1788)
// {
//     u64 addr = ctx->r14+ctx->di * 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x15a")
// int BPF_KPROBE(do_mov_1789)
// {
//     u64 addr = ctx->r14+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x167")
// int BPF_KPROBE(do_mov_1790)
// {
//     u64 addr = ctx->r14+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x170")
// int BPF_KPROBE(do_mov_1791)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x183")
// int BPF_KPROBE(do_mov_1792)
// {
//     u64 addr = ctx->r14+ctx->ax * 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x1b5")
// int BPF_KPROBE(do_mov_1793)
// {
//     u64 addr = ctx->r14+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_parse_options+0x1c2")
// int BPF_KPROBE(do_mov_1794)
// {
//     u64 addr = ctx->r14+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_redirect_rcv+0xee")
// int BPF_KPROBE(do_mov_1795)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x11b")
// int BPF_KPROBE(do_mov_1796)
// {
//     u64 addr = ctx->r12+0x274;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x14a")
// int BPF_KPROBE(do_mov_1797)
// {
//     u64 addr = ctx->r12+0x274;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x358")
// int BPF_KPROBE(do_mov_1798)
// {
//     u64 addr = ctx->cx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x35c")
// int BPF_KPROBE(do_mov_1799)
// {
//     u64 addr = ctx->cx+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x3d5")
// int BPF_KPROBE(do_mov_1800)
// {
//     u64 addr = ctx->cx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x3df")
// int BPF_KPROBE(do_mov_1801)
// {
//     u64 addr = ctx->r12+0x3f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x44b")
// int BPF_KPROBE(do_mov_1802)
// {
//     u64 addr = ctx->ax+0x6c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x461")
// int BPF_KPROBE(do_mov_1803)
// {
//     u64 addr = ctx->ax+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x478")
// int BPF_KPROBE(do_mov_1804)
// {
//     u64 addr = ctx->dx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x482")
// int BPF_KPROBE(do_mov_1805)
// {
//     u64 addr = ctx->r12+0x3f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x6b1")
// int BPF_KPROBE(do_mov_1806)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x6cd")
// int BPF_KPROBE(do_mov_1807)
// {
//     u64 addr = ctx->r8+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x6d6")
// int BPF_KPROBE(do_mov_1808)
// {
//     u64 addr = ctx->r8+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x6df")
// int BPF_KPROBE(do_mov_1809)
// {
//     u64 addr = ctx->r8+0x19;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x6ea")
// int BPF_KPROBE(do_mov_1810)
// {
//     u64 addr = ctx->r8+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x706")
// int BPF_KPROBE(do_mov_1811)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x777")
// int BPF_KPROBE(do_mov_1812)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0x9fe")
// int BPF_KPROBE(do_mov_1813)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0xa09")
// int BPF_KPROBE(do_mov_1814)
// {
//     u64 addr = ctx->dx+ctx->cx * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0xa21")
// int BPF_KPROBE(do_mov_1815)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0xa97")
// int BPF_KPROBE(do_mov_1816)
// {
//     u64 addr = ctx->r12+0x408;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0xad2")
// int BPF_KPROBE(do_mov_1817)
// {
//     u64 addr = ctx->r12+0x2b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0xc08")
// int BPF_KPROBE(do_mov_1818)
// {
//     u64 addr = ctx->r14+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_router_discovery+0xc93")
// int BPF_KPROBE(do_mov_1819)
// {
//     u64 addr = ctx->r12+0x2ac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0xff")
// int BPF_KPROBE(do_mov_1820)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x109")
// int BPF_KPROBE(do_mov_1821)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x10e")
// int BPF_KPROBE(do_mov_1822)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x114")
// int BPF_KPROBE(do_mov_1823)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x118")
// int BPF_KPROBE(do_mov_1824)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x239")
// int BPF_KPROBE(do_mov_1825)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x246")
// int BPF_KPROBE(do_mov_1826)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x24b")
// int BPF_KPROBE(do_mov_1827)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x256")
// int BPF_KPROBE(do_mov_1828)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_na+0x25d")
// int BPF_KPROBE(do_mov_1829)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_rs+0x44")
// int BPF_KPROBE(do_mov_1830)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_rs+0xcc")
// int BPF_KPROBE(do_mov_1831)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x39d")
// int BPF_KPROBE(do_mov_1832)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x3a6")
// int BPF_KPROBE(do_mov_1833)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x3ad")
// int BPF_KPROBE(do_mov_1834)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x3b1")
// int BPF_KPROBE(do_mov_1835)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x3b4")
// int BPF_KPROBE(do_mov_1836)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x3b8")
// int BPF_KPROBE(do_mov_1837)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x423")
// int BPF_KPROBE(do_mov_1838)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x442")
// int BPF_KPROBE(do_mov_1839)
// {
//     u64 addr = ctx->r13+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x47e")
// int BPF_KPROBE(do_mov_1840)
// {
//     u64 addr = ctx->ax+0x5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x488")
// int BPF_KPROBE(do_mov_1841)
// {
//     u64 addr = ctx->ax+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x48f")
// int BPF_KPROBE(do_mov_1842)
// {
//     u64 addr = ctx->ax+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x493")
// int BPF_KPROBE(do_mov_1843)
// {
//     u64 addr = ctx->ax+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x49a")
// int BPF_KPROBE(do_mov_1844)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_send_redirect+0x4d8")
// int BPF_KPROBE(do_mov_1845)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_rcv+0x67")
// int BPF_KPROBE(do_mov_1846)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_rcv+0xcb")
// int BPF_KPROBE(do_mov_1847)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ndisc_rcv+0xd7")
// int BPF_KPROBE(do_mov_1848)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_init_sock+0xd")
// int BPF_KPROBE(do_mov_1849)
// {
//     u64 addr = ctx->di+0x440;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_init_sock+0x14")
// int BPF_KPROBE(do_mov_1850)
// {
//     u64 addr = ctx->di+0x448;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_init_sock+0x22")
// int BPF_KPROBE(do_mov_1851)
// {
//     u64 addr = ctx->di+0x450;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_init_sock+0x30")
// int BPF_KPROBE(do_mov_1852)
// {
//     u64 addr = ctx->di+0x2d0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x4f")
// int BPF_KPROBE(do_mov_1853)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x58")
// int BPF_KPROBE(do_mov_1854)
// {
//     u64 addr = ctx->r13+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x64")
// int BPF_KPROBE(do_mov_1855)
// {
//     u64 addr = ctx->r13+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x6b")
// int BPF_KPROBE(do_mov_1856)
// {
//     u64 addr = ctx->r13+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x10c")
// int BPF_KPROBE(do_mov_1857)
// {
//     u64 addr = ctx->si+ctx->cx * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x121")
// int BPF_KPROBE(do_mov_1858)
// {
//     u64 addr = ctx->cx+ctx->dx * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x145")
// int BPF_KPROBE(do_mov_1859)
// {
//     u64 addr = ctx->di+ctx->si * 0x1+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x1c0")
// int BPF_KPROBE(do_mov_1860)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x1f9")
// int BPF_KPROBE(do_mov_1861)
// {
//     u64 addr = ctx->r13+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x344")
// int BPF_KPROBE(do_mov_1862)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x355")
// int BPF_KPROBE(do_mov_1863)
// {
//     u64 addr = ctx->r12+0x8a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x365")
// int BPF_KPROBE(do_mov_1864)
// {
//     u64 addr = ctx->r13+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_send_skb+0x3eb")
// int BPF_KPROBE(do_mov_1865)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_push_pending_frames+0x70")
// int BPF_KPROBE(do_mov_1866)
// {
//     u64 addr = ctx->r12+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_push_pending_frames+0x7e")
// int BPF_KPROBE(do_mov_1867)
// {
//     u64 addr = ctx->r12+0x3e2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x2a5")
// int BPF_KPROBE(do_mov_1868)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x2bd")
// int BPF_KPROBE(do_mov_1869)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x2c4")
// int BPF_KPROBE(do_mov_1870)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x2eb")
// int BPF_KPROBE(do_mov_1871)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x2ef")
// int BPF_KPROBE(do_mov_1872)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x339")
// int BPF_KPROBE(do_mov_1873)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x33c")
// int BPF_KPROBE(do_mov_1874)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x691")
// int BPF_KPROBE(do_mov_1875)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x69b")
// int BPF_KPROBE(do_mov_1876)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x6a2")
// int BPF_KPROBE(do_mov_1877)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x6eb")
// int BPF_KPROBE(do_mov_1878)
// {
//     u64 addr = ctx->r13+0x258;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_recvmsg+0x72d")
// int BPF_KPROBE(do_mov_1879)
// {
//     u64 addr = ctx->r13+0x258;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_destroy_sock+0x85")
// int BPF_KPROBE(do_mov_1880)
// {
//     u64 addr = ctx->r12+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_destroy_sock+0x91")
// int BPF_KPROBE(do_mov_1881)
// {
//     u64 addr = ctx->r12+0x3e2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x312")
// int BPF_KPROBE(do_mov_1882)
// {
//     u64 addr = ctx->bx+0x114;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x337")
// int BPF_KPROBE(do_mov_1883)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x34a")
// int BPF_KPROBE(do_mov_1884)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x393")
// int BPF_KPROBE(do_mov_1885)
// {
//     u64 addr = ctx->bx+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x39b")
// int BPF_KPROBE(do_mov_1886)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x3a6")
// int BPF_KPROBE(do_mov_1887)
// {
//     u64 addr = ctx->bx+0x114;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_one_skb+0x3b1")
// int BPF_KPROBE(do_mov_1888)
// {
//     u64 addr = ctx->bx+0x7a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_skb+0x86")
// int BPF_KPROBE(do_mov_1889)
// {
//     u64 addr = ctx->r13+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_skb+0xb4")
// int BPF_KPROBE(do_mov_1890)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_skb+0x10c")
// int BPF_KPROBE(do_mov_1891)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_skb+0x123")
// int BPF_KPROBE(do_mov_1892)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_queue_rcv_skb+0x12d")
// int BPF_KPROBE(do_mov_1893)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_unicast_rcv_skb+0x80")
// int BPF_KPROBE(do_mov_1894)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_unicast_rcv_skb+0x95")
// int BPF_KPROBE(do_mov_1895)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_get_port+0x50")
// int BPF_KPROBE(do_mov_1896)
// {
//     u64 addr = ctx->r12+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x1a8")
// int BPF_KPROBE(do_mov_1897)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x1bd")
// int BPF_KPROBE(do_mov_1898)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x1e9")
// int BPF_KPROBE(do_mov_1899)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x1f6")
// int BPF_KPROBE(do_mov_1900)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x408")
// int BPF_KPROBE(do_mov_1901)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x74d")
// int BPF_KPROBE(do_mov_1902)
// {
//     u64 addr = ctx->r12+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x75d")
// int BPF_KPROBE(do_mov_1903)
// {
//     u64 addr = ctx->r12+0x3e2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x7b7")
// int BPF_KPROBE(do_mov_1904)
// {
//     u64 addr = ctx->r12+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x891")
// int BPF_KPROBE(do_mov_1905)
// {
//     u64 addr = ctx->r12+0x3e2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udpv6_sendmsg+0x89a")
// int BPF_KPROBE(do_mov_1906)
// {
//     u64 addr = ctx->r12+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__udp6_lib_err+0x158")
// int BPF_KPROBE(do_mov_1907)
// {
//     u64 addr = ctx->r13+0x220;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__udp6_lib_rcv+0x229")
// int BPF_KPROBE(do_mov_1908)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__udp6_lib_rcv+0x237")
// int BPF_KPROBE(do_mov_1909)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__udp6_lib_rcv+0x797")
// int BPF_KPROBE(do_mov_1910)
// {
//     u64 addr = ctx->r8+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_early_demux+0x18e")
// int BPF_KPROBE(do_mov_1911)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_early_demux+0x192")
// int BPF_KPROBE(do_mov_1912)
// {
//     u64 addr = ctx->bx+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp_v6_early_demux+0x1d0")
// int BPF_KPROBE(do_mov_1913)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udplitev6_sk_init+0x12")
// int BPF_KPROBE(do_mov_1914)
// {
//     u64 addr = ctx->bx+0x3ea;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_init_sk+0x23")
// int BPF_KPROBE(do_mov_1915)
// {
//     u64 addr = ctx->di+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_init_sk+0x39")
// int BPF_KPROBE(do_mov_1916)
// {
//     u64 addr = ctx->di+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0xba")
// int BPF_KPROBE(do_mov_1917)
// {
//     u64 addr = ctx->r14+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0xc4")
// int BPF_KPROBE(do_mov_1918)
// {
//     u64 addr = ctx->r14+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0xd0")
// int BPF_KPROBE(do_mov_1919)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0xd4")
// int BPF_KPROBE(do_mov_1920)
// {
//     u64 addr = ctx->r14+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0xe5")
// int BPF_KPROBE(do_mov_1921)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0xe8")
// int BPF_KPROBE(do_mov_1922)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0x10b")
// int BPF_KPROBE(do_mov_1923)
// {
//     u64 addr = ctx->r14+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0x119")
// int BPF_KPROBE(do_mov_1924)
// {
//     u64 addr = ctx->r14+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0x129")
// int BPF_KPROBE(do_mov_1925)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0x12d")
// int BPF_KPROBE(do_mov_1926)
// {
//     u64 addr = ctx->r14+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_bind+0x140")
// int BPF_KPROBE(do_mov_1927)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/raw6_getfrag+0xdd")
// int BPF_KPROBE(do_mov_1928)
// {
//     u64 addr = ctx->r9+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x154")
// int BPF_KPROBE(do_mov_1929)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x175")
// int BPF_KPROBE(do_mov_1930)
// {
//     u64 addr = ctx->si+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x17c")
// int BPF_KPROBE(do_mov_1931)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x180")
// int BPF_KPROBE(do_mov_1932)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x1c3")
// int BPF_KPROBE(do_mov_1933)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x1cb")
// int BPF_KPROBE(do_mov_1934)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x280")
// int BPF_KPROBE(do_mov_1935)
// {
//     u64 addr = ctx->r12+0x258;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_recvmsg+0x2f6")
// int BPF_KPROBE(do_mov_1936)
// {
//     u64 addr = ctx->r12+0x258;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0xd4")
// int BPF_KPROBE(do_mov_1937)
// {
//     u64 addr = ctx->r14+0x328;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x12d")
// int BPF_KPROBE(do_mov_1938)
// {
//     u64 addr = ctx->r14+0x3e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x13d")
// int BPF_KPROBE(do_mov_1939)
// {
//     u64 addr = ctx->r13+ctx->ax * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x1c6")
// int BPF_KPROBE(do_mov_1940)
// {
//     u64 addr = ctx->r14+0x3dc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x1cf")
// int BPF_KPROBE(do_mov_1941)
// {
//     u64 addr = ctx->r14+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x1ea")
// int BPF_KPROBE(do_mov_1942)
// {
//     u64 addr = ctx->r14+0x3e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x1f6")
// int BPF_KPROBE(do_mov_1943)
// {
//     u64 addr = ctx->r13+ctx->r12 * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x221")
// int BPF_KPROBE(do_mov_1944)
// {
//     u64 addr = ctx->di+ctx->si * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x232")
// int BPF_KPROBE(do_mov_1945)
// {
//     u64 addr = ctx->r14+0x3d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x264")
// int BPF_KPROBE(do_mov_1946)
// {
//     u64 addr = ctx->r14+0x3e0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_setsockopt+0x26f")
// int BPF_KPROBE(do_mov_1947)
// {
//     u64 addr = ctx->r13+ctx->ax * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x819")
// int BPF_KPROBE(do_mov_1948)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x837")
// int BPF_KPROBE(do_mov_1949)
// {
//     u64 addr = ctx->r12+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x845")
// int BPF_KPROBE(do_mov_1950)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x854")
// int BPF_KPROBE(do_mov_1951)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x86e")
// int BPF_KPROBE(do_mov_1952)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x8fa")
// int BPF_KPROBE(do_mov_1953)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x92c")
// int BPF_KPROBE(do_mov_1954)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x95a")
// int BPF_KPROBE(do_mov_1955)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_sendmsg+0x109b")
// int BPF_KPROBE(do_mov_1956)
// {
//     u64 addr = ctx->cx+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/raw6_icmp_error+0x14f")
// int BPF_KPROBE(do_mov_1957)
// {
//     u64 addr = ctx->bx+0x1b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_rcv+0x86")
// int BPF_KPROBE(do_mov_1958)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_rcv+0xf7")
// int BPF_KPROBE(do_mov_1959)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_rcv+0x2d0")
// int BPF_KPROBE(do_mov_1960)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_rcv+0x324")
// int BPF_KPROBE(do_mov_1961)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/rawv6_rcv+0x377")
// int BPF_KPROBE(do_mov_1962)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/raw6_local_deliver+0x11a")
// int BPF_KPROBE(do_mov_1963)
// {
//     u64 addr = ctx->r9+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_getfrag+0x48")
// int BPF_KPROBE(do_mov_1964)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_err_convert+0x6")
// int BPF_KPROBE(do_mov_1965)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_err_convert+0x23")
// int BPF_KPROBE(do_mov_1966)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_err_convert+0x38")
// int BPF_KPROBE(do_mov_1967)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_err_convert+0x59")
// int BPF_KPROBE(do_mov_1968)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_push_pending_frames+0x59")
// int BPF_KPROBE(do_mov_1969)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_push_pending_frames+0x5e")
// int BPF_KPROBE(do_mov_1970)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_push_pending_frames+0xb8")
// int BPF_KPROBE(do_mov_1971)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_push_pending_frames+0xf8")
// int BPF_KPROBE(do_mov_1972)
// {
//     u64 addr = ctx->r10+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_send+0x3d8")
// int BPF_KPROBE(do_mov_1973)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_send+0x6a9")
// int BPF_KPROBE(do_mov_1974)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_send+0x72e")
// int BPF_KPROBE(do_mov_1975)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_send+0x732")
// int BPF_KPROBE(do_mov_1976)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_send+0x736")
// int BPF_KPROBE(do_mov_1977)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmp6_send+0x73a")
// int BPF_KPROBE(do_mov_1978)
// {
//     u64 addr = ctx->ax+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_err_gen_icmpv6_unreach+0xac")
// int BPF_KPROBE(do_mov_1979)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_err_gen_icmpv6_unreach+0xdf")
// int BPF_KPROBE(do_mov_1980)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_err_gen_icmpv6_unreach+0x137")
// int BPF_KPROBE(do_mov_1981)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_err_gen_icmpv6_unreach+0x143")
// int BPF_KPROBE(do_mov_1982)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_err_gen_icmpv6_unreach+0x208")
// int BPF_KPROBE(do_mov_1983)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_echo_reply+0x1d5")
// int BPF_KPROBE(do_mov_1984)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_echo_reply+0x2b3")
// int BPF_KPROBE(do_mov_1985)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0xda")
// int BPF_KPROBE(do_mov_1986)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x129")
// int BPF_KPROBE(do_mov_1987)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x150")
// int BPF_KPROBE(do_mov_1988)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x184")
// int BPF_KPROBE(do_mov_1989)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x320")
// int BPF_KPROBE(do_mov_1990)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x3a5")
// int BPF_KPROBE(do_mov_1991)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x3e7")
// int BPF_KPROBE(do_mov_1992)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x488")
// int BPF_KPROBE(do_mov_1993)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x49b")
// int BPF_KPROBE(do_mov_1994)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_rcv+0x538")
// int BPF_KPROBE(do_mov_1995)
// {
//     u64 addr = ctx->r12+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x1c")
// int BPF_KPROBE(do_mov_1996)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x26")
// int BPF_KPROBE(do_mov_1997)
// {
//     u64 addr = ctx->si+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x42")
// int BPF_KPROBE(do_mov_1998)
// {
//     u64 addr = ctx->si+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x46")
// int BPF_KPROBE(do_mov_1999)
// {
//     u64 addr = ctx->si+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x51")
// int BPF_KPROBE(do_mov_2000)
// {
//     u64 addr = ctx->si+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x55")
// int BPF_KPROBE(do_mov_2001)
// {
//     u64 addr = ctx->si+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x59")
// int BPF_KPROBE(do_mov_2002)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x5d")
// int BPF_KPROBE(do_mov_2003)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_flow_init+0x60")
// int BPF_KPROBE(do_mov_2004)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_sysctl_init+0x2f")
// int BPF_KPROBE(do_mov_2005)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_sysctl_init+0x3a")
// int BPF_KPROBE(do_mov_2006)
// {
//     u64 addr = ctx->ax+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_sysctl_init+0x45")
// int BPF_KPROBE(do_mov_2007)
// {
//     u64 addr = ctx->ax+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_sysctl_init+0x5a")
// int BPF_KPROBE(do_mov_2008)
// {
//     u64 addr = ctx->ax+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_sysctl_init+0x61")
// int BPF_KPROBE(do_mov_2009)
// {
//     u64 addr = ctx->ax+0x108;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_markstate+0x2b")
// int BPF_KPROBE(do_mov_2010)
// {
//     u64 addr = ctx->ax+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_markstate+0x47")
// int BPF_KPROBE(do_mov_2011)
// {
//     u64 addr = ctx->ax+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_stop+0x14")
// int BPF_KPROBE(do_mov_2012)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_stop+0x23")
// int BPF_KPROBE(do_mov_2013)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_stop+0x2b")
// int BPF_KPROBE(do_mov_2014)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_stop+0x14")
// int BPF_KPROBE(do_mov_2015)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_stop+0x1c")
// int BPF_KPROBE(do_mov_2016)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sf_setstate+0xad")
// int BPF_KPROBE(do_mov_2017)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }

// // ==========================================================================================
// // SEC("kprobe/sf_setstate+0xbe")
// // int BPF_KPROBE(do_mov_2018)
// // {
// //     u64 addr = ctx->bx+0x2a;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0xdc")
// // int BPF_KPROBE(do_mov_2019)
// // {
// //     u64 addr = ctx->bx+0x2a;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x10f")
// // int BPF_KPROBE(do_mov_2020)
// // {
// //     u64 addr = ctx->ax+0x2a;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x14e")
// // int BPF_KPROBE(do_mov_2021)
// // {
// //     u64 addr = ctx->ax;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x155")
// // int BPF_KPROBE(do_mov_2022)
// // {
// //     u64 addr = ctx->ax+0x8;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x15d")
// // int BPF_KPROBE(do_mov_2023)
// // {
// //     u64 addr = ctx->ax+0x10;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x165")
// // int BPF_KPROBE(do_mov_2024)
// // {
// //     u64 addr = ctx->ax+0x18;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x16d")
// // int BPF_KPROBE(do_mov_2025)
// // {
// //     u64 addr = ctx->ax+0x20;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x175")
// // int BPF_KPROBE(do_mov_2026)
// // {
// //     u64 addr = ctx->ax+0x28;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x17d")
// // int BPF_KPROBE(do_mov_2027)
// // {
// //     u64 addr = ctx->ax+0x30;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x185")
// // int BPF_KPROBE(do_mov_2028)
// // {
// //     u64 addr = ctx->ax+0x38;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x18e")
// // int BPF_KPROBE(do_mov_2029)
// // {
// //     u64 addr = ctx->ax;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x191")
// // int BPF_KPROBE(do_mov_2030)
// // {
// //     u64 addr = ctx->r12+0x28;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x19a")
// // int BPF_KPROBE(do_mov_2031)
// // {
// //     u64 addr = ctx->ax+0x2a;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/sf_setstate+0x1a3")
// // int BPF_KPROBE(do_mov_2032)
// // {
// //     u64 addr = ctx->r12+0x28;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// SEC("kprobe/igmp6_net_init+0x74")
// int BPF_KPROBE(do_mov_2033)
// {
//     u64 addr = ctx->dx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_net_init+0x84")
// int BPF_KPROBE(do_mov_2034)
// {
//     u64 addr = ctx->ax+0x1f8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x2b")
// int BPF_KPROBE(do_mov_2035)
// {
//     u64 addr = ctx->si+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x43")
// int BPF_KPROBE(do_mov_2036)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x47")
// int BPF_KPROBE(do_mov_2037)
// {
//     u64 addr = ctx->si+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x6b")
// int BPF_KPROBE(do_mov_2038)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x71")
// int BPF_KPROBE(do_mov_2039)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x76")
// int BPF_KPROBE(do_mov_2040)
// {
//     u64 addr = ctx->ax+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0x98")
// int BPF_KPROBE(do_mov_2041)
// {
//     u64 addr = ctx->ax+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0xa2")
// int BPF_KPROBE(do_mov_2042)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0xa6")
// int BPF_KPROBE(do_mov_2043)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0xb1")
// int BPF_KPROBE(do_mov_2044)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_hdr.constprop.0+0xb5")
// int BPF_KPROBE(do_mov_2045)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_get_next.isra.0+0x1f")
// int BPF_KPROBE(do_mov_2046)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_get_next.isra.0+0x2f")
// int BPF_KPROBE(do_mov_2047)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_get_next.isra.0+0x3c")
// int BPF_KPROBE(do_mov_2048)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_get_next.isra.0+0x5f")
// int BPF_KPROBE(do_mov_2049)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_get_next.isra.0+0x67")
// int BPF_KPROBE(do_mov_2050)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_start+0x38")
// int BPF_KPROBE(do_mov_2051)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_start+0x40")
// int BPF_KPROBE(do_mov_2052)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_start+0x5a")
// int BPF_KPROBE(do_mov_2053)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_start+0x81")
// int BPF_KPROBE(do_mov_2054)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_start+0x85")
// int BPF_KPROBE(do_mov_2055)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_start+0xba")
// int BPF_KPROBE(do_mov_2056)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_next+0x34")
// int BPF_KPROBE(do_mov_2057)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_next+0x44")
// int BPF_KPROBE(do_mov_2058)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_next+0x5f")
// int BPF_KPROBE(do_mov_2059)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_next+0x6a")
// int BPF_KPROBE(do_mov_2060)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_sendpack+0xca")
// int BPF_KPROBE(do_mov_2061)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_sendpack+0x106")
// int BPF_KPROBE(do_mov_2062)
// {
//     u64 addr = ctx->r15+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_sendpack+0x167")
// int BPF_KPROBE(do_mov_2063)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_sendpack+0x185")
// int BPF_KPROBE(do_mov_2064)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_sendpack+0x20f")
// int BPF_KPROBE(do_mov_2065)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0x22")
// int BPF_KPROBE(do_mov_2066)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0x3c")
// int BPF_KPROBE(do_mov_2067)
// {
//     u64 addr = ctx->r8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0x62")
// int BPF_KPROBE(do_mov_2068)
// {
//     u64 addr = ctx->r8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0x76")
// int BPF_KPROBE(do_mov_2069)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0xaa")
// int BPF_KPROBE(do_mov_2070)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0xba")
// int BPF_KPROBE(do_mov_2071)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0xdd")
// int BPF_KPROBE(do_mov_2072)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mc_seq_start+0xe5")
// int BPF_KPROBE(do_mov_2073)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0xf5")
// int BPF_KPROBE(do_mov_2074)
// {
//     u64 addr = ctx->ax+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x16c")
// int BPF_KPROBE(do_mov_2075)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x180")
// int BPF_KPROBE(do_mov_2076)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x187")
// int BPF_KPROBE(do_mov_2077)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x192")
// int BPF_KPROBE(do_mov_2078)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x194")
// int BPF_KPROBE(do_mov_2079)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x1ad")
// int BPF_KPROBE(do_mov_2080)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x1b3")
// int BPF_KPROBE(do_mov_2081)
// {
//     u64 addr = ctx->r9+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x1db")
// int BPF_KPROBE(do_mov_2082)
// {
//     u64 addr = ctx->r9+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x24c")
// int BPF_KPROBE(do_mov_2083)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_send+0x26a")
// int BPF_KPROBE(do_mov_2084)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_next+0x29")
// int BPF_KPROBE(do_mov_2085)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_next+0x31")
// int BPF_KPROBE(do_mov_2086)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_next+0x4b")
// int BPF_KPROBE(do_mov_2087)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_next+0x72")
// int BPF_KPROBE(do_mov_2088)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_next+0x76")
// int BPF_KPROBE(do_mov_2089)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_mcf_seq_next+0x8c")
// int BPF_KPROBE(do_mov_2090)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0x19")
// int BPF_KPROBE(do_mov_2091)
// {
//     u64 addr = ctx->di+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0x5a")
// int BPF_KPROBE(do_mov_2092)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0x8e")
// int BPF_KPROBE(do_mov_2093)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0x97")
// int BPF_KPROBE(do_mov_2094)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0xa0")
// int BPF_KPROBE(do_mov_2095)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0xb0")
// int BPF_KPROBE(do_mov_2096)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_clear_delrec+0xf3")
// int BPF_KPROBE(do_mov_2097)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_newpack.isra.0+0x94")
// int BPF_KPROBE(do_mov_2098)
// {
//     u64 addr = ctx->ax+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_newpack.isra.0+0xb6")
// int BPF_KPROBE(do_mov_2099)
// {
//     u64 addr = ctx->r12+0xbc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_newpack.isra.0+0xf4")
// int BPF_KPROBE(do_mov_2100)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_newpack.isra.0+0x148")
// int BPF_KPROBE(do_mov_2101)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_newpack.isra.0+0x154")
// int BPF_KPROBE(do_mov_2102)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_newpack.isra.0+0x173")
// int BPF_KPROBE(do_mov_2103)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// // SEC("kprobe/add_grhead+0x30")
// // int BPF_KPROBE(do_mov_2104)
// // {
// //     u64 addr = ctx->ax;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grhead+0x33")
// // int BPF_KPROBE(do_mov_2105)
// // {
// //     u64 addr = ctx->ax+0x1;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grhead+0x37")
// // int BPF_KPROBE(do_mov_2106)
// // {
// //     u64 addr = ctx->ax+0x2;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grhead+0x42")
// // int BPF_KPROBE(do_mov_2107)
// // {
// //     u64 addr = ctx->ax+0x4;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grhead+0x46")
// // int BPF_KPROBE(do_mov_2108)
// // {
// //     u64 addr = ctx->ax+0xc;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grhead+0x67")
// // int BPF_KPROBE(do_mov_2109)
// // {
// //     u64 addr = ctx->cx+0x6;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grhead+0x6b")
// // int BPF_KPROBE(do_mov_2110)
// // {
// //     u64 addr = ctx->r12;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x1e3")
// // int BPF_KPROBE(do_mov_2111)
// // {
// //     u64 addr = ctx->r15+0x28;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x256")
// // int BPF_KPROBE(do_mov_2112)
// // {
// //     u64 addr = ctx->ax;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x259")
// // int BPF_KPROBE(do_mov_2113)
// // {
// //     u64 addr = ctx->ax+0x8;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x2e2")
// // int BPF_KPROBE(do_mov_2114)
// // {
// //     u64 addr = ctx->r15+0x2a;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x31a")
// // int BPF_KPROBE(do_mov_2115)
// // {
// //     u64 addr = ctx->ax+0x2;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x371")
// // int BPF_KPROBE(do_mov_2116)
// // {
// //     u64 addr = ctx->ax+0x2;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x3e2")
// // int BPF_KPROBE(do_mov_2117)
// // {
// //     u64 addr = ctx->r15+0x2a;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x40a")
// // int BPF_KPROBE(do_mov_2118)
// // {
// //     u64 addr = ctx->cx;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/add_grec+0x4d7")
// // int BPF_KPROBE(do_mov_2119)
// // {
// //     u64 addr = ctx->di;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// SEC("kprobe/mld_gq_work+0x2e")
// int BPF_KPROBE(do_mov_2120)
// {
//     u64 addr = ctx->bx - 0x27;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x58")
// int BPF_KPROBE(do_mov_2121)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x65")
// int BPF_KPROBE(do_mov_2122)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x74")
// int BPF_KPROBE(do_mov_2123)
// {
//     u64 addr = ctx->r9+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0xc8")
// int BPF_KPROBE(do_mov_2124)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0xef")
// int BPF_KPROBE(do_mov_2125)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x103")
// int BPF_KPROBE(do_mov_2126)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x10a")
// int BPF_KPROBE(do_mov_2127)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x112")
// int BPF_KPROBE(do_mov_2128)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x124")
// int BPF_KPROBE(do_mov_2129)
// {
//     u64 addr = ctx->r10+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x131")
// int BPF_KPROBE(do_mov_2130)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x143")
// int BPF_KPROBE(do_mov_2131)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x147")
// int BPF_KPROBE(do_mov_2132)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x153")
// int BPF_KPROBE(do_mov_2133)
// {
//     u64 addr = ctx->r9+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x157")
// int BPF_KPROBE(do_mov_2134)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_del_delrec+0x16d")
// int BPF_KPROBE(do_mov_2135)
// {
//     u64 addr = ctx->ax+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_mca_work+0x74")
// int BPF_KPROBE(do_mov_2136)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x68")
// int BPF_KPROBE(do_mov_2137)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x75")
// int BPF_KPROBE(do_mov_2138)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x7d")
// int BPF_KPROBE(do_mov_2139)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x84")
// int BPF_KPROBE(do_mov_2140)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x88")
// int BPF_KPROBE(do_mov_2141)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x90")
// int BPF_KPROBE(do_mov_2142)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x93")
// int BPF_KPROBE(do_mov_2143)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x9c")
// int BPF_KPROBE(do_mov_2144)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x109")
// int BPF_KPROBE(do_mov_2145)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x111")
// int BPF_KPROBE(do_mov_2146)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x118")
// int BPF_KPROBE(do_mov_2147)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_report_work+0x11c")
// int BPF_KPROBE(do_mov_2148)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_event+0x4e")
// int BPF_KPROBE(do_mov_2149)
// {
//     u64 addr = ctx->bx+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_added+0xa4")
// int BPF_KPROBE(do_mov_2150)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_added+0xd2")
// int BPF_KPROBE(do_mov_2151)
// {
//     u64 addr = ctx->di+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_dad_work+0x79")
// int BPF_KPROBE(do_mov_2152)
// {
//     u64 addr = ctx->bx - 0xd5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x5c")
// int BPF_KPROBE(do_mov_2153)
// {
//     u64 addr = ctx->r14+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0xaf")
// int BPF_KPROBE(do_mov_2154)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x1a9")
// int BPF_KPROBE(do_mov_2155)
// {
//     u64 addr = ctx->cx - 0x7e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x245")
// int BPF_KPROBE(do_mov_2156)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x283")
// int BPF_KPROBE(do_mov_2157)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x2be")
// int BPF_KPROBE(do_mov_2158)
// {
//     u64 addr = ctx->r14+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x2ec")
// int BPF_KPROBE(do_mov_2159)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_ifc_work+0x43a")
// int BPF_KPROBE(do_mov_2160)
// {
//     u64 addr = ctx->ax - 0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del1_src+0x5a")
// int BPF_KPROBE(do_mov_2161)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del1_src+0x79")
// int BPF_KPROBE(do_mov_2162)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del1_src+0xac")
// int BPF_KPROBE(do_mov_2163)
// {
//     u64 addr = ctx->r10+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del1_src+0xed")
// int BPF_KPROBE(do_mov_2164)
// {
//     u64 addr = ctx->ax+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del1_src+0xf4")
// int BPF_KPROBE(do_mov_2165)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del1_src+0xfd")
// int BPF_KPROBE(do_mov_2166)
// {
//     u64 addr = ctx->r10+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x12d")
// int BPF_KPROBE(do_mov_2167)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x13f")
// int BPF_KPROBE(do_mov_2168)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x144")
// int BPF_KPROBE(do_mov_2169)
// {
//     u64 addr = ctx->cx+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x151")
// int BPF_KPROBE(do_mov_2170)
// {
//     u64 addr = ctx->ax+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x1a8")
// int BPF_KPROBE(do_mov_2171)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x1ac")
// int BPF_KPROBE(do_mov_2172)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x1b0")
// int BPF_KPROBE(do_mov_2173)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x20c")
// int BPF_KPROBE(do_mov_2174)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x210")
// int BPF_KPROBE(do_mov_2175)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x214")
// int BPF_KPROBE(do_mov_2176)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_add_src+0x21d")
// int BPF_KPROBE(do_mov_2177)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del_src.isra.0+0xff")
// int BPF_KPROBE(do_mov_2178)
// {
//     u64 addr = ctx->bx+ctx->ax * 0x8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del_src.isra.0+0x11d")
// int BPF_KPROBE(do_mov_2179)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del_src.isra.0+0x128")
// int BPF_KPROBE(do_mov_2180)
// {
//     u64 addr = ctx->bx+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del_src.isra.0+0x12b")
// int BPF_KPROBE(do_mov_2181)
// {
//     u64 addr = ctx->cx+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_del_src.isra.0+0x137")
// int BPF_KPROBE(do_mov_2182)
// {
//     u64 addr = ctx->ax+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_leave_src.isra.0+0x4e")
// int BPF_KPROBE(do_mov_2183)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x89")
// int BPF_KPROBE(do_mov_2184)
// {
//     u64 addr = ctx->di+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x13d")
// int BPF_KPROBE(do_mov_2185)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x16a")
// int BPF_KPROBE(do_mov_2186)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x16e")
// int BPF_KPROBE(do_mov_2187)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x178")
// int BPF_KPROBE(do_mov_2188)
// {
//     u64 addr = ctx->r13+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x17f")
// int BPF_KPROBE(do_mov_2189)
// {
//     u64 addr = ctx->r13+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x18d")
// int BPF_KPROBE(do_mov_2190)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x191")
// int BPF_KPROBE(do_mov_2191)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x1d2")
// int BPF_KPROBE(do_mov_2192)
// {
//     u64 addr = ctx->r13+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x1da")
// int BPF_KPROBE(do_mov_2193)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x1de")
// int BPF_KPROBE(do_mov_2194)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x1e6")
// int BPF_KPROBE(do_mov_2195)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_group_dropped+0x1f8")
// int BPF_KPROBE(do_mov_2196)
// {
//     u64 addr = ctx->ax+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x152")
// int BPF_KPROBE(do_mov_2197)
// {
//     u64 addr = ctx->r9+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x15a")
// int BPF_KPROBE(do_mov_2198)
// {
//     u64 addr = ctx->r9+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x162")
// int BPF_KPROBE(do_mov_2199)
// {
//     u64 addr = ctx->r9+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x166")
// int BPF_KPROBE(do_mov_2200)
// {
//     u64 addr = ctx->r9+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x17e")
// int BPF_KPROBE(do_mov_2201)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x188")
// int BPF_KPROBE(do_mov_2202)
// {
//     u64 addr = ctx->r9+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x196")
// int BPF_KPROBE(do_mov_2203)
// {
//     u64 addr = ctx->r9+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x19d")
// int BPF_KPROBE(do_mov_2204)
// {
//     u64 addr = ctx->r9+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1a4")
// int BPF_KPROBE(do_mov_2205)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1a8")
// int BPF_KPROBE(do_mov_2206)
// {
//     u64 addr = ctx->r9+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1b3")
// int BPF_KPROBE(do_mov_2207)
// {
//     u64 addr = ctx->r9+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1be")
// int BPF_KPROBE(do_mov_2208)
// {
//     u64 addr = ctx->r9+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1c2")
// int BPF_KPROBE(do_mov_2209)
// {
//     u64 addr = ctx->r9+ctx->r12 * 0x8+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1e8")
// int BPF_KPROBE(do_mov_2210)
// {
//     u64 addr = ctx->r9+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_inc+0x1f1")
// int BPF_KPROBE(do_mov_2211)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0xc8")
// int BPF_KPROBE(do_mov_2212)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0xd7")
// int BPF_KPROBE(do_mov_2213)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0xdb")
// int BPF_KPROBE(do_mov_2214)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0x10a")
// int BPF_KPROBE(do_mov_2215)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0x112")
// int BPF_KPROBE(do_mov_2216)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0x11a")
// int BPF_KPROBE(do_mov_2217)
// {
//     u64 addr = ctx->r13+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0x12d")
// int BPF_KPROBE(do_mov_2218)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_join+0x131")
// int BPF_KPROBE(do_mov_2219)
// {
//     u64 addr = ctx->bx+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x6c")
// int BPF_KPROBE(do_mov_2220)
// {
//     u64 addr = ctx->r15+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x7a")
// int BPF_KPROBE(do_mov_2221)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x82")
// int BPF_KPROBE(do_mov_2222)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x89")
// int BPF_KPROBE(do_mov_2223)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x8d")
// int BPF_KPROBE(do_mov_2224)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x95")
// int BPF_KPROBE(do_mov_2225)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x98")
// int BPF_KPROBE(do_mov_2226)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0xa1")
// int BPF_KPROBE(do_mov_2227)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x11f")
// int BPF_KPROBE(do_mov_2228)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x126")
// int BPF_KPROBE(do_mov_2229)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x12e")
// int BPF_KPROBE(do_mov_2230)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x132")
// int BPF_KPROBE(do_mov_2231)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x414")
// int BPF_KPROBE(do_mov_2232)
// {
//     u64 addr = ctx->r9+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x434")
// int BPF_KPROBE(do_mov_2233)
// {
//     u64 addr = ctx->r9+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x4e2")
// int BPF_KPROBE(do_mov_2234)
// {
//     u64 addr = ctx->r9+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x586")
// int BPF_KPROBE(do_mov_2235)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x5bd")
// int BPF_KPROBE(do_mov_2236)
// {
//     u64 addr = ctx->r9+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x5fe")
// int BPF_KPROBE(do_mov_2237)
// {
//     u64 addr = ctx->r9+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x606")
// int BPF_KPROBE(do_mov_2238)
// {
//     u64 addr = ctx->r9+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x644")
// int BPF_KPROBE(do_mov_2239)
// {
//     u64 addr = ctx->r9+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x783")
// int BPF_KPROBE(do_mov_2240)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x7b0")
// int BPF_KPROBE(do_mov_2241)
// {
//     u64 addr = ctx->r10+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x86b")
// int BPF_KPROBE(do_mov_2242)
// {
//     u64 addr = ctx->r10+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x87e")
// int BPF_KPROBE(do_mov_2243)
// {
//     u64 addr = ctx->r10+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x8f3")
// int BPF_KPROBE(do_mov_2244)
// {
//     u64 addr = ctx->r10+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x984")
// int BPF_KPROBE(do_mov_2245)
// {
//     u64 addr = ctx->r10+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mld_query_work+0x9b7")
// int BPF_KPROBE(do_mov_2246)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0xbd")
// int BPF_KPROBE(do_mov_2247)
// {
//     u64 addr = ctx->si+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0xdb")
// int BPF_KPROBE(do_mov_2248)
// {
//     u64 addr = ctx->si+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x115")
// int BPF_KPROBE(do_mov_2249)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x11d")
// int BPF_KPROBE(do_mov_2250)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x126")
// int BPF_KPROBE(do_mov_2251)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x12f")
// int BPF_KPROBE(do_mov_2252)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x138")
// int BPF_KPROBE(do_mov_2253)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x141")
// int BPF_KPROBE(do_mov_2254)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x14a")
// int BPF_KPROBE(do_mov_2255)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x153")
// int BPF_KPROBE(do_mov_2256)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x15c")
// int BPF_KPROBE(do_mov_2257)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x165")
// int BPF_KPROBE(do_mov_2258)
// {
//     u64 addr = ctx->bx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x16e")
// int BPF_KPROBE(do_mov_2259)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x177")
// int BPF_KPROBE(do_mov_2260)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x180")
// int BPF_KPROBE(do_mov_2261)
// {
//     u64 addr = ctx->bx+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x189")
// int BPF_KPROBE(do_mov_2262)
// {
//     u64 addr = ctx->bx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x192")
// int BPF_KPROBE(do_mov_2263)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x19b")
// int BPF_KPROBE(do_mov_2264)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfget+0x205")
// int BPF_KPROBE(do_mov_2265)
// {
//     u64 addr = ctx->si+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0x82")
// int BPF_KPROBE(do_mov_2266)
// {
//     u64 addr = ctx->r12+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0x98")
// int BPF_KPROBE(do_mov_2267)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0xc6")
// int BPF_KPROBE(do_mov_2268)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0xf2")
// int BPF_KPROBE(do_mov_2269)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0xfe")
// int BPF_KPROBE(do_mov_2270)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0x107")
// int BPF_KPROBE(do_mov_2271)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_dev_mc_dec+0x110")
// int BPF_KPROBE(do_mov_2272)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sock_mc_drop+0x9a")
// int BPF_KPROBE(do_mov_2273)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x1c0")
// int BPF_KPROBE(do_mov_2274)
// {
//     u64 addr = ctx->ax+ctx->r11 * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x1c5")
// int BPF_KPROBE(do_mov_2275)
// {
//     u64 addr = ctx->ax+ctx->r11 * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x1d4")
// int BPF_KPROBE(do_mov_2276)
// {
//     u64 addr = ctx->r11+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x2b6")
// int BPF_KPROBE(do_mov_2277)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x30a")
// int BPF_KPROBE(do_mov_2278)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x30c")
// int BPF_KPROBE(do_mov_2279)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x334")
// int BPF_KPROBE(do_mov_2280)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x339")
// int BPF_KPROBE(do_mov_2281)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x357")
// int BPF_KPROBE(do_mov_2282)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x3ed")
// int BPF_KPROBE(do_mov_2283)
// {
//     u64 addr = ctx->di+ctx->r11 * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x3f2")
// int BPF_KPROBE(do_mov_2284)
// {
//     u64 addr = ctx->di+ctx->r11 * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x421")
// int BPF_KPROBE(do_mov_2285)
// {
//     u64 addr = ctx->si+ctx->r11 * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x42a")
// int BPF_KPROBE(do_mov_2286)
// {
//     u64 addr = ctx->si+ctx->r11 * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x432")
// int BPF_KPROBE(do_mov_2287)
// {
//     u64 addr = ctx->r11+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x4c9")
// int BPF_KPROBE(do_mov_2288)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_source+0x4cc")
// int BPF_KPROBE(do_mov_2289)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfilter+0x112")
// int BPF_KPROBE(do_mov_2290)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfilter+0x115")
// int BPF_KPROBE(do_mov_2291)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfilter+0x12f")
// int BPF_KPROBE(do_mov_2292)
// {
//     u64 addr = ctx->si+ctx->r14 * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfilter+0x134")
// int BPF_KPROBE(do_mov_2293)
// {
//     u64 addr = ctx->si+ctx->r14 * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfilter+0x1d3")
// int BPF_KPROBE(do_mov_2294)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mc_msfilter+0x1fe")
// int BPF_KPROBE(do_mov_2295)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_sock_mc_close+0xab")
// int BPF_KPROBE(do_mov_2296)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_query+0x76")
// int BPF_KPROBE(do_mov_2297)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_query+0x88")
// int BPF_KPROBE(do_mov_2298)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_query+0x8d")
// int BPF_KPROBE(do_mov_2299)
// {
//     u64 addr = ctx->bx+0x210;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_query+0x94")
// int BPF_KPROBE(do_mov_2300)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_query+0xa0")
// int BPF_KPROBE(do_mov_2301)
// {
//     u64 addr = ctx->bx+0x218;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_report+0x76")
// int BPF_KPROBE(do_mov_2302)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_report+0x88")
// int BPF_KPROBE(do_mov_2303)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_report+0x8d")
// int BPF_KPROBE(do_mov_2304)
// {
//     u64 addr = ctx->bx+0x228;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_report+0x94")
// int BPF_KPROBE(do_mov_2305)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/igmp6_event_report+0xa0")
// int BPF_KPROBE(do_mov_2306)
// {
//     u64 addr = ctx->bx+0x230;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_dad_complete+0x25")
// int BPF_KPROBE(do_mov_2307)
// {
//     u64 addr = ctx->r12+0x2b;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_dad_complete+0x84")
// int BPF_KPROBE(do_mov_2308)
// {
//     u64 addr = ctx->r12+0x2b;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_down+0x86")
// int BPF_KPROBE(do_mov_2309)
// {
//     u64 addr = ctx->r12+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_down+0xa1")
// int BPF_KPROBE(do_mov_2310)
// {
//     u64 addr = ctx->r12+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_up+0x17")
// int BPF_KPROBE(do_mov_2311)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_up+0x1d")
// int BPF_KPROBE(do_mov_2312)
// {
//     u64 addr = ctx->di+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_up+0x25")
// int BPF_KPROBE(do_mov_2313)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_up+0x2d")
// int BPF_KPROBE(do_mov_2314)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_up+0x7b")
// int BPF_KPROBE(do_mov_2315)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x32")
// int BPF_KPROBE(do_mov_2316)
// {
//     u64 addr = ctx->di - 0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x36")
// int BPF_KPROBE(do_mov_2317)
// {
//     u64 addr = ctx->di - 0x47;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x3a")
// int BPF_KPROBE(do_mov_2318)
// {
//     u64 addr = ctx->di - 0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x3e")
// int BPF_KPROBE(do_mov_2319)
// {
//     u64 addr = ctx->di - 0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x42")
// int BPF_KPROBE(do_mov_2320)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x4f")
// int BPF_KPROBE(do_mov_2321)
// {
//     u64 addr = ctx->bx+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x64")
// int BPF_KPROBE(do_mov_2322)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x73")
// int BPF_KPROBE(do_mov_2323)
// {
//     u64 addr = ctx->bx+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x81")
// int BPF_KPROBE(do_mov_2324)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x88")
// int BPF_KPROBE(do_mov_2325)
// {
//     u64 addr = ctx->bx+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x8f")
// int BPF_KPROBE(do_mov_2326)
// {
//     u64 addr = ctx->bx+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0xb0")
// int BPF_KPROBE(do_mov_2327)
// {
//     u64 addr = ctx->bx+0x100;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0xc5")
// int BPF_KPROBE(do_mov_2328)
// {
//     u64 addr = ctx->bx+0x108;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0xcc")
// int BPF_KPROBE(do_mov_2329)
// {
//     u64 addr = ctx->bx+0x118;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0xd7")
// int BPF_KPROBE(do_mov_2330)
// {
//     u64 addr = ctx->bx+0x110;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0xf4")
// int BPF_KPROBE(do_mov_2331)
// {
//     u64 addr = ctx->bx+0x158;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x109")
// int BPF_KPROBE(do_mov_2332)
// {
//     u64 addr = ctx->bx+0x160;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x110")
// int BPF_KPROBE(do_mov_2333)
// {
//     u64 addr = ctx->bx+0x170;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x11b")
// int BPF_KPROBE(do_mov_2334)
// {
//     u64 addr = ctx->bx+0x168;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x138")
// int BPF_KPROBE(do_mov_2335)
// {
//     u64 addr = ctx->bx+0x1b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x14d")
// int BPF_KPROBE(do_mov_2336)
// {
//     u64 addr = ctx->bx+0x1b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x154")
// int BPF_KPROBE(do_mov_2337)
// {
//     u64 addr = ctx->bx+0x1c8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x15f")
// int BPF_KPROBE(do_mov_2338)
// {
//     u64 addr = ctx->bx+0x1c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x172")
// int BPF_KPROBE(do_mov_2339)
// {
//     u64 addr = ctx->bx+0x218;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x184")
// int BPF_KPROBE(do_mov_2340)
// {
//     u64 addr = ctx->bx+0x208;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x199")
// int BPF_KPROBE(do_mov_2341)
// {
//     u64 addr = ctx->bx+0x210;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1a7")
// int BPF_KPROBE(do_mov_2342)
// {
//     u64 addr = ctx->bx+0x220;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1ae")
// int BPF_KPROBE(do_mov_2343)
// {
//     u64 addr = ctx->bx+0x228;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1b5")
// int BPF_KPROBE(do_mov_2344)
// {
//     u64 addr = ctx->bx+0x230;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1c0")
// int BPF_KPROBE(do_mov_2345)
// {
//     u64 addr = ctx->bx+0x238;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1d6")
// int BPF_KPROBE(do_mov_2346)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1de")
// int BPF_KPROBE(do_mov_2347)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1e6")
// int BPF_KPROBE(do_mov_2348)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x1ec")
// int BPF_KPROBE(do_mov_2349)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_init_dev+0x22b")
// int BPF_KPROBE(do_mov_2350)
// {
//     u64 addr = ctx->bx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x6d")
// int BPF_KPROBE(do_mov_2351)
// {
//     u64 addr = ctx->r13+0x218;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x7b")
// int BPF_KPROBE(do_mov_2352)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x82")
// int BPF_KPROBE(do_mov_2353)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x8a")
// int BPF_KPROBE(do_mov_2354)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x8e")
// int BPF_KPROBE(do_mov_2355)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0xe5")
// int BPF_KPROBE(do_mov_2356)
// {
//     u64 addr = ctx->r13+0x230;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0xf3")
// int BPF_KPROBE(do_mov_2357)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0xfa")
// int BPF_KPROBE(do_mov_2358)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x102")
// int BPF_KPROBE(do_mov_2359)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x106")
// int BPF_KPROBE(do_mov_2360)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x15a")
// int BPF_KPROBE(do_mov_2361)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x181")
// int BPF_KPROBE(do_mov_2362)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x1ad")
// int BPF_KPROBE(do_mov_2363)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x1b9")
// int BPF_KPROBE(do_mov_2364)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x1c2")
// int BPF_KPROBE(do_mov_2365)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_destroy_dev+0x1cb")
// int BPF_KPROBE(do_mov_2366)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_pre_exit_net+0xd")
// int BPF_KPROBE(do_mov_2367)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_pre_exit_net+0x17")
// int BPF_KPROBE(do_mov_2368)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0x34")
// int BPF_KPROBE(do_mov_2369)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0x42")
// int BPF_KPROBE(do_mov_2370)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0x51")
// int BPF_KPROBE(do_mov_2371)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0x9b")
// int BPF_KPROBE(do_mov_2372)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0xab")
// int BPF_KPROBE(do_mov_2373)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0xbb")
// int BPF_KPROBE(do_mov_2374)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0xc7")
// int BPF_KPROBE(do_mov_2375)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0xd7")
// int BPF_KPROBE(do_mov_2376)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frags_init_net+0xe9")
// int BPF_KPROBE(do_mov_2377)
// {
//     u64 addr = ctx->bx+0x698;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0xea")
// int BPF_KPROBE(do_mov_2378)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x13c")
// int BPF_KPROBE(do_mov_2379)
// {
//     u64 addr = ctx->r12+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x153")
// int BPF_KPROBE(do_mov_2380)
// {
//     u64 addr = ctx->r12+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x26c")
// int BPF_KPROBE(do_mov_2381)
// {
//     u64 addr = ctx->r14+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x33e")
// int BPF_KPROBE(do_mov_2382)
// {
//     u64 addr = ctx->r14+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x345")
// int BPF_KPROBE(do_mov_2383)
// {
//     u64 addr = ctx->r14+0x91;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x380")
// int BPF_KPROBE(do_mov_2384)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x385")
// int BPF_KPROBE(do_mov_2385)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x3df")
// int BPF_KPROBE(do_mov_2386)
// {
//     u64 addr = ctx->r14+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x3f0")
// int BPF_KPROBE(do_mov_2387)
// {
//     u64 addr = ctx->r14+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x40d")
// int BPF_KPROBE(do_mov_2388)
// {
//     u64 addr = ctx->r14+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x471")
// int BPF_KPROBE(do_mov_2389)
// {
//     u64 addr = ctx->r14+0x92;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x489")
// int BPF_KPROBE(do_mov_2390)
// {
//     u64 addr = ctx->r14+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x491")
// int BPF_KPROBE(do_mov_2391)
// {
//     u64 addr = ctx->r14+0x91;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x4c0")
// int BPF_KPROBE(do_mov_2392)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x4fa")
// int BPF_KPROBE(do_mov_2393)
// {
//     u64 addr = ctx->r14+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x6f4")
// int BPF_KPROBE(do_mov_2394)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x71e")
// int BPF_KPROBE(do_mov_2395)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x7e5")
// int BPF_KPROBE(do_mov_2396)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x824")
// int BPF_KPROBE(do_mov_2397)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x85a")
// int BPF_KPROBE(do_mov_2398)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x86d")
// int BPF_KPROBE(do_mov_2399)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x88c")
// int BPF_KPROBE(do_mov_2400)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x8b9")
// int BPF_KPROBE(do_mov_2401)
// {
//     u64 addr = ctx->r12+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x8c7")
// int BPF_KPROBE(do_mov_2402)
// {
//     u64 addr = ctx->r12+0x3c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x964")
// int BPF_KPROBE(do_mov_2403)
// {
//     u64 addr = ctx->r14+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x971")
// int BPF_KPROBE(do_mov_2404)
// {
//     u64 addr = ctx->r14+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x979")
// int BPF_KPROBE(do_mov_2405)
// {
//     u64 addr = ctx->r14+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0x981")
// int BPF_KPROBE(do_mov_2406)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_frag_rcv+0xc5e")
// int BPF_KPROBE(do_mov_2407)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_frag_expire+0x100")
// int BPF_KPROBE(do_mov_2408)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_restore_cb+0xe")
// int BPF_KPROBE(do_mov_2409)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_restore_cb+0x19")
// int BPF_KPROBE(do_mov_2410)
// {
//     u64 addr = ctx->di+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_restore_cb+0x1e")
// int BPF_KPROBE(do_mov_2411)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x17")
// int BPF_KPROBE(do_mov_2412)
// {
//     u64 addr = ctx->ax+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x22")
// int BPF_KPROBE(do_mov_2413)
// {
//     u64 addr = ctx->ax+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x26")
// int BPF_KPROBE(do_mov_2414)
// {
//     u64 addr = ctx->ax+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x2f")
// int BPF_KPROBE(do_mov_2415)
// {
//     u64 addr = ctx->ax+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x58")
// int BPF_KPROBE(do_mov_2416)
// {
//     u64 addr = ctx->ax+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x60")
// int BPF_KPROBE(do_mov_2417)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x67")
// int BPF_KPROBE(do_mov_2418)
// {
//     u64 addr = ctx->ax+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x6e")
// int BPF_KPROBE(do_mov_2419)
// {
//     u64 addr = ctx->ax+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x75")
// int BPF_KPROBE(do_mov_2420)
// {
//     u64 addr = ctx->ax+0x35;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0x82")
// int BPF_KPROBE(do_mov_2421)
// {
//     u64 addr = ctx->ax+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_fill_cb+0xb3")
// int BPF_KPROBE(do_mov_2422)
// {
//     u64 addr = ctx->ax+0x37;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_init_sock+0x14")
// int BPF_KPROBE(do_mov_2423)
// {
//     u64 addr = ctx->bx+0x4a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_init_sock+0x1f")
// int BPF_KPROBE(do_mov_2424)
// {
//     u64 addr = ctx->bx+0x890;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rx_dst_set+0x2f")
// int BPF_KPROBE(do_mov_2425)
// {
//     u64 addr = ctx->di+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rx_dst_set+0x3c")
// int BPF_KPROBE(do_mov_2426)
// {
//     u64 addr = ctx->di+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_sk_rx_dst_set+0x4b")
// int BPF_KPROBE(do_mov_2427)
// {
//     u64 addr = ctx->di+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_parse_md5_keys+0x53")
// int BPF_KPROBE(do_mov_2428)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x3a")
// int BPF_KPROBE(do_mov_2429)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x3d")
// int BPF_KPROBE(do_mov_2430)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x48")
// int BPF_KPROBE(do_mov_2431)
// {
//     u64 addr = ctx->si+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x4f")
// int BPF_KPROBE(do_mov_2432)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x55")
// int BPF_KPROBE(do_mov_2433)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x59")
// int BPF_KPROBE(do_mov_2434)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x60")
// int BPF_KPROBE(do_mov_2435)
// {
//     u64 addr = ctx->si+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x68")
// int BPF_KPROBE(do_mov_2436)
// {
//     u64 addr = ctx->si+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x70")
// int BPF_KPROBE(do_mov_2437)
// {
//     u64 addr = ctx->si+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x78")
// int BPF_KPROBE(do_mov_2438)
// {
//     u64 addr = ctx->si+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x84")
// int BPF_KPROBE(do_mov_2439)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x88")
// int BPF_KPROBE(do_mov_2440)
// {
//     u64 addr = ctx->ax+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x8f")
// int BPF_KPROBE(do_mov_2441)
// {
//     u64 addr = ctx->ax+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_skb+0x82")
// int BPF_KPROBE(do_mov_2442)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_skb+0x8e")
// int BPF_KPROBE(do_mov_2443)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_skb+0x10c")
// int BPF_KPROBE(do_mov_2444)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_skb+0x117")
// int BPF_KPROBE(do_mov_2445)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_md5_hash_skb+0x11f")
// int BPF_KPROBE(do_mov_2446)
// {
//     u64 addr = ctx->r15+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0xb1")
// int BPF_KPROBE(do_mov_2447)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x111")
// int BPF_KPROBE(do_mov_2448)
// {
//     u64 addr = ctx->bx+0x6a4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x11c")
// int BPF_KPROBE(do_mov_2449)
// {
//     u64 addr = ctx->bx+0x70c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x135")
// int BPF_KPROBE(do_mov_2450)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x139")
// int BPF_KPROBE(do_mov_2451)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x13d")
// int BPF_KPROBE(do_mov_2452)
// {
//     u64 addr = ctx->bx+0x8f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x188")
// int BPF_KPROBE(do_mov_2453)
// {
//     u64 addr = ctx->bx+0x4a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x1aa")
// int BPF_KPROBE(do_mov_2454)
// {
//     u64 addr = ctx->bx+0x2c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x1b5")
// int BPF_KPROBE(do_mov_2455)
// {
//     u64 addr = ctx->bx+0x890;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x1d8")
// int BPF_KPROBE(do_mov_2456)
// {
//     u64 addr = ctx->bx+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x1e0")
// int BPF_KPROBE(do_mov_2457)
// {
//     u64 addr = ctx->bx+0x4a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x1f1")
// int BPF_KPROBE(do_mov_2458)
// {
//     u64 addr = ctx->bx+0x2c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x1fc")
// int BPF_KPROBE(do_mov_2459)
// {
//     u64 addr = ctx->bx+0x890;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x207")
// int BPF_KPROBE(do_mov_2460)
// {
//     u64 addr = ctx->bx+0x1e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x214")
// int BPF_KPROBE(do_mov_2461)
// {
//     u64 addr = ctx->bx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x329")
// int BPF_KPROBE(do_mov_2462)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x330")
// int BPF_KPROBE(do_mov_2463)
// {
//     u64 addr = ctx->bx+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x33e")
// int BPF_KPROBE(do_mov_2464)
// {
//     u64 addr = ctx->bx+0x8c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x345")
// int BPF_KPROBE(do_mov_2465)
// {
//     u64 addr = ctx->bx+0x1f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x36f")
// int BPF_KPROBE(do_mov_2466)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x381")
// int BPF_KPROBE(do_mov_2467)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x389")
// int BPF_KPROBE(do_mov_2468)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x391")
// int BPF_KPROBE(do_mov_2469)
// {
//     u64 addr = ctx->bx+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x3a8")
// int BPF_KPROBE(do_mov_2470)
// {
//     u64 addr = ctx->bx+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x3b9")
// int BPF_KPROBE(do_mov_2471)
// {
//     u64 addr = ctx->bx+0x6ba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x3c8")
// int BPF_KPROBE(do_mov_2472)
// {
//     u64 addr = ctx->bx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x3f5")
// int BPF_KPROBE(do_mov_2473)
// {
//     u64 addr = ctx->bx+0x1fc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x42d")
// int BPF_KPROBE(do_mov_2474)
// {
//     u64 addr = ctx->bx+0x5cc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x490")
// int BPF_KPROBE(do_mov_2475)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x494")
// int BPF_KPROBE(do_mov_2476)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x508")
// int BPF_KPROBE(do_mov_2477)
// {
//     u64 addr = ctx->bx+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x50f")
// int BPF_KPROBE(do_mov_2478)
// {
//     u64 addr = ctx->bx+0x8c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x5b1")
// int BPF_KPROBE(do_mov_2479)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_connect+0x61b")
// int BPF_KPROBE(do_mov_2480)
// {
//     u64 addr = ctx->bx+0x70c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x177")
// int BPF_KPROBE(do_mov_2481)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x184")
// int BPF_KPROBE(do_mov_2482)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x18b")
// int BPF_KPROBE(do_mov_2483)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x193")
// int BPF_KPROBE(do_mov_2484)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x19e")
// int BPF_KPROBE(do_mov_2485)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x1a7")
// int BPF_KPROBE(do_mov_2486)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x1b7")
// int BPF_KPROBE(do_mov_2487)
// {
//     u64 addr = ctx->bx+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x1c2")
// int BPF_KPROBE(do_mov_2488)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x1cd")
// int BPF_KPROBE(do_mov_2489)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x201")
// int BPF_KPROBE(do_mov_2490)
// {
//     u64 addr = ctx->bx+0xd;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x20f")
// int BPF_KPROBE(do_mov_2491)
// {
//     u64 addr = ctx->bx+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x22a")
// int BPF_KPROBE(do_mov_2492)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x23e")
// int BPF_KPROBE(do_mov_2493)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x2c7")
// int BPF_KPROBE(do_mov_2494)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x2ce")
// int BPF_KPROBE(do_mov_2495)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x364")
// int BPF_KPROBE(do_mov_2496)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x372")
// int BPF_KPROBE(do_mov_2497)
// {
//     u64 addr = ctx->r12+0x8a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x37f")
// int BPF_KPROBE(do_mov_2498)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x3e2")
// int BPF_KPROBE(do_mov_2499)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x3f8")
// int BPF_KPROBE(do_mov_2500)
// {
//     u64 addr = ctx->r12+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x413")
// int BPF_KPROBE(do_mov_2501)
// {
//     u64 addr = ctx->r12+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x421")
// int BPF_KPROBE(do_mov_2502)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x4e1")
// int BPF_KPROBE(do_mov_2503)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x505")
// int BPF_KPROBE(do_mov_2504)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x617")
// int BPF_KPROBE(do_mov_2505)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x629")
// int BPF_KPROBE(do_mov_2506)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x630")
// int BPF_KPROBE(do_mov_2507)
// {
//     u64 addr = ctx->bx+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x7c7")
// int BPF_KPROBE(do_mov_2508)
// {
//     u64 addr = ctx->r10+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x7d2")
// int BPF_KPROBE(do_mov_2509)
// {
//     u64 addr = ctx->r10+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_response+0x7da")
// int BPF_KPROBE(do_mov_2510)
// {
//     u64 addr = ctx->r10+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_check+0x38")
// int BPF_KPROBE(do_mov_2511)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_check+0x45")
// int BPF_KPROBE(do_mov_2512)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_check+0x51")
// int BPF_KPROBE(do_mov_2513)
// {
//     u64 addr = ctx->bx+0x8a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_synack+0x8e")
// int BPF_KPROBE(do_mov_2514)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_synack+0x9c")
// int BPF_KPROBE(do_mov_2515)
// {
//     u64 addr = ctx->r12+0x8a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_synack+0xa5")
// int BPF_KPROBE(do_mov_2516)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_synack+0xb6")
// int BPF_KPROBE(do_mov_2517)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_synack+0xba")
// int BPF_KPROBE(do_mov_2518)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_send_synack+0xea")
// int BPF_KPROBE(do_mov_2519)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_route_req+0x3e")
// int BPF_KPROBE(do_mov_2520)
// {
//     u64 addr = ctx->r13+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_route_req+0x42")
// int BPF_KPROBE(do_mov_2521)
// {
//     u64 addr = ctx->r13+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_route_req+0x60")
// int BPF_KPROBE(do_mov_2522)
// {
//     u64 addr = ctx->r13+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_route_req+0x64")
// int BPF_KPROBE(do_mov_2523)
// {
//     u64 addr = ctx->r13+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_route_req+0xc4")
// int BPF_KPROBE(do_mov_2524)
// {
//     u64 addr = ctx->r13+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_route_req+0x114")
// int BPF_KPROBE(do_mov_2525)
// {
//     u64 addr = ctx->r13+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0xc5")
// int BPF_KPROBE(do_mov_2526)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x240")
// int BPF_KPROBE(do_mov_2527)
// {
//     u64 addr = ctx->r12+0x900;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x271")
// int BPF_KPROBE(do_mov_2528)
// {
//     u64 addr = ctx->r12+0x8fa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x299")
// int BPF_KPROBE(do_mov_2529)
// {
//     u64 addr = ctx->r12+0x90c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x2c3")
// int BPF_KPROBE(do_mov_2530)
// {
//     u64 addr = ctx->r12+0x8f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x2f4")
// int BPF_KPROBE(do_mov_2531)
// {
//     u64 addr = ctx->r14+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x2ff")
// int BPF_KPROBE(do_mov_2532)
// {
//     u64 addr = ctx->r14+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x42e")
// int BPF_KPROBE(do_mov_2533)
// {
//     u64 addr = ctx->r12+0x114;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x43b")
// int BPF_KPROBE(do_mov_2534)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x448")
// int BPF_KPROBE(do_mov_2535)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_do_rcv+0x455")
// int BPF_KPROBE(do_mov_2536)
// {
//     u64 addr = ctx->r12+0x7a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_err+0x1d5")
// int BPF_KPROBE(do_mov_2537)
// {
//     u64 addr = ctx->r12+0x224;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_err+0x303")
// int BPF_KPROBE(do_mov_2538)
// {
//     u64 addr = ctx->r12+0x878;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_err+0x44e")
// int BPF_KPROBE(do_mov_2539)
// {
//     u64 addr = ctx->r12+0x220;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_err+0x46f")
// int BPF_KPROBE(do_mov_2540)
// {
//     u64 addr = ctx->r12+0x220;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x9e")
// int BPF_KPROBE(do_mov_2541)
// {
//     u64 addr = ctx->ax+0x1f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0xd0")
// int BPF_KPROBE(do_mov_2542)
// {
//     u64 addr = ctx->dx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0xf2")
// int BPF_KPROBE(do_mov_2543)
// {
//     u64 addr = ctx->dx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0xfa")
// int BPF_KPROBE(do_mov_2544)
// {
//     u64 addr = ctx->dx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x117")
// int BPF_KPROBE(do_mov_2545)
// {
//     u64 addr = ctx->r12+0x308;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x12d")
// int BPF_KPROBE(do_mov_2546)
// {
//     u64 addr = ctx->r12+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x14f")
// int BPF_KPROBE(do_mov_2547)
// {
//     u64 addr = ctx->r12+0x950;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x157")
// int BPF_KPROBE(do_mov_2548)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x162")
// int BPF_KPROBE(do_mov_2549)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x167")
// int BPF_KPROBE(do_mov_2550)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x174")
// int BPF_KPROBE(do_mov_2551)
// {
//     u64 addr = ctx->r12+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x17c")
// int BPF_KPROBE(do_mov_2552)
// {
//     u64 addr = ctx->r12+0x8c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x18c")
// int BPF_KPROBE(do_mov_2553)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x191")
// int BPF_KPROBE(do_mov_2554)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x19a")
// int BPF_KPROBE(do_mov_2555)
// {
//     u64 addr = ctx->r12+0x318;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1a6")
// int BPF_KPROBE(do_mov_2556)
// {
//     u64 addr = ctx->r12+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1ab")
// int BPF_KPROBE(do_mov_2557)
// {
//     u64 addr = ctx->r12+0x918;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1b7")
// int BPF_KPROBE(do_mov_2558)
// {
//     u64 addr = ctx->r12+0x920;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1c3")
// int BPF_KPROBE(do_mov_2559)
// {
//     u64 addr = ctx->r12+0x928;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1d6")
// int BPF_KPROBE(do_mov_2560)
// {
//     u64 addr = ctx->r12+0x938;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1e2")
// int BPF_KPROBE(do_mov_2561)
// {
//     u64 addr = ctx->r12+0x904;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1eb")
// int BPF_KPROBE(do_mov_2562)
// {
//     u64 addr = ctx->r12+0x930;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x1fb")
// int BPF_KPROBE(do_mov_2563)
// {
//     u64 addr = ctx->r12+0x900;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x228")
// int BPF_KPROBE(do_mov_2564)
// {
//     u64 addr = ctx->r12+0x8fa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x245")
// int BPF_KPROBE(do_mov_2565)
// {
//     u64 addr = ctx->r12+0x90c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x26d")
// int BPF_KPROBE(do_mov_2566)
// {
//     u64 addr = ctx->r12+0x8f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x28f")
// int BPF_KPROBE(do_mov_2567)
// {
//     u64 addr = ctx->r12+0x909;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x2b1")
// int BPF_KPROBE(do_mov_2568)
// {
//     u64 addr = ctx->r12+0x930;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x2b9")
// int BPF_KPROBE(do_mov_2569)
// {
//     u64 addr = ctx->r12+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x2cf")
// int BPF_KPROBE(do_mov_2570)
// {
//     u64 addr = ctx->r12+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x32b")
// int BPF_KPROBE(do_mov_2571)
// {
//     u64 addr = ctx->r12+0x620;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x346")
// int BPF_KPROBE(do_mov_2572)
// {
//     u64 addr = ctx->r12+0x310;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x352")
// int BPF_KPROBE(do_mov_2573)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x3c0")
// int BPF_KPROBE(do_mov_2574)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x3d1")
// int BPF_KPROBE(do_mov_2575)
// {
//     u64 addr = ctx->r12+0x8b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x3e0")
// int BPF_KPROBE(do_mov_2576)
// {
//     u64 addr = ctx->r13+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x40b")
// int BPF_KPROBE(do_mov_2577)
// {
//     u64 addr = ctx->r12+0x938;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x41f")
// int BPF_KPROBE(do_mov_2578)
// {
//     u64 addr = ctx->r13+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x456")
// int BPF_KPROBE(do_mov_2579)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x460")
// int BPF_KPROBE(do_mov_2580)
// {
//     u64 addr = ctx->bx+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x515")
// int BPF_KPROBE(do_mov_2581)
// {
//     u64 addr = ctx->r12+0x4d6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x645")
// int BPF_KPROBE(do_mov_2582)
// {
//     u64 addr = ctx->ax+0x308;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x65a")
// int BPF_KPROBE(do_mov_2583)
// {
//     u64 addr = ctx->r12+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x669")
// int BPF_KPROBE(do_mov_2584)
// {
//     u64 addr = ctx->r12+0x950;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x684")
// int BPF_KPROBE(do_mov_2585)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x687")
// int BPF_KPROBE(do_mov_2586)
// {
//     u64 addr = ctx->r12+0x4a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6a6")
// int BPF_KPROBE(do_mov_2587)
// {
//     u64 addr = ctx->r12+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6ae")
// int BPF_KPROBE(do_mov_2588)
// {
//     u64 addr = ctx->r12+0x8c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6bc")
// int BPF_KPROBE(do_mov_2589)
// {
//     u64 addr = ctx->r12+0x2c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6c8")
// int BPF_KPROBE(do_mov_2590)
// {
//     u64 addr = ctx->r12+0x890;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6d4")
// int BPF_KPROBE(do_mov_2591)
// {
//     u64 addr = ctx->r12+0x918;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6e0")
// int BPF_KPROBE(do_mov_2592)
// {
//     u64 addr = ctx->r12+0x920;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6ec")
// int BPF_KPROBE(do_mov_2593)
// {
//     u64 addr = ctx->r12+0x928;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x6f8")
// int BPF_KPROBE(do_mov_2594)
// {
//     u64 addr = ctx->r12+0x938;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x704")
// int BPF_KPROBE(do_mov_2595)
// {
//     u64 addr = ctx->r12+0x930;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x728")
// int BPF_KPROBE(do_mov_2596)
// {
//     u64 addr = ctx->r12+0x900;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x74d")
// int BPF_KPROBE(do_mov_2597)
// {
//     u64 addr = ctx->r12+0x90c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x761")
// int BPF_KPROBE(do_mov_2598)
// {
//     u64 addr = ctx->r12+0x8fa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_syn_recv_sock+0x773")
// int BPF_KPROBE(do_mov_2599)
// {
//     u64 addr = ctx->r12+0x8f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x12a")
// int BPF_KPROBE(do_mov_2600)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x18a")
// int BPF_KPROBE(do_mov_2601)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x1c6")
// int BPF_KPROBE(do_mov_2602)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x1e2")
// int BPF_KPROBE(do_mov_2603)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x248")
// int BPF_KPROBE(do_mov_2604)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x251")
// int BPF_KPROBE(do_mov_2605)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x69d")
// int BPF_KPROBE(do_mov_2606)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x6f4")
// int BPF_KPROBE(do_mov_2607)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0x71e")
// int BPF_KPROBE(do_mov_2608)
// {
//     u64 addr = ctx->r12+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0xd29")
// int BPF_KPROBE(do_mov_2609)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0xd93")
// int BPF_KPROBE(do_mov_2610)
// {
//     u64 addr = ctx->r13+0x580;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0xdc7")
// int BPF_KPROBE(do_mov_2611)
// {
//     u64 addr = ctx->r13+0x584;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_rcv+0xe0d")
// int BPF_KPROBE(do_mov_2612)
// {
//     u64 addr = ctx->r13+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_get_syncookie+0x82")
// int BPF_KPROBE(do_mov_2613)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_get_syncookie+0xb4")
// int BPF_KPROBE(do_mov_2614)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_get_syncookie+0xd1")
// int BPF_KPROBE(do_mov_2615)
// {
//     u64 addr = ctx->bx+0x6a4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_early_demux+0xcc")
// int BPF_KPROBE(do_mov_2616)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_early_demux+0xd5")
// int BPF_KPROBE(do_mov_2617)
// {
//     u64 addr = ctx->bx+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp_v6_early_demux+0x142")
// int BPF_KPROBE(do_mov_2618)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_update_dst+0x22")
// int BPF_KPROBE(do_mov_2619)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_update_dst+0x25")
// int BPF_KPROBE(do_mov_2620)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_update_dst+0x50")
// int BPF_KPROBE(do_mov_2621)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_update_dst+0x54")
// int BPF_KPROBE(do_mov_2622)
// {
//     u64 addr = ctx->ax+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_update_dst+0x68")
// int BPF_KPROBE(do_mov_2623)
// {
//     u64 addr = ctx->ax+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_update_dst+0x6c")
// int BPF_KPROBE(do_mov_2624)
// {
//     u64 addr = ctx->ax+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_exthdr+0x3d")
// int BPF_KPROBE(do_mov_2625)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_exthdr+0x47")
// int BPF_KPROBE(do_mov_2626)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_exthdr+0x5d")
// int BPF_KPROBE(do_mov_2627)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_exthdr+0x65")
// int BPF_KPROBE(do_mov_2628)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_exthdr+0x68")
// int BPF_KPROBE(do_mov_2629)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_option+0x2e")
// int BPF_KPROBE(do_mov_2630)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_option+0x38")
// int BPF_KPROBE(do_mov_2631)
// {
//     u64 addr = ctx->dx+ctx->di * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_option+0x50")
// int BPF_KPROBE(do_mov_2632)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_option+0x56")
// int BPF_KPROBE(do_mov_2633)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_option+0x63")
// int BPF_KPROBE(do_mov_2634)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dup_options+0x49")
// int BPF_KPROBE(do_mov_2635)
// {
//     u64 addr = ctx->r8+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dup_options+0x59")
// int BPF_KPROBE(do_mov_2636)
// {
//     u64 addr = ctx->r8+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dup_options+0x69")
// int BPF_KPROBE(do_mov_2637)
// {
//     u64 addr = ctx->r8+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dup_options+0x79")
// int BPF_KPROBE(do_mov_2638)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_dup_options+0x7d")
// int BPF_KPROBE(do_mov_2639)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x27")
// int BPF_KPROBE(do_mov_2640)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x2e")
// int BPF_KPROBE(do_mov_2641)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x36")
// int BPF_KPROBE(do_mov_2642)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x3e")
// int BPF_KPROBE(do_mov_2643)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x46")
// int BPF_KPROBE(do_mov_2644)
// {
//     u64 addr = ctx->di+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x4e")
// int BPF_KPROBE(do_mov_2645)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x56")
// int BPF_KPROBE(do_mov_2646)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x5e")
// int BPF_KPROBE(do_mov_2647)
// {
//     u64 addr = ctx->di+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ipv6_fixup_options+0x6a")
// int BPF_KPROBE(do_mov_2648)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x2a7")
// int BPF_KPROBE(do_mov_2649)
// {
//     u64 addr = ctx->r10+0x3a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x2b1")
// int BPF_KPROBE(do_mov_2650)
// {
//     u64 addr = ctx->r10+0x32;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x5f3")
// int BPF_KPROBE(do_mov_2651)
// {
//     u64 addr = ctx->r10+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x6c7")
// int BPF_KPROBE(do_mov_2652)
// {
//     u64 addr = ctx->r10+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x6e3")
// int BPF_KPROBE(do_mov_2653)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x6e7")
// int BPF_KPROBE(do_mov_2654)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x6eb")
// int BPF_KPROBE(do_mov_2655)
// {
//     u64 addr = ctx->r11+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x6ef")
// int BPF_KPROBE(do_mov_2656)
// {
//     u64 addr = ctx->r11+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_parse_tlv+0x72e")
// int BPF_KPROBE(do_mov_2657)
// {
//     u64 addr = ctx->r10+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_destopt_rcv+0x97")
// int BPF_KPROBE(do_mov_2658)
// {
//     u64 addr = ctx->r12+0x32;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_destopt_rcv+0x9f")
// int BPF_KPROBE(do_mov_2659)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_destopt_rcv+0x157")
// int BPF_KPROBE(do_mov_2660)
// {
//     u64 addr = ctx->r12+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x14e")
// int BPF_KPROBE(do_mov_2661)
// {
//     u64 addr = ctx->dx+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1e2")
// int BPF_KPROBE(do_mov_2662)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1f1")
// int BPF_KPROBE(do_mov_2663)
// {
//     u64 addr = ctx->r14+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x241")
// int BPF_KPROBE(do_mov_2664)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x244")
// int BPF_KPROBE(do_mov_2665)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x257")
// int BPF_KPROBE(do_mov_2666)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x25c")
// int BPF_KPROBE(do_mov_2667)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x278")
// int BPF_KPROBE(do_mov_2668)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x32e")
// int BPF_KPROBE(do_mov_2669)
// {
//     u64 addr = ctx->ax+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x3ae")
// int BPF_KPROBE(do_mov_2670)
// {
//     u64 addr = ctx->r14+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x3ec")
// int BPF_KPROBE(do_mov_2671)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x3f1")
// int BPF_KPROBE(do_mov_2672)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x40d")
// int BPF_KPROBE(do_mov_2673)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x647")
// int BPF_KPROBE(do_mov_2674)
// {
//     u64 addr = ctx->si+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x71c")
// int BPF_KPROBE(do_mov_2675)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x720")
// int BPF_KPROBE(do_mov_2676)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x72f")
// int BPF_KPROBE(do_mov_2677)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x73a")
// int BPF_KPROBE(do_mov_2678)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x7c0")
// int BPF_KPROBE(do_mov_2679)
// {
//     u64 addr = ctx->r13+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x7db")
// int BPF_KPROBE(do_mov_2680)
// {
//     u64 addr = ctx->r13+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x815")
// int BPF_KPROBE(do_mov_2681)
// {
//     u64 addr = ctx->r13+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x848")
// int BPF_KPROBE(do_mov_2682)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x852")
// int BPF_KPROBE(do_mov_2683)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x865")
// int BPF_KPROBE(do_mov_2684)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x883")
// int BPF_KPROBE(do_mov_2685)
// {
//     u64 addr = ctx->cx+ctx->dx * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x902")
// int BPF_KPROBE(do_mov_2686)
// {
//     u64 addr = ctx->ax+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x947")
// int BPF_KPROBE(do_mov_2687)
// {
//     u64 addr = ctx->r13+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x94c")
// int BPF_KPROBE(do_mov_2688)
// {
//     u64 addr = ctx->r13+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x959")
// int BPF_KPROBE(do_mov_2689)
// {
//     u64 addr = ctx->r13+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x962")
// int BPF_KPROBE(do_mov_2690)
// {
//     u64 addr = ctx->r13+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xa29")
// int BPF_KPROBE(do_mov_2691)
// {
//     u64 addr = ctx->ax+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xa2e")
// int BPF_KPROBE(do_mov_2692)
// {
//     u64 addr = ctx->ax+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xa5b")
// int BPF_KPROBE(do_mov_2693)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xaaf")
// int BPF_KPROBE(do_mov_2694)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xac5")
// int BPF_KPROBE(do_mov_2695)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xb0f")
// int BPF_KPROBE(do_mov_2696)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xb6d")
// int BPF_KPROBE(do_mov_2697)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xbab")
// int BPF_KPROBE(do_mov_2698)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xde8")
// int BPF_KPROBE(do_mov_2699)
// {
//     u64 addr = ctx->r13+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xded")
// int BPF_KPROBE(do_mov_2700)
// {
//     u64 addr = ctx->r13+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xdff")
// int BPF_KPROBE(do_mov_2701)
// {
//     u64 addr = ctx->r13+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xe08")
// int BPF_KPROBE(do_mov_2702)
// {
//     u64 addr = ctx->r13+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xe15")
// int BPF_KPROBE(do_mov_2703)
// {
//     u64 addr = ctx->r13+0x2e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xe1c")
// int BPF_KPROBE(do_mov_2704)
// {
//     u64 addr = ctx->r13+0x32;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xeb1")
// int BPF_KPROBE(do_mov_2705)
// {
//     u64 addr = ctx->r13+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xebf")
// int BPF_KPROBE(do_mov_2706)
// {
//     u64 addr = ctx->r13+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xf05")
// int BPF_KPROBE(do_mov_2707)
// {
//     u64 addr = ctx->r13+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xf0d")
// int BPF_KPROBE(do_mov_2708)
// {
//     u64 addr = ctx->r13+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xf20")
// int BPF_KPROBE(do_mov_2709)
// {
//     u64 addr = ctx->r13+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xf38")
// int BPF_KPROBE(do_mov_2710)
// {
//     u64 addr = ctx->r13+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xf46")
// int BPF_KPROBE(do_mov_2711)
// {
//     u64 addr = ctx->r13+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0xf54")
// int BPF_KPROBE(do_mov_2712)
// {
//     u64 addr = ctx->r13+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1072")
// int BPF_KPROBE(do_mov_2713)
// {
//     u64 addr = ctx->r13+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1080")
// int BPF_KPROBE(do_mov_2714)
// {
//     u64 addr = ctx->r13+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x10c0")
// int BPF_KPROBE(do_mov_2715)
// {
//     u64 addr = ctx->r13+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x10c8")
// int BPF_KPROBE(do_mov_2716)
// {
//     u64 addr = ctx->r13+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x10dd")
// int BPF_KPROBE(do_mov_2717)
// {
//     u64 addr = ctx->r13+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x10ec")
// int BPF_KPROBE(do_mov_2718)
// {
//     u64 addr = ctx->r13+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x10fa")
// int BPF_KPROBE(do_mov_2719)
// {
//     u64 addr = ctx->r13+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1108")
// int BPF_KPROBE(do_mov_2720)
// {
//     u64 addr = ctx->r13+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x112d")
// int BPF_KPROBE(do_mov_2721)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1151")
// int BPF_KPROBE(do_mov_2722)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1170")
// int BPF_KPROBE(do_mov_2723)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1192")
// int BPF_KPROBE(do_mov_2724)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x11ef")
// int BPF_KPROBE(do_mov_2725)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1212")
// int BPF_KPROBE(do_mov_2726)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1237")
// int BPF_KPROBE(do_mov_2727)
// {
//     u64 addr = ctx->r13+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rthdr_rcv+0x1264")
// int BPF_KPROBE(do_mov_2728)
// {
//     u64 addr = ctx->r13+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_parse_hopopts+0x8e")
// int BPF_KPROBE(do_mov_2729)
// {
//     u64 addr = ctx->r12+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x69")
// int BPF_KPROBE(do_mov_2730)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x97")
// int BPF_KPROBE(do_mov_2731)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x9b")
// int BPF_KPROBE(do_mov_2732)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0xac")
// int BPF_KPROBE(do_mov_2733)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0xe1")
// int BPF_KPROBE(do_mov_2734)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x11c")
// int BPF_KPROBE(do_mov_2735)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x11e")
// int BPF_KPROBE(do_mov_2736)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x179")
// int BPF_KPROBE(do_mov_2737)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1a6")
// int BPF_KPROBE(do_mov_2738)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1b1")
// int BPF_KPROBE(do_mov_2739)
// {
//     u64 addr = ctx->dx+ctx->di * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1c9")
// int BPF_KPROBE(do_mov_2740)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1de")
// int BPF_KPROBE(do_mov_2741)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1e3")
// int BPF_KPROBE(do_mov_2742)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1e8")
// int BPF_KPROBE(do_mov_2743)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1f0")
// int BPF_KPROBE(do_mov_2744)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x1f2")
// int BPF_KPROBE(do_mov_2745)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x20e")
// int BPF_KPROBE(do_mov_2746)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x217")
// int BPF_KPROBE(do_mov_2747)
// {
//     u64 addr = ctx->cx+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x233")
// int BPF_KPROBE(do_mov_2748)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x24a")
// int BPF_KPROBE(do_mov_2749)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x252")
// int BPF_KPROBE(do_mov_2750)
// {
//     u64 addr = ctx->r9+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x265")
// int BPF_KPROBE(do_mov_2751)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_push_nfrag_opts+0x271")
// int BPF_KPROBE(do_mov_2752)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_options+0xcb")
// int BPF_KPROBE(do_mov_2753)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_options+0xd0")
// int BPF_KPROBE(do_mov_2754)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_options+0x19c")
// int BPF_KPROBE(do_mov_2755)
// {
//     u64 addr = ctx->r12+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_options+0x1b4")
// int BPF_KPROBE(do_mov_2756)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_options+0x2e4")
// int BPF_KPROBE(do_mov_2757)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_renew_options+0x2e9")
// int BPF_KPROBE(do_mov_2758)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x141")
// int BPF_KPROBE(do_mov_2759)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x25d")
// int BPF_KPROBE(do_mov_2760)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x2b2")
// int BPF_KPROBE(do_mov_2761)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x2b9")
// int BPF_KPROBE(do_mov_2762)
// {
//     u64 addr = ctx->r15+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x2da")
// int BPF_KPROBE(do_mov_2763)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x2de")
// int BPF_KPROBE(do_mov_2764)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x2f4")
// int BPF_KPROBE(do_mov_2765)
// {
//     u64 addr = ctx->r15+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x31a")
// int BPF_KPROBE(do_mov_2766)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x39e")
// int BPF_KPROBE(do_mov_2767)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x3c2")
// int BPF_KPROBE(do_mov_2768)
// {
//     u64 addr = ctx->cx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x3c6")
// int BPF_KPROBE(do_mov_2769)
// {
//     u64 addr = ctx->cx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x3ff")
// int BPF_KPROBE(do_mov_2770)
// {
//     u64 addr = ctx->bx+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x476")
// int BPF_KPROBE(do_mov_2771)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x4bd")
// int BPF_KPROBE(do_mov_2772)
// {
//     u64 addr = ctx->cx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x4ea")
// int BPF_KPROBE(do_mov_2773)
// {
//     u64 addr = ctx->bx+0x16;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_send_ctl+0x52e")
// int BPF_KPROBE(do_mov_2774)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_dst_update+0x1ec")
// int BPF_KPROBE(do_mov_2775)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_dst_update+0x1ef")
// int BPF_KPROBE(do_mov_2776)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_dst_update+0x20d")
// int BPF_KPROBE(do_mov_2777)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_dst_update+0x216")
// int BPF_KPROBE(do_mov_2778)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_datagram_dst_update+0x220")
// int BPF_KPROBE(do_mov_2779)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0xa8")
// int BPF_KPROBE(do_mov_2780)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x139")
// int BPF_KPROBE(do_mov_2781)
// {
//     u64 addr = ctx->r14+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x13d")
// int BPF_KPROBE(do_mov_2782)
// {
//     u64 addr = ctx->r14+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x141")
// int BPF_KPROBE(do_mov_2783)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x14a")
// int BPF_KPROBE(do_mov_2784)
// {
//     u64 addr = ctx->r14+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x162")
// int BPF_KPROBE(do_mov_2785)
// {
//     u64 addr = ctx->r14+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x166")
// int BPF_KPROBE(do_mov_2786)
// {
//     u64 addr = ctx->r14+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x16a")
// int BPF_KPROBE(do_mov_2787)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x173")
// int BPF_KPROBE(do_mov_2788)
// {
//     u64 addr = ctx->r14+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x1ce")
// int BPF_KPROBE(do_mov_2789)
// {
//     u64 addr = ctx->r14+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x1d6")
// int BPF_KPROBE(do_mov_2790)
// {
//     u64 addr = ctx->r14+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x1de")
// int BPF_KPROBE(do_mov_2791)
// {
//     u64 addr = ctx->r14+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x1f9")
// int BPF_KPROBE(do_mov_2792)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x200")
// int BPF_KPROBE(do_mov_2793)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x208")
// int BPF_KPROBE(do_mov_2794)
// {
//     u64 addr = ctx->r15+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x23c")
// int BPF_KPROBE(do_mov_2795)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x244")
// int BPF_KPROBE(do_mov_2796)
// {
//     u64 addr = ctx->r14+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x24c")
// int BPF_KPROBE(do_mov_2797)
// {
//     u64 addr = ctx->r14+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x27c")
// int BPF_KPROBE(do_mov_2798)
// {
//     u64 addr = ctx->r9+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x280")
// int BPF_KPROBE(do_mov_2799)
// {
//     u64 addr = ctx->r9+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x352")
// int BPF_KPROBE(do_mov_2800)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x363")
// int BPF_KPROBE(do_mov_2801)
// {
//     u64 addr = ctx->r14+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x377")
// int BPF_KPROBE(do_mov_2802)
// {
//     u64 addr = ctx->r14+0x1fc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_datagram_connect+0x387")
// int BPF_KPROBE(do_mov_2803)
// {
//     u64 addr = ctx->r14+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0x88")
// int BPF_KPROBE(do_mov_2804)
// {
//     u64 addr = ctx->r12+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0x8e")
// int BPF_KPROBE(do_mov_2805)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xaf")
// int BPF_KPROBE(do_mov_2806)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xbb")
// int BPF_KPROBE(do_mov_2807)
// {
//     u64 addr = ctx->r12+0x45;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xc4")
// int BPF_KPROBE(do_mov_2808)
// {
//     u64 addr = ctx->r12+0x47;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xca")
// int BPF_KPROBE(do_mov_2809)
// {
//     u64 addr = ctx->r12+0x46;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xd7")
// int BPF_KPROBE(do_mov_2810)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xdf")
// int BPF_KPROBE(do_mov_2811)
// {
//     u64 addr = ctx->r12+0x52;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xe5")
// int BPF_KPROBE(do_mov_2812)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0xf6")
// int BPF_KPROBE(do_mov_2813)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0x109")
// int BPF_KPROBE(do_mov_2814)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0x123")
// int BPF_KPROBE(do_mov_2815)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_icmp_error+0x152")
// int BPF_KPROBE(do_mov_2816)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0x74")
// int BPF_KPROBE(do_mov_2817)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0x92")
// int BPF_KPROBE(do_mov_2818)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xb1")
// int BPF_KPROBE(do_mov_2819)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xb9")
// int BPF_KPROBE(do_mov_2820)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xbc")
// int BPF_KPROBE(do_mov_2821)
// {
//     u64 addr = ctx->cx - 0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xd4")
// int BPF_KPROBE(do_mov_2822)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xd9")
// int BPF_KPROBE(do_mov_2823)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xe6")
// int BPF_KPROBE(do_mov_2824)
// {
//     u64 addr = ctx->r12+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xf2")
// int BPF_KPROBE(do_mov_2825)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0xfe")
// int BPF_KPROBE(do_mov_2826)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0x10e")
// int BPF_KPROBE(do_mov_2827)
// {
//     u64 addr = ctx->r12+0x52;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0x124")
// int BPF_KPROBE(do_mov_2828)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0x138")
// int BPF_KPROBE(do_mov_2829)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_error+0x146")
// int BPF_KPROBE(do_mov_2830)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0x7e")
// int BPF_KPROBE(do_mov_2831)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0x90")
// int BPF_KPROBE(do_mov_2832)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0x95")
// int BPF_KPROBE(do_mov_2833)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xa1")
// int BPF_KPROBE(do_mov_2834)
// {
//     u64 addr = ctx->bx+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xa8")
// int BPF_KPROBE(do_mov_2835)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xb4")
// int BPF_KPROBE(do_mov_2836)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xc8")
// int BPF_KPROBE(do_mov_2837)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xd2")
// int BPF_KPROBE(do_mov_2838)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xe5")
// int BPF_KPROBE(do_mov_2839)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xf5")
// int BPF_KPROBE(do_mov_2840)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_local_rxpmtu+0xff")
// int BPF_KPROBE(do_mov_2841)
// {
//     u64 addr = ctx->bx+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_rxpmtu+0x146")
// int BPF_KPROBE(do_mov_2842)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_rxpmtu+0x151")
// int BPF_KPROBE(do_mov_2843)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_rxpmtu+0x15f")
// int BPF_KPROBE(do_mov_2844)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_rxpmtu+0x167")
// int BPF_KPROBE(do_mov_2845)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_rxpmtu+0x16b")
// int BPF_KPROBE(do_mov_2846)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_rxpmtu+0x1b8")
// int BPF_KPROBE(do_mov_2847)
// {
//     u64 addr = ctx->r14+0x258;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x11e")
// int BPF_KPROBE(do_mov_2848)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x121")
// int BPF_KPROBE(do_mov_2849)
// {
//     u64 addr = ctx->si+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x12d")
// int BPF_KPROBE(do_mov_2850)
// {
//     u64 addr = ctx->si+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x14e")
// int BPF_KPROBE(do_mov_2851)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x158")
// int BPF_KPROBE(do_mov_2852)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x15f")
// int BPF_KPROBE(do_mov_2853)
// {
//     u64 addr = ctx->di+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x167")
// int BPF_KPROBE(do_mov_2854)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x16f")
// int BPF_KPROBE(do_mov_2855)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x2fb")
// int BPF_KPROBE(do_mov_2856)
// {
//     u64 addr = ctx->r14+0x258;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x36e")
// int BPF_KPROBE(do_mov_2857)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x377")
// int BPF_KPROBE(do_mov_2858)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_recv_error+0x386")
// int BPF_KPROBE(do_mov_2859)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x22")
// int BPF_KPROBE(do_mov_2860)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x2a")
// int BPF_KPROBE(do_mov_2861)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x32")
// int BPF_KPROBE(do_mov_2862)
// {
//     u64 addr = ctx->di+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x3a")
// int BPF_KPROBE(do_mov_2863)
// {
//     u64 addr = ctx->di+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x42")
// int BPF_KPROBE(do_mov_2864)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x4a")
// int BPF_KPROBE(do_mov_2865)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x51")
// int BPF_KPROBE(do_mov_2866)
// {
//     u64 addr = ctx->di+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x63")
// int BPF_KPROBE(do_mov_2867)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x6d")
// int BPF_KPROBE(do_mov_2868)
// {
//     u64 addr = ctx->di+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_merge_options+0x75")
// int BPF_KPROBE(do_mov_2869)
// {
//     u64 addr = ctx->di+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__fl6_sock_lookup+0x7f")
// int BPF_KPROBE(do_mov_2870)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_release+0x22")
// int BPF_KPROBE(do_mov_2871)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_release+0x72")
// int BPF_KPROBE(do_mov_2872)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_release+0x8c")
// int BPF_KPROBE(do_mov_2873)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6fl_get_next.isra.0+0x2c")
// int BPF_KPROBE(do_mov_2874)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6fl_seq_start+0x31")
// int BPF_KPROBE(do_mov_2875)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6fl_seq_start+0x57")
// int BPF_KPROBE(do_mov_2876)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6fl_seq_start+0xad")
// int BPF_KPROBE(do_mov_2877)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_renew+0x62")
// int BPF_KPROBE(do_mov_2878)
// {
//     u64 addr = ctx->r13+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_renew+0x6b")
// int BPF_KPROBE(do_mov_2879)
// {
//     u64 addr = ctx->r13+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_renew+0x82")
// int BPF_KPROBE(do_mov_2880)
// {
//     u64 addr = ctx->r13+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x9d")
// int BPF_KPROBE(do_mov_2881)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0xbd")
// int BPF_KPROBE(do_mov_2882)
// {
//     u64 addr = ctx->r8+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x15e")
// int BPF_KPROBE(do_mov_2883)
// {
//     u64 addr = ctx->r14+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x171")
// int BPF_KPROBE(do_mov_2884)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x18d")
// int BPF_KPROBE(do_mov_2885)
// {
//     u64 addr = ctx->r14+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x1ab")
// int BPF_KPROBE(do_mov_2886)
// {
//     u64 addr = ctx->r14+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x1b3")
// int BPF_KPROBE(do_mov_2887)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x1bc")
// int BPF_KPROBE(do_mov_2888)
// {
//     u64 addr = ctx->r14+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x1e2")
// int BPF_KPROBE(do_mov_2889)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x208")
// int BPF_KPROBE(do_mov_2890)
// {
//     u64 addr = ctx->ax+0x7d0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x23b")
// int BPF_KPROBE(do_mov_2891)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x2aa")
// int BPF_KPROBE(do_mov_2892)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl_create+0x2ca")
// int BPF_KPROBE(do_mov_2893)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fl_gc+0x6e")
// int BPF_KPROBE(do_mov_2894)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_fl_gc+0x87")
// int BPF_KPROBE(do_mov_2895)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_flowlabel_net_exit+0x50")
// int BPF_KPROBE(do_mov_2896)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6fl_seq_next+0x26")
// int BPF_KPROBE(do_mov_2897)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6fl_seq_next+0x53")
// int BPF_KPROBE(do_mov_2898)
// {
//     u64 addr = ctx->di+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fl6_free_socklist+0x3e")
// int BPF_KPROBE(do_mov_2899)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0x9e")
// int BPF_KPROBE(do_mov_2900)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0xae")
// int BPF_KPROBE(do_mov_2901)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0xb2")
// int BPF_KPROBE(do_mov_2902)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0xbe")
// int BPF_KPROBE(do_mov_2903)
// {
//     u64 addr = ctx->r13+0x15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0xe1")
// int BPF_KPROBE(do_mov_2904)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0xfb")
// int BPF_KPROBE(do_mov_2905)
// {
//     u64 addr = ctx->r13+0x1a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0x124")
// int BPF_KPROBE(do_mov_2906)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt_get+0x13d")
// int BPF_KPROBE(do_mov_2907)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x2f6")
// int BPF_KPROBE(do_mov_2908)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x3ac")
// int BPF_KPROBE(do_mov_2909)
// {
//     u64 addr = ctx->r8+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x3c0")
// int BPF_KPROBE(do_mov_2910)
// {
//     u64 addr = ctx->r8+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x3dc")
// int BPF_KPROBE(do_mov_2911)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x3e4")
// int BPF_KPROBE(do_mov_2912)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x3e7")
// int BPF_KPROBE(do_mov_2913)
// {
//     u64 addr = ctx->si+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x4f3")
// int BPF_KPROBE(do_mov_2914)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x4ff")
// int BPF_KPROBE(do_mov_2915)
// {
//     u64 addr = ctx->r12+0x4e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x58b")
// int BPF_KPROBE(do_mov_2916)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x59d")
// int BPF_KPROBE(do_mov_2917)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x6d2")
// int BPF_KPROBE(do_mov_2918)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x6e2")
// int BPF_KPROBE(do_mov_2919)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x6ee")
// int BPF_KPROBE(do_mov_2920)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x6f9")
// int BPF_KPROBE(do_mov_2921)
// {
//     u64 addr =  - 0x7c90d620+ctx->ax * 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x72f")
// int BPF_KPROBE(do_mov_2922)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x737")
// int BPF_KPROBE(do_mov_2923)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x73a")
// int BPF_KPROBE(do_mov_2924)
// {
//     u64 addr = ctx->si+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_flowlabel_opt+0x7ac")
// int BPF_KPROBE(do_mov_2925)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0x5b")
// int BPF_KPROBE(do_mov_2926)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0x63")
// int BPF_KPROBE(do_mov_2927)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0x7f")
// int BPF_KPROBE(do_mov_2928)
// {
//     u64 addr = ctx->r12+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0x8c")
// int BPF_KPROBE(do_mov_2929)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0x91")
// int BPF_KPROBE(do_mov_2930)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xc0")
// int BPF_KPROBE(do_mov_2931)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xc5")
// int BPF_KPROBE(do_mov_2932)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xce")
// int BPF_KPROBE(do_mov_2933)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xd9")
// int BPF_KPROBE(do_mov_2934)
// {
//     u64 addr = ctx->r12+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xe3")
// int BPF_KPROBE(do_mov_2935)
// {
//     u64 addr = ctx->r12+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xf2")
// int BPF_KPROBE(do_mov_2936)
// {
//     u64 addr = ctx->r12+0x56;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_req+0xff")
// int BPF_KPROBE(do_mov_2937)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_addr2sockaddr+0xb")
// int BPF_KPROBE(do_mov_2938)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_addr2sockaddr+0x1f")
// int BPF_KPROBE(do_mov_2939)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_addr2sockaddr+0x23")
// int BPF_KPROBE(do_mov_2940)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_addr2sockaddr+0x2b")
// int BPF_KPROBE(do_mov_2941)
// {
//     u64 addr = ctx->si+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_addr2sockaddr+0x32")
// int BPF_KPROBE(do_mov_2942)
// {
//     u64 addr = ctx->si+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_addr2sockaddr+0x5a")
// int BPF_KPROBE(do_mov_2943)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x60")
// int BPF_KPROBE(do_mov_2944)
// {
//     u64 addr = ctx->r12+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x6d")
// int BPF_KPROBE(do_mov_2945)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x72")
// int BPF_KPROBE(do_mov_2946)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x7e")
// int BPF_KPROBE(do_mov_2947)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x88")
// int BPF_KPROBE(do_mov_2948)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x91")
// int BPF_KPROBE(do_mov_2949)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0xb6")
// int BPF_KPROBE(do_mov_2950)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0xc5")
// int BPF_KPROBE(do_mov_2951)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0xd0")
// int BPF_KPROBE(do_mov_2952)
// {
//     u64 addr = ctx->r12+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0xdd")
// int BPF_KPROBE(do_mov_2953)
// {
//     u64 addr = ctx->r12+0x56;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0xe8")
// int BPF_KPROBE(do_mov_2954)
// {
//     u64 addr = ctx->r12+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0xf5")
// int BPF_KPROBE(do_mov_2955)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x1bb")
// int BPF_KPROBE(do_mov_2956)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x1ca")
// int BPF_KPROBE(do_mov_2957)
// {
//     u64 addr = ctx->r14+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_route_socket+0x1d2")
// int BPF_KPROBE(do_mov_2958)
// {
//     u64 addr = ctx->r14+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_xmit+0x8f")
// int BPF_KPROBE(do_mov_2959)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_xmit+0x98")
// int BPF_KPROBE(do_mov_2960)
// {
//     u64 addr = ctx->r14+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_xmit+0x10b")
// int BPF_KPROBE(do_mov_2961)
// {
//     u64 addr = ctx->r12+0x1e8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/inet6_csk_xmit+0x117")
// int BPF_KPROBE(do_mov_2962)
// {
//     u64 addr = ctx->r12+0x224;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_complete+0x81")
// int BPF_KPROBE(do_mov_2963)
// {
//     u64 addr = ctx->bx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_complete+0x94")
// int BPF_KPROBE(do_mov_2964)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_complete+0xc5")
// int BPF_KPROBE(do_mov_2965)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_complete+0xeb")
// int BPF_KPROBE(do_mov_2966)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_complete+0x128")
// int BPF_KPROBE(do_mov_2967)
// {
//     u64 addr = ctx->r12+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0xd6")
// int BPF_KPROBE(do_mov_2968)
// {
//     u64 addr = ctx->r14+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x10a")
// int BPF_KPROBE(do_mov_2969)
// {
//     u64 addr = ctx->r14+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x11e")
// int BPF_KPROBE(do_mov_2970)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x194")
// int BPF_KPROBE(do_mov_2971)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x1bb")
// int BPF_KPROBE(do_mov_2972)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x20f")
// int BPF_KPROBE(do_mov_2973)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x226")
// int BPF_KPROBE(do_mov_2974)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x229")
// int BPF_KPROBE(do_mov_2975)
// {
//     u64 addr = ctx->bx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_ufo_fragment+0x244")
// int BPF_KPROBE(do_mov_2976)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x9b")
// int BPF_KPROBE(do_mov_2977)
// {
//     u64 addr = ctx->r12+0x4a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x248")
// int BPF_KPROBE(do_mov_2978)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x25a")
// int BPF_KPROBE(do_mov_2979)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x28e")
// int BPF_KPROBE(do_mov_2980)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x2b9")
// int BPF_KPROBE(do_mov_2981)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x2c2")
// int BPF_KPROBE(do_mov_2982)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x328")
// int BPF_KPROBE(do_mov_2983)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_gro_receive+0x36f")
// int BPF_KPROBE(do_mov_2984)
// {
//     u64 addr = ctx->r12+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_set_tunsrc+0x4e")
// int BPF_KPROBE(do_mov_2985)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_dumphmac_start+0x48")
// int BPF_KPROBE(do_mov_2986)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_dumphmac+0x127")
// int BPF_KPROBE(do_mov_2987)
// {
//     u64 addr = ctx->bx - 0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_get_tunsrc+0xa8")
// int BPF_KPROBE(do_mov_2988)
// {
//     u64 addr = ctx->r13 - 0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x12e")
// int BPF_KPROBE(do_mov_2989)
// {
//     u64 addr = ctx->bx+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x13e")
// int BPF_KPROBE(do_mov_2990)
// {
//     u64 addr = ctx->bx+0x5c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x147")
// int BPF_KPROBE(do_mov_2991)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x14e")
// int BPF_KPROBE(do_mov_2992)
// {
//     u64 addr = ctx->bx+0x5d;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x18b")
// int BPF_KPROBE(do_mov_2993)
// {
//     u64 addr = ctx->bx+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x194")
// int BPF_KPROBE(do_mov_2994)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x1bd")
// int BPF_KPROBE(do_mov_2995)
// {
//     u64 addr = ctx->r9+ctx->di * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x1ee")
// int BPF_KPROBE(do_mov_2996)
// {
//     u64 addr = ctx->bx+0x1c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x1f6")
// int BPF_KPROBE(do_mov_2997)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_genl_sethmac+0x205")
// int BPF_KPROBE(do_mov_2998)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_net_init+0x5a")
// int BPF_KPROBE(do_mov_2999)
// {
//     u64 addr = ctx->r12+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_net_init+0x64")
// int BPF_KPROBE(do_mov_3000)
// {
//     u64 addr = ctx->r13+0x8a8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_icmp_srh+0x2c")
// int BPF_KPROBE(do_mov_3001)
// {
//     u64 addr = ctx->di+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_icmp_srh+0x43")
// int BPF_KPROBE(do_mov_3002)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_icmp_srh+0x61")
// int BPF_KPROBE(do_mov_3003)
// {
//     u64 addr = ctx->r12+0x16;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_icmp_srh+0x67")
// int BPF_KPROBE(do_mov_3004)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/call_fib6_notifier+0x6")
// int BPF_KPROBE(do_mov_3005)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/call_fib6_notifiers+0x6")
// int BPF_KPROBE(do_mov_3006)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_notifier_init+0x24")
// int BPF_KPROBE(do_mov_3007)
// {
//     u64 addr = ctx->bx+0x8b0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x27")
// int BPF_KPROBE(do_mov_3008)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x49")
// int BPF_KPROBE(do_mov_3009)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x53")
// int BPF_KPROBE(do_mov_3010)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x7e")
// int BPF_KPROBE(do_mov_3011)
// {
//     u64 addr = ctx->si+ctx->cx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x93")
// int BPF_KPROBE(do_mov_3012)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x9b")
// int BPF_KPROBE(do_mov_3013)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0xc8")
// int BPF_KPROBE(do_mov_3014)
// {
//     u64 addr = ctx->r9+ctx->r10 * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0xf1")
// int BPF_KPROBE(do_mov_3015)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0xff")
// int BPF_KPROBE(do_mov_3016)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x108")
// int BPF_KPROBE(do_mov_3017)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x10e")
// int BPF_KPROBE(do_mov_3018)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x11c")
// int BPF_KPROBE(do_mov_3019)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x12a")
// int BPF_KPROBE(do_mov_3020)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_decompress+0x130")
// int BPF_KPROBE(do_mov_3021)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x2c")
// int BPF_KPROBE(do_mov_3022)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x3b")
// int BPF_KPROBE(do_mov_3023)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x44")
// int BPF_KPROBE(do_mov_3024)
// {
//     u64 addr = ctx->di+ctx->ax * 0x1 - 0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x6a")
// int BPF_KPROBE(do_mov_3025)
// {
//     u64 addr = ctx->di+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x7b")
// int BPF_KPROBE(do_mov_3026)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x81")
// int BPF_KPROBE(do_mov_3027)
// {
//     u64 addr = ctx->di+ctx->ax * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_addr_compress+0x8c")
// int BPF_KPROBE(do_mov_3028)
// {
//     u64 addr = ctx->di+ctx->ax * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_decompress+0x2c")
// int BPF_KPROBE(do_mov_3029)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_decompress+0x40")
// int BPF_KPROBE(do_mov_3030)
// {
//     u64 addr = ctx->bx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_decompress+0x47")
// int BPF_KPROBE(do_mov_3031)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_decompress+0x4e")
// int BPF_KPROBE(do_mov_3032)
// {
//     u64 addr = ctx->bx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_decompress+0x52")
// int BPF_KPROBE(do_mov_3033)
// {
//     u64 addr = ctx->bx+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0xba")
// int BPF_KPROBE(do_mov_3034)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0xd8")
// int BPF_KPROBE(do_mov_3035)
// {
//     u64 addr = ctx->r12+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0xf7")
// int BPF_KPROBE(do_mov_3036)
// {
//     u64 addr = ctx->r12+0x5;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0x101")
// int BPF_KPROBE(do_mov_3037)
// {
//     u64 addr = ctx->r12+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0x10b")
// int BPF_KPROBE(do_mov_3038)
// {
//     u64 addr = ctx->r12+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0x117")
// int BPF_KPROBE(do_mov_3039)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_rpl_srh_compress+0x1c9")
// int BPF_KPROBE(do_mov_3040)
// {
//     u64 addr = ctx->r12+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_dumpsc_start+0x48")
// int BPF_KPROBE(do_mov_3041)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_dumpns_start+0x48")
// int BPF_KPROBE(do_mov_3042)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_dumpns+0x15c")
// int BPF_KPROBE(do_mov_3043)
// {
//     u64 addr = ctx->bx - 0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_dumpsc+0x109")
// int BPF_KPROBE(do_mov_3044)
// {
//     u64 addr = ctx->r13 - 0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_net_init+0x47")
// int BPF_KPROBE(do_mov_3045)
// {
//     u64 addr = ctx->bx+0x8d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_net_init+0x71")
// int BPF_KPROBE(do_mov_3046)
// {
//     u64 addr = ctx->bx+0x8d8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_ns_set_schema+0x113")
// int BPF_KPROBE(do_mov_3047)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_ns_set_schema+0x11e")
// int BPF_KPROBE(do_mov_3048)
// {
//     u64 addr = ctx->r9+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_ns_set_schema+0x130")
// int BPF_KPROBE(do_mov_3049)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_ns_set_schema+0x138")
// int BPF_KPROBE(do_mov_3050)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_delns+0x172")
// int BPF_KPROBE(do_mov_3051)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_delsc+0x176")
// int BPF_KPROBE(do_mov_3052)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addsc+0x17c")
// int BPF_KPROBE(do_mov_3053)
// {
//     u64 addr = ctx->r15+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addsc+0x188")
// int BPF_KPROBE(do_mov_3054)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addsc+0x196")
// int BPF_KPROBE(do_mov_3055)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addsc+0x3f4")
// int BPF_KPROBE(do_mov_3056)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addsc+0x400")
// int BPF_KPROBE(do_mov_3057)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addns+0x14f")
// int BPF_KPROBE(do_mov_3058)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addns+0x190")
// int BPF_KPROBE(do_mov_3059)
// {
//     u64 addr = ctx->r14+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addns+0x194")
// int BPF_KPROBE(do_mov_3060)
// {
//     u64 addr = ctx->r14+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addns+0x3d4")
// int BPF_KPROBE(do_mov_3061)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_genl_addns+0x3e0")
// int BPF_KPROBE(do_mov_3062)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0xde")
// int BPF_KPROBE(do_mov_3063)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x10e")
// int BPF_KPROBE(do_mov_3064)
// {
//     u64 addr = ctx->r12+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x178")
// int BPF_KPROBE(do_mov_3065)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x1b9")
// int BPF_KPROBE(do_mov_3066)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x1c9")
// int BPF_KPROBE(do_mov_3067)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x1e5")
// int BPF_KPROBE(do_mov_3068)
// {
//     u64 addr = ctx->r12 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x20f")
// int BPF_KPROBE(do_mov_3069)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x21f")
// int BPF_KPROBE(do_mov_3070)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x258")
// int BPF_KPROBE(do_mov_3071)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x284")
// int BPF_KPROBE(do_mov_3072)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x29d")
// int BPF_KPROBE(do_mov_3073)
// {
//     u64 addr = ctx->r12 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x2aa")
// int BPF_KPROBE(do_mov_3074)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x2be")
// int BPF_KPROBE(do_mov_3075)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x2d2")
// int BPF_KPROBE(do_mov_3076)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x2e6")
// int BPF_KPROBE(do_mov_3077)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x2fa")
// int BPF_KPROBE(do_mov_3078)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x316")
// int BPF_KPROBE(do_mov_3079)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x32a")
// int BPF_KPROBE(do_mov_3080)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x33e")
// int BPF_KPROBE(do_mov_3081)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x352")
// int BPF_KPROBE(do_mov_3082)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x366")
// int BPF_KPROBE(do_mov_3083)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x38f")
// int BPF_KPROBE(do_mov_3084)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x3b8")
// int BPF_KPROBE(do_mov_3085)
// {
//     u64 addr = ctx->bx+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x3e4")
// int BPF_KPROBE(do_mov_3086)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x437")
// int BPF_KPROBE(do_mov_3087)
// {
//     u64 addr = ctx->r12 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x480")
// int BPF_KPROBE(do_mov_3088)
// {
//     u64 addr = ctx->r12 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_fill_trace_data+0x55a")
// int BPF_KPROBE(do_mov_3089)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sysctl_net_init+0x91")
// int BPF_KPROBE(do_mov_3090)
// {
//     u64 addr = ctx->bx+0x680;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sysctl_net_init+0xaf")
// int BPF_KPROBE(do_mov_3091)
// {
//     u64 addr = ctx->bx+0x688;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_sysctl_net_init+0xcd")
// int BPF_KPROBE(do_mov_3092)
// {
//     u64 addr = ctx->bx+0x690;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rule_action+0x36")
// int BPF_KPROBE(do_mov_3093)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rule_action+0x68")
// int BPF_KPROBE(do_mov_3094)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rule_fill+0x8")
// int BPF_KPROBE(do_mov_3095)
// {
//     u64 addr = ctx->dx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rule_fill+0xe")
// int BPF_KPROBE(do_mov_3096)
// {
//     u64 addr = ctx->dx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_new_table_set+0x14")
// int BPF_KPROBE(do_mov_3097)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_new_table_set+0x17")
// int BPF_KPROBE(do_mov_3098)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_new_table_set+0x1e")
// int BPF_KPROBE(do_mov_3099)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_new_table_set+0x22")
// int BPF_KPROBE(do_mov_3100)
// {
//     u64 addr = ctx->si+0x890;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x16")
// int BPF_KPROBE(do_mov_3101)
// {
//     u64 addr = ctx->di+0x128;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x20")
// int BPF_KPROBE(do_mov_3102)
// {
//     u64 addr = ctx->di+0xe0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x2b")
// int BPF_KPROBE(do_mov_3103)
// {
//     u64 addr = ctx->di+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x35")
// int BPF_KPROBE(do_mov_3104)
// {
//     u64 addr = ctx->di+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/reg_vif_setup+0x40")
// int BPF_KPROBE(do_mov_3105)
// {
//     u64 addr = ctx->di+0x524;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rtm_dumproute+0x13b")
// int BPF_KPROBE(do_mov_3106)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fib_lookup+0x7a")
// int BPF_KPROBE(do_mov_3107)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_destroy_unres+0x68")
// int BPF_KPROBE(do_mov_3108)
// {
//     u64 addr = ctx->r15+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_destroy_unres+0x6d")
// int BPF_KPROBE(do_mov_3109)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_destroy_unres+0x79")
// int BPF_KPROBE(do_mov_3110)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_exit+0x3f")
// int BPF_KPROBE(do_mov_3111)
// {
//     u64 addr = ctx->bx+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x9")
// int BPF_KPROBE(do_mov_3112)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x11")
// int BPF_KPROBE(do_mov_3113)
// {
//     u64 addr = ctx->si+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x19")
// int BPF_KPROBE(do_mov_3114)
// {
//     u64 addr = ctx->si+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x24")
// int BPF_KPROBE(do_mov_3115)
// {
//     u64 addr = ctx->si+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x2c")
// int BPF_KPROBE(do_mov_3116)
// {
//     u64 addr = ctx->si+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x77")
// int BPF_KPROBE(do_mov_3117)
// {
//     u64 addr = ctx->r8+ctx->ax * 0x1+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x84")
// int BPF_KPROBE(do_mov_3118)
// {
//     u64 addr = ctx->r8+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0x8e")
// int BPF_KPROBE(do_mov_3119)
// {
//     u64 addr = ctx->r8+0x24;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_update_thresholds+0xa6")
// int BPF_KPROBE(do_mov_3120)
// {
//     u64 addr = ctx->r8+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_mfc_seq_start+0x37")
// int BPF_KPROBE(do_mov_3121)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_mfc_seq_start+0x40")
// int BPF_KPROBE(do_mov_3122)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_mfc_seq_start+0x48")
// int BPF_KPROBE(do_mov_3123)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x1a3")
// int BPF_KPROBE(do_mov_3124)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x1c6")
// int BPF_KPROBE(do_mov_3125)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x1d8")
// int BPF_KPROBE(do_mov_3126)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x205")
// int BPF_KPROBE(do_mov_3127)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x20e")
// int BPF_KPROBE(do_mov_3128)
// {
//     u64 addr = ctx->r12+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x21d")
// int BPF_KPROBE(do_mov_3129)
// {
//     u64 addr = ctx->r12+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/pim6_rcv+0x22c")
// int BPF_KPROBE(do_mov_3130)
// {
//     u64 addr = ctx->r12+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_vif_seq_start+0x44")
// int BPF_KPROBE(do_mov_3131)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fill_mroute+0x87")
// int BPF_KPROBE(do_mov_3132)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fill_mroute+0x97")
// int BPF_KPROBE(do_mov_3133)
// {
//     u64 addr = ctx->bx+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fill_mroute+0xc2")
// int BPF_KPROBE(do_mov_3134)
// {
//     u64 addr = ctx->bx+0x16;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fill_mroute+0xcf")
// int BPF_KPROBE(do_mov_3135)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fill_mroute+0xe4")
// int BPF_KPROBE(do_mov_3136)
// {
//     u64 addr = ctx->bx+0x15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_fill_mroute+0x141")
// int BPF_KPROBE(do_mov_3137)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_do_expire_process+0x58")
// int BPF_KPROBE(do_mov_3138)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_do_expire_process+0x5c")
// int BPF_KPROBE(do_mov_3139)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_do_expire_process+0x6e")
// int BPF_KPROBE(do_mov_3140)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipmr_do_expire_process+0x77")
// int BPF_KPROBE(do_mov_3141)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x79")
// int BPF_KPROBE(do_mov_3142)
// {
//     u64 addr = ctx->r15+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x9e")
// int BPF_KPROBE(do_mov_3143)
// {
//     u64 addr = ctx->r15+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xb7")
// int BPF_KPROBE(do_mov_3144)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xbe")
// int BPF_KPROBE(do_mov_3145)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xc6")
// int BPF_KPROBE(do_mov_3146)
// {
//     u64 addr = ctx->dx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xce")
// int BPF_KPROBE(do_mov_3147)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xd6")
// int BPF_KPROBE(do_mov_3148)
// {
//     u64 addr = ctx->dx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xed")
// int BPF_KPROBE(do_mov_3149)
// {
//     u64 addr = ctx->r15+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0xff")
// int BPF_KPROBE(do_mov_3150)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x105")
// int BPF_KPROBE(do_mov_3151)
// {
//     u64 addr = ctx->ax+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x109")
// int BPF_KPROBE(do_mov_3152)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x10e")
// int BPF_KPROBE(do_mov_3153)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x12f")
// int BPF_KPROBE(do_mov_3154)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x133")
// int BPF_KPROBE(do_mov_3155)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x151")
// int BPF_KPROBE(do_mov_3156)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x155")
// int BPF_KPROBE(do_mov_3157)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x180")
// int BPF_KPROBE(do_mov_3158)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x1a5")
// int BPF_KPROBE(do_mov_3159)
// {
//     u64 addr = ctx->r15+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x1b2")
// int BPF_KPROBE(do_mov_3160)
// {
//     u64 addr = ctx->r15+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x252")
// int BPF_KPROBE(do_mov_3161)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x371")
// int BPF_KPROBE(do_mov_3162)
// {
//     u64 addr = ctx->r15+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x3b3")
// int BPF_KPROBE(do_mov_3163)
// {
//     u64 addr = ctx->r15+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x3c9")
// int BPF_KPROBE(do_mov_3164)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x3cf")
// int BPF_KPROBE(do_mov_3165)
// {
//     u64 addr = ctx->ax+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x3de")
// int BPF_KPROBE(do_mov_3166)
// {
//     u64 addr = ctx->cx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x3e2")
// int BPF_KPROBE(do_mov_3167)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x403")
// int BPF_KPROBE(do_mov_3168)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x407")
// int BPF_KPROBE(do_mov_3169)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x425")
// int BPF_KPROBE(do_mov_3170)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x429")
// int BPF_KPROBE(do_mov_3171)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x43b")
// int BPF_KPROBE(do_mov_3172)
// {
//     u64 addr = ctx->r15+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_report+0x514")
// int BPF_KPROBE(do_mov_3173)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0xd1")
// int BPF_KPROBE(do_mov_3174)
// {
//     u64 addr = ctx->bx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0xd8")
// int BPF_KPROBE(do_mov_3175)
// {
//     u64 addr = ctx->bx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0xe3")
// int BPF_KPROBE(do_mov_3176)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0xf1")
// int BPF_KPROBE(do_mov_3177)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0xfa")
// int BPF_KPROBE(do_mov_3178)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x106")
// int BPF_KPROBE(do_mov_3179)
// {
//     u64 addr = ctx->bx+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x10d")
// int BPF_KPROBE(do_mov_3180)
// {
//     u64 addr = ctx->bx+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x121")
// int BPF_KPROBE(do_mov_3181)
// {
//     u64 addr = ctx->bx+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x12c")
// int BPF_KPROBE(do_mov_3182)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x15b")
// int BPF_KPROBE(do_mov_3183)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x15f")
// int BPF_KPROBE(do_mov_3184)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x168")
// int BPF_KPROBE(do_mov_3185)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x16c")
// int BPF_KPROBE(do_mov_3186)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x18d")
// int BPF_KPROBE(do_mov_3187)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_cache_unresolved+0x197")
// int BPF_KPROBE(do_mov_3188)
// {
//     u64 addr = ctx->r15+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mif6_delete+0xe5")
// int BPF_KPROBE(do_mov_3189)
// {
//     u64 addr = ctx->ax+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mif6_delete+0xf6")
// int BPF_KPROBE(do_mov_3190)
// {
//     u64 addr = ctx->bx+0xe14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/mif6_delete+0x1d7")
// int BPF_KPROBE(do_mov_3191)
// {
//     u64 addr = ctx->bx+0xe08;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rtm_getroute+0x2e1")
// int BPF_KPROBE(do_mov_3192)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rtm_getroute+0x307")
// int BPF_KPROBE(do_mov_3193)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rtm_getroute+0x335")
// int BPF_KPROBE(do_mov_3194)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rtm_getroute+0x36d")
// int BPF_KPROBE(do_mov_3195)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rtm_getroute+0x396")
// int BPF_KPROBE(do_mov_3196)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_delete+0x120")
// int BPF_KPROBE(do_mov_3197)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_delete+0x124")
// int BPF_KPROBE(do_mov_3198)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_delete+0x131")
// int BPF_KPROBE(do_mov_3199)
// {
//     u64 addr = ctx->r12+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// // SEC("kprobe/mroute_clean_tables+0x153")
// // int BPF_KPROBE(do_mov_3200)
// // {
// //     u64 addr = ctx->dx+0x8;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/mroute_clean_tables+0x157")
// // int BPF_KPROBE(do_mov_3201)
// // {
// //     u64 addr = ctx->ax;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/mroute_clean_tables+0x164")
// // int BPF_KPROBE(do_mov_3202)
// // {
// //     u64 addr = ctx->r15+0x78;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/mroute_clean_tables+0x349")
// // int BPF_KPROBE(do_mov_3203)
// // {
// //     u64 addr = ctx->ax+0x8;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/mroute_clean_tables+0x34d")
// // int BPF_KPROBE(do_mov_3204)
// // {
// //     u64 addr = ctx->dx;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/mroute_clean_tables+0x355")
// // int BPF_KPROBE(do_mov_3205)
// // {
// //     u64 addr = ctx->r12+0x70;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// // SEC("kprobe/mroute_clean_tables+0x35a")
// // int BPF_KPROBE(do_mov_3206)
// // {
// //     u64 addr = ctx->r12+0x78;
// //     sampling(addr, (u64) (ctx->ip) -1);
// //     return 0;
// // }


// SEC("kprobe/ip6mr_rules_exit+0x60")
// int BPF_KPROBE(do_mov_3207)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rules_exit+0x64")
// int BPF_KPROBE(do_mov_3208)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rules_exit+0x67")
// int BPF_KPROBE(do_mov_3209)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_rules_exit+0x6b")
// int BPF_KPROBE(do_mov_3210)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_init+0x16")
// int BPF_KPROBE(do_mov_3211)
// {
//     u64 addr = ctx->di+0x8c0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_init+0x38")
// int BPF_KPROBE(do_mov_3212)
// {
//     u64 addr = ctx->bx+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_init+0x67")
// int BPF_KPROBE(do_mov_3213)
// {
//     u64 addr = ctx->bx+0x888;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_init+0x6e")
// int BPF_KPROBE(do_mov_3214)
// {
//     u64 addr = ctx->bx+0x890;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_init+0xd6")
// int BPF_KPROBE(do_mov_3215)
// {
//     u64 addr = ctx->bx+0x898;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_net_init+0x17a")
// int BPF_KPROBE(do_mov_3216)
// {
//     u64 addr = ctx->bx+0x8b8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0xce")
// int BPF_KPROBE(do_mov_3217)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0xd3")
// int BPF_KPROBE(do_mov_3218)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0xf8")
// int BPF_KPROBE(do_mov_3219)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0x10f")
// int BPF_KPROBE(do_mov_3220)
// {
//     u64 addr = ctx->ax+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0x122")
// int BPF_KPROBE(do_mov_3221)
// {
//     u64 addr = ctx->ax+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0x19a")
// int BPF_KPROBE(do_mov_3222)
// {
//     u64 addr = ctx->ax+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_forward2.isra.0+0x1ad")
// int BPF_KPROBE(do_mov_3223)
// {
//     u64 addr = ctx->ax+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mr_forward+0x6d")
// int BPF_KPROBE(do_mov_3224)
// {
//     u64 addr = ctx->r13+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mr_forward+0xfc")
// int BPF_KPROBE(do_mov_3225)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mr_forward+0x144")
// int BPF_KPROBE(do_mov_3226)
// {
//     u64 addr = ctx->r13+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mr_forward+0x17b")
// int BPF_KPROBE(do_mov_3227)
// {
//     u64 addr = ctx->ax+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mr_forward+0x18a")
// int BPF_KPROBE(do_mov_3228)
// {
//     u64 addr = ctx->ax+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x101")
// int BPF_KPROBE(do_mov_3229)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x10f")
// int BPF_KPROBE(do_mov_3230)
// {
//     u64 addr = ctx->r13+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x11a")
// int BPF_KPROBE(do_mov_3231)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x122")
// int BPF_KPROBE(do_mov_3232)
// {
//     u64 addr = ctx->r13+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x12d")
// int BPF_KPROBE(do_mov_3233)
// {
//     u64 addr = ctx->r13+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x138")
// int BPF_KPROBE(do_mov_3234)
// {
//     u64 addr = ctx->r13+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x143")
// int BPF_KPROBE(do_mov_3235)
// {
//     u64 addr = ctx->r13+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x14f")
// int BPF_KPROBE(do_mov_3236)
// {
//     u64 addr = ctx->r13+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x157")
// int BPF_KPROBE(do_mov_3237)
// {
//     u64 addr = ctx->r13+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x2be")
// int BPF_KPROBE(do_mov_3238)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x2c5")
// int BPF_KPROBE(do_mov_3239)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x2d2")
// int BPF_KPROBE(do_mov_3240)
// {
//     u64 addr = ctx->r11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x310")
// int BPF_KPROBE(do_mov_3241)
// {
//     u64 addr = ctx->r13+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x314")
// int BPF_KPROBE(do_mov_3242)
// {
//     u64 addr = ctx->r13+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x318")
// int BPF_KPROBE(do_mov_3243)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x322")
// int BPF_KPROBE(do_mov_3244)
// {
//     u64 addr = ctx->r12+0xe00;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x437")
// int BPF_KPROBE(do_mov_3245)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x565")
// int BPF_KPROBE(do_mov_3246)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x569")
// int BPF_KPROBE(do_mov_3247)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x576")
// int BPF_KPROBE(do_mov_3248)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x57e")
// int BPF_KPROBE(do_mov_3249)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x5cc")
// int BPF_KPROBE(do_mov_3250)
// {
//     u64 addr = ctx->bx+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x5d6")
// int BPF_KPROBE(do_mov_3251)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x5dd")
// int BPF_KPROBE(do_mov_3252)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x5e5")
// int BPF_KPROBE(do_mov_3253)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x5e9")
// int BPF_KPROBE(do_mov_3254)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x638")
// int BPF_KPROBE(do_mov_3255)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x6a6")
// int BPF_KPROBE(do_mov_3256)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x6b5")
// int BPF_KPROBE(do_mov_3257)
// {
//     u64 addr = ctx->r14+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x6bf")
// int BPF_KPROBE(do_mov_3258)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x6cc")
// int BPF_KPROBE(do_mov_3259)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x77d")
// int BPF_KPROBE(do_mov_3260)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x781")
// int BPF_KPROBE(do_mov_3261)
// {
//     u64 addr = ctx->r13+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_mfc_add+0x792")
// int BPF_KPROBE(do_mov_3262)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_sk_done+0x85")
// int BPF_KPROBE(do_mov_3263)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x378")
// int BPF_KPROBE(do_mov_3264)
// {
//     u64 addr = ctx->ax+0x538;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x481")
// int BPF_KPROBE(do_mov_3265)
// {
//     u64 addr = ctx->dx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x492")
// int BPF_KPROBE(do_mov_3266)
// {
//     u64 addr = ctx->r12+0xe14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x4ab")
// int BPF_KPROBE(do_mov_3267)
// {
//     u64 addr = ctx->r12+0xe08;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x5c3")
// int BPF_KPROBE(do_mov_3268)
// {
//     u64 addr = ctx->r12+0xe11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x5cb")
// int BPF_KPROBE(do_mov_3269)
// {
//     u64 addr = ctx->r12+0xe10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x64f")
// int BPF_KPROBE(do_mov_3270)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_setsockopt+0x7b4")
// int BPF_KPROBE(do_mov_3271)
// {
//     u64 addr = ctx->r13+0x400;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_mroute_getsockopt+0xfa")
// int BPF_KPROBE(do_mov_3272)
// {
//     u64 addr = ctx->r14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x1c5")
// int BPF_KPROBE(do_mov_3273)
// {
//     u64 addr = ctx->r15+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x1d7")
// int BPF_KPROBE(do_mov_3274)
// {
//     u64 addr = ctx->r15+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x1f9")
// int BPF_KPROBE(do_mov_3275)
// {
//     u64 addr = ctx->r15+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x218")
// int BPF_KPROBE(do_mov_3276)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x229")
// int BPF_KPROBE(do_mov_3277)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x22d")
// int BPF_KPROBE(do_mov_3278)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x23c")
// int BPF_KPROBE(do_mov_3279)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6mr_get_route+0x243")
// int BPF_KPROBE(do_mov_3280)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_net_init+0x34")
// int BPF_KPROBE(do_mov_3281)
// {
//     u64 addr = ctx->di - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_net_init+0x46")
// int BPF_KPROBE(do_mov_3282)
// {
//     u64 addr = ctx->di+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_net_init+0x60")
// int BPF_KPROBE(do_mov_3283)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_net_init+0xc2")
// int BPF_KPROBE(do_mov_3284)
// {
//     u64 addr = ctx->r14+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_net_init+0xd0")
// int BPF_KPROBE(do_mov_3285)
// {
//     u64 addr = ctx->bx+0x6a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x1a")
// int BPF_KPROBE(do_mov_3286)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x75")
// int BPF_KPROBE(do_mov_3287)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x88")
// int BPF_KPROBE(do_mov_3288)
// {
//     u64 addr = ctx->r12+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0xb9")
// int BPF_KPROBE(do_mov_3289)
// {
//     u64 addr = ctx->r12+0x128;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0xd2")
// int BPF_KPROBE(do_mov_3290)
// {
//     u64 addr = ctx->r12+0xa4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0xda")
// int BPF_KPROBE(do_mov_3291)
// {
//     u64 addr = ctx->r12+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0xe6")
// int BPF_KPROBE(do_mov_3292)
// {
//     u64 addr = ctx->r12+0x7c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0xf2")
// int BPF_KPROBE(do_mov_3293)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x100")
// int BPF_KPROBE(do_mov_3294)
// {
//     u64 addr = ctx->r12+0x8c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x10f")
// int BPF_KPROBE(do_mov_3295)
// {
//     u64 addr = ctx->r12+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x11e")
// int BPF_KPROBE(do_mov_3296)
// {
//     u64 addr = ctx->r12+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x12c")
// int BPF_KPROBE(do_mov_3297)
// {
//     u64 addr = ctx->r12+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x13c")
// int BPF_KPROBE(do_mov_3298)
// {
//     u64 addr = ctx->r12+0xc8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x144")
// int BPF_KPROBE(do_mov_3299)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x17c")
// int BPF_KPROBE(do_mov_3300)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_fill_dst+0x1ad")
// int BPF_KPROBE(do_mov_3301)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_dst_ifdown+0xca")
// int BPF_KPROBE(do_mov_3302)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_spi+0x10")
// int BPF_KPROBE(do_mov_3303)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_spi+0x16")
// int BPF_KPROBE(do_mov_3304)
// {
//     u64 addr = ctx->di+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_tnl+0x21")
// int BPF_KPROBE(do_mov_3305)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_tnl+0x31")
// int BPF_KPROBE(do_mov_3306)
// {
//     u64 addr = ctx->di+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_input_addr+0x16f")
// int BPF_KPROBE(do_mov_3307)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_input_addr+0x171")
// int BPF_KPROBE(do_mov_3308)
// {
//     u64 addr = ctx->cx+ctx->ax * 0x8+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv+0x1e")
// int BPF_KPROBE(do_mov_3309)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv+0x32")
// int BPF_KPROBE(do_mov_3310)
// {
//     u64 addr = ctx->di+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_transport_finish+0x8a")
// int BPF_KPROBE(do_mov_3311)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_transport_finish+0xaf")
// int BPF_KPROBE(do_mov_3312)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_transport_finish+0xbb")
// int BPF_KPROBE(do_mov_3313)
// {
//     u64 addr = ctx->cx+ctx->dx * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_transport_finish+0x1bb")
// int BPF_KPROBE(do_mov_3314)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_transport_finish+0x1f7")
// int BPF_KPROBE(do_mov_3315)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_transport_finish+0x223")
// int BPF_KPROBE(do_mov_3316)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_udp_encap_rcv+0xdf")
// int BPF_KPROBE(do_mov_3317)
// {
//     u64 addr = ctx->dx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_udp_encap_rcv+0xf3")
// int BPF_KPROBE(do_mov_3318)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_udp_encap_rcv+0x113")
// int BPF_KPROBE(do_mov_3319)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_udp_encap_rcv+0x128")
// int BPF_KPROBE(do_mov_3320)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_encap+0x56")
// int BPF_KPROBE(do_mov_3321)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_encap+0x5e")
// int BPF_KPROBE(do_mov_3322)
// {
//     u64 addr = ctx->di+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_encap+0xc0")
// int BPF_KPROBE(do_mov_3323)
// {
//     u64 addr = ctx->r14+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_encap+0xc8")
// int BPF_KPROBE(do_mov_3324)
// {
//     u64 addr = ctx->r14+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_encap+0x19b")
// int BPF_KPROBE(do_mov_3325)
// {
//     u64 addr = ctx->r14+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_rcv_encap+0x1b8")
// int BPF_KPROBE(do_mov_3326)
// {
//     u64 addr = ctx->r14+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_protocol_register+0x88")
// int BPF_KPROBE(do_mov_3327)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_protocol_register+0x8c")
// int BPF_KPROBE(do_mov_3328)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_protocol_deregister+0xa4")
// int BPF_KPROBE(do_mov_3329)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_ah_rcv+0x16")
// int BPF_KPROBE(do_mov_3330)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_ipcomp_rcv+0x16")
// int BPF_KPROBE(do_mov_3331)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/xfrm6_esp_rcv+0x16")
// int BPF_KPROBE(do_mov_3332)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__nf_ip6_route+0x32")
// int BPF_KPROBE(do_mov_3333)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_me_harder+0x19e")
// int BPF_KPROBE(do_mov_3334)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_me_harder+0x1be")
// int BPF_KPROBE(do_mov_3335)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_me_harder+0x3ee")
// int BPF_KPROBE(do_mov_3336)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_me_harder+0x410")
// int BPF_KPROBE(do_mov_3337)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_route_me_harder+0x42e")
// int BPF_KPROBE(do_mov_3338)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/br_ip6_fragment+0x23b")
// int BPF_KPROBE(do_mov_3339)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/br_ip6_fragment+0x270")
// int BPF_KPROBE(do_mov_3340)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/br_ip6_fragment+0x27a")
// int BPF_KPROBE(do_mov_3341)
// {
//     u64 addr = ctx->cx+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/br_ip6_fragment+0x313")
// int BPF_KPROBE(do_mov_3342)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/br_ip6_fragment+0x339")
// int BPF_KPROBE(do_mov_3343)
// {
//     u64 addr = ctx->cx+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rules_net_init+0x73")
// int BPF_KPROBE(do_mov_3344)
// {
//     u64 addr = ctx->bx+0x7f8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rules_net_init+0x7d")
// int BPF_KPROBE(do_mov_3345)
// {
//     u64 addr = ctx->bx+0x7d4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_fill+0x18")
// int BPF_KPROBE(do_mov_3346)
// {
//     u64 addr = ctx->dx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_fill+0x21")
// int BPF_KPROBE(do_mov_3347)
// {
//     u64 addr = ctx->dx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_fill+0x2b")
// int BPF_KPROBE(do_mov_3348)
// {
//     u64 addr = ctx->dx+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x4f")
// int BPF_KPROBE(do_mov_3349)
// {
//     u64 addr = ctx->di+0xc0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x80")
// int BPF_KPROBE(do_mov_3350)
// {
//     u64 addr = ctx->bx+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x8c")
// int BPF_KPROBE(do_mov_3351)
// {
//     u64 addr = ctx->bx+0xbc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0xa2")
// int BPF_KPROBE(do_mov_3352)
// {
//     u64 addr = ctx->r14+0x7d1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x135")
// int BPF_KPROBE(do_mov_3353)
// {
//     u64 addr = ctx->bx+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x13c")
// int BPF_KPROBE(do_mov_3354)
// {
//     u64 addr = ctx->bx+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x165")
// int BPF_KPROBE(do_mov_3355)
// {
//     u64 addr = ctx->bx+0x98;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x16c")
// int BPF_KPROBE(do_mov_3356)
// {
//     u64 addr = ctx->bx+0xa0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x1a6")
// int BPF_KPROBE(do_mov_3357)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_configure+0x1d3")
// int BPF_KPROBE(do_mov_3358)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_delete+0x3a")
// int BPF_KPROBE(do_mov_3359)
// {
//     u64 addr = ctx->dx+0x7d4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/fib6_rule_action+0x6a")
// int BPF_KPROBE(do_mov_3360)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_proc_init_net+0x6e")
// int BPF_KPROBE(do_mov_3361)
// {
//     u64 addr = ctx->bx+0x1f0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/snmp6_register_dev+0x46")
// int BPF_KPROBE(do_mov_3362)
// {
//     u64 addr = ctx->bx+0x3a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/snmp6_unregister_dev+0x34")
// int BPF_KPROBE(do_mov_3363)
// {
//     u64 addr = ctx->bx+0x3a0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__cookie_v6_init_sequence+0x56")
// int BPF_KPROBE(do_mov_3364)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x23f")
// int BPF_KPROBE(do_mov_3365)
// {
//     u64 addr = ctx->ax+0x110;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x270")
// int BPF_KPROBE(do_mov_3366)
// {
//     u64 addr = ctx->r15+0x90;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x27c")
// int BPF_KPROBE(do_mov_3367)
// {
//     u64 addr = ctx->r15+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x28a")
// int BPF_KPROBE(do_mov_3368)
// {
//     u64 addr = ctx->r15+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x2aa")
// int BPF_KPROBE(do_mov_3369)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x2ae")
// int BPF_KPROBE(do_mov_3370)
// {
//     u64 addr = ctx->r15+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x2cd")
// int BPF_KPROBE(do_mov_3371)
// {
//     u64 addr = ctx->r15+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x2d1")
// int BPF_KPROBE(do_mov_3372)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x318")
// int BPF_KPROBE(do_mov_3373)
// {
//     u64 addr = ctx->r15+0xf8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x33c")
// int BPF_KPROBE(do_mov_3374)
// {
//     u64 addr = ctx->r15+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x377")
// int BPF_KPROBE(do_mov_3375)
// {
//     u64 addr = ctx->r15+0xec;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x385")
// int BPF_KPROBE(do_mov_3376)
// {
//     u64 addr = ctx->r15+0x92;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x38d")
// int BPF_KPROBE(do_mov_3377)
// {
//     u64 addr = ctx->r15+0x108;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x3ce")
// int BPF_KPROBE(do_mov_3378)
// {
//     u64 addr = ctx->r15+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x3e2")
// int BPF_KPROBE(do_mov_3379)
// {
//     u64 addr = ctx->r15+0x94;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x3ed")
// int BPF_KPROBE(do_mov_3380)
// {
//     u64 addr = ctx->r15+0x11c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x3f4")
// int BPF_KPROBE(do_mov_3381)
// {
//     u64 addr = ctx->r15+0x120;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x404")
// int BPF_KPROBE(do_mov_3382)
// {
//     u64 addr = ctx->r15+0x118;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x431")
// int BPF_KPROBE(do_mov_3383)
// {
//     u64 addr = ctx->r15+0x114;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x504")
// int BPF_KPROBE(do_mov_3384)
// {
//     u64 addr = ctx->r15+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x54a")
// int BPF_KPROBE(do_mov_3385)
// {
//     u64 addr = ctx->r15+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x5b1")
// int BPF_KPROBE(do_mov_3386)
// {
//     u64 addr = ctx->r15+0xe8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x5e5")
// int BPF_KPROBE(do_mov_3387)
// {
//     u64 addr = ctx->r15+0xe9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/cookie_v6_check+0x696")
// int BPF_KPROBE(do_mov_3388)
// {
//     u64 addr = ctx->r15+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_walk+0x7d")
// int BPF_KPROBE(do_mov_3389)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_invalidate+0x5b")
// int BPF_KPROBE(do_mov_3390)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_invalidate+0x5f")
// int BPF_KPROBE(do_mov_3391)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_invalidate+0x62")
// int BPF_KPROBE(do_mov_3392)
// {
//     u64 addr = ctx->di+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_invalidate+0x66")
// int BPF_KPROBE(do_mov_3393)
// {
//     u64 addr = ctx->di+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_invalidate+0x91")
// int BPF_KPROBE(do_mov_3394)
// {
//     u64 addr = ctx->r8+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_pad_write.isra.0+0x1f")
// int BPF_KPROBE(do_mov_3395)
// {
//     u64 addr = ctx->di+ctx->ax * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_pad_write.isra.0+0x23")
// int BPF_KPROBE(do_mov_3396)
// {
//     u64 addr = ctx->di+ctx->cx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_pad_write.isra.0+0x3d")
// int BPF_KPROBE(do_mov_3397)
// {
//     u64 addr = ctx->si+ctx->cx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_pad_write.isra.0+0x4a")
// int BPF_KPROBE(do_mov_3398)
// {
//     u64 addr = ctx->di+ctx->si * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_genopt+0x118")
// int BPF_KPROBE(do_mov_3399)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_genopt+0x11e")
// int BPF_KPROBE(do_mov_3400)
// {
//     u64 addr = ctx->bx+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_genopt+0x129")
// int BPF_KPROBE(do_mov_3401)
// {
//     u64 addr = ctx->bx+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_genopt+0x130")
// int BPF_KPROBE(do_mov_3402)
// {
//     u64 addr = ctx->bx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_genopt+0x138")
// int BPF_KPROBE(do_mov_3403)
// {
//     u64 addr = ctx->bx+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_genopt+0x142")
// int BPF_KPROBE(do_mov_3404)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x6e")
// int BPF_KPROBE(do_mov_3405)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x82")
// int BPF_KPROBE(do_mov_3406)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x90")
// int BPF_KPROBE(do_mov_3407)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0xbb")
// int BPF_KPROBE(do_mov_3408)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0xf5")
// int BPF_KPROBE(do_mov_3409)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0xf9")
// int BPF_KPROBE(do_mov_3410)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x102")
// int BPF_KPROBE(do_mov_3411)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x10b")
// int BPF_KPROBE(do_mov_3412)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x12d")
// int BPF_KPROBE(do_mov_3413)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x131")
// int BPF_KPROBE(do_mov_3414)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x13e")
// int BPF_KPROBE(do_mov_3415)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x145")
// int BPF_KPROBE(do_mov_3416)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x14d")
// int BPF_KPROBE(do_mov_3417)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x151")
// int BPF_KPROBE(do_mov_3418)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x15a")
// int BPF_KPROBE(do_mov_3419)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_cache_add+0x15f")
// int BPF_KPROBE(do_mov_3420)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_find+0xab")
// int BPF_KPROBE(do_mov_3421)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_find+0xb3")
// int BPF_KPROBE(do_mov_3422)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_find+0xdb")
// int BPF_KPROBE(do_mov_3423)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_find+0xf8")
// int BPF_KPROBE(do_mov_3424)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_del+0x95")
// int BPF_KPROBE(do_mov_3425)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_del+0x117")
// int BPF_KPROBE(do_mov_3426)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_skbuff_setattr+0x1b7")
// int BPF_KPROBE(do_mov_3427)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_skbuff_setattr+0x1d4")
// int BPF_KPROBE(do_mov_3428)
// {
//     u64 addr = ctx->r9+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_skbuff_setattr+0x273")
// int BPF_KPROBE(do_mov_3429)
// {
//     u64 addr = ctx->r9+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_skbuff_delattr+0x10d")
// int BPF_KPROBE(do_mov_3430)
// {
//     u64 addr = ctx->r13+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_skbuff_delattr+0x145")
// int BPF_KPROBE(do_mov_3431)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_skbuff_delattr+0x198")
// int BPF_KPROBE(do_mov_3432)
// {
//     u64 addr = ctx->r13+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_insert+0x11b")
// int BPF_KPROBE(do_mov_3433)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_insert+0x123")
// int BPF_KPROBE(do_mov_3434)
// {
//     u64 addr = ctx->r13+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_remove+0x79")
// int BPF_KPROBE(do_mov_3435)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_remove+0x7d")
// int BPF_KPROBE(do_mov_3436)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_remove+0x8a")
// int BPF_KPROBE(do_mov_3437)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_add+0x22")
// int BPF_KPROBE(do_mov_3438)
// {
//     u64 addr = ctx->di+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_add+0x81")
// int BPF_KPROBE(do_mov_3439)
// {
//     u64 addr = ctx->r14+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_add+0x89")
// int BPF_KPROBE(do_mov_3440)
// {
//     u64 addr = ctx->r14+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_doi_add+0x8d")
// int BPF_KPROBE(do_mov_3441)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x13f")
// int BPF_KPROBE(do_mov_3442)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x143")
// int BPF_KPROBE(do_mov_3443)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x15a")
// int BPF_KPROBE(do_mov_3444)
// {
//     u64 addr = ctx->r14+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x17c")
// int BPF_KPROBE(do_mov_3445)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x180")
// int BPF_KPROBE(do_mov_3446)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x187")
// int BPF_KPROBE(do_mov_3447)
// {
//     u64 addr = ctx->r14+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x18b")
// int BPF_KPROBE(do_mov_3448)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x190")
// int BPF_KPROBE(do_mov_3449)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x195")
// int BPF_KPROBE(do_mov_3450)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x20d")
// int BPF_KPROBE(do_mov_3451)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/calipso_opt_getattr+0x220")
// int BPF_KPROBE(do_mov_3452)
// {
//     u64 addr = ctx->cx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/set_tun_src+0x3e")
// int BPF_KPROBE(do_mov_3453)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/set_tun_src+0x42")
// int BPF_KPROBE(do_mov_3454)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_fill_encap_info+0x41")
// int BPF_KPROBE(do_mov_3455)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_fill_encap_info+0x4c")
// int BPF_KPROBE(do_mov_3456)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_fill_encap_info+0x69")
// int BPF_KPROBE(do_mov_3457)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_build_state+0x113")
// int BPF_KPROBE(do_mov_3458)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_build_state+0x11d")
// int BPF_KPROBE(do_mov_3459)
// {
//     u64 addr = ctx->r13+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_build_state+0x12e")
// int BPF_KPROBE(do_mov_3460)
// {
//     u64 addr = ctx->r13+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_build_state+0x153")
// int BPF_KPROBE(do_mov_3461)
// {
//     u64 addr = ctx->r13+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_build_state+0x158")
// int BPF_KPROBE(do_mov_3462)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0xf0")
// int BPF_KPROBE(do_mov_3463)
// {
//     u64 addr = ctx->r15+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x10b")
// int BPF_KPROBE(do_mov_3464)
// {
//     u64 addr = ctx->r15+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x14d")
// int BPF_KPROBE(do_mov_3465)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x154")
// int BPF_KPROBE(do_mov_3466)
// {
//     u64 addr = ctx->r9+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x158")
// int BPF_KPROBE(do_mov_3467)
// {
//     u64 addr = ctx->r9+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x16f")
// int BPF_KPROBE(do_mov_3468)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x18f")
// int BPF_KPROBE(do_mov_3469)
// {
//     u64 addr = ctx->r9+ctx->ax * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x194")
// int BPF_KPROBE(do_mov_3470)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x1a7")
// int BPF_KPROBE(do_mov_3471)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x1be")
// int BPF_KPROBE(do_mov_3472)
// {
//     u64 addr = ctx->r9+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x1c6")
// int BPF_KPROBE(do_mov_3473)
// {
//     u64 addr = ctx->r9+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x207")
// int BPF_KPROBE(do_mov_3474)
// {
//     u64 addr = ctx->r9+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x23a")
// int BPF_KPROBE(do_mov_3475)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x24e")
// int BPF_KPROBE(do_mov_3476)
// {
//     u64 addr = ctx->r9+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x259")
// int BPF_KPROBE(do_mov_3477)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x261")
// int BPF_KPROBE(do_mov_3478)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x269")
// int BPF_KPROBE(do_mov_3479)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x271")
// int BPF_KPROBE(do_mov_3480)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap+0x300")
// int BPF_KPROBE(do_mov_3481)
// {
//     u64 addr = ctx->r15+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0xdb")
// int BPF_KPROBE(do_mov_3482)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0xf4")
// int BPF_KPROBE(do_mov_3483)
// {
//     u64 addr = ctx->bx+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x138")
// int BPF_KPROBE(do_mov_3484)
// {
//     u64 addr = ctx->r13+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x148")
// int BPF_KPROBE(do_mov_3485)
// {
//     u64 addr = ctx->r13+ctx->ax * 0x1+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x15c")
// int BPF_KPROBE(do_mov_3486)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x168")
// int BPF_KPROBE(do_mov_3487)
// {
//     u64 addr = ctx->r13+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x171")
// int BPF_KPROBE(do_mov_3488)
// {
//     u64 addr = ctx->r13+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x17a")
// int BPF_KPROBE(do_mov_3489)
// {
//     u64 addr = ctx->r13+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x182")
// int BPF_KPROBE(do_mov_3490)
// {
//     u64 addr = ctx->r13+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x190")
// int BPF_KPROBE(do_mov_3491)
// {
//     u64 addr = ctx->r13+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x194")
// int BPF_KPROBE(do_mov_3492)
// {
//     u64 addr = ctx->r13+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x1c9")
// int BPF_KPROBE(do_mov_3493)
// {
//     u64 addr = ctx->r13+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x234")
// int BPF_KPROBE(do_mov_3494)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x25b")
// int BPF_KPROBE(do_mov_3495)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_inline+0x27d")
// int BPF_KPROBE(do_mov_3496)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x114")
// int BPF_KPROBE(do_mov_3497)
// {
//     u64 addr = ctx->r15+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x12f")
// int BPF_KPROBE(do_mov_3498)
// {
//     u64 addr = ctx->r15+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x171")
// int BPF_KPROBE(do_mov_3499)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x178")
// int BPF_KPROBE(do_mov_3500)
// {
//     u64 addr = ctx->r9+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x19b")
// int BPF_KPROBE(do_mov_3501)
// {
//     u64 addr = ctx->r9+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x1a3")
// int BPF_KPROBE(do_mov_3502)
// {
//     u64 addr = ctx->r9+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x1ad")
// int BPF_KPROBE(do_mov_3503)
// {
//     u64 addr = ctx->r9+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x1d7")
// int BPF_KPROBE(do_mov_3504)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x1f5")
// int BPF_KPROBE(do_mov_3505)
// {
//     u64 addr = ctx->ax - 0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x202")
// int BPF_KPROBE(do_mov_3506)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x230")
// int BPF_KPROBE(do_mov_3507)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x260")
// int BPF_KPROBE(do_mov_3508)
// {
//     u64 addr = ctx->r9+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x292")
// int BPF_KPROBE(do_mov_3509)
// {
//     u64 addr = ctx->r9;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x2a6")
// int BPF_KPROBE(do_mov_3510)
// {
//     u64 addr = ctx->r9+0x7;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x2b1")
// int BPF_KPROBE(do_mov_3511)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x2b9")
// int BPF_KPROBE(do_mov_3512)
// {
//     u64 addr = ctx->r15+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x2c1")
// int BPF_KPROBE(do_mov_3513)
// {
//     u64 addr = ctx->r15+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x2c9")
// int BPF_KPROBE(do_mov_3514)
// {
//     u64 addr = ctx->r15+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x397")
// int BPF_KPROBE(do_mov_3515)
// {
//     u64 addr = ctx->r9+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x3d0")
// int BPF_KPROBE(do_mov_3516)
// {
//     u64 addr = ctx->r15+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x410")
// int BPF_KPROBE(do_mov_3517)
// {
//     u64 addr = ctx->r9+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x41d")
// int BPF_KPROBE(do_mov_3518)
// {
//     u64 addr = ctx->r12+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x430")
// int BPF_KPROBE(do_mov_3519)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x44e")
// int BPF_KPROBE(do_mov_3520)
// {
//     u64 addr = ctx->r11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x45d")
// int BPF_KPROBE(do_mov_3521)
// {
//     u64 addr = ctx->r11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x467")
// int BPF_KPROBE(do_mov_3522)
// {
//     u64 addr = ctx->di+ctx->r11 * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh_encap_red+0x47b")
// int BPF_KPROBE(do_mov_3523)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0x81")
// int BPF_KPROBE(do_mov_3524)
// {
//     u64 addr = ctx->bx+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0xcd")
// int BPF_KPROBE(do_mov_3525)
// {
//     u64 addr = ctx->bx+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0xe9")
// int BPF_KPROBE(do_mov_3526)
// {
//     u64 addr = ctx->bx+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0x110")
// int BPF_KPROBE(do_mov_3527)
// {
//     u64 addr = ctx->bx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0x19e")
// int BPF_KPROBE(do_mov_3528)
// {
//     u64 addr = ctx->bx+0xae;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0x1a5")
// int BPF_KPROBE(do_mov_3529)
// {
//     u64 addr = ctx->bx+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_do_srh+0x1b1")
// int BPF_KPROBE(do_mov_3530)
// {
//     u64 addr = ctx->bx+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_input_core+0x85")
// int BPF_KPROBE(do_mov_3531)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_input_core+0x16f")
// int BPF_KPROBE(do_mov_3532)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_output_core+0x8f")
// int BPF_KPROBE(do_mov_3533)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_output_core+0xb5")
// int BPF_KPROBE(do_mov_3534)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_table+0x10")
// int BPF_KPROBE(do_mov_3535)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_iif+0x10")
// int BPF_KPROBE(do_mov_3536)
// {
//     u64 addr = ctx->si+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_oif+0x10")
// int BPF_KPROBE(do_mov_3537)
// {
//     u64 addr = ctx->si+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_vrftable+0x1c")
// int BPF_KPROBE(do_mov_3538)
// {
//     u64 addr = ctx->si+0x54;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_srh+0x44")
// int BPF_KPROBE(do_mov_3539)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_nh6+0x29")
// int BPF_KPROBE(do_mov_3540)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_nh6+0x2d")
// int BPF_KPROBE(do_mov_3541)
// {
//     u64 addr = ctx->ax+0xc;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_nh4+0x24")
// int BPF_KPROBE(do_mov_3542)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_nh6+0x15")
// int BPF_KPROBE(do_mov_3543)
// {
//     u64 addr = ctx->si+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_nh6+0x1b")
// int BPF_KPROBE(do_mov_3544)
// {
//     u64 addr = ctx->si+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_nh4+0x10")
// int BPF_KPROBE(do_mov_3545)
// {
//     u64 addr = ctx->si+0x14;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_srh+0x3e")
// int BPF_KPROBE(do_mov_3546)
// {
//     u64 addr = ctx->ax+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_srh+0x49")
// int BPF_KPROBE(do_mov_3547)
// {
//     u64 addr = ctx->ax+ctx->cx * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_srh+0x66")
// int BPF_KPROBE(do_mov_3548)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__seg6_end_dt_vrf_build+0x38")
// int BPF_KPROBE(do_mov_3549)
// {
//     u64 addr = ctx->bx+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__seg6_end_dt_vrf_build+0x3c")
// int BPF_KPROBE(do_mov_3550)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__seg6_end_dt_vrf_build+0x41")
// int BPF_KPROBE(do_mov_3551)
// {
//     u64 addr = ctx->bx+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__seg6_end_dt_vrf_build+0x48")
// int BPF_KPROBE(do_mov_3552)
// {
//     u64 addr = ctx->bx+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__seg6_end_dt_vrf_build+0x9c")
// int BPF_KPROBE(do_mov_3553)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__seg6_end_dt_vrf_build+0xbd")
// int BPF_KPROBE(do_mov_3554)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_end_dt6_build+0x2e")
// int BPF_KPROBE(do_mov_3555)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_end_dt6_build+0x66")
// int BPF_KPROBE(do_mov_3556)
// {
//     u64 addr = ctx->dx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/decap_and_validate+0x8f")
// int BPF_KPROBE(do_mov_3557)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/decap_and_validate+0x92")
// int BPF_KPROBE(do_mov_3558)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/decap_and_validate+0xd1")
// int BPF_KPROBE(do_mov_3559)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/decap_and_validate+0xd9")
// int BPF_KPROBE(do_mov_3560)
// {
//     u64 addr = ctx->bx+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/decap_and_validate+0x164")
// int BPF_KPROBE(do_mov_3561)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/decap_and_validate+0x18f")
// int BPF_KPROBE(do_mov_3562)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_counters+0xa6")
// int BPF_KPROBE(do_mov_3563)
// {
//     u64 addr = ctx->bx+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/end_dt_vrf_core+0x7e")
// int BPF_KPROBE(do_mov_3564)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/end_dt_vrf_core+0xad")
// int BPF_KPROBE(do_mov_3565)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/end_dt_vrf_core+0xd6")
// int BPF_KPROBE(do_mov_3566)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/end_dt_vrf_core+0x110")
// int BPF_KPROBE(do_mov_3567)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/end_dt_vrf_core+0x18a")
// int BPF_KPROBE(do_mov_3568)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_counters+0x136")
// int BPF_KPROBE(do_mov_3569)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_flavors+0x6e")
// int BPF_KPROBE(do_mov_3570)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_flavors+0xd7")
// int BPF_KPROBE(do_mov_3571)
// {
//     u64 addr = ctx->r12+0x64;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_flavors+0xde")
// int BPF_KPROBE(do_mov_3572)
// {
//     u64 addr = ctx->r12+0x65;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_flavors+0x118")
// int BPF_KPROBE(do_mov_3573)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_flavors+0x143")
// int BPF_KPROBE(do_mov_3574)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_flavors+0x94")
// int BPF_KPROBE(do_mov_3575)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_bpf+0x75")
// int BPF_KPROBE(do_mov_3576)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/parse_nla_bpf+0x9a")
// int BPF_KPROBE(do_mov_3577)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/put_nla_bpf+0xc1")
// int BPF_KPROBE(do_mov_3578)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx4_finish+0x93")
// int BPF_KPROBE(do_mov_3579)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx4_finish+0xd4")
// int BPF_KPROBE(do_mov_3580)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx4_finish+0xeb")
// int BPF_KPROBE(do_mov_3581)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_lookup_any_nexthop+0x103")
// int BPF_KPROBE(do_mov_3582)
// {
//     u64 addr = ctx->bx+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_lookup_any_nexthop+0x11f")
// int BPF_KPROBE(do_mov_3583)
// {
//     u64 addr = ctx->bx+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dt6+0x9e")
// int BPF_KPROBE(do_mov_3584)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dt4+0xf1")
// int BPF_KPROBE(do_mov_3585)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dt4+0x108")
// int BPF_KPROBE(do_mov_3586)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx2+0x5d")
// int BPF_KPROBE(do_mov_3587)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx2+0xc2")
// int BPF_KPROBE(do_mov_3588)
// {
//     u64 addr = ctx->r12+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx2+0xcb")
// int BPF_KPROBE(do_mov_3589)
// {
//     u64 addr = ctx->r12+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx2+0x114")
// int BPF_KPROBE(do_mov_3590)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx2+0x12c")
// int BPF_KPROBE(do_mov_3591)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx2+0x13b")
// int BPF_KPROBE(do_mov_3592)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx6+0x65")
// int BPF_KPROBE(do_mov_3593)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx6+0x86")
// int BPF_KPROBE(do_mov_3594)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx4+0x67")
// int BPF_KPROBE(do_mov_3595)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx4+0x73")
// int BPF_KPROBE(do_mov_3596)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_dx4+0x94")
// int BPF_KPROBE(do_mov_3597)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6+0x73")
// int BPF_KPROBE(do_mov_3598)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_core.constprop.0+0x4a")
// int BPF_KPROBE(do_mov_3599)
// {
//     u64 addr = ctx->bx+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_core.constprop.0+0x60")
// int BPF_KPROBE(do_mov_3600)
// {
//     u64 addr = ctx->ax+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_core.constprop.0+0x66")
// int BPF_KPROBE(do_mov_3601)
// {
//     u64 addr = ctx->ax+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0xbb")
// int BPF_KPROBE(do_mov_3602)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0xc2")
// int BPF_KPROBE(do_mov_3603)
// {
//     u64 addr = ctx->bx+ctx->r8 * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0xe7")
// int BPF_KPROBE(do_mov_3604)
// {
//     u64 addr = ctx->dx+ctx->cx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0x120")
// int BPF_KPROBE(do_mov_3605)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0x12b")
// int BPF_KPROBE(do_mov_3606)
// {
//     u64 addr = ctx->bx+ctx->r8 * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0x133")
// int BPF_KPROBE(do_mov_3607)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end+0x13a")
// int BPF_KPROBE(do_mov_3608)
// {
//     u64 addr = ctx->bx+ctx->r8 * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_x+0x52")
// int BPF_KPROBE(do_mov_3609)
// {
//     u64 addr = ctx->r13+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_x+0x67")
// int BPF_KPROBE(do_mov_3610)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_x+0x6b")
// int BPF_KPROBE(do_mov_3611)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_t+0x50")
// int BPF_KPROBE(do_mov_3612)
// {
//     u64 addr = ctx->r13+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_t+0x65")
// int BPF_KPROBE(do_mov_3613)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_t+0x69")
// int BPF_KPROBE(do_mov_3614)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6_encap+0x56")
// int BPF_KPROBE(do_mov_3615)
// {
//     u64 addr = ctx->r13+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6_encap+0x6b")
// int BPF_KPROBE(do_mov_3616)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6_encap+0x6f")
// int BPF_KPROBE(do_mov_3617)
// {
//     u64 addr = ctx->cx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6_encap+0x8a")
// int BPF_KPROBE(do_mov_3618)
// {
//     u64 addr = ctx->r12+0xae;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6_encap+0x9b")
// int BPF_KPROBE(do_mov_3619)
// {
//     u64 addr = ctx->r12+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_b6_encap+0xe6")
// int BPF_KPROBE(do_mov_3620)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_local_build_state+0xa9")
// int BPF_KPROBE(do_mov_3621)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_local_build_state+0x121")
// int BPF_KPROBE(do_mov_3622)
// {
//     u64 addr = ctx->r12+0xa8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_local_build_state+0x22b")
// int BPF_KPROBE(do_mov_3623)
// {
//     u64 addr = ctx->r12+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_local_build_state+0x263")
// int BPF_KPROBE(do_mov_3624)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_local_build_state+0x26b")
// int BPF_KPROBE(do_mov_3625)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_local_build_state+0x278")
// int BPF_KPROBE(do_mov_3626)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_bpf_has_valid_srh+0x48")
// int BPF_KPROBE(do_mov_3627)
// {
//     u64 addr = ctx->di+0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_bpf_has_valid_srh+0x5e")
// int BPF_KPROBE(do_mov_3628)
// {
//     u64 addr = ctx->bx+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x7a")
// int BPF_KPROBE(do_mov_3629)
// {
//     u64 addr = ctx->r14+0x3;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x96")
// int BPF_KPROBE(do_mov_3630)
// {
//     u64 addr = ctx->dx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x9a")
// int BPF_KPROBE(do_mov_3631)
// {
//     u64 addr = ctx->dx+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x9e")
// int BPF_KPROBE(do_mov_3632)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0xa6")
// int BPF_KPROBE(do_mov_3633)
// {
//     u64 addr = ctx->bx+0xa;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0xad")
// int BPF_KPROBE(do_mov_3634)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0xd9")
// int BPF_KPROBE(do_mov_3635)
// {
//     u64 addr = ctx->r12+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0xeb")
// int BPF_KPROBE(do_mov_3636)
// {
//     u64 addr = ctx->r12+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x233")
// int BPF_KPROBE(do_mov_3637)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x259")
// int BPF_KPROBE(do_mov_3638)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x261")
// int BPF_KPROBE(do_mov_3639)
// {
//     u64 addr = ctx->ax+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x272")
// int BPF_KPROBE(do_mov_3640)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x27c")
// int BPF_KPROBE(do_mov_3641)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/input_action_end_bpf+0x285")
// int BPF_KPROBE(do_mov_3642)
// {
//     u64 addr = ctx->r12+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x76")
// int BPF_KPROBE(do_mov_3643)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x7d")
// int BPF_KPROBE(do_mov_3644)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x86")
// int BPF_KPROBE(do_mov_3645)
// {
//     u64 addr = ctx->r12+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x8f")
// int BPF_KPROBE(do_mov_3646)
// {
//     u64 addr = ctx->r12+0x12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x96")
// int BPF_KPROBE(do_mov_3647)
// {
//     u64 addr = ctx->r12+0x11;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0xb1")
// int BPF_KPROBE(do_mov_3648)
// {
//     u64 addr = ctx->ax - 0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0xb5")
// int BPF_KPROBE(do_mov_3649)
// {
//     u64 addr = ctx->ax - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x18f")
// int BPF_KPROBE(do_mov_3650)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x1c6")
// int BPF_KPROBE(do_mov_3651)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x1d5")
// int BPF_KPROBE(do_mov_3652)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x1e1")
// int BPF_KPROBE(do_mov_3653)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x1e9")
// int BPF_KPROBE(do_mov_3654)
// {
//     u64 addr = ctx->bx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x20b")
// int BPF_KPROBE(do_mov_3655)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x24d")
// int BPF_KPROBE(do_mov_3656)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x258")
// int BPF_KPROBE(do_mov_3657)
// {
//     u64 addr = ctx->bx+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x27c")
// int BPF_KPROBE(do_mov_3658)
// {
//     u64 addr = ctx->si+ctx->dx * 0x1;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x2b7")
// int BPF_KPROBE(do_mov_3659)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x2be")
// int BPF_KPROBE(do_mov_3660)
// {
//     u64 addr = ctx->bx+ctx->r15 * 0x1 - 0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_compute+0x2ec")
// int BPF_KPROBE(do_mov_3661)
// {
//     u64 addr = ctx->bx+ctx->r15 * 0x1 - 0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_push_hmac+0x6d")
// int BPF_KPROBE(do_mov_3662)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_push_hmac+0x7b")
// int BPF_KPROBE(do_mov_3663)
// {
//     u64 addr = ctx->cx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_push_hmac+0x83")
// int BPF_KPROBE(do_mov_3664)
// {
//     u64 addr = ctx->cx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_push_hmac+0x8b")
// int BPF_KPROBE(do_mov_3665)
// {
//     u64 addr = ctx->cx+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_info_add+0x18d")
// int BPF_KPROBE(do_mov_3666)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_info_add+0x1a2")
// int BPF_KPROBE(do_mov_3667)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_info_del+0x162")
// int BPF_KPROBE(do_mov_3668)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/seg6_hmac_info_del+0x2ae")
// int BPF_KPROBE(do_mov_3669)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x1bd")
// int BPF_KPROBE(do_mov_3670)
// {
//     u64 addr = ctx->r12+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x1f7")
// int BPF_KPROBE(do_mov_3671)
// {
//     u64 addr = ctx->r15+0x48;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x1ff")
// int BPF_KPROBE(do_mov_3672)
// {
//     u64 addr = ctx->r15+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x203")
// int BPF_KPROBE(do_mov_3673)
// {
//     u64 addr = ctx->r15+0x44;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x207")
// int BPF_KPROBE(do_mov_3674)
// {
//     u64 addr = ctx->r15+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x234")
// int BPF_KPROBE(do_mov_3675)
// {
//     u64 addr = ctx->r15+0x50;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x238")
// int BPF_KPROBE(do_mov_3676)
// {
//     u64 addr = ctx->r15+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x23f")
// int BPF_KPROBE(do_mov_3677)
// {
//     u64 addr = ctx->r15+0x62;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x246")
// int BPF_KPROBE(do_mov_3678)
// {
//     u64 addr = ctx->r15+0x67;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x24f")
// int BPF_KPROBE(do_mov_3679)
// {
//     u64 addr = ctx->r15+0x64;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x257")
// int BPF_KPROBE(do_mov_3680)
// {
//     u64 addr = ctx->r15+0x61;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x268")
// int BPF_KPROBE(do_mov_3681)
// {
//     u64 addr = ctx->r15+0x65;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x271")
// int BPF_KPROBE(do_mov_3682)
// {
//     u64 addr = ctx->r15+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x28b")
// int BPF_KPROBE(do_mov_3683)
// {
//     u64 addr = ctx->r15+ctx->ax * 0x1+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x29a")
// int BPF_KPROBE(do_mov_3684)
// {
//     u64 addr = ctx->r15+ctx->ax * 0x4+0x71;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x2ab")
// int BPF_KPROBE(do_mov_3685)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x2b6")
// int BPF_KPROBE(do_mov_3686)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x32b")
// int BPF_KPROBE(do_mov_3687)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x376")
// int BPF_KPROBE(do_mov_3688)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x37d")
// int BPF_KPROBE(do_mov_3689)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x385")
// int BPF_KPROBE(do_mov_3690)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x3a9")
// int BPF_KPROBE(do_mov_3691)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x3b6")
// int BPF_KPROBE(do_mov_3692)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x3be")
// int BPF_KPROBE(do_mov_3693)
// {
//     u64 addr = ctx->bx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x3d8")
// int BPF_KPROBE(do_mov_3694)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x406")
// int BPF_KPROBE(do_mov_3695)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_build_state+0x42d")
// int BPF_KPROBE(do_mov_3696)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x28e")
// int BPF_KPROBE(do_mov_3697)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x2a8")
// int BPF_KPROBE(do_mov_3698)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x2dc")
// int BPF_KPROBE(do_mov_3699)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x2e5")
// int BPF_KPROBE(do_mov_3700)
// {
//     u64 addr = ctx->r14+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x2ff")
// int BPF_KPROBE(do_mov_3701)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x312")
// int BPF_KPROBE(do_mov_3702)
// {
//     u64 addr = ctx->cx+ctx->ax * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x323")
// int BPF_KPROBE(do_mov_3703)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x342")
// int BPF_KPROBE(do_mov_3704)
// {
//     u64 addr = ctx->r15;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x349")
// int BPF_KPROBE(do_mov_3705)
// {
//     u64 addr = ctx->r15+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x351")
// int BPF_KPROBE(do_mov_3706)
// {
//     u64 addr = ctx->r15+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x359")
// int BPF_KPROBE(do_mov_3707)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x365")
// int BPF_KPROBE(do_mov_3708)
// {
//     u64 addr = ctx->r15+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x36a")
// int BPF_KPROBE(do_mov_3709)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x37b")
// int BPF_KPROBE(do_mov_3710)
// {
//     u64 addr = ctx->r15+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x388")
// int BPF_KPROBE(do_mov_3711)
// {
//     u64 addr = ctx->r15+0x18;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x391")
// int BPF_KPROBE(do_mov_3712)
// {
//     u64 addr = ctx->r15+0x20;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x4b4")
// int BPF_KPROBE(do_mov_3713)
// {
//     u64 addr = ctx->r12+0x58;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x4d8")
// int BPF_KPROBE(do_mov_3714)
// {
//     u64 addr = ctx->r12+0x84;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x5b9")
// int BPF_KPROBE(do_mov_3715)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x5d7")
// int BPF_KPROBE(do_mov_3716)
// {
//     u64 addr = ctx->r12+0xba;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x61c")
// int BPF_KPROBE(do_mov_3717)
// {
//     u64 addr = ctx->r14+0x60;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x642")
// int BPF_KPROBE(do_mov_3718)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x662")
// int BPF_KPROBE(do_mov_3719)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x676")
// int BPF_KPROBE(do_mov_3720)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1 - 0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x68c")
// int BPF_KPROBE(do_mov_3721)
// {
//     u64 addr = ctx->di;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x68f")
// int BPF_KPROBE(do_mov_3722)
// {
//     u64 addr = ctx->r11+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x6a1")
// int BPF_KPROBE(do_mov_3723)
// {
//     u64 addr = ctx->r11+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x77c")
// int BPF_KPROBE(do_mov_3724)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x7bd")
// int BPF_KPROBE(do_mov_3725)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x7e9")
// int BPF_KPROBE(do_mov_3726)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ioam6_output+0x828")
// int BPF_KPROBE(do_mov_3727)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/eafnosupport_fib6_nh_init+0x1e")
// int BPF_KPROBE(do_mov_3728)
// {
//     u64 addr = ctx->bx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_skip_exthdr+0x41")
// int BPF_KPROBE(do_mov_3729)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_skip_exthdr+0x53")
// int BPF_KPROBE(do_mov_3730)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_skip_exthdr+0xf8")
// int BPF_KPROBE(do_mov_3731)
// {
//     u64 addr = ctx->r12;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_find_hdr+0x54")
// int BPF_KPROBE(do_mov_3732)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_find_hdr+0x10b")
// int BPF_KPROBE(do_mov_3733)
// {
//     u64 addr = ctx->r10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_find_hdr+0x338")
// int BPF_KPROBE(do_mov_3734)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_find_hdr+0x371")
// int BPF_KPROBE(do_mov_3735)
// {
//     u64 addr = ctx->cx;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0x31")
// int BPF_KPROBE(do_mov_3736)
// {
//     u64 addr = ctx->bx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0x67")
// int BPF_KPROBE(do_mov_3737)
// {
//     u64 addr = ctx->ax+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0x6e")
// int BPF_KPROBE(do_mov_3738)
// {
//     u64 addr = ctx->ax+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0x79")
// int BPF_KPROBE(do_mov_3739)
// {
//     u64 addr = ctx->ax+0x8a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0x98")
// int BPF_KPROBE(do_mov_3740)
// {
//     u64 addr = ctx->bx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0xa7")
// int BPF_KPROBE(do_mov_3741)
// {
//     u64 addr = ctx->bx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_set_csum+0xfb")
// int BPF_KPROBE(do_mov_3742)
// {
//     u64 addr = ctx->bx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x15")
// int BPF_KPROBE(do_mov_3743)
// {
//     u64 addr = ctx->di+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x19")
// int BPF_KPROBE(do_mov_3744)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x34")
// int BPF_KPROBE(do_mov_3745)
// {
//     u64 addr = ctx->bx+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0xa9")
// int BPF_KPROBE(do_mov_3746)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0xd1")
// int BPF_KPROBE(do_mov_3747)
// {
//     u64 addr = ctx->bx+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x100")
// int BPF_KPROBE(do_mov_3748)
// {
//     u64 addr = ctx->bx+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x15f")
// int BPF_KPROBE(do_mov_3749)
// {
//     u64 addr = ctx->di+0x42;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x163")
// int BPF_KPROBE(do_mov_3750)
// {
//     u64 addr = ctx->di+0x40;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x175")
// int BPF_KPROBE(do_mov_3751)
// {
//     u64 addr = ctx->di+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x1ad")
// int BPF_KPROBE(do_mov_3752)
// {
//     u64 addr = ctx->bx+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x1ea")
// int BPF_KPROBE(do_mov_3753)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x1ff")
// int BPF_KPROBE(do_mov_3754)
// {
//     u64 addr = ctx->bx+0x81;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x20d")
// int BPF_KPROBE(do_mov_3755)
// {
//     u64 addr = ctx->bx+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/udp6_csum_init+0x281")
// int BPF_KPROBE(do_mov_3756)
// {
//     u64 addr = ctx->bx+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_ndo_send+0x10f")
// int BPF_KPROBE(do_mov_3757)
// {
//     u64 addr = ctx->si+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_ndo_send+0x113")
// int BPF_KPROBE(do_mov_3758)
// {
//     u64 addr = ctx->si+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_ndo_send+0x137")
// int BPF_KPROBE(do_mov_3759)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/icmpv6_ndo_send+0x13c")
// int BPF_KPROBE(do_mov_3760)
// {
//     u64 addr = ctx->dx+ctx->ax * 0x1+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_find_1stfragopt+0x32")
// int BPF_KPROBE(do_mov_3761)
// {
//     u64 addr = ctx->si;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip6_find_1stfragopt+0xa4")
// int BPF_KPROBE(do_mov_3762)
// {
//     u64 addr = ctx->r13;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_local_out+0x56")
// int BPF_KPROBE(do_mov_3763)
// {
//     u64 addr = ctx->cx+ctx->dx * 0x1+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_local_out+0x65")
// int BPF_KPROBE(do_mov_3764)
// {
//     u64 addr = ctx->r12+0x36;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__ip6_local_out+0x92")
// int BPF_KPROBE(do_mov_3765)
// {
//     u64 addr = ctx->r12+0xb4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip4ip6_gro_receive+0x11")
// int BPF_KPROBE(do_mov_3766)
// {
//     u64 addr = ctx->si+0x4a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ip4ip6_gro_receive+0x23")
// int BPF_KPROBE(do_mov_3767)
// {
//     u64 addr = ctx->si+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x3a")
// int BPF_KPROBE(do_mov_3768)
// {
//     u64 addr = ctx->di+0xac;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x41")
// int BPF_KPROBE(do_mov_3769)
// {
//     u64 addr = ctx->di+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x6d")
// int BPF_KPROBE(do_mov_3770)
// {
//     u64 addr = ctx->dx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x138")
// int BPF_KPROBE(do_mov_3771)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x144")
// int BPF_KPROBE(do_mov_3772)
// {
//     u64 addr = ctx->dx+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x14a")
// int BPF_KPROBE(do_mov_3773)
// {
//     u64 addr = ctx->dx+0x29;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x14e")
// int BPF_KPROBE(do_mov_3774)
// {
//     u64 addr = ctx->dx+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x156")
// int BPF_KPROBE(do_mov_3775)
// {
//     u64 addr = ctx->dx+0x2a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x15a")
// int BPF_KPROBE(do_mov_3776)
// {
//     u64 addr = ctx->dx+0x2c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_complete+0x15e")
// int BPF_KPROBE(do_mov_3777)
// {
//     u64 addr = ctx->dx+0x6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_pull_exthdrs+0x5d")
// int BPF_KPROBE(do_mov_3778)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_pull_exthdrs+0x6a")
// int BPF_KPROBE(do_mov_3779)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x46")
// int BPF_KPROBE(do_mov_3780)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0xa0")
// int BPF_KPROBE(do_mov_3781)
// {
//     u64 addr = ctx->bx+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0xa3")
// int BPF_KPROBE(do_mov_3782)
// {
//     u64 addr = ctx->bx+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x10c")
// int BPF_KPROBE(do_mov_3783)
// {
//     u64 addr = ctx->bx+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x177")
// int BPF_KPROBE(do_mov_3784)
// {
//     u64 addr = ctx->r12+0x4;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x187")
// int BPF_KPROBE(do_mov_3785)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x195")
// int BPF_KPROBE(do_mov_3786)
// {
//     u64 addr = ctx->bx+0x78;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x1b1")
// int BPF_KPROBE(do_mov_3787)
// {
//     u64 addr = ctx->bx+0xae;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x1be")
// int BPF_KPROBE(do_mov_3788)
// {
//     u64 addr = ctx->bx+0xb0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x26c")
// int BPF_KPROBE(do_mov_3789)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x27d")
// int BPF_KPROBE(do_mov_3790)
// {
//     u64 addr = ctx->ax+0x2;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x2a4")
// int BPF_KPROBE(do_mov_3791)
// {
//     u64 addr = ctx->bx+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x3ac")
// int BPF_KPROBE(do_mov_3792)
// {
//     u64 addr = ctx->bx+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gso_segment+0x3b3")
// int BPF_KPROBE(do_mov_3793)
// {
//     u64 addr = ctx->ax+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x6a")
// int BPF_KPROBE(do_mov_3794)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x71")
// int BPF_KPROBE(do_mov_3795)
// {
//     u64 addr = ctx->r12+0xb8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x7a")
// int BPF_KPROBE(do_mov_3796)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0xc0")
// int BPF_KPROBE(do_mov_3797)
// {
//     u64 addr = ctx->r12+0x3e;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x17d")
// int BPF_KPROBE(do_mov_3798)
// {
//     u64 addr = ctx->bx+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x18b")
// int BPF_KPROBE(do_mov_3799)
// {
//     u64 addr = ctx->bx+0x3a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x1d0")
// int BPF_KPROBE(do_mov_3800)
// {
//     u64 addr = ctx->r12+0x4b;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x1f9")
// int BPF_KPROBE(do_mov_3801)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x281")
// int BPF_KPROBE(do_mov_3802)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x286")
// int BPF_KPROBE(do_mov_3803)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x28e")
// int BPF_KPROBE(do_mov_3804)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x29d")
// int BPF_KPROBE(do_mov_3805)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x2ed")
// int BPF_KPROBE(do_mov_3806)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x304")
// int BPF_KPROBE(do_mov_3807)
// {
//     u64 addr = ctx->r12+0x34;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x30f")
// int BPF_KPROBE(do_mov_3808)
// {
//     u64 addr = ctx->r12+0xd0;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x355")
// int BPF_KPROBE(do_mov_3809)
// {
//     u64 addr = ctx->r12+0x28;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x35e")
// int BPF_KPROBE(do_mov_3810)
// {
//     u64 addr = ctx->r12+0x30;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_gro_receive+0x393")
// int BPF_KPROBE(do_mov_3811)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sit_ip6ip6_gro_receive+0x11")
// int BPF_KPROBE(do_mov_3812)
// {
//     u64 addr = ctx->si+0x4a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/sit_ip6ip6_gro_receive+0x23")
// int BPF_KPROBE(do_mov_3813)
// {
//     u64 addr = ctx->si+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gro_complete+0x53")
// int BPF_KPROBE(do_mov_3814)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gro_receive+0xd1")
// int BPF_KPROBE(do_mov_3815)
// {
//     u64 addr = ctx->r12+0x4c;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gro_receive+0xe8")
// int BPF_KPROBE(do_mov_3816)
// {
//     u64 addr = ctx->r12+0x38;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gro_receive+0x115")
// int BPF_KPROBE(do_mov_3817)
// {
//     u64 addr = ctx->r12+0x4a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gro_receive+0x18c")
// int BPF_KPROBE(do_mov_3818)
// {
//     u64 addr = ctx->r12+0x82;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gro_receive+0x1aa")
// int BPF_KPROBE(do_mov_3819)
// {
//     u64 addr = ctx->r12+0x80;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gso_segment+0xa2")
// int BPF_KPROBE(do_mov_3820)
// {
//     u64 addr = ctx->ax+ctx->dx * 0x1+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gso_segment+0xe2")
// int BPF_KPROBE(do_mov_3821)
// {
//     u64 addr = ctx->bx+0x10;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gso_segment+0xef")
// int BPF_KPROBE(do_mov_3822)
// {
//     u64 addr = ctx->r12+0x8a;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/tcp6_gso_segment+0xf8")
// int BPF_KPROBE(do_mov_3823)
// {
//     u64 addr = ctx->r12+0x88;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0xf9")
// int BPF_KPROBE(do_mov_3824)
// {
//     u64 addr = ctx->r12+0xe;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0xff")
// int BPF_KPROBE(do_mov_3825)
// {
//     u64 addr = ctx->r12+0x320;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x108")
// int BPF_KPROBE(do_mov_3826)
// {
//     u64 addr = ctx->r12+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x11b")
// int BPF_KPROBE(do_mov_3827)
// {
//     u64 addr = ctx->r12+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x120")
// int BPF_KPROBE(do_mov_3828)
// {
//     u64 addr = ctx->r12+0x68;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x125")
// int BPF_KPROBE(do_mov_3829)
// {
//     u64 addr = ctx->r8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x12c")
// int BPF_KPROBE(do_mov_3830)
// {
//     u64 addr = ctx->ax+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x17f")
// int BPF_KPROBE(do_mov_3831)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x2a9")
// int BPF_KPROBE(do_mov_3832)
// {
//     u64 addr = ctx->ax;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x2b1")
// int BPF_KPROBE(do_mov_3833)
// {
//     u64 addr = ctx->dx+0x8;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/__inet6_check_established+0x2b5")
// int BPF_KPROBE(do_mov_3834)
// {
//     u64 addr = ctx->r15+0x70;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_check_mld+0x92")
// int BPF_KPROBE(do_mov_3835)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }


// SEC("kprobe/ipv6_mc_check_mld+0xee")
// int BPF_KPROBE(do_mov_3836)
// {
//     u64 addr = ctx->r12+0xb6;
//     sampling(addr, (u64) (ctx->ip) -1);
//     return 0;
// }

