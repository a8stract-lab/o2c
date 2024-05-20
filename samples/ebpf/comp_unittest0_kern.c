
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "comp_header.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_NODES 10
#define MAX_DEPTH 5





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




// Define BPF array maps
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, s32);
	__type(value, s64);
	__uint(max_entries, MAX_NODES); 
} childrenLeft SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, s32);
	__type(value, s64);
	__uint(max_entries, MAX_NODES); 
} childrenRight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, s32);
	__type(value, s64);
	__uint(max_entries, MAX_NODES); 
} features SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, s32);
	__type(value, s64);
	__uint(max_entries, MAX_NODES); 
} threshold SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, s32);
	__type(value, s64);
	__uint(max_entries, MAX_NODES); 
} value SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct event);
	__uint(max_entries, 66); 
} l1pool SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct event);
	__uint(max_entries, 1000); 
} l2pool SEC(".maps");




// SEC("tp/kmem/kfree")
// int handle_mm_kfree(struct trace_event_raw_kfree *ctx)
// {
// 	struct event *e;
// 	if (ML_enable) {
// 		// if (++cnt_slab % 1000000 == 0)
// 		// 	bpf_printk("slab: %lu allocated\n", cnt_slab);
// 		u64 k = (u64) (ctx->ptr);
// 		u64 *pv = bpf_map_lookup_elem(&ml_record, &k);
// 		if (pv == NULL) return 0;
// 		struct kmem_cache *s = bpf_get_slab_cache(k);
// 		if (s == NULL) return 0;

// 		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
// 		if (!e)
// 			return 0;
// 		e->alloc_addr = k;
// 		e->cache_addr = (u64) s;
// 		// u64 name_addr = (u64)BPF_CORE_READ(s, name);
// 		e->sz = BPF_CORE_READ(s, size);
// 		// bpf_core_read(e->cache, 32, name_addr);
// 		bpf_core_read(e->content, getsize(e->sz), k);
		
// 		bpf_ringbuf_submit(e, 0);
// 		bpf_map_delete_elem(&ml_record, &k);
// 	}

// 	return 0;
// }
// long sample[] = {4, 2};
// SEC("tp/kmem/kmalloc")
// int handle_mm_kmalloc(struct trace_event_raw_kmalloc *ctx)
// {
//     u64 addr = ctx->ptr;
//     u64 bytes_alloc = ctx->bytes_alloc;
    
//     int node = 0;
//     long *pres = 0;
//     if (bytes_alloc >8000) {
//         bpf_printk("alloc: %016lx\n", addr);
//         for (int i = 0;i < MAX_DEPTH;i++) {
//             long *pf = bpf_map_lookup_elem(&features, &node);
//             if (pf) {
//                 long idx = *pf;
//                 bpf_printk("feature[%d]:%ld\n", node, idx);
//                 if (idx == -2) break;
//                 long *pt = bpf_map_lookup_elem(&threshold, &node);
                
//                 long s = 0;
//                 u64 sample_i_addr = (u64)sample;
//                 bpf_core_read(&s, 8, sample_i_addr + (idx * 8) % 2);
                
//                 if (pt) {
//                     bpf_printk("threshold[%d]:%lu\n", node, *pt);
//                     bpf_printk("sample[%ld]: %ld\n", idx, s);
//                     long *pc;
//                     if (s <= *pt) {
//                         pc = bpf_map_lookup_elem(&childrenLeft, &node);
//                         bpf_printk("\t\tleft subtree: %016lx\n", pc);
//                     } else {
//                         pc = bpf_map_lookup_elem(&childrenRight, &node);
//                         bpf_printk("\t\tright subtree: %016lx\n", pc);
//                     }
//                     if (pc) {
//                         node = *pc;
//                         bpf_printk("new node: %d\n", node);
//                     }
//                 }
//             } 
//         }

//         pres = bpf_map_lookup_elem(&value, &node);
//         bpf_printk("value[%ld]: ptr:%016lx\n", node, pres);
//         if (pres) {
//             bpf_printk("get res: %ld\n", *pres);
//         }
//     }
    

//     return 0;
// }

// bpf_for_each_map_elem
static int callback_tn(void *map, void *key, void *value, void *ctx)
{
	
	/* Without the fix this would cause underflow */
	return 0;
}

struct event empty = {};

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
	u32 cpuid = bpf_get_smp_processor_id();
    
    u64 k = (u64) ctx->ptr;
    struct visited *pv = bpf_map_lookup_elem(&slab_objs, &k);
	if (pv) {
        
        struct kmem_cache *s = NULL;
		// bpf_core_read(pe, sizeof(struct event), &empty);


		if (k >= 0xffff888000000000 && k < 0xffffc87fffffffff) {
			struct page *page = (struct page *)bpf_virt_to_page(k);
			u32 flags = BPF_CORE_READ(page, flags);
			if (flags & 0x200) {
				// slab objects
				u64 slab_addr = (u64) page;
				slab_addr += 24;
				bpf_core_read(&s, 8, slab_addr);
			}
		}
		u64 cache_addr = (u64) s;
		u64 name_addr = (u64)BPF_CORE_READ(s, name);
		u64 sz = BPF_CORE_READ(s, size);
		struct event *pe = bpf_map_lookup_elem(&l1pool, &cpuid );
		if (pe) {
			bpf_core_read(pe, sizeof(struct event), &empty);
			pe->alloc_addr = k;
			pe->sz = sz;
			bpf_core_read(pe->cache, 32, name_addr);
			bpf_core_read(pe->content, 2048, )

			int err = bpf_map_update_elem(&l2pool, &k, pe, BPF_ANY);
        
        	// bpf_printk("%s, %ld, err:%d\n", pe->cache, pe->sz, err);
		}
		
    }
    return 0;
}



// SEC("tp/kmem/kfree")
// int handle_mm_kfree(struct trace_event_raw_kfree *ctx)
// {
// 	struct event *e;
// 	u64 k = (u64) ctx->ptr;
// 	struct visited *pv = bpf_map_lookup_elem(&slab_objs, &k);
// 	if (pv) {
// 		if (++cnt_slab % 1000000 == 0)
// 			bpf_printk("slab: %lu allocated\n", cnt_slab);

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