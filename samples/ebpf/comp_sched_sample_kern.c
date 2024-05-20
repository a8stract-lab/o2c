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


SEC("kprobe/noop_enqueue+0x14")
int BPF_KPROBE(do_mov_0)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/noqueue_init+0x8")
int BPF_KPROBE(do_mov_1)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x3a")
int BPF_KPROBE(do_mov_2)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x42")
int BPF_KPROBE(do_mov_3)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_swap+0x63")
int BPF_KPROBE(do_mov_4)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0xa")
int BPF_KPROBE(do_mov_5)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x2e")
int BPF_KPROBE(do_mov_6)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x3b")
int BPF_KPROBE(do_mov_7)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mini_qdisc_pair_init+0x37")
int BPF_KPROBE(do_mov_8)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0xe")
int BPF_KPROBE(do_mov_9)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x3b")
int BPF_KPROBE(do_mov_10)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ratecfg_precompute+0x5b")
int BPF_KPROBE(do_mov_11)
{
    u64 addr = ctx->di + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0xa7")
int BPF_KPROBE(do_mov_12)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0x113")
int BPF_KPROBE(do_mov_13)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_enqueue+0x117")
int BPF_KPROBE(do_mov_14)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0x9d")
int BPF_KPROBE(do_mov_15)
{
    u64 addr = ctx->bx - 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_init+0xaf")
int BPF_KPROBE(do_mov_16)
{
    u64 addr = ctx->bx - 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x6")
int BPF_KPROBE(do_mov_17)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x9")
int BPF_KPROBE(do_mov_18)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/psched_ppscfg_precompute+0x1f")
int BPF_KPROBE(do_mov_19)
{
    u64 addr = ctx->di + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1cc")
int BPF_KPROBE(do_mov_20)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x1ba")
int BPF_KPROBE(do_mov_21)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_fast_change_tx_queue_len+0x201")
int BPF_KPROBE(do_mov_22)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x5a")
int BPF_KPROBE(do_mov_23)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0x6d")
int BPF_KPROBE(do_mov_24)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xb9")
int BPF_KPROBE(do_mov_25)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_reset+0xcc")
int BPF_KPROBE(do_mov_26)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x220")
int BPF_KPROBE(do_mov_27)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x2f4")
int BPF_KPROBE(do_mov_28)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_direct_xmit+0x303")
int BPF_KPROBE(do_mov_29)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0xd6")
int BPF_KPROBE(do_mov_30)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0xf2")
int BPF_KPROBE(do_mov_31)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x1fd")
int BPF_KPROBE(do_mov_32)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x20a")
int BPF_KPROBE(do_mov_33)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x24f")
int BPF_KPROBE(do_mov_34)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x25e")
int BPF_KPROBE(do_mov_35)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x3c5")
int BPF_KPROBE(do_mov_36)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x47a")
int BPF_KPROBE(do_mov_37)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__qdisc_run+0x48e")
int BPF_KPROBE(do_mov_38)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xba")
int BPF_KPROBE(do_mov_39)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_alloc+0xaf")
int BPF_KPROBE(do_mov_40)
{
    u64 addr = ctx->r15 + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_create_dflt+0xf3")
int BPF_KPROBE(do_mov_41)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_deactivate+0x48")
int BPF_KPROBE(do_mov_42)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_qdisc_change_tx_queue_len+0xe1")
int BPF_KPROBE(do_mov_43)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0x31")
int BPF_KPROBE(do_mov_44)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_init_scheduler+0x3c")
int BPF_KPROBE(do_mov_45)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x36")
int BPF_KPROBE(do_mov_46)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_shutdown+0x3e")
int BPF_KPROBE(do_mov_47)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_walk+0x66")
int BPF_KPROBE(do_mov_48)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mq_graft+0x73")
int BPF_KPROBE(do_mov_49)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x40")
int BPF_KPROBE(do_mov_50)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x48")
int BPF_KPROBE(do_mov_51)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0x63")
int BPF_KPROBE(do_mov_52)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xd3")
int BPF_KPROBE(do_mov_53)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_prepare_frag+0xe5")
int BPF_KPROBE(do_mov_54)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0xec")
int BPF_KPROBE(do_mov_55)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_frag_xmit+0x176")
int BPF_KPROBE(do_mov_56)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_fragment+0xfc")
int BPF_KPROBE(do_mov_57)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sch_fragment+0x125")
int BPF_KPROBE(do_mov_58)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x7")
int BPF_KPROBE(do_mov_59)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x13")
int BPF_KPROBE(do_mov_60)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_insert+0x47")
int BPF_KPROBE(do_mov_61)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_remove+0xe")
int BPF_KPROBE(do_mov_62)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xc4")
int BPF_KPROBE(do_mov_63)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xf8")
int BPF_KPROBE(do_mov_64)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_qdisc+0xd8")
int BPF_KPROBE(do_mov_65)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_offload_graft_helper+0x96")
int BPF_KPROBE(do_mov_66)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xa6")
int BPF_KPROBE(do_mov_67)
{
    u64 addr = ctx->cx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tclass_qdisc+0xdb")
int BPF_KPROBE(do_mov_68)
{
    u64 addr = ctx->cx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_qdisc+0x74")
int BPF_KPROBE(do_mov_69)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_hash_del+0x35")
int BPF_KPROBE(do_mov_70)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_rtab+0x54")
int BPF_KPROBE(do_mov_71)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_put_stab+0x20")
int BPF_KPROBE(do_mov_72)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x9f")
int BPF_KPROBE(do_mov_73)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x190")
int BPF_KPROBE(do_mov_74)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x16d")
int BPF_KPROBE(do_mov_75)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x228")
int BPF_KPROBE(do_mov_76)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x24c")
int BPF_KPROBE(do_mov_77)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_stab+0x270")
int BPF_KPROBE(do_mov_78)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0xa8")
int BPF_KPROBE(do_mov_79)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x103")
int BPF_KPROBE(do_mov_80)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x10a")
int BPF_KPROBE(do_mov_81)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x11f")
int BPF_KPROBE(do_mov_82)
{
    u64 addr = ctx->r12 + 0x404;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_get_rtab+0x23e")
int BPF_KPROBE(do_mov_83)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x2d")
int BPF_KPROBE(do_mov_84)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x34")
int BPF_KPROBE(do_mov_85)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x44")
int BPF_KPROBE(do_mov_86)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x4c")
int BPF_KPROBE(do_mov_87)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_init+0x59")
int BPF_KPROBE(do_mov_88)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xc1")
int BPF_KPROBE(do_mov_89)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0xcf")
int BPF_KPROBE(do_mov_90)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_qdisc+0x327")
int BPF_KPROBE(do_mov_91)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_qdisc_root+0x17e")
int BPF_KPROBE(do_mov_92)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0xf8")
int BPF_KPROBE(do_mov_93)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_class_hash_grow+0x10d")
int BPF_KPROBE(do_mov_94)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0x1bf")
int BPF_KPROBE(do_mov_95)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_fill_tclass+0xde")
int BPF_KPROBE(do_mov_96)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x53a")
int BPF_KPROBE(do_mov_97)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qdisc_graft+0x565")
int BPF_KPROBE(do_mov_98)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_tclass+0x541")
int BPF_KPROBE(do_mov_99)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_tclass+0x565")
int BPF_KPROBE(do_mov_100)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0xf6")
int BPF_KPROBE(do_mov_101)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x298")
int BPF_KPROBE(do_mov_102)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x310")
int BPF_KPROBE(do_mov_103)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x332")
int BPF_KPROBE(do_mov_104)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x354")
int BPF_KPROBE(do_mov_105)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x380")
int BPF_KPROBE(do_mov_106)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x3a2")
int BPF_KPROBE(do_mov_107)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_qdisc+0x3c8")
int BPF_KPROBE(do_mov_108)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x1bf")
int BPF_KPROBE(do_mov_109)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x4d7")
int BPF_KPROBE(do_mov_110)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x52f")
int BPF_KPROBE(do_mov_111)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x56b")
int BPF_KPROBE(do_mov_112)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x60f")
int BPF_KPROBE(do_mov_113)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x6c4")
int BPF_KPROBE(do_mov_114)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x6e6")
int BPF_KPROBE(do_mov_115)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x72c")
int BPF_KPROBE(do_mov_116)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x752")
int BPF_KPROBE(do_mov_117)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x77b")
int BPF_KPROBE(do_mov_118)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x7f4")
int BPF_KPROBE(do_mov_119)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x82e")
int BPF_KPROBE(do_mov_120)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x854")
int BPF_KPROBE(do_mov_121)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x87a")
int BPF_KPROBE(do_mov_122)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_modify_qdisc+0x8a5")
int BPF_KPROBE(do_mov_123)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/blackhole_enqueue+0x9")
int BPF_KPROBE(do_mov_124)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/blackhole_enqueue+0x14")
int BPF_KPROBE(do_mov_125)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_head_change_dflt+0x9")
int BPF_KPROBE(do_mov_126)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x40")
int BPF_KPROBE(do_mov_127)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x5c")
int BPF_KPROBE(do_mov_128)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x6a")
int BPF_KPROBE(do_mov_129)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_cls_offload_cnt_update+0x89")
int BPF_KPROBE(do_mov_130)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_tcf_proto_ops+0x68")
int BPF_KPROBE(do_mov_131)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/register_tcf_proto_ops+0x74")
int BPF_KPROBE(do_mov_132)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_tcf_proto_ops+0x95")
int BPF_KPROBE(do_mov_133)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unregister_tcf_proto_ops+0xa2")
int BPF_KPROBE(do_mov_134)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x10")
int BPF_KPROBE(do_mov_135)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x17")
int BPF_KPROBE(do_mov_136)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_queue_work+0x1b")
int BPF_KPROBE(do_mov_137)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_net_init+0x3b")
int BPF_KPROBE(do_mov_138)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain0_head_change_cb_del+0x7f")
int BPF_KPROBE(do_mov_139)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain0_head_change_cb_del+0x8c")
int BPF_KPROBE(do_mov_140)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_owner_del+0x3e")
int BPF_KPROBE(do_mov_141)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_owner_del+0x4b")
int BPF_KPROBE(do_mov_142)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x107")
int BPF_KPROBE(do_mov_143)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_validate_ex+0x11a")
int BPF_KPROBE(do_mov_144)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0x8a")
int BPF_KPROBE(do_mov_145)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0x8e")
int BPF_KPROBE(do_mov_146)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0x94")
int BPF_KPROBE(do_mov_147)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xa6")
int BPF_KPROBE(do_mov_148)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xaa")
int BPF_KPROBE(do_mov_149)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xb0")
int BPF_KPROBE(do_mov_150)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_handle+0xd6")
int BPF_KPROBE(do_mov_151)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x65")
int BPF_KPROBE(do_mov_152)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_create+0x6f")
int BPF_KPROBE(do_mov_153)
{
    u64 addr = ctx->r12 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_validate_change+0x3e")
int BPF_KPROBE(do_mov_154)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_validate_change+0x65")
int BPF_KPROBE(do_mov_155)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_replace+0xa4")
int BPF_KPROBE(do_mov_156)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_replace+0xb8")
int BPF_KPROBE(do_mov_157)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_dump+0xee")
int BPF_KPROBE(do_mov_158)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x12")
int BPF_KPROBE(do_mov_159)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x19")
int BPF_KPROBE(do_mov_160)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_change+0x29")
int BPF_KPROBE(do_mov_161)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_find+0x46")
int BPF_KPROBE(do_mov_162)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_tp_find+0x4c")
int BPF_KPROBE(do_mov_163)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_block_find+0x6d")
int BPF_KPROBE(do_mov_164)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_block_find+0x98")
int BPF_KPROBE(do_mov_165)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0x158")
int BPF_KPROBE(do_mov_166)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_chain_fill_node+0xc8")
int BPF_KPROBE(do_mov_167)
{
    u64 addr = ctx->r14 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x7f")
int BPF_KPROBE(do_mov_168)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x8f")
int BPF_KPROBE(do_mov_169)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__tcf_chain_put+0x12c")
int BPF_KPROBE(do_mov_170)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_proto_destroy+0x7e")
int BPF_KPROBE(do_mov_171)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_flush+0x44")
int BPF_KPROBE(do_mov_172)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_flush+0x57")
int BPF_KPROBE(do_mov_173)
{
    u64 addr = ctx->r12 + 0x4d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_playback_offloads+0xda")
int BPF_KPROBE(do_mov_174)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_unbind+0x87")
int BPF_KPROBE(do_mov_175)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xd9")
int BPF_KPROBE(do_mov_176)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0xee")
int BPF_KPROBE(do_mov_177)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_block_indr_cleanup+0x101")
int BPF_KPROBE(do_mov_178)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x124")
int BPF_KPROBE(do_mov_179)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_setup+0x1b3")
int BPF_KPROBE(do_mov_180)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_offload_cmd.isra.0+0xd4")
int BPF_KPROBE(do_mov_181)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x8b")
int BPF_KPROBE(do_mov_182)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x14a")
int BPF_KPROBE(do_mov_183)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x283")
int BPF_KPROBE(do_mov_184)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x2b2")
int BPF_KPROBE(do_mov_185)
{
    u64 addr = ctx->r13 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3ab")
int BPF_KPROBE(do_mov_186)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x3e5")
int BPF_KPROBE(do_mov_187)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x40b")
int BPF_KPROBE(do_mov_188)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x452")
int BPF_KPROBE(do_mov_189)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_block_get_ext+0x47a")
int BPF_KPROBE(do_mov_190)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x1f")
int BPF_KPROBE(do_mov_191)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_qevent_init+0x36")
int BPF_KPROBE(do_mov_192)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_chain+0x348")
int BPF_KPROBE(do_mov_193)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0x19b")
int BPF_KPROBE(do_mov_194)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_fill_node+0xde")
int BPF_KPROBE(do_mov_195)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1b8")
int BPF_KPROBE(do_mov_196)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_chain_dump+0x1d8")
int BPF_KPROBE(do_mov_197)
{
    u64 addr = ctx->r15 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_tfilter+0x357")
int BPF_KPROBE(do_mov_198)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x303")
int BPF_KPROBE(do_mov_199)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x333")
int BPF_KPROBE(do_mov_200)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x52c")
int BPF_KPROBE(do_mov_201)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x553")
int BPF_KPROBE(do_mov_202)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x582")
int BPF_KPROBE(do_mov_203)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x5e1")
int BPF_KPROBE(do_mov_204)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x5ff")
int BPF_KPROBE(do_mov_205)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x63c")
int BPF_KPROBE(do_mov_206)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_chain+0x65f")
int BPF_KPROBE(do_mov_207)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_destroy+0xeb")
int BPF_KPROBE(do_mov_208)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_setup_cb_destroy+0xff")
int BPF_KPROBE(do_mov_209)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x438")
int BPF_KPROBE(do_mov_210)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x4b6")
int BPF_KPROBE(do_mov_211)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x52e")
int BPF_KPROBE(do_mov_212)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x5a9")
int BPF_KPROBE(do_mov_213)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x615")
int BPF_KPROBE(do_mov_214)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x63c")
int BPF_KPROBE(do_mov_215)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x663")
int BPF_KPROBE(do_mov_216)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x68a")
int BPF_KPROBE(do_mov_217)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x6a8")
int BPF_KPROBE(do_mov_218)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x6d7")
int BPF_KPROBE(do_mov_219)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x719")
int BPF_KPROBE(do_mov_220)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x75d")
int BPF_KPROBE(do_mov_221)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_del_tfilter+0x7af")
int BPF_KPROBE(do_mov_222)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_exts_terse_dump+0x7a")
int BPF_KPROBE(do_mov_223)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x376")
int BPF_KPROBE(do_mov_224)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x41d")
int BPF_KPROBE(do_mov_225)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x444")
int BPF_KPROBE(do_mov_226)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x46b")
int BPF_KPROBE(do_mov_227)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x48f")
int BPF_KPROBE(do_mov_228)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x4c4")
int BPF_KPROBE(do_mov_229)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x4e1")
int BPF_KPROBE(do_mov_230)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x512")
int BPF_KPROBE(do_mov_231)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x53c")
int BPF_KPROBE(do_mov_232)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x563")
int BPF_KPROBE(do_mov_233)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_get_tfilter+0x580")
int BPF_KPROBE(do_mov_234)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x43a")
int BPF_KPROBE(do_mov_235)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x4ca")
int BPF_KPROBE(do_mov_236)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x687")
int BPF_KPROBE(do_mov_237)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x696")
int BPF_KPROBE(do_mov_238)
{
    u64 addr = ctx->r9 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x824")
int BPF_KPROBE(do_mov_239)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x874")
int BPF_KPROBE(do_mov_240)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x89d")
int BPF_KPROBE(do_mov_241)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x8ec")
int BPF_KPROBE(do_mov_242)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0x91f")
int BPF_KPROBE(do_mov_243)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xa76")
int BPF_KPROBE(do_mov_244)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xaa1")
int BPF_KPROBE(do_mov_245)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xace")
int BPF_KPROBE(do_mov_246)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xb27")
int BPF_KPROBE(do_mov_247)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xb51")
int BPF_KPROBE(do_mov_248)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xb9f")
int BPF_KPROBE(do_mov_249)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_new_tfilter+0xbe5")
int BPF_KPROBE(do_mov_250)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_pernet_del_id_list+0x50")
int BPF_KPROBE(do_mov_251)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_pernet_del_id_list+0x5d")
int BPF_KPROBE(do_mov_252)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0x5f")
int BPF_KPROBE(do_mov_253)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0x7e")
int BPF_KPROBE(do_mov_254)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0x98")
int BPF_KPROBE(do_mov_255)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_check_ctrlact+0xba")
int BPF_KPROBE(do_mov_256)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_unregister_action+0x6c")
int BPF_KPROBE(do_mov_257)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_unregister_action+0x79")
int BPF_KPROBE(do_mov_258)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_exec+0xd6")
int BPF_KPROBE(do_mov_259)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_cmd.constprop.0+0x30")
int BPF_KPROBE(do_mov_260)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_cmd.constprop.0+0x59")
int BPF_KPROBE(do_mov_261)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0x98")
int BPF_KPROBE(do_mov_262)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_offload_add_ex+0x1db")
int BPF_KPROBE(do_mov_263)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0x7a")
int BPF_KPROBE(do_mov_264)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0xa4")
int BPF_KPROBE(do_mov_265)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0x10e")
int BPF_KPROBE(do_mov_266)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_check_alloc+0x121")
int BPF_KPROBE(do_mov_267)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0xef")
int BPF_KPROBE(do_mov_268)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0xfa")
int BPF_KPROBE(do_mov_269)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0x18a")
int BPF_KPROBE(do_mov_270)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_register_action+0x195")
int BPF_KPROBE(do_mov_271)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x1cf")
int BPF_KPROBE(do_mov_272)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_idr_create+0x17c")
int BPF_KPROBE(do_mov_273)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_destroy+0x55")
int BPF_KPROBE(do_mov_274)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_action_load_ops+0x96")
int BPF_KPROBE(do_mov_275)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_action_load_ops+0x161")
int BPF_KPROBE(do_mov_276)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_action_load_ops+0x17e")
int BPF_KPROBE(do_mov_277)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x6d")
int BPF_KPROBE(do_mov_278)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x119")
int BPF_KPROBE(do_mov_279)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x1fa")
int BPF_KPROBE(do_mov_280)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init_1+0x2b3")
int BPF_KPROBE(do_mov_281)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init+0x29e")
int BPF_KPROBE(do_mov_282)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_init+0x2c9")
int BPF_KPROBE(do_mov_283)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_dump_1+0xfa")
int BPF_KPROBE(do_mov_284)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0xdb")
int BPF_KPROBE(do_mov_285)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0x3c9")
int BPF_KPROBE(do_mov_286)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_generic_walker+0x3fe")
int BPF_KPROBE(do_mov_287)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x1e6")
int BPF_KPROBE(do_mov_288)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x20d")
int BPF_KPROBE(do_mov_289)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x2d5")
int BPF_KPROBE(do_mov_290)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_dump_action+0x2fb")
int BPF_KPROBE(do_mov_291)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0xe5")
int BPF_KPROBE(do_mov_292)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x21c")
int BPF_KPROBE(do_mov_293)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x246")
int BPF_KPROBE(do_mov_294)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x29e")
int BPF_KPROBE(do_mov_295)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x2c4")
int BPF_KPROBE(do_mov_296)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_flush+0x2e1")
int BPF_KPROBE(do_mov_297)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_dump+0x56")
int BPF_KPROBE(do_mov_298)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_get_fill.constprop.0+0xc7")
int BPF_KPROBE(do_mov_299)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_get_fill.constprop.0+0xde")
int BPF_KPROBE(do_mov_300)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x1eb")
int BPF_KPROBE(do_mov_301)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x243")
int BPF_KPROBE(do_mov_302)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x313")
int BPF_KPROBE(do_mov_303)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x394")
int BPF_KPROBE(do_mov_304)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x43b")
int BPF_KPROBE(do_mov_305)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x52a")
int BPF_KPROBE(do_mov_306)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x568")
int BPF_KPROBE(do_mov_307)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tca_action_gd+0x585")
int BPF_KPROBE(do_mov_308)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_action_add+0x1b7")
int BPF_KPROBE(do_mov_309)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_action+0x124")
int BPF_KPROBE(do_mov_310)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tc_ctl_action+0x14a")
int BPF_KPROBE(do_mov_311)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x20")
int BPF_KPROBE(do_mov_312)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x27")
int BPF_KPROBE(do_mov_313)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x54")
int BPF_KPROBE(do_mov_314)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x3b")
int BPF_KPROBE(do_mov_315)
{
    u64 addr = ctx->si + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_enqueue+0x68")
int BPF_KPROBE(do_mov_316)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x25")
int BPF_KPROBE(do_mov_317)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x2c")
int BPF_KPROBE(do_mov_318)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x57")
int BPF_KPROBE(do_mov_319)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x46")
int BPF_KPROBE(do_mov_320)
{
    u64 addr = ctx->si + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bfifo_enqueue+0x6b")
int BPF_KPROBE(do_mov_321)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0x29")
int BPF_KPROBE(do_mov_322)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xa0")
int BPF_KPROBE(do_mov_323)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xa3")
int BPF_KPROBE(do_mov_324)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xb9")
int BPF_KPROBE(do_mov_325)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xc0")
int BPF_KPROBE(do_mov_326)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xfa")
int BPF_KPROBE(do_mov_327)
{
    u64 addr = ctx->di + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pfifo_tail_enqueue+0xdf")
int BPF_KPROBE(do_mov_328)
{
    u64 addr = ctx->di + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x3d")
int BPF_KPROBE(do_mov_329)
{
    u64 addr = ctx->di + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_lss+0x6f")
int BPF_KPROBE(do_mov_330)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x18")
int BPF_KPROBE(do_mov_331)
{
    u64 addr = ctx->di - 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x1f")
int BPF_KPROBE(do_mov_332)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x26")
int BPF_KPROBE(do_mov_333)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x2e")
int BPF_KPROBE(do_mov_334)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x52")
int BPF_KPROBE(do_mov_335)
{
    u64 addr = ctx->r13 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0x3b")
int BPF_KPROBE(do_mov_336)
{
    u64 addr = ctx->r13 + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xc1")
int BPF_KPROBE(do_mov_337)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_reset+0xdf")
int BPF_KPROBE(do_mov_338)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_walk+0x83")
int BPF_KPROBE(do_mov_339)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_opt_parse+0x65")
int BPF_KPROBE(do_mov_340)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_opt_parse+0x8b")
int BPF_KPROBE(do_mov_341)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_fopt.isra.0+0x36")
int BPF_KPROBE(do_mov_342)
{
    u64 addr = ctx->r12 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_fopt.isra.0+0x87")
int BPF_KPROBE(do_mov_343)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x6b")
int BPF_KPROBE(do_mov_344)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_set_wrr.isra.0+0x6e")
int BPF_KPROBE(do_mov_345)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_graft+0xef")
int BPF_KPROBE(do_mov_346)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x16b")
int BPF_KPROBE(do_mov_347)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x2f5")
int BPF_KPROBE(do_mov_348)
{
    u64 addr = ctx->bx + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_delete+0x310")
int BPF_KPROBE(do_mov_349)
{
    u64 addr = ctx->bx + 0x400;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x112")
int BPF_KPROBE(do_mov_350)
{
    u64 addr = ctx->bx + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x1a2")
int BPF_KPROBE(do_mov_351)
{
    u64 addr = ctx->bx + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_init+0x29b")
int BPF_KPROBE(do_mov_352)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0xbf")
int BPF_KPROBE(do_mov_353)
{
    u64 addr = ctx->ax + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0xb3")
int BPF_KPROBE(do_mov_354)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x457")
int BPF_KPROBE(do_mov_355)
{
    u64 addr = ctx->ax + ctx->si * 0x8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x47f")
int BPF_KPROBE(do_mov_356)
{
    u64 addr = ctx->ax + 0x478;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x489")
int BPF_KPROBE(do_mov_357)
{
    u64 addr = ctx->ax + 0x298;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x4a6")
int BPF_KPROBE(do_mov_358)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x501")
int BPF_KPROBE(do_mov_359)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5ba")
int BPF_KPROBE(do_mov_360)
{
    u64 addr = ctx->r14 + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5c1")
int BPF_KPROBE(do_mov_361)
{
    u64 addr = ctx->r14 + 0x400;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5e0")
int BPF_KPROBE(do_mov_362)
{
    u64 addr = ctx->r14 + 0x408;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dequeue+0x5f6")
int BPF_KPROBE(do_mov_363)
{
    u64 addr = ctx->r14 + ctx->cx * 0x8 + 0x3a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump+0x64")
int BPF_KPROBE(do_mov_364)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class+0x38")
int BPF_KPROBE(do_mov_365)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_dump_class+0x45")
int BPF_KPROBE(do_mov_366)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0xee")
int BPF_KPROBE(do_mov_367)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0xf1")
int BPF_KPROBE(do_mov_368)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x12f")
int BPF_KPROBE(do_mov_369)
{
    u64 addr = ctx->r12 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_enqueue+0x12f")
int BPF_KPROBE(do_mov_370)
{
    u64 addr = ctx->r12 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x156")
int BPF_KPROBE(do_mov_371)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x3ea")
int BPF_KPROBE(do_mov_372)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x604")
int BPF_KPROBE(do_mov_373)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x5d7")
int BPF_KPROBE(do_mov_374)
{
    u64 addr = ctx->r11 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x769")
int BPF_KPROBE(do_mov_375)
{
    u64 addr = ctx->r11 + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x790")
int BPF_KPROBE(do_mov_376)
{
    u64 addr = ctx->r11 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x88c")
int BPF_KPROBE(do_mov_377)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x8ba")
int BPF_KPROBE(do_mov_378)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x952")
int BPF_KPROBE(do_mov_379)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x9a8")
int BPF_KPROBE(do_mov_380)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0x9e3")
int BPF_KPROBE(do_mov_381)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbq_change_class+0xa86")
int BPF_KPROBE(do_mov_382)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xa2")
int BPF_KPROBE(do_mov_383)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0xfa")
int BPF_KPROBE(do_mov_384)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0x10f")
int BPF_KPROBE(do_mov_385)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_lookup_leaf+0x13d")
int BPF_KPROBE(do_mov_386)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0x8e")
int BPF_KPROBE(do_mov_387)
{
    u64 addr = ctx->si + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_add_to_wait_tree+0xa0")
int BPF_KPROBE(do_mov_388)
{
    u64 addr = ctx->si + 0x1d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class_stats+0x144")
int BPF_KPROBE(do_mov_389)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class_stats+0x104")
int BPF_KPROBE(do_mov_390)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_walk+0x83")
int BPF_KPROBE(do_mov_391)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class+0x44")
int BPF_KPROBE(do_mov_392)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dump_class+0x5d")
int BPF_KPROBE(do_mov_393)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x1bf")
int BPF_KPROBE(do_mov_394)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x156")
int BPF_KPROBE(do_mov_395)
{
    u64 addr = ctx->bx + 0x8f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x2e4")
int BPF_KPROBE(do_mov_396)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_init+0x308")
int BPF_KPROBE(do_mov_397)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0xd4")
int BPF_KPROBE(do_mov_398)
{
    u64 addr = ctx->dx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0xe6")
int BPF_KPROBE(do_mov_399)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0x201")
int BPF_KPROBE(do_mov_400)
{
    u64 addr = ctx->dx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_activate_prios+0x213")
int BPF_KPROBE(do_mov_401)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x4d")
int BPF_KPROBE(do_mov_402)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x77")
int BPF_KPROBE(do_mov_403)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x17d")
int BPF_KPROBE(do_mov_404)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_reset+0x10f")
int BPF_KPROBE(do_mov_405)
{
    u64 addr = ctx->r12 + 0x8e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0x22a")
int BPF_KPROBE(do_mov_406)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_deactivate_prios+0x13c")
int BPF_KPROBE(do_mov_407)
{
    u64 addr = ctx->cx + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class_mode+0x87")
int BPF_KPROBE(do_mov_408)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_dequeue+0x52")
int BPF_KPROBE(do_mov_409)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_graft+0xee")
int BPF_KPROBE(do_mov_410)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x45")
int BPF_KPROBE(do_mov_411)
{
    u64 addr = ctx->bx + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_parent_to_leaf+0x137")
int BPF_KPROBE(do_mov_412)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy+0x379")
int BPF_KPROBE(do_mov_413)
{
    u64 addr = ctx->r12 + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_destroy+0x391")
int BPF_KPROBE(do_mov_414)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0xe9")
int BPF_KPROBE(do_mov_415)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x20d")
int BPF_KPROBE(do_mov_416)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x214")
int BPF_KPROBE(do_mov_417)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x25d")
int BPF_KPROBE(do_mov_418)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x32b")
int BPF_KPROBE(do_mov_419)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_enqueue+0x333")
int BPF_KPROBE(do_mov_420)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x3c9")
int BPF_KPROBE(do_mov_421)
{
    u64 addr = ctx->si + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x54a")
int BPF_KPROBE(do_mov_422)
{
    u64 addr = ctx->si + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x76e")
int BPF_KPROBE(do_mov_423)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x8b4")
int BPF_KPROBE(do_mov_424)
{
    u64 addr = ctx->cx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x8d5")
int BPF_KPROBE(do_mov_425)
{
    u64 addr = ctx->cx + 0x1bc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0x964")
int BPF_KPROBE(do_mov_426)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xb4b")
int BPF_KPROBE(do_mov_427)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xc32")
int BPF_KPROBE(do_mov_428)
{
    u64 addr = ctx->bx + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/htb_change_class+0xdf0")
int BPF_KPROBE(do_mov_429)
{
    u64 addr = ctx->bx + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0x38")
int BPF_KPROBE(do_mov_430)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sc2isc+0xf4")
int BPF_KPROBE(do_mov_431)
{
    u64 addr = ctx->si + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0x9b")
int BPF_KPROBE(do_mov_432)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xe1")
int BPF_KPROBE(do_mov_433)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtsc_min+0xce")
int BPF_KPROBE(do_mov_434)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xd8")
int BPF_KPROBE(do_mov_435)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_reset_qdisc+0xcd")
int BPF_KPROBE(do_mov_436)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x5b")
int BPF_KPROBE(do_mov_437)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_init_qdisc+0x86")
int BPF_KPROBE(do_mov_438)
{
    u64 addr = ctx->r12 + 0x498;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_walk+0x83")
int BPF_KPROBE(do_mov_439)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0x141")
int BPF_KPROBE(do_mov_440)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_ed+0xad")
int BPF_KPROBE(do_mov_441)
{
    u64 addr = ctx->bx + 0x258;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0x9d")
int BPF_KPROBE(do_mov_442)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_ed+0x3b")
int BPF_KPROBE(do_mov_443)
{
    u64 addr = ctx->bx + 0x110;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x50")
int BPF_KPROBE(do_mov_444)
{
    u64 addr = ctx->bx + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x85")
int BPF_KPROBE(do_mov_445)
{
    u64 addr = ctx->bx + 0x2ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x1bc")
int BPF_KPROBE(do_mov_446)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x158")
int BPF_KPROBE(do_mov_447)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x27b")
int BPF_KPROBE(do_mov_448)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x221")
int BPF_KPROBE(do_mov_449)
{
    u64 addr = ctx->bx + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x306")
int BPF_KPROBE(do_mov_450)
{
    u64 addr = ctx->bx + 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/update_vf.constprop.0+0x2f8")
int BPF_KPROBE(do_mov_451)
{
    u64 addr = ctx->bx + 0x140;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0xca")
int BPF_KPROBE(do_mov_452)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x3d")
int BPF_KPROBE(do_mov_453)
{
    u64 addr = ctx->bx + 0x2ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x226")
int BPF_KPROBE(do_mov_454)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x1cd")
int BPF_KPROBE(do_mov_455)
{
    u64 addr = ctx->bx + 0x2e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x296")
int BPF_KPROBE(do_mov_456)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_vf.constprop.0+0x2a8")
int BPF_KPROBE(do_mov_457)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_graft_class+0xf8")
int BPF_KPROBE(do_mov_458)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_delete_class+0x82")
int BPF_KPROBE(do_mov_459)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xd2")
int BPF_KPROBE(do_mov_460)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dequeue+0xe6")
int BPF_KPROBE(do_mov_461)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class+0x3c")
int BPF_KPROBE(do_mov_462)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_dump_class+0x50")
int BPF_KPROBE(do_mov_463)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x273")
int BPF_KPROBE(do_mov_464)
{
    u64 addr = ctx->r12 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x33d")
int BPF_KPROBE(do_mov_465)
{
    u64 addr = ctx->r12 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8b9")
int BPF_KPROBE(do_mov_466)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0x8ab")
int BPF_KPROBE(do_mov_467)
{
    u64 addr = ctx->r10 + 0x2d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_change_class+0xa21")
int BPF_KPROBE(do_mov_468)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_enqueue+0xaa")
int BPF_KPROBE(do_mov_469)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hfsc_enqueue+0xad")
int BPF_KPROBE(do_mov_470)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_reset+0x2f")
int BPF_KPROBE(do_mov_471)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_reset+0x19")
int BPF_KPROBE(do_mov_472)
{
    u64 addr = ctx->bx + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_walk+0x3a")
int BPF_KPROBE(do_mov_473)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x173")
int BPF_KPROBE(do_mov_474)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x188")
int BPF_KPROBE(do_mov_475)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_enqueue+0x277")
int BPF_KPROBE(do_mov_476)
{
    u64 addr = ctx->bx + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/red_graft+0xfd")
int BPF_KPROBE(do_mov_477)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x19d")
int BPF_KPROBE(do_mov_478)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x1fa")
int BPF_KPROBE(do_mov_479)
{
    u64 addr = ctx->r14 + 0x310;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x2e5")
int BPF_KPROBE(do_mov_480)
{
    u64 addr = ctx->r14 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x32b")
int BPF_KPROBE(do_mov_481)
{
    u64 addr = ctx->r14 + 0x2d7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x347")
int BPF_KPROBE(do_mov_482)
{
    u64 addr = ctx->r14 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x442")
int BPF_KPROBE(do_mov_483)
{
    u64 addr = ctx->r14 + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__red_change+0x510")
int BPF_KPROBE(do_mov_484)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x43")
int BPF_KPROBE(do_mov_485)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x51")
int BPF_KPROBE(do_mov_486)
{
    u64 addr = ctx->r10 + 0x2c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0xe1")
int BPF_KPROBE(do_mov_487)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_offload+0x124")
int BPF_KPROBE(do_mov_488)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x5d")
int BPF_KPROBE(do_mov_489)
{
    u64 addr = ctx->ax + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x3d")
int BPF_KPROBE(do_mov_490)
{
    u64 addr = ctx->ax + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x89")
int BPF_KPROBE(do_mov_491)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_reset+0x9f")
int BPF_KPROBE(do_mov_492)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dequeue+0x3c")
int BPF_KPROBE(do_mov_493)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0xd6")
int BPF_KPROBE(do_mov_494)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0xf6")
int BPF_KPROBE(do_mov_495)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0x116")
int BPF_KPROBE(do_mov_496)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0x136")
int BPF_KPROBE(do_mov_497)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_vq_validate+0x159")
int BPF_KPROBE(do_mov_498)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x88")
int BPF_KPROBE(do_mov_499)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x67b")
int BPF_KPROBE(do_mov_500)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x7be")
int BPF_KPROBE(do_mov_501)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_dump+0x7d5")
int BPF_KPROBE(do_mov_502)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x82")
int BPF_KPROBE(do_mov_503)
{
    u64 addr = ctx->bx + 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x91")
int BPF_KPROBE(do_mov_504)
{
    u64 addr = ctx->bx + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x184")
int BPF_KPROBE(do_mov_505)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x18d")
int BPF_KPROBE(do_mov_506)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x2ff")
int BPF_KPROBE(do_mov_507)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x2ef")
int BPF_KPROBE(do_mov_508)
{
    u64 addr = ctx->bx + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x398")
int BPF_KPROBE(do_mov_509)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x44c")
int BPF_KPROBE(do_mov_510)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x498")
int BPF_KPROBE(do_mov_511)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x50c")
int BPF_KPROBE(do_mov_512)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_enqueue+0x504")
int BPF_KPROBE(do_mov_513)
{
    u64 addr = ctx->r12 + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0xd5")
int BPF_KPROBE(do_mov_514)
{
    u64 addr = ctx->r12 + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0xc8")
int BPF_KPROBE(do_mov_515)
{
    u64 addr = ctx->r12 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x2e0")
int BPF_KPROBE(do_mov_516)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x30a")
int BPF_KPROBE(do_mov_517)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x334")
int BPF_KPROBE(do_mov_518)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change_table_def+0x35e")
int BPF_KPROBE(do_mov_519)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x23f")
int BPF_KPROBE(do_mov_520)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x2f2")
int BPF_KPROBE(do_mov_521)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x341")
int BPF_KPROBE(do_mov_522)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x375")
int BPF_KPROBE(do_mov_523)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x380")
int BPF_KPROBE(do_mov_524)
{
    u64 addr = ctx->r15 + 0x160;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x458")
int BPF_KPROBE(do_mov_525)
{
    u64 addr = ctx->r15 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x48f")
int BPF_KPROBE(do_mov_526)
{
    u64 addr = ctx->r15 + 0x143;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x736")
int BPF_KPROBE(do_mov_527)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gred_change+0x75d")
int BPF_KPROBE(do_mov_528)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0x64")
int BPF_KPROBE(do_mov_529)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/clsact_init+0xaf")
int BPF_KPROBE(do_mov_530)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_init+0x5b")
int BPF_KPROBE(do_mov_531)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ingress_init+0x4d")
int BPF_KPROBE(do_mov_532)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_walk+0x81")
int BPF_KPROBE(do_mov_533)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dump_class+0x143")
int BPF_KPROBE(do_mov_534)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dump_class+0xbc")
int BPF_KPROBE(do_mov_535)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x196")
int BPF_KPROBE(do_mov_536)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_init+0x17e")
int BPF_KPROBE(do_mov_537)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x6c")
int BPF_KPROBE(do_mov_538)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x81")
int BPF_KPROBE(do_mov_539)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_dequeue+0x175")
int BPF_KPROBE(do_mov_540)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_graft+0xdc")
int BPF_KPROBE(do_mov_541)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x263")
int BPF_KPROBE(do_mov_542)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x5b")
int BPF_KPROBE(do_mov_543)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x291")
int BPF_KPROBE(do_mov_544)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dsmark_enqueue+0x29a")
int BPF_KPROBE(do_mov_545)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dump+0xd7")
int BPF_KPROBE(do_mov_546)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_walk+0x3a")
int BPF_KPROBE(do_mov_547)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dequeue+0x96")
int BPF_KPROBE(do_mov_548)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_dequeue+0xcd")
int BPF_KPROBE(do_mov_549)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_graft+0xd8")
int BPF_KPROBE(do_mov_550)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x150")
int BPF_KPROBE(do_mov_551)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_change+0x1e1")
int BPF_KPROBE(do_mov_552)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x2e7")
int BPF_KPROBE(do_mov_553)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x379")
int BPF_KPROBE(do_mov_554)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x39c")
int BPF_KPROBE(do_mov_555)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x39f")
int BPF_KPROBE(do_mov_556)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x6b2")
int BPF_KPROBE(do_mov_557)
{
    u64 addr = ctx->bx + 0x1c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfb_enqueue+0x623")
int BPF_KPROBE(do_mov_558)
{
    u64 addr = ctx->bx + 0x1d9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x76")
int BPF_KPROBE(do_mov_559)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0xba")
int BPF_KPROBE(do_mov_560)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x16d")
int BPF_KPROBE(do_mov_561)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x170")
int BPF_KPROBE(do_mov_562)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x18a")
int BPF_KPROBE(do_mov_563)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x198")
int BPF_KPROBE(do_mov_564)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_drop+0x1b8")
int BPF_KPROBE(do_mov_565)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_walk+0x6e")
int BPF_KPROBE(do_mov_566)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x92")
int BPF_KPROBE(do_mov_567)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x95")
int BPF_KPROBE(do_mov_568)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x1c5")
int BPF_KPROBE(do_mov_569)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x1e7")
int BPF_KPROBE(do_mov_570)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x207")
int BPF_KPROBE(do_mov_571)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x216")
int BPF_KPROBE(do_mov_572)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x27d")
int BPF_KPROBE(do_mov_573)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x55d")
int BPF_KPROBE(do_mov_574)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x4fd")
int BPF_KPROBE(do_mov_575)
{
    u64 addr = ctx->r14 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x567")
int BPF_KPROBE(do_mov_576)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x58f")
int BPF_KPROBE(do_mov_577)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x594")
int BPF_KPROBE(do_mov_578)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5a5")
int BPF_KPROBE(do_mov_579)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5b0")
int BPF_KPROBE(do_mov_580)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x5b3")
int BPF_KPROBE(do_mov_581)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_enqueue+0x64b")
int BPF_KPROBE(do_mov_582)
{
    u64 addr = ctx->r14 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x85")
int BPF_KPROBE(do_mov_583)
{
    u64 addr = ctx->dx - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x8d")
int BPF_KPROBE(do_mov_584)
{
    u64 addr = ctx->dx - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xae")
int BPF_KPROBE(do_mov_585)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0xf2")
int BPF_KPROBE(do_mov_586)
{
    u64 addr = ctx->r13 + 0x3f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2e8")
int BPF_KPROBE(do_mov_587)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2ff")
int BPF_KPROBE(do_mov_588)
{
    u64 addr = ctx->r11 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x2f8")
int BPF_KPROBE(do_mov_589)
{
    u64 addr = ctx->r11 + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x382")
int BPF_KPROBE(do_mov_590)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x368")
int BPF_KPROBE(do_mov_591)
{
    u64 addr = ctx->di + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x39d")
int BPF_KPROBE(do_mov_592)
{
    u64 addr = ctx->r13 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x497")
int BPF_KPROBE(do_mov_593)
{
    u64 addr = ctx->r13 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x574")
int BPF_KPROBE(do_mov_594)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x56c")
int BPF_KPROBE(do_mov_595)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x5b3")
int BPF_KPROBE(do_mov_596)
{
    u64 addr = ctx->r13 + ctx->cx * 0x4 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x5e5")
int BPF_KPROBE(do_mov_597)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x607")
int BPF_KPROBE(do_mov_598)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_init+0x611")
int BPF_KPROBE(do_mov_599)
{
    u64 addr = ctx->r13 + 0x3f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x76")
int BPF_KPROBE(do_mov_600)
{
    u64 addr = ctx->r13 - 0x268;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x164")
int BPF_KPROBE(do_mov_601)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x170")
int BPF_KPROBE(do_mov_602)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x18f")
int BPF_KPROBE(do_mov_603)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x19e")
int BPF_KPROBE(do_mov_604)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x1d6")
int BPF_KPROBE(do_mov_605)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x363")
int BPF_KPROBE(do_mov_606)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x376")
int BPF_KPROBE(do_mov_607)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3de")
int BPF_KPROBE(do_mov_608)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3e9")
int BPF_KPROBE(do_mov_609)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x3ef")
int BPF_KPROBE(do_mov_610)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x421")
int BPF_KPROBE(do_mov_611)
{
    u64 addr = ctx->si + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_perturbation+0x55c")
int BPF_KPROBE(do_mov_612)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x6a")
int BPF_KPROBE(do_mov_613)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x79")
int BPF_KPROBE(do_mov_614)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0xb5")
int BPF_KPROBE(do_mov_615)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x1cd")
int BPF_KPROBE(do_mov_616)
{
    u64 addr = ctx->dx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sfq_dequeue+0x269")
int BPF_KPROBE(do_mov_617)
{
    u64 addr = ctx->dx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_reset+0x33")
int BPF_KPROBE(do_mov_618)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_reset+0x25")
int BPF_KPROBE(do_mov_619)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_walk+0x3a")
int BPF_KPROBE(do_mov_620)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0x48")
int BPF_KPROBE(do_mov_621)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0x51")
int BPF_KPROBE(do_mov_622)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_enqueue+0xbc")
int BPF_KPROBE(do_mov_623)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dump+0x1b0")
int BPF_KPROBE(do_mov_624)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_graft+0xf3")
int BPF_KPROBE(do_mov_625)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0xf4")
int BPF_KPROBE(do_mov_626)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x107")
int BPF_KPROBE(do_mov_627)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x19d")
int BPF_KPROBE(do_mov_628)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_dequeue+0x191")
int BPF_KPROBE(do_mov_629)
{
    u64 addr = ctx->bx + 0x1d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2c1")
int BPF_KPROBE(do_mov_630)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tbf_change+0x2ae")
int BPF_KPROBE(do_mov_631)
{
    u64 addr = ctx->r14 + 0x1e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x3f")
int BPF_KPROBE(do_mov_632)
{
    u64 addr = ctx->di + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x54")
int BPF_KPROBE(do_mov_633)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x190")
int BPF_KPROBE(do_mov_634)
{
    u64 addr = ctx->cx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_qdisc_init+0x16f")
int BPF_KPROBE(do_mov_635)
{
    u64 addr = ctx->cx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_stats64+0xd")
int BPF_KPROBE(do_mov_636)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_master_stats64+0x32")
int BPF_KPROBE(do_mov_637)
{
    u64 addr = ctx->si + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x4d")
int BPF_KPROBE(do_mov_638)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_dequeue+0x58")
int BPF_KPROBE(do_mov_639)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x29")
int BPF_KPROBE(do_mov_640)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x43")
int BPF_KPROBE(do_mov_641)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/teql_enqueue+0x51")
int BPF_KPROBE(do_mov_642)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


// SEC("kprobe/teql_master_xmit+0x361")
// int BPF_KPROBE(do_mov_643)
// {
//     u64 addr = ctx->gs + 0x3253a;
//     sampling(addr, ctx->ip);
//     return 0;
// }


SEC("kprobe/prio_dequeue+0x60")
int BPF_KPROBE(do_mov_644)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_dequeue+0x73")
int BPF_KPROBE(do_mov_645)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x11f")
int BPF_KPROBE(do_mov_646)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x123")
int BPF_KPROBE(do_mov_647)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x135")
int BPF_KPROBE(do_mov_648)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_enqueue+0x139")
int BPF_KPROBE(do_mov_649)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_walk+0x56")
int BPF_KPROBE(do_mov_650)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_graft+0x104")
int BPF_KPROBE(do_mov_651)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0xfb")
int BPF_KPROBE(do_mov_652)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0x10a")
int BPF_KPROBE(do_mov_653)
{
    u64 addr = ctx->r14 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0x115")
int BPF_KPROBE(do_mov_654)
{
    u64 addr = ctx->r14 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/prio_tune+0x1a6")
int BPF_KPROBE(do_mov_655)
{
    u64 addr = ctx->r14 + ctx->ax * 0x8 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_enqueue+0x64")
int BPF_KPROBE(do_mov_656)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_enqueue+0x68")
int BPF_KPROBE(do_mov_657)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_walk+0x62")
int BPF_KPROBE(do_mov_658)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0xee")
int BPF_KPROBE(do_mov_659)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_tune+0x242")
int BPF_KPROBE(do_mov_660)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_graft+0x61")
int BPF_KPROBE(do_mov_661)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/multiq_graft+0xdc")
int BPF_KPROBE(do_mov_662)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0xdb")
int BPF_KPROBE(do_mov_663)
{
    u64 addr = ctx->r12 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_reset+0x9a")
int BPF_KPROBE(do_mov_664)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_walk+0x3a")
int BPF_KPROBE(do_mov_665)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_dist_table+0x5f")
int BPF_KPROBE(do_mov_666)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_dist_table+0x9b")
int BPF_KPROBE(do_mov_667)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x16d")
int BPF_KPROBE(do_mov_668)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_change+0x3cd")
int BPF_KPROBE(do_mov_669)
{
    u64 addr = ctx->bx + 0x2cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dump+0x252")
int BPF_KPROBE(do_mov_670)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dump+0x287")
int BPF_KPROBE(do_mov_671)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_graft+0xcd")
int BPF_KPROBE(do_mov_672)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x4f")
int BPF_KPROBE(do_mov_673)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x160")
int BPF_KPROBE(do_mov_674)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x271")
int BPF_KPROBE(do_mov_675)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_dequeue+0x1a1")
int BPF_KPROBE(do_mov_676)
{
    u64 addr = ctx->bx + 0x2cc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x240")
int BPF_KPROBE(do_mov_677)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x2a5")
int BPF_KPROBE(do_mov_678)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x392")
int BPF_KPROBE(do_mov_679)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x3ae")
int BPF_KPROBE(do_mov_680)
{
    u64 addr = ctx->r15 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x41e")
int BPF_KPROBE(do_mov_681)
{
    u64 addr = ctx->r15 + 0x214;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x638")
int BPF_KPROBE(do_mov_682)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x63b")
int BPF_KPROBE(do_mov_683)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x6cf")
int BPF_KPROBE(do_mov_684)
{
    u64 addr = ctx->r15 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x6a1")
int BPF_KPROBE(do_mov_685)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x960")
int BPF_KPROBE(do_mov_686)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x973")
int BPF_KPROBE(do_mov_687)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0x97a")
int BPF_KPROBE(do_mov_688)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xabf")
int BPF_KPROBE(do_mov_689)
{
    u64 addr = ctx->r15 + 0x244;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xb10")
int BPF_KPROBE(do_mov_690)
{
    u64 addr = ctx->r15 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbaf")
int BPF_KPROBE(do_mov_691)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbd2")
int BPF_KPROBE(do_mov_692)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbe1")
int BPF_KPROBE(do_mov_693)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netem_enqueue+0xbe4")
int BPF_KPROBE(do_mov_694)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_qlen_notify+0x15")
int BPF_KPROBE(do_mov_695)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_reset_qdisc+0x6d")
int BPF_KPROBE(do_mov_696)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x47")
int BPF_KPROBE(do_mov_697)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x58")
int BPF_KPROBE(do_mov_698)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x5f")
int BPF_KPROBE(do_mov_699)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xd9")
int BPF_KPROBE(do_mov_700)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0xee")
int BPF_KPROBE(do_mov_701)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x12a")
int BPF_KPROBE(do_mov_702)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dequeue+0x137")
int BPF_KPROBE(do_mov_703)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_walk+0x83")
int BPF_KPROBE(do_mov_704)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dump_class+0x33")
int BPF_KPROBE(do_mov_705)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_dump_class+0x42")
int BPF_KPROBE(do_mov_706)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_graft_class+0xd0")
int BPF_KPROBE(do_mov_707)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x17c")
int BPF_KPROBE(do_mov_708)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x2af")
int BPF_KPROBE(do_mov_709)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x321")
int BPF_KPROBE(do_mov_710)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x422")
int BPF_KPROBE(do_mov_711)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_change_class+0x445")
int BPF_KPROBE(do_mov_712)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0x15e")
int BPF_KPROBE(do_mov_713)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/drr_enqueue+0x161")
int BPF_KPROBE(do_mov_714)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x1e")
int BPF_KPROBE(do_mov_715)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_init+0x11")
int BPF_KPROBE(do_mov_716)
{
    u64 addr = ctx->di + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0x94")
int BPF_KPROBE(do_mov_717)
{
    u64 addr = ctx->di + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_change+0xb4")
int BPF_KPROBE(do_mov_718)
{
    u64 addr = ctx->di + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x38")
int BPF_KPROBE(do_mov_719)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x76")
int BPF_KPROBE(do_mov_720)
{
    u64 addr = ctx->si + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x52")
int BPF_KPROBE(do_mov_721)
{
    u64 addr = ctx->si + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/plug_enqueue+0x8a")
int BPF_KPROBE(do_mov_722)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_qlen_notify+0x42")
int BPF_KPROBE(do_mov_723)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_offload_change+0xfb")
int BPF_KPROBE(do_mov_724)
{
    u64 addr = ctx->cx - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_reset+0x6e")
int BPF_KPROBE(do_mov_725)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_walk+0x56")
int BPF_KPROBE(do_mov_726)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_tcf_block+0x35")
int BPF_KPROBE(do_mov_727)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x17c")
int BPF_KPROBE(do_mov_728)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x17f")
int BPF_KPROBE(do_mov_729)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x194")
int BPF_KPROBE(do_mov_730)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x197")
int BPF_KPROBE(do_mov_731)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1ad")
int BPF_KPROBE(do_mov_732)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_enqueue+0x1b6")
int BPF_KPROBE(do_mov_733)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x78")
int BPF_KPROBE(do_mov_734)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x8b")
int BPF_KPROBE(do_mov_735)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x162")
int BPF_KPROBE(do_mov_736)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x173")
int BPF_KPROBE(do_mov_737)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x17c")
int BPF_KPROBE(do_mov_738)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x210")
int BPF_KPROBE(do_mov_739)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x223")
int BPF_KPROBE(do_mov_740)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x26a")
int BPF_KPROBE(do_mov_741)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dequeue+0x26d")
int BPF_KPROBE(do_mov_742)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_dump+0x71")
int BPF_KPROBE(do_mov_743)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_dump+0x80")
int BPF_KPROBE(do_mov_744)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x189")
int BPF_KPROBE(do_mov_745)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x294")
int BPF_KPROBE(do_mov_746)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x34d")
int BPF_KPROBE(do_mov_747)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x4e4")
int BPF_KPROBE(do_mov_748)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x4ec")
int BPF_KPROBE(do_mov_749)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x56d")
int BPF_KPROBE(do_mov_750)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x577")
int BPF_KPROBE(do_mov_751)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x682")
int BPF_KPROBE(do_mov_752)
{
    u64 addr = ctx->r12 - 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x68b")
int BPF_KPROBE(do_mov_753)
{
    u64 addr = ctx->r12 - 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x694")
int BPF_KPROBE(do_mov_754)
{
    u64 addr = ctx->r12 - 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x6a2")
int BPF_KPROBE(do_mov_755)
{
    u64 addr = ctx->r12 - 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x6ab")
int BPF_KPROBE(do_mov_756)
{
    u64 addr = ctx->r12 - 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x6b4")
int BPF_KPROBE(do_mov_757)
{
    u64 addr = ctx->r12 - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x727")
int BPF_KPROBE(do_mov_758)
{
    u64 addr = ctx->bx + 0x1a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x731")
int BPF_KPROBE(do_mov_759)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x767")
int BPF_KPROBE(do_mov_760)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_change+0x779")
int BPF_KPROBE(do_mov_761)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dump+0x201")
int BPF_KPROBE(do_mov_762)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_qdisc_dump+0x218")
int BPF_KPROBE(do_mov_763)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_graft+0xed")
int BPF_KPROBE(do_mov_764)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x1f6")
int BPF_KPROBE(do_mov_765)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x224")
int BPF_KPROBE(do_mov_766)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ets_class_change+0x202")
int BPF_KPROBE(do_mov_767)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_walk+0x76")
int BPF_KPROBE(do_mov_768)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_graft+0x59")
int BPF_KPROBE(do_mov_769)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x134")
int BPF_KPROBE(do_mov_770)
{
    u64 addr = ctx->r14 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x154")
int BPF_KPROBE(do_mov_771)
{
    u64 addr = ctx->r14 + 0x18a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x1b6")
int BPF_KPROBE(do_mov_772)
{
    u64 addr = ctx->r14 + ctx->si * 0x8 + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x216")
int BPF_KPROBE(do_mov_773)
{
    u64 addr = ctx->r14 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x485")
int BPF_KPROBE(do_mov_774)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_init+0x649")
int BPF_KPROBE(do_mov_775)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x82")
int BPF_KPROBE(do_mov_776)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0xbb")
int BPF_KPROBE(do_mov_777)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x40b")
int BPF_KPROBE(do_mov_778)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mqprio_dump+0x43d")
int BPF_KPROBE(do_mov_779)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x1a")
int BPF_KPROBE(do_mov_780)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x25")
int BPF_KPROBE(do_mov_781)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x63")
int BPF_KPROBE(do_mov_782)
{
    u64 addr = ctx->r8 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_init+0x6b")
int BPF_KPROBE(do_mov_783)
{
    u64 addr = ctx->r8 + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x5b")
int BPF_KPROBE(do_mov_784)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_dequeue+0x6e")
int BPF_KPROBE(do_mov_785)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x77")
int BPF_KPROBE(do_mov_786)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x8a")
int BPF_KPROBE(do_mov_787)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x95")
int BPF_KPROBE(do_mov_788)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x10d")
int BPF_KPROBE(do_mov_789)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x120")
int BPF_KPROBE(do_mov_790)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x131")
int BPF_KPROBE(do_mov_791)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x134")
int BPF_KPROBE(do_mov_792)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x196")
int BPF_KPROBE(do_mov_793)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1a1")
int BPF_KPROBE(do_mov_794)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1db")
int BPF_KPROBE(do_mov_795)
{
    u64 addr = ctx->ax + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_enqueue+0x1eb")
int BPF_KPROBE(do_mov_796)
{
    u64 addr = ctx->ax + 0xc82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_walk+0x4d")
int BPF_KPROBE(do_mov_797)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x34")
int BPF_KPROBE(do_mov_798)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_destroy+0x47")
int BPF_KPROBE(do_mov_799)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x36")
int BPF_KPROBE(do_mov_800)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x49")
int BPF_KPROBE(do_mov_801)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x73")
int BPF_KPROBE(do_mov_802)
{
    u64 addr = ctx->r13 + 0x780;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skbprio_reset+0x9c")
int BPF_KPROBE(do_mov_803)
{
    u64 addr = ctx->r13 + 0xc80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x8c")
int BPF_KPROBE(do_mov_804)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_reset+0x1e")
int BPF_KPROBE(do_mov_805)
{
    u64 addr = ctx->bx + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x9b")
int BPF_KPROBE(do_mov_806)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0xa4")
int BPF_KPROBE(do_mov_807)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x268")
int BPF_KPROBE(do_mov_808)
{
    u64 addr = ctx->bx + 0x2b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x213")
int BPF_KPROBE(do_mov_809)
{
    u64 addr = ctx->bx + 0x2e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x3e8")
int BPF_KPROBE(do_mov_810)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x3ec")
int BPF_KPROBE(do_mov_811)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x424")
int BPF_KPROBE(do_mov_812)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_enqueue+0x42d")
int BPF_KPROBE(do_mov_813)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x23f")
int BPF_KPROBE(do_mov_814)
{
    u64 addr = ctx->r15 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x221")
int BPF_KPROBE(do_mov_815)
{
    u64 addr = ctx->r15 + 0x2f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x313")
int BPF_KPROBE(do_mov_816)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x359")
int BPF_KPROBE(do_mov_817)
{
    u64 addr = ctx->r15 + 0x2a7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x3c8")
int BPF_KPROBE(do_mov_818)
{
    u64 addr = ctx->r15 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/choke_change+0x389")
int BPF_KPROBE(do_mov_819)
{
    u64 addr = ctx->r15 + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0xce")
int BPF_KPROBE(do_mov_820)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0xca")
int BPF_KPROBE(do_mov_821)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x16e")
int BPF_KPROBE(do_mov_822)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x2af")
int BPF_KPROBE(do_mov_823)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_choose_next_agg+0x265")
int BPF_KPROBE(do_mov_824)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x74")
int BPF_KPROBE(do_mov_825)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_destroy_agg+0x53")
int BPF_KPROBE(do_mov_826)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xa0")
int BPF_KPROBE(do_mov_827)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xac")
int BPF_KPROBE(do_mov_828)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_update_agg+0xb4")
int BPF_KPROBE(do_mov_829)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x7c")
int BPF_KPROBE(do_mov_830)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0x5a")
int BPF_KPROBE(do_mov_831)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_schedule_agg+0xe3")
int BPF_KPROBE(do_mov_832)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_walk+0x83")
int BPF_KPROBE(do_mov_833)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0x9f")
int BPF_KPROBE(do_mov_834)
{
    u64 addr = ctx->dx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0xb3")
int BPF_KPROBE(do_mov_835)
{
    u64 addr = ctx->dx - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_init_qdisc+0xc1")
int BPF_KPROBE(do_mov_836)
{
    u64 addr = ctx->dx - 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x48")
int BPF_KPROBE(do_mov_837)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x63")
int BPF_KPROBE(do_mov_838)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x134")
int BPF_KPROBE(do_mov_839)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_deactivate_agg+0x144")
int BPF_KPROBE(do_mov_840)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0x6b")
int BPF_KPROBE(do_mov_841)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0x13")
int BPF_KPROBE(do_mov_842)
{
    u64 addr = ctx->si + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0xd6")
int BPF_KPROBE(do_mov_843)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_activate_agg.constprop.0+0xc6")
int BPF_KPROBE(do_mov_844)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dump_class+0x33")
int BPF_KPROBE(do_mov_845)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dump_class+0x42")
int BPF_KPROBE(do_mov_846)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_reset_qdisc+0x91")
int BPF_KPROBE(do_mov_847)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_qlen_notify+0x15")
int BPF_KPROBE(do_mov_848)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0xf7")
int BPF_KPROBE(do_mov_849)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x10a")
int BPF_KPROBE(do_mov_850)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x186")
int BPF_KPROBE(do_mov_851)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x15f")
int BPF_KPROBE(do_mov_852)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x21d")
int BPF_KPROBE(do_mov_853)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_dequeue+0x2ab")
int BPF_KPROBE(do_mov_854)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_graft_class+0xd0")
int BPF_KPROBE(do_mov_855)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x20f")
int BPF_KPROBE(do_mov_856)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x293")
int BPF_KPROBE(do_mov_857)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3a6")
int BPF_KPROBE(do_mov_858)
{
    u64 addr = ctx->r14 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3b6")
int BPF_KPROBE(do_mov_859)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3db")
int BPF_KPROBE(do_mov_860)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x3d7")
int BPF_KPROBE(do_mov_861)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x440")
int BPF_KPROBE(do_mov_862)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x477")
int BPF_KPROBE(do_mov_863)
{
    u64 addr = ctx->r13 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_change_class+0x455")
int BPF_KPROBE(do_mov_864)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x286")
int BPF_KPROBE(do_mov_865)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x2b2")
int BPF_KPROBE(do_mov_866)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x2b5")
int BPF_KPROBE(do_mov_867)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x47a")
int BPF_KPROBE(do_mov_868)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4d0")
int BPF_KPROBE(do_mov_869)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4df")
int BPF_KPROBE(do_mov_870)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x501")
int BPF_KPROBE(do_mov_871)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x4fd")
int BPF_KPROBE(do_mov_872)
{
    u64 addr = ctx->ax + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/qfq_enqueue+0x520")
int BPF_KPROBE(do_mov_873)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x37")
int BPF_KPROBE(do_mov_874)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x3f")
int BPF_KPROBE(do_mov_875)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x69")
int BPF_KPROBE(do_mov_876)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x42")
int BPF_KPROBE(do_mov_877)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_enqueue+0x88")
int BPF_KPROBE(do_mov_878)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0x6")
int BPF_KPROBE(do_mov_879)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_reset+0x45")
int BPF_KPROBE(do_mov_880)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_reset+0x5b")
int BPF_KPROBE(do_mov_881)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0xe4")
int BPF_KPROBE(do_mov_882)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0xce")
int BPF_KPROBE(do_mov_883)
{
    u64 addr = ctx->bx + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x159")
int BPF_KPROBE(do_mov_884)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_change+0x153")
int BPF_KPROBE(do_mov_885)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x2e")
int BPF_KPROBE(do_mov_886)
{
    u64 addr = ctx->di - 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x38")
int BPF_KPROBE(do_mov_887)
{
    u64 addr = ctx->di - 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x3f")
int BPF_KPROBE(do_mov_888)
{
    u64 addr = ctx->di - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x43")
int BPF_KPROBE(do_mov_889)
{
    u64 addr = ctx->di - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x94")
int BPF_KPROBE(do_mov_890)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_init+0x50")
int BPF_KPROBE(do_mov_891)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x53")
int BPF_KPROBE(do_mov_892)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x192")
int BPF_KPROBE(do_mov_893)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x8d")
int BPF_KPROBE(do_mov_894)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x1c1")
int BPF_KPROBE(do_mov_895)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x253")
int BPF_KPROBE(do_mov_896)
{
    u64 addr = ctx->bx + 0x1b0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x560")
int BPF_KPROBE(do_mov_897)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x462")
int BPF_KPROBE(do_mov_898)
{
    u64 addr = ctx->bx + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x711")
int BPF_KPROBE(do_mov_899)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_qdisc_dequeue+0x5c3")
int BPF_KPROBE(do_mov_900)
{
    u64 addr = ctx->bx + 0x1ac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dequeue_func+0x20")
int BPF_KPROBE(do_mov_901)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/codel_vars_init+0x6")
int BPF_KPROBE(do_mov_902)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x18")
int BPF_KPROBE(do_mov_903)
{
    u64 addr = ctx->di + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x34")
int BPF_KPROBE(do_mov_904)
{
    u64 addr = ctx->di + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x6a")
int BPF_KPROBE(do_mov_905)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_reset+0x79")
int BPF_KPROBE(do_mov_906)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_walk+0x78")
int BPF_KPROBE(do_mov_907)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dump+0x1e5")
int BPF_KPROBE(do_mov_908)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x90")
int BPF_KPROBE(do_mov_909)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x94")
int BPF_KPROBE(do_mov_910)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x114")
int BPF_KPROBE(do_mov_911)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x11f")
int BPF_KPROBE(do_mov_912)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x230")
int BPF_KPROBE(do_mov_913)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x240")
int BPF_KPROBE(do_mov_914)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x249")
int BPF_KPROBE(do_mov_915)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x2a9")
int BPF_KPROBE(do_mov_916)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x33a")
int BPF_KPROBE(do_mov_917)
{
    u64 addr = ctx->r12 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_enqueue+0x366")
int BPF_KPROBE(do_mov_918)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x234")
int BPF_KPROBE(do_mov_919)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x245")
int BPF_KPROBE(do_mov_920)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x24d")
int BPF_KPROBE(do_mov_921)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x307")
int BPF_KPROBE(do_mov_922)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x30a")
int BPF_KPROBE(do_mov_923)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x32b")
int BPF_KPROBE(do_mov_924)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x33c")
int BPF_KPROBE(do_mov_925)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x344")
int BPF_KPROBE(do_mov_926)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x386")
int BPF_KPROBE(do_mov_927)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_dequeue+0x3fe")
int BPF_KPROBE(do_mov_928)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x162")
int BPF_KPROBE(do_mov_929)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_change+0x210")
int BPF_KPROBE(do_mov_930)
{
    u64 addr = ctx->bx + 0x1c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x22")
int BPF_KPROBE(do_mov_931)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x82")
int BPF_KPROBE(do_mov_932)
{
    u64 addr = ctx->di + 0x200;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x113")
int BPF_KPROBE(do_mov_933)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x136")
int BPF_KPROBE(do_mov_934)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_codel_init+0x1c3")
int BPF_KPROBE(do_mov_935)
{
    u64 addr = ctx->di - 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_calc_overhead+0x6f")
int BPF_KPROBE(do_mov_936)
{
    u64 addr = ctx->cx + 0x410e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_calc_overhead+0x81")
int BPF_KPROBE(do_mov_937)
{
    u64 addr = ctx->cx + 0x4112;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue_one+0x46")
int BPF_KPROBE(do_mov_938)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x5b")
int BPF_KPROBE(do_mov_939)
{
    u64 addr = ctx->r9 + 0x19808;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_set_rate+0x53")
int BPF_KPROBE(do_mov_940)
{
    u64 addr = ctx->r9 + 0x19880;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x98")
int BPF_KPROBE(do_mov_941)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0xa6")
int BPF_KPROBE(do_mov_942)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x15e")
int BPF_KPROBE(do_mov_943)
{
    u64 addr = ctx->bx + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x166")
int BPF_KPROBE(do_mov_944)
{
    u64 addr = ctx->bx + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x1eb")
int BPF_KPROBE(do_mov_945)
{
    u64 addr = ctx->bx + 0x41a6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x235")
int BPF_KPROBE(do_mov_946)
{
    u64 addr = ctx->bx + 0x41e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x288")
int BPF_KPROBE(do_mov_947)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x29a")
int BPF_KPROBE(do_mov_948)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x356")
int BPF_KPROBE(do_mov_949)
{
    u64 addr = ctx->bx + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x36b")
int BPF_KPROBE(do_mov_950)
{
    u64 addr = ctx->bx + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x3f7")
int BPF_KPROBE(do_mov_951)
{
    u64 addr = ctx->ax + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x413")
int BPF_KPROBE(do_mov_952)
{
    u64 addr = ctx->ax + 0x4ca22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x439")
int BPF_KPROBE(do_mov_953)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x44c")
int BPF_KPROBE(do_mov_954)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x516")
int BPF_KPROBE(do_mov_955)
{
    u64 addr = ctx->ax + 0x19882;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x543")
int BPF_KPROBE(do_mov_956)
{
    u64 addr = ctx->ax + 0x662f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x571")
int BPF_KPROBE(do_mov_957)
{
    u64 addr = ctx->di + 0x419a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reconfigure+0x57b")
int BPF_KPROBE(do_mov_958)
{
    u64 addr = ctx->di + 0x4250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_walk+0xc4")
int BPF_KPROBE(do_mov_959)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reset+0x1e")
int BPF_KPROBE(do_mov_960)
{
    u64 addr = ctx->bx + 0x41f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_reset+0x26")
int BPF_KPROBE(do_mov_961)
{
    u64 addr = ctx->bx + 0x41f2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_stats+0x629")
int BPF_KPROBE(do_mov_962)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_stats+0x65c")
int BPF_KPROBE(do_mov_963)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dump_stats+0x673")
int BPF_KPROBE(do_mov_964)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0xc3")
int BPF_KPROBE(do_mov_965)
{
    u64 addr = ctx->bx + 0x419c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_change+0x14c")
int BPF_KPROBE(do_mov_966)
{
    u64 addr = ctx->bx + 0x428c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x36")
int BPF_KPROBE(do_mov_967)
{
    u64 addr = ctx->di - 0x41e4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x40")
int BPF_KPROBE(do_mov_968)
{
    u64 addr = ctx->di - 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x48")
int BPF_KPROBE(do_mov_969)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x50")
int BPF_KPROBE(do_mov_970)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x58")
int BPF_KPROBE(do_mov_971)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x162")
int BPF_KPROBE(do_mov_972)
{
    u64 addr = ctx->r10 + 0x1982c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x16d")
int BPF_KPROBE(do_mov_973)
{
    u64 addr = ctx->r10 + 0x19860;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1d2")
int BPF_KPROBE(do_mov_974)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1dd")
int BPF_KPROBE(do_mov_975)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_init+0x1e9")
int BPF_KPROBE(do_mov_976)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x62a")
int BPF_KPROBE(do_mov_977)
{
    u64 addr = ctx->bx + ctx->r10 * 0x4 + 0x15000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x6aa")
int BPF_KPROBE(do_mov_978)
{
    u64 addr = ctx->bx + ctx->cx * 0x4 + 0x16800;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x6df")
int BPF_KPROBE(do_mov_979)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x75a")
int BPF_KPROBE(do_mov_980)
{
    u64 addr = ctx->bx + ctx->cx * 0x4 + 0x16804;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x790")
int BPF_KPROBE(do_mov_981)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0x4a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_hash+0x836")
int BPF_KPROBE(do_mov_982)
{
    u64 addr = ctx->bx + ctx->r10 * 0x4 + 0x15000;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_ack_filter.isra.0+0x509")
int BPF_KPROBE(do_mov_983)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_ack_filter.isra.0+0x513")
int BPF_KPROBE(do_mov_984)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa1")
int BPF_KPROBE(do_mov_985)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa4")
int BPF_KPROBE(do_mov_986)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x247")
int BPF_KPROBE(do_mov_987)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x4d6")
int BPF_KPROBE(do_mov_988)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x51b")
int BPF_KPROBE(do_mov_989)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x509")
int BPF_KPROBE(do_mov_990)
{
    u64 addr = ctx->ax + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x5b3")
int BPF_KPROBE(do_mov_991)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x656")
int BPF_KPROBE(do_mov_992)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x6a2")
int BPF_KPROBE(do_mov_993)
{
    u64 addr = ctx->ax + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x727")
int BPF_KPROBE(do_mov_994)
{
    u64 addr = ctx->r12 + 0x4198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x8bd")
int BPF_KPROBE(do_mov_995)
{
    u64 addr = ctx->r12 + 0x4278;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x909")
int BPF_KPROBE(do_mov_996)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0x9b3")
int BPF_KPROBE(do_mov_997)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa32")
int BPF_KPROBE(do_mov_998)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa44")
int BPF_KPROBE(do_mov_999)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa64")
int BPF_KPROBE(do_mov_1000)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xa78")
int BPF_KPROBE(do_mov_1001)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xab8")
int BPF_KPROBE(do_mov_1002)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_enqueue+0xbd6")
int BPF_KPROBE(do_mov_1003)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x2dd")
int BPF_KPROBE(do_mov_1004)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x22b")
int BPF_KPROBE(do_mov_1005)
{
    u64 addr = ctx->bx + 0x35;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x3bd")
int BPF_KPROBE(do_mov_1006)
{
    u64 addr = ctx->r12 + 0x198a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x426")
int BPF_KPROBE(do_mov_1007)
{
    u64 addr = ctx->r12 + 0x198b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x510")
int BPF_KPROBE(do_mov_1008)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x489")
int BPF_KPROBE(do_mov_1009)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x763")
int BPF_KPROBE(do_mov_1010)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x77e")
int BPF_KPROBE(do_mov_1011)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x785")
int BPF_KPROBE(do_mov_1012)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa1b")
int BPF_KPROBE(do_mov_1013)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0x9da")
int BPF_KPROBE(do_mov_1014)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa62")
int BPF_KPROBE(do_mov_1015)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa79")
int BPF_KPROBE(do_mov_1016)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xa7c")
int BPF_KPROBE(do_mov_1017)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb3a")
int BPF_KPROBE(do_mov_1018)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xb41")
int BPF_KPROBE(do_mov_1019)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xbe8")
int BPF_KPROBE(do_mov_1020)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cake_dequeue+0xc8d")
int BPF_KPROBE(do_mov_1021)
{
    u64 addr = ctx->bx + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0xe6")
int BPF_KPROBE(do_mov_1022)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0xda")
int BPF_KPROBE(do_mov_1023)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x250")
int BPF_KPROBE(do_mov_1024)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x262")
int BPF_KPROBE(do_mov_1025)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x328")
int BPF_KPROBE(do_mov_1026)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x350")
int BPF_KPROBE(do_mov_1027)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x39a")
int BPF_KPROBE(do_mov_1028)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x3a1")
int BPF_KPROBE(do_mov_1029)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_enqueue+0x56f")
int BPF_KPROBE(do_mov_1030)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0x1c")
int BPF_KPROBE(do_mov_1031)
{
    u64 addr = ctx->di - 0x118;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0x26")
int BPF_KPROBE(do_mov_1032)
{
    u64 addr = ctx->di - 0xfc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xa6")
int BPF_KPROBE(do_mov_1033)
{
    u64 addr = ctx->r13 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_reset+0xd2")
int BPF_KPROBE(do_mov_1034)
{
    u64 addr = ctx->r13 + 0x280;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x78")
int BPF_KPROBE(do_mov_1035)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x101")
int BPF_KPROBE(do_mov_1036)
{
    u64 addr = ctx->r14 + 0x1a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x127")
int BPF_KPROBE(do_mov_1037)
{
    u64 addr = ctx->r14 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x142")
int BPF_KPROBE(do_mov_1038)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x240")
int BPF_KPROBE(do_mov_1039)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x20e")
int BPF_KPROBE(do_mov_1040)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x300")
int BPF_KPROBE(do_mov_1041)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x347")
int BPF_KPROBE(do_mov_1042)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x3c1")
int BPF_KPROBE(do_mov_1043)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x4a6")
int BPF_KPROBE(do_mov_1044)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x452")
int BPF_KPROBE(do_mov_1045)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_dequeue+0x638")
int BPF_KPROBE(do_mov_1046)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x203")
int BPF_KPROBE(do_mov_1047)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_resize+0x216")
int BPF_KPROBE(do_mov_1048)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0xc2")
int BPF_KPROBE(do_mov_1049)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_change+0xd5")
int BPF_KPROBE(do_mov_1050)
{
    u64 addr = ctx->r14 + 0x24c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x23")
int BPF_KPROBE(do_mov_1051)
{
    u64 addr = ctx->di - 0x2c4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x30")
int BPF_KPROBE(do_mov_1052)
{
    u64 addr = ctx->di - 0x8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x4c")
int BPF_KPROBE(do_mov_1053)
{
    u64 addr = ctx->di - 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x62")
int BPF_KPROBE(do_mov_1054)
{
    u64 addr = ctx->di - 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x74")
int BPF_KPROBE(do_mov_1055)
{
    u64 addr = ctx->di - 0x5e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x7a")
int BPF_KPROBE(do_mov_1056)
{
    u64 addr = ctx->di - 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x85")
int BPF_KPROBE(do_mov_1057)
{
    u64 addr = ctx->di - 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0x95")
int BPF_KPROBE(do_mov_1058)
{
    u64 addr = ctx->di - 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xa3")
int BPF_KPROBE(do_mov_1059)
{
    u64 addr = ctx->di - 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xb1")
int BPF_KPROBE(do_mov_1060)
{
    u64 addr = ctx->di - 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xba")
int BPF_KPROBE(do_mov_1061)
{
    u64 addr = ctx->di - 0x158;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xc5")
int BPF_KPROBE(do_mov_1062)
{
    u64 addr = ctx->di - 0x148;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xd0")
int BPF_KPROBE(do_mov_1063)
{
    u64 addr = ctx->di - 0x138;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xdb")
int BPF_KPROBE(do_mov_1064)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xe2")
int BPF_KPROBE(do_mov_1065)
{
    u64 addr = ctx->di - 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xed")
int BPF_KPROBE(do_mov_1066)
{
    u64 addr = ctx->di - 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_init+0xf5")
int BPF_KPROBE(do_mov_1067)
{
    u64 addr = ctx->di - 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x52")
int BPF_KPROBE(do_mov_1068)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0xbc")
int BPF_KPROBE(do_mov_1069)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0xbf")
int BPF_KPROBE(do_mov_1070)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x11c")
int BPF_KPROBE(do_mov_1071)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x12d")
int BPF_KPROBE(do_mov_1072)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x134")
int BPF_KPROBE(do_mov_1073)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_dequeue+0x15a")
int BPF_KPROBE(do_mov_1074)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_destroy+0x94")
int BPF_KPROBE(do_mov_1075)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0xf2")
int BPF_KPROBE(do_mov_1076)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0xff")
int BPF_KPROBE(do_mov_1077)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x107")
int BPF_KPROBE(do_mov_1078)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x184")
int BPF_KPROBE(do_mov_1079)
{
    u64 addr = ctx->di + ctx->cx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x224")
int BPF_KPROBE(do_mov_1080)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x239")
int BPF_KPROBE(do_mov_1081)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2c6")
int BPF_KPROBE(do_mov_1082)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2cd")
int BPF_KPROBE(do_mov_1083)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2e9")
int BPF_KPROBE(do_mov_1084)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x2ec")
int BPF_KPROBE(do_mov_1085)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x33c")
int BPF_KPROBE(do_mov_1086)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x38b")
int BPF_KPROBE(do_mov_1087)
{
    u64 addr = ctx->r15 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x384")
int BPF_KPROBE(do_mov_1088)
{
    u64 addr = ctx->r15 + 0x250;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3e3")
int BPF_KPROBE(do_mov_1089)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x3dc")
int BPF_KPROBE(do_mov_1090)
{
    u64 addr = ctx->r15 + 0x260;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x452")
int BPF_KPROBE(do_mov_1091)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x45a")
int BPF_KPROBE(do_mov_1092)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_enqueue+0x4dc")
int BPF_KPROBE(do_mov_1093)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0xcc")
int BPF_KPROBE(do_mov_1094)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_change+0xda")
int BPF_KPROBE(do_mov_1095)
{
    u64 addr = ctx->bx + 0x274;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0xe3")
int BPF_KPROBE(do_mov_1096)
{
    u64 addr = ctx->r12 + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x9a")
int BPF_KPROBE(do_mov_1097)
{
    u64 addr = ctx->r12 + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x18f")
int BPF_KPROBE(do_mov_1098)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x1a9")
int BPF_KPROBE(do_mov_1099)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/hhf_init+0x1c9")
int BPF_KPROBE(do_mov_1100)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x142")
int BPF_KPROBE(do_mov_1101)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_calculate_probability+0x145")
int BPF_KPROBE(do_mov_1102)
{
    u64 addr = ctx->di + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0x35")
int BPF_KPROBE(do_mov_1103)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_process_dequeue+0xc9")
int BPF_KPROBE(do_mov_1104)
{
    u64 addr = ctx->bx + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_dequeue+0x2e")
int BPF_KPROBE(do_mov_1105)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x6f")
int BPF_KPROBE(do_mov_1106)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_reset+0x4c")
int BPF_KPROBE(do_mov_1107)
{
    u64 addr = ctx->bx + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_dump+0x1a9")
int BPF_KPROBE(do_mov_1108)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x82")
int BPF_KPROBE(do_mov_1109)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x8b")
int BPF_KPROBE(do_mov_1110)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x13a")
int BPF_KPROBE(do_mov_1111)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x1fd")
int BPF_KPROBE(do_mov_1112)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x240")
int BPF_KPROBE(do_mov_1113)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_qdisc_enqueue+0x22e")
int BPF_KPROBE(do_mov_1114)
{
    u64 addr = ctx->bx + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0xc8")
int BPF_KPROBE(do_mov_1115)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x11f")
int BPF_KPROBE(do_mov_1116)
{
    u64 addr = ctx->bx + 0x1da;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x182")
int BPF_KPROBE(do_mov_1117)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_change+0x17c")
int BPF_KPROBE(do_mov_1118)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0xd8")
int BPF_KPROBE(do_mov_1119)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pie_init+0x3c")
int BPF_KPROBE(do_mov_1120)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x21")
int BPF_KPROBE(do_mov_1121)
{
    u64 addr = ctx->di + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x13")
int BPF_KPROBE(do_mov_1122)
{
    u64 addr = ctx->di + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x86")
int BPF_KPROBE(do_mov_1123)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_reset+0x7a")
int BPF_KPROBE(do_mov_1124)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x5c")
int BPF_KPROBE(do_mov_1125)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0xe6")
int BPF_KPROBE(do_mov_1126)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0xe9")
int BPF_KPROBE(do_mov_1127)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x129")
int BPF_KPROBE(do_mov_1128)
{
    u64 addr = ctx->dx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x133")
int BPF_KPROBE(do_mov_1129)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x144")
int BPF_KPROBE(do_mov_1130)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x14b")
int BPF_KPROBE(do_mov_1131)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_dequeue+0x163")
int BPF_KPROBE(do_mov_1132)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_dump+0x245")
int BPF_KPROBE(do_mov_1133)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x8d")
int BPF_KPROBE(do_mov_1134)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x91")
int BPF_KPROBE(do_mov_1135)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x1d8")
int BPF_KPROBE(do_mov_1136)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x1e1")
int BPF_KPROBE(do_mov_1137)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x203")
int BPF_KPROBE(do_mov_1138)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x27b")
int BPF_KPROBE(do_mov_1139)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_qdisc_enqueue+0x286")
int BPF_KPROBE(do_mov_1140)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0xa2")
int BPF_KPROBE(do_mov_1141)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x14a")
int BPF_KPROBE(do_mov_1142)
{
    u64 addr = ctx->bx + 0x1ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x2c5")
int BPF_KPROBE(do_mov_1143)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_change+0x2cd")
int BPF_KPROBE(do_mov_1144)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x3a")
int BPF_KPROBE(do_mov_1145)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0xe5")
int BPF_KPROBE(do_mov_1146)
{
    u64 addr = ctx->bx + 0x1ec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1af")
int BPF_KPROBE(do_mov_1147)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fq_pie_init+0x1c3")
int BPF_KPROBE(do_mov_1148)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x150")
int BPF_KPROBE(do_mov_1149)
{
    u64 addr = ctx->bx + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_dequeue_soft+0x79")
int BPF_KPROBE(do_mov_1150)
{
    u64 addr = ctx->bx + 0x198;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_destroy+0x69")
int BPF_KPROBE(do_mov_1151)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x105")
int BPF_KPROBE(do_mov_1152)
{
    u64 addr = ctx->bx + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0xec")
int BPF_KPROBE(do_mov_1153)
{
    u64 addr = ctx->bx + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x1c4")
int BPF_KPROBE(do_mov_1154)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_change+0x1e2")
int BPF_KPROBE(do_mov_1155)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0xe4")
int BPF_KPROBE(do_mov_1156)
{
    u64 addr = ctx->r12 + 0x184;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_init+0x83")
int BPF_KPROBE(do_mov_1157)
{
    u64 addr = ctx->r12 + 0x228;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_walk+0x3a")
int BPF_KPROBE(do_mov_1158)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cbs_graft+0xd3")
int BPF_KPROBE(do_mov_1159)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x6f")
int BPF_KPROBE(do_mov_1160)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/report_sock_error+0x7d")
int BPF_KPROBE(do_mov_1161)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x60")
int BPF_KPROBE(do_mov_1162)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x69")
int BPF_KPROBE(do_mov_1163)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0xf0")
int BPF_KPROBE(do_mov_1164)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_enqueue_timesortedlist+0x173")
int BPF_KPROBE(do_mov_1165)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0xe8")
int BPF_KPROBE(do_mov_1166)
{
    u64 addr = ctx->r12 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x13e")
int BPF_KPROBE(do_mov_1167)
{
    u64 addr = ctx->r12 + 0x1f8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x244")
int BPF_KPROBE(do_mov_1168)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x279")
int BPF_KPROBE(do_mov_1169)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x29b")
int BPF_KPROBE(do_mov_1170)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x2c1")
int BPF_KPROBE(do_mov_1171)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x2e3")
int BPF_KPROBE(do_mov_1172)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x305")
int BPF_KPROBE(do_mov_1173)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_init+0x327")
int BPF_KPROBE(do_mov_1174)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/timesortedlist_remove+0x3e")
int BPF_KPROBE(do_mov_1175)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0xb7")
int BPF_KPROBE(do_mov_1176)
{
    u64 addr = ctx->r13 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_reset+0x52")
int BPF_KPROBE(do_mov_1177)
{
    u64 addr = ctx->r13 + 0x1a0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0xdf")
int BPF_KPROBE(do_mov_1178)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0x115")
int BPF_KPROBE(do_mov_1179)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/etf_dequeue_timesortedlist+0x162")
int BPF_KPROBE(do_mov_1180)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_walk+0x6f")
int BPF_KPROBE(do_mov_1181)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_free_sched_cb+0x41")
int BPF_KPROBE(do_mov_1182)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_free_sched_cb+0x44")
int BPF_KPROBE(do_mov_1183)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_graft+0x7c")
int BPF_KPROBE(do_mov_1184)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_graft+0xe2")
int BPF_KPROBE(do_mov_1185)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x223")
int BPF_KPROBE(do_mov_1186)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x245")
int BPF_KPROBE(do_mov_1187)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x26c")
int BPF_KPROBE(do_mov_1188)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_parse_tc_entries+0x292")
int BPF_KPROBE(do_mov_1189)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x4e")
int BPF_KPROBE(do_mov_1190)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x71")
int BPF_KPROBE(do_mov_1191)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x188")
int BPF_KPROBE(do_mov_1192)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x193")
int BPF_KPROBE(do_mov_1193)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x201")
int BPF_KPROBE(do_mov_1194)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x208")
int BPF_KPROBE(do_mov_1195)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x21f")
int BPF_KPROBE(do_mov_1196)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_entry_to_transmit+0x226")
int BPF_KPROBE(do_mov_1197)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x97")
int BPF_KPROBE(do_mov_1198)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x57")
int BPF_KPROBE(do_mov_1199)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x180")
int BPF_KPROBE(do_mov_1200)
{
    u64 addr = ctx->r11 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1b4")
int BPF_KPROBE(do_mov_1201)
{
    u64 addr = ctx->r11 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1f2")
int BPF_KPROBE(do_mov_1202)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x1f9")
int BPF_KPROBE(do_mov_1203)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x21a")
int BPF_KPROBE(do_mov_1204)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x27c")
int BPF_KPROBE(do_mov_1205)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x2c9")
int BPF_KPROBE(do_mov_1206)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x2f0")
int BPF_KPROBE(do_mov_1207)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x315")
int BPF_KPROBE(do_mov_1208)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x34d")
int BPF_KPROBE(do_mov_1209)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_taprio_schedule+0x367")
int BPF_KPROBE(do_mov_1210)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_offload_alloc+0x38")
int BPF_KPROBE(do_mov_1211)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0x48")
int BPF_KPROBE(do_mov_1212)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0x8f")
int BPF_KPROBE(do_mov_1213)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_disable_offload+0xb3")
int BPF_KPROBE(do_mov_1214)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_destroy+0x37")
int BPF_KPROBE(do_mov_1215)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc7")
int BPF_KPROBE(do_mov_1216)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x4e9")
int BPF_KPROBE(do_mov_1217)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x4f0")
int BPF_KPROBE(do_mov_1218)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x500")
int BPF_KPROBE(do_mov_1219)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x7c8")
int BPF_KPROBE(do_mov_1220)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x7ef")
int BPF_KPROBE(do_mov_1221)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x81f")
int BPF_KPROBE(do_mov_1222)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x8d5")
int BPF_KPROBE(do_mov_1223)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x919")
int BPF_KPROBE(do_mov_1224)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x943")
int BPF_KPROBE(do_mov_1225)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x994")
int BPF_KPROBE(do_mov_1226)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x9b7")
int BPF_KPROBE(do_mov_1227)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0x9e8")
int BPF_KPROBE(do_mov_1228)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xa2f")
int BPF_KPROBE(do_mov_1229)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xa53")
int BPF_KPROBE(do_mov_1230)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc1a")
int BPF_KPROBE(do_mov_1231)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc51")
int BPF_KPROBE(do_mov_1232)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xc78")
int BPF_KPROBE(do_mov_1233)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xcc0")
int BPF_KPROBE(do_mov_1234)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xcf4")
int BPF_KPROBE(do_mov_1235)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd07")
int BPF_KPROBE(do_mov_1236)
{
    u64 addr = ctx->r12 + 0x1b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd42")
int BPF_KPROBE(do_mov_1237)
{
    u64 addr = ctx->r12 + 0x1c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xd99")
int BPF_KPROBE(do_mov_1238)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_change+0xdbc")
int BPF_KPROBE(do_mov_1239)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x38")
int BPF_KPROBE(do_mov_1240)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x5d")
int BPF_KPROBE(do_mov_1241)
{
    u64 addr = ctx->r15 + 0x188;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x52")
int BPF_KPROBE(do_mov_1242)
{
    u64 addr = ctx->r15 + 0x1f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0xc0")
int BPF_KPROBE(do_mov_1243)
{
    u64 addr = ctx->r15 + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x8a")
int BPF_KPROBE(do_mov_1244)
{
    u64 addr = ctx->r15 + 0x210;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x19d")
int BPF_KPROBE(do_mov_1245)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_init+0x1bd")
int BPF_KPROBE(do_mov_1246)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x92")
int BPF_KPROBE(do_mov_1247)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue_one+0x9b")
int BPF_KPROBE(do_mov_1248)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0xa4")
int BPF_KPROBE(do_mov_1249)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0x12d")
int BPF_KPROBE(do_mov_1250)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_enqueue+0x136")
int BPF_KPROBE(do_mov_1251)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_schedule+0x1ad")
int BPF_KPROBE(do_mov_1252)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_schedule+0x276")
int BPF_KPROBE(do_mov_1253)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x92")
int BPF_KPROBE(do_mov_1254)
{
    u64 addr = ctx->bx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x96")
int BPF_KPROBE(do_mov_1255)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xcb")
int BPF_KPROBE(do_mov_1256)
{
    u64 addr = ctx->bx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0xdb")
int BPF_KPROBE(do_mov_1257)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x138")
int BPF_KPROBE(do_mov_1258)
{
    u64 addr = ctx->bx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/advance_sched+0x141")
int BPF_KPROBE(do_mov_1259)
{
    u64 addr = ctx->bx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump+0x1b7")
int BPF_KPROBE(do_mov_1260)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump+0x26a")
int BPF_KPROBE(do_mov_1261)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/taprio_dump+0x281")
int BPF_KPROBE(do_mov_1262)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_walk+0xa5")
int BPF_KPROBE(do_mov_1263)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_reset_fastmap+0x1d")
int BPF_KPROBE(do_mov_1264)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_dump+0xe0")
int BPF_KPROBE(do_mov_1265)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0x82")
int BPF_KPROBE(do_mov_1266)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0xaa")
int BPF_KPROBE(do_mov_1267)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_delete+0xe2")
int BPF_KPROBE(do_mov_1268)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x139")
int BPF_KPROBE(do_mov_1269)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x15e")
int BPF_KPROBE(do_mov_1270)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x4cf")
int BPF_KPROBE(do_mov_1271)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x3b0")
int BPF_KPROBE(do_mov_1272)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x566")
int BPF_KPROBE(do_mov_1273)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x619")
int BPF_KPROBE(do_mov_1274)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x641")
int BPF_KPROBE(do_mov_1275)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_change+0x6da")
int BPF_KPROBE(do_mov_1276)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x114")
int BPF_KPROBE(do_mov_1277)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x175")
int BPF_KPROBE(do_mov_1278)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x1ea")
int BPF_KPROBE(do_mov_1279)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x216")
int BPF_KPROBE(do_mov_1280)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x298")
int BPF_KPROBE(do_mov_1281)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x28f")
int BPF_KPROBE(do_mov_1282)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x2ff")
int BPF_KPROBE(do_mov_1283)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/route4_classify+0x2fb")
int BPF_KPROBE(do_mov_1284)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_walk+0x66")
int BPF_KPROBE(do_mov_1285)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0x65")
int BPF_KPROBE(do_mov_1286)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0xdb")
int BPF_KPROBE(do_mov_1287)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_classify+0x69")
int BPF_KPROBE(do_mov_1288)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_dump+0xe9")
int BPF_KPROBE(do_mov_1289)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_delete+0x8d")
int BPF_KPROBE(do_mov_1290)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_delete+0xa9")
int BPF_KPROBE(do_mov_1291)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x263")
int BPF_KPROBE(do_mov_1292)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_set_parms+0x26e")
int BPF_KPROBE(do_mov_1293)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x19d")
int BPF_KPROBE(do_mov_1294)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x114")
int BPF_KPROBE(do_mov_1295)
{
    u64 addr = ctx->r13 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x227")
int BPF_KPROBE(do_mov_1296)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x350")
int BPF_KPROBE(do_mov_1297)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x2f7")
int BPF_KPROBE(do_mov_1298)
{
    u64 addr = ctx->r10 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x362")
int BPF_KPROBE(do_mov_1299)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fw_change+0x3e5")
int BPF_KPROBE(do_mov_1300)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_unregister+0x2c")
int BPF_KPROBE(do_mov_1301)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x222")
int BPF_KPROBE(do_mov_1302)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_validate+0x179")
int BPF_KPROBE(do_mov_1303)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_dump+0x1fe")
int BPF_KPROBE(do_mov_1304)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcf_em_tree_dump+0x212")
int BPF_KPROBE(do_mov_1305)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}



