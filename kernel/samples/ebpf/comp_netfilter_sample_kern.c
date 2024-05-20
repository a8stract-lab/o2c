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



SEC("kprobe/__nf_hook_entries_try_shrink+0xaf")
int BPF_KPROBE(do_mov_0)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_hook_entries_try_shrink+0x14e")
int BPF_KPROBE(do_mov_1)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x62")
int BPF_KPROBE(do_mov_2)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x65")
int BPF_KPROBE(do_mov_3)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x82")
int BPF_KPROBE(do_mov_4)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0x89")
int BPF_KPROBE(do_mov_5)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0xbc")
int BPF_KPROBE(do_mov_6)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_slow_list+0xbf")
int BPF_KPROBE(do_mov_7)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0x1f")
int BPF_KPROBE(do_mov_8)
{
    u64 addr = ctx->di + 0xaa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/netfilter_net_init+0xda")
int BPF_KPROBE(do_mov_9)
{
    u64 addr = ctx->di + 0xb28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_unregister_net_hook+0xa9")
int BPF_KPROBE(do_mov_10)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0xbb")
int BPF_KPROBE(do_mov_11)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_grow+0xde")
int BPF_KPROBE(do_mov_12)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_delete_raw+0x44")
int BPF_KPROBE(do_mov_13)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_hook_entries_insert_raw+0x5f")
int BPF_KPROBE(do_mov_14)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_register_net_hook+0xb0")
int BPF_KPROBE(do_mov_15)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_next+0x10")
int BPF_KPROBE(do_mov_16)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x7c")
int BPF_KPROBE(do_mov_17)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0xe4")
int BPF_KPROBE(do_mov_18)
{
    u64 addr = ctx->r12 - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0xf2")
int BPF_KPROBE(do_mov_19)
{
    u64 addr = ctx->r12 - 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0xf7")
int BPF_KPROBE(do_mov_20)
{
    u64 addr = ctx->r12 - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x100")
int BPF_KPROBE(do_mov_21)
{
    u64 addr = ctx->r12 - 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_net_init+0x106")
int BPF_KPROBE(do_mov_22)
{
    u64 addr = ctx->r12 - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_add+0x80")
int BPF_KPROBE(do_mov_23)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_add+0xa8")
int BPF_KPROBE(do_mov_24)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_open+0x24")
int BPF_KPROBE(do_mov_25)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_log_buf_open+0x48")
int BPF_KPROBE(do_mov_26)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0xcf")
int BPF_KPROBE(do_mov_27)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_queue+0x1cf")
int BPF_KPROBE(do_mov_28)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_register_sockopt+0x7f")
int BPF_KPROBE(do_mov_29)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_unregister_sockopt+0x2b")
int BPF_KPROBE(do_mov_30)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_unregister_sockopt+0x38")
int BPF_KPROBE(do_mov_31)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip_checksum+0xaa")
int BPF_KPROBE(do_mov_32)
{
    u64 addr = ctx->di + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ip_checksum+0xcb")
int BPF_KPROBE(do_mov_33)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_net_init+0x7e")
int BPF_KPROBE(do_mov_34)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x20b")
int BPF_KPROBE(do_mov_35)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x26c")
int BPF_KPROBE(do_mov_36)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x25a")
int BPF_KPROBE(do_mov_37)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x322")
int BPF_KPROBE(do_mov_38)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x32f")
int BPF_KPROBE(do_mov_39)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x3bd")
int BPF_KPROBE(do_mov_40)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x3ce")
int BPF_KPROBE(do_mov_41)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x43d")
int BPF_KPROBE(do_mov_42)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x44e")
int BPF_KPROBE(do_mov_43)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x4b8")
int BPF_KPROBE(do_mov_44)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x4c5")
int BPF_KPROBE(do_mov_45)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x693")
int BPF_KPROBE(do_mov_46)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x6a4")
int BPF_KPROBE(do_mov_47)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x7d3")
int BPF_KPROBE(do_mov_48)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x7e0")
int BPF_KPROBE(do_mov_49)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x892")
int BPF_KPROBE(do_mov_50)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnetlink_rcv_batch+0x89f")
int BPF_KPROBE(do_mov_51)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_fill_info.constprop.0+0x162")
int BPF_KPROBE(do_mov_52)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0xac")
int BPF_KPROBE(do_mov_53)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x19c")
int BPF_KPROBE(do_mov_54)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_new+0x19f")
int BPF_KPROBE(do_mov_55)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_start+0x94")
int BPF_KPROBE(do_mov_56)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_init+0x2d")
int BPF_KPROBE(do_mov_57)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_net_exit+0x74")
int BPF_KPROBE(do_mov_58)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_dump+0xdb")
int BPF_KPROBE(do_mov_59)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_dump+0xba")
int BPF_KPROBE(do_mov_60)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x9d")
int BPF_KPROBE(do_mov_61)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_acct_del+0x10d")
int BPF_KPROBE(do_mov_62)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/instance_destroy_rcu+0x5f")
int BPF_KPROBE(do_mov_63)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/instance_destroy_rcu+0x62")
int BPF_KPROBE(do_mov_64)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x2ff")
int BPF_KPROBE(do_mov_65)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x2e9")
int BPF_KPROBE(do_mov_66)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x736")
int BPF_KPROBE(do_mov_67)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0x752")
int BPF_KPROBE(do_mov_68)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb57")
int BPF_KPROBE(do_mov_69)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xb60")
int BPF_KPROBE(do_mov_70)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nfqnl_enqueue_packet+0xcad")
int BPF_KPROBE(do_mov_71)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_dev_event+0xbc")
int BPF_KPROBE(do_mov_72)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_rcv_dev_event+0xc9")
int BPF_KPROBE(do_mov_73)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_queue_net_init+0x6a")
int BPF_KPROBE(do_mov_74)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_queue_net_init+0x4a")
int BPF_KPROBE(do_mov_75)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x136")
int BPF_KPROBE(do_mov_76)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x139")
int BPF_KPROBE(do_mov_77)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x14c")
int BPF_KPROBE(do_mov_78)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict_batch+0x156")
int BPF_KPROBE(do_mov_79)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_enqueue_packet+0x18d")
int BPF_KPROBE(do_mov_80)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x135")
int BPF_KPROBE(do_mov_81)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_verdict+0x142")
int BPF_KPROBE(do_mov_82)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x375")
int BPF_KPROBE(do_mov_83)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_recv_config+0x337")
int BPF_KPROBE(do_mov_84)
{
    u64 addr = ctx->r8 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_nf_hook_drop+0x9c")
int BPF_KPROBE(do_mov_85)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfqnl_nf_hook_drop+0x9f")
int BPF_KPROBE(do_mov_86)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_log_net_init+0x6e")
int BPF_KPROBE(do_mov_87)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_log_net_init+0x4e")
int BPF_KPROBE(do_mov_88)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0x4a")
int BPF_KPROBE(do_mov_89)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seq_start+0x4a")
int BPF_KPROBE(do_mov_90)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x3b8")
int BPF_KPROBE(do_mov_91)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_recv_config+0x193")
int BPF_KPROBE(do_mov_92)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x57e")
int BPF_KPROBE(do_mov_93)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x258")
int BPF_KPROBE(do_mov_94)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x735")
int BPF_KPROBE(do_mov_95)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfulnl_log_packet+0x8fe")
int BPF_KPROBE(do_mov_96)
{
    u64 addr = ctx->r15 + 0x74;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_remove_callback+0x8c")
int BPF_KPROBE(do_mov_97)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_osf_add_callback+0x7e")
int BPF_KPROBE(do_mov_98)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x8b")
int BPF_KPROBE(do_mov_99)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0x96")
int BPF_KPROBE(do_mov_100)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_osf_hdr_ctx_init+0xc6")
int BPF_KPROBE(do_mov_101)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0xe8")
int BPF_KPROBE(do_mov_102)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x101")
int BPF_KPROBE(do_mov_103)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x3a0")
int BPF_KPROBE(do_mov_104)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x3b6")
int BPF_KPROBE(do_mov_105)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump_one.isra.0+0x3d0")
int BPF_KPROBE(do_mov_106)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump+0xf1")
int BPF_KPROBE(do_mov_107)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_hook_dump+0xfc")
int BPF_KPROBE(do_mov_108)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0xe")
int BPF_KPROBE(do_mov_109)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x4c")
int BPF_KPROBE(do_mov_110)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_invert_tuple+0x6e")
int BPF_KPROBE(do_mov_111)
{
    u64 addr = ctx->di + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tmpl_alloc+0x63")
int BPF_KPROBE(do_mov_112)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_tmpl_alloc+0x4e")
int BPF_KPROBE(do_mov_113)
{
    u64 addr = ctx->ax + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x37")
int BPF_KPROBE(do_mov_114)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0x18b")
int BPF_KPROBE(do_mov_115)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_get_tuple+0xb9")
int BPF_KPROBE(do_mov_116)
{
    u64 addr = ctx->r12 + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_l4proto+0x89")
int BPF_KPROBE(do_mov_117)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_l4proto+0xe3")
int BPF_KPROBE(do_mov_118)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_insert_prepare+0x4c")
int BPF_KPROBE(do_mov_119)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x5f")
int BPF_KPROBE(do_mov_120)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_alter_reply+0x83")
int BPF_KPROBE(do_mov_121)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_delete_from_lists+0xda")
int BPF_KPROBE(do_mov_122)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0x11b")
int BPF_KPROBE(do_mov_123)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conntrack_alloc+0xd2")
int BPF_KPROBE(do_mov_124)
{
    u64 addr = ctx->r8 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x256")
int BPF_KPROBE(do_mov_125)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/init_conntrack.constprop.0+0x386")
int BPF_KPROBE(do_mov_126)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x348")
int BPF_KPROBE(do_mov_127)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x3b1")
int BPF_KPROBE(do_mov_128)
{
    u64 addr = ctx->bx + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x4e0")
int BPF_KPROBE(do_mov_129)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gc_worker+0x3c6")
int BPF_KPROBE(do_mov_130)
{
    u64 addr = ctx->ax + 0x69;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x50")
int BPF_KPROBE(do_mov_131)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x57")
int BPF_KPROBE(do_mov_132)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x6f")
int BPF_KPROBE(do_mov_133)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x15a")
int BPF_KPROBE(do_mov_134)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_get_tuple_skb+0x17d")
int BPF_KPROBE(do_mov_135)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x14a")
int BPF_KPROBE(do_mov_136)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_hash_resize+0x109")
int BPF_KPROBE(do_mov_137)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_init_net+0x39")
int BPF_KPROBE(do_mov_138)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x319")
int BPF_KPROBE(do_mov_139)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_pernet_init+0x2f9")
int BPF_KPROBE(do_mov_140)
{
    u64 addr = ctx->r12 + 0xc08;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x69")
int BPF_KPROBE(do_mov_141)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x29")
int BPF_KPROBE(do_mov_142)
{
    u64 addr = ctx->ax + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x9e")
int BPF_KPROBE(do_mov_143)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0xf5")
int BPF_KPROBE(do_mov_144)
{
    u64 addr = ctx->ax + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x189")
int BPF_KPROBE(do_mov_145)
{
    u64 addr = ctx->di + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x169")
int BPF_KPROBE(do_mov_146)
{
    u64 addr = ctx->di + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1b6")
int BPF_KPROBE(do_mov_147)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x1e4")
int BPF_KPROBE(do_mov_148)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x26d")
int BPF_KPROBE(do_mov_149)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x271")
int BPF_KPROBE(do_mov_150)
{
    u64 addr = ctx->ax + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x2aa")
int BPF_KPROBE(do_mov_151)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_init+0x301")
int BPF_KPROBE(do_mov_152)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0x76")
int BPF_KPROBE(do_mov_153)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_unlink_expect_report+0xc4")
int BPF_KPROBE(do_mov_154)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x3b7")
int BPF_KPROBE(do_mov_155)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_expect_related_report+0x39a")
int BPF_KPROBE(do_mov_156)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_register+0x28")
int BPF_KPROBE(do_mov_157)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_expectfn_unregister+0x2b")
int BPF_KPROBE(do_mov_158)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_register+0x28")
int BPF_KPROBE(do_mov_159)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_helper_unregister+0x2b")
int BPF_KPROBE(do_mov_160)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_unregister+0x23")
int BPF_KPROBE(do_mov_161)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x2a")
int BPF_KPROBE(do_mov_162)
{
    u64 addr = ctx->di - 0x46;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x32")
int BPF_KPROBE(do_mov_163)
{
    u64 addr = ctx->di - 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x3b")
int BPF_KPROBE(do_mov_164)
{
    u64 addr = ctx->di - 0x5e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x42")
int BPF_KPROBE(do_mov_165)
{
    u64 addr = ctx->di - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x4c")
int BPF_KPROBE(do_mov_166)
{
    u64 addr = ctx->di - 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x53")
int BPF_KPROBE(do_mov_167)
{
    u64 addr = ctx->di - 0x2e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x5b")
int BPF_KPROBE(do_mov_168)
{
    u64 addr = ctx->di - 0x1e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_helper_init+0x63")
int BPF_KPROBE(do_mov_169)
{
    u64 addr = ctx->di - 0x66;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x18d")
int BPF_KPROBE(do_mov_170)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_helper_register+0x17c")
int BPF_KPROBE(do_mov_171)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/unhelp+0x6c")
int BPF_KPROBE(do_mov_172)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_try_assign_helper+0xa1")
int BPF_KPROBE(do_mov_173)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ct_try_assign_helper+0xc7")
int BPF_KPROBE(do_mov_174)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0xbc")
int BPF_KPROBE(do_mov_175)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_get+0x16c")
int BPF_KPROBE(do_mov_176)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_put+0x91")
int BPF_KPROBE(do_mov_177)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_netns_do_put+0x75")
int BPF_KPROBE(do_mov_178)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/generic_timeout_nlattr_to_obj+0x37")
int BPF_KPROBE(do_mov_179)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x20")
int BPF_KPROBE(do_mov_180)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x45")
int BPF_KPROBE(do_mov_181)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x5c")
int BPF_KPROBE(do_mov_182)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x73")
int BPF_KPROBE(do_mov_183)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x8a")
int BPF_KPROBE(do_mov_184)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xa1")
int BPF_KPROBE(do_mov_185)
{
    u64 addr = ctx->dx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xb8")
int BPF_KPROBE(do_mov_186)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xcf")
int BPF_KPROBE(do_mov_187)
{
    u64 addr = ctx->dx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xe6")
int BPF_KPROBE(do_mov_188)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0xfd")
int BPF_KPROBE(do_mov_189)
{
    u64 addr = ctx->dx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x114")
int BPF_KPROBE(do_mov_190)
{
    u64 addr = ctx->dx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x12b")
int BPF_KPROBE(do_mov_191)
{
    u64 addr = ctx->dx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_timeout_nlattr_to_obj+0x12e")
int BPF_KPROBE(do_mov_192)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0x12c")
int BPF_KPROBE(do_mov_193)
{
    u64 addr = ctx->bx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_tcp+0x88")
int BPF_KPROBE(do_mov_194)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x59")
int BPF_KPROBE(do_mov_195)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x64")
int BPF_KPROBE(do_mov_196)
{
    u64 addr = ctx->bx + 0xec;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x18a")
int BPF_KPROBE(do_mov_197)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_new+0x1a9")
int BPF_KPROBE(do_mov_198)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x2f2")
int BPF_KPROBE(do_mov_199)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x31c")
int BPF_KPROBE(do_mov_200)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x60c")
int BPF_KPROBE(do_mov_201)
{
    u64 addr = ctx->dx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x644")
int BPF_KPROBE(do_mov_202)
{
    u64 addr = ctx->dx + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x67a")
int BPF_KPROBE(do_mov_203)
{
    u64 addr = ctx->ax + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x690")
int BPF_KPROBE(do_mov_204)
{
    u64 addr = ctx->ax + 0xc8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x8bb")
int BPF_KPROBE(do_mov_205)
{
    u64 addr = ctx->r12 + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x71a")
int BPF_KPROBE(do_mov_206)
{
    u64 addr = ctx->r12 + 0xf3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xaf7")
int BPF_KPROBE(do_mov_207)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xd22")
int BPF_KPROBE(do_mov_208)
{
    u64 addr = ctx->r11 + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xdc4")
int BPF_KPROBE(do_mov_209)
{
    u64 addr = ctx->r12 + 0xe2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xdea")
int BPF_KPROBE(do_mov_210)
{
    u64 addr = ctx->r12 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xee0")
int BPF_KPROBE(do_mov_211)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0xf00")
int BPF_KPROBE(do_mov_212)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x1080")
int BPF_KPROBE(do_mov_213)
{
    u64 addr = ctx->r11 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x10a0")
int BPF_KPROBE(do_mov_214)
{
    u64 addr = ctx->r11 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x28c8b2")
int BPF_KPROBE(do_mov_215)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_packet+0x16c3")
int BPF_KPROBE(do_mov_216)
{
    u64 addr = ctx->r12 + 0xf2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_init_net+0x15")
int BPF_KPROBE(do_mov_217)
{
    u64 addr = ctx->di + ctx->ax * 0x1 + 0xb54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_init_net+0x31")
int BPF_KPROBE(do_mov_218)
{
    u64 addr = ctx->di + 0xb54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_tcp_init_net+0x3b")
int BPF_KPROBE(do_mov_219)
{
    u64 addr = ctx->di + 0xb8c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_timeout_nlattr_to_obj+0x1a")
int BPF_KPROBE(do_mov_220)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_timeout_nlattr_to_obj+0x25")
int BPF_KPROBE(do_mov_221)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_nlattr_to_tuple+0x54")
int BPF_KPROBE(do_mov_222)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_nlattr_to_tuple+0x3d")
int BPF_KPROBE(do_mov_223)
{
    u64 addr = ctx->si + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_timeout_nlattr_to_obj+0x3c")
int BPF_KPROBE(do_mov_224)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_pkt_to_tuple+0x44")
int BPF_KPROBE(do_mov_225)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp_pkt_to_tuple+0x4c")
int BPF_KPROBE(do_mov_226)
{
    u64 addr = ctx->bx + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmp_tuple+0x27")
int BPF_KPROBE(do_mov_227)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmp_tuple+0x40")
int BPF_KPROBE(do_mov_228)
{
    u64 addr = ctx->di + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xe1")
int BPF_KPROBE(do_mov_229)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0xf6")
int BPF_KPROBE(do_mov_230)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_ext_add+0x131")
int BPF_KPROBE(do_mov_231)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seqadj_set+0xa0")
int BPF_KPROBE(do_mov_232)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_seq_adjust+0x3d5")
int BPF_KPROBE(do_mov_233)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_nlattr_to_tuple+0x61")
int BPF_KPROBE(do_mov_234)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_nlattr_to_tuple+0x4a")
int BPF_KPROBE(do_mov_235)
{
    u64 addr = ctx->si + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_timeout_nlattr_to_obj+0x37")
int BPF_KPROBE(do_mov_236)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_pkt_to_tuple+0x44")
int BPF_KPROBE(do_mov_237)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_pkt_to_tuple+0x4c")
int BPF_KPROBE(do_mov_238)
{
    u64 addr = ctx->bx + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmpv6_tuple+0x35")
int BPF_KPROBE(do_mov_239)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_invert_icmpv6_tuple+0x3d")
int BPF_KPROBE(do_mov_240)
{
    u64 addr = ctx->di + 0x25;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_set_timeout+0x10f")
int BPF_KPROBE(do_mov_241)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_destroy_timeout+0x50")
int BPF_KPROBE(do_mov_242)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/untimeout+0x45")
int BPF_KPROBE(do_mov_243)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xc3")
int BPF_KPROBE(do_mov_244)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xda")
int BPF_KPROBE(do_mov_245)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0xe6")
int BPF_KPROBE(do_mov_246)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ecache_work+0x17e")
int BPF_KPROBE(do_mov_247)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x58")
int BPF_KPROBE(do_mov_248)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_ecache_pernet_init+0x81")
int BPF_KPROBE(do_mov_249)
{
    u64 addr = ctx->bx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_new+0x47")
int BPF_KPROBE(do_mov_250)
{
    u64 addr = ctx->r9 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_new+0x5f")
int BPF_KPROBE(do_mov_251)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_timeout_nlattr_to_obj+0x20")
int BPF_KPROBE(do_mov_252)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_timeout_nlattr_to_obj+0x46")
int BPF_KPROBE(do_mov_253)
{
    u64 addr = ctx->dx + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dccp_timeout_nlattr_to_obj+0x56")
int BPF_KPROBE(do_mov_254)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_dccp+0xc0")
int BPF_KPROBE(do_mov_255)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_dccp+0xe6")
int BPF_KPROBE(do_mov_256)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x1e3")
int BPF_KPROBE(do_mov_257)
{
    u64 addr = ctx->r13 + ctx->ax * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x1ec")
int BPF_KPROBE(do_mov_258)
{
    u64 addr = ctx->r13 + ctx->cx * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x214")
int BPF_KPROBE(do_mov_259)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x22e")
int BPF_KPROBE(do_mov_260)
{
    u64 addr = ctx->r13 + 0xbb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x235")
int BPF_KPROBE(do_mov_261)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x23c")
int BPF_KPROBE(do_mov_262)
{
    u64 addr = ctx->r13 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x2fb")
int BPF_KPROBE(do_mov_263)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x31f")
int BPF_KPROBE(do_mov_264)
{
    u64 addr = ctx->r13 + ctx->cx * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x336")
int BPF_KPROBE(do_mov_265)
{
    u64 addr = ctx->r13 + ctx->ax * 0x1 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x398")
int BPF_KPROBE(do_mov_266)
{
    u64 addr = ctx->r13 + 0xbb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x39f")
int BPF_KPROBE(do_mov_267)
{
    u64 addr = ctx->r13 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x3a6")
int BPF_KPROBE(do_mov_268)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x544")
int BPF_KPROBE(do_mov_269)
{
    u64 addr = ctx->r13 + 0xbb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_packet+0x54f")
int BPF_KPROBE(do_mov_270)
{
    u64 addr = ctx->r13 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x47")
int BPF_KPROBE(do_mov_271)
{
    u64 addr = ctx->di + 0xba8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_dccp_init_net+0x4e")
int BPF_KPROBE(do_mov_272)
{
    u64 addr = ctx->di + 0xbc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_timeout_nlattr_to_obj+0x20")
int BPF_KPROBE(do_mov_273)
{
    u64 addr = ctx->dx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_timeout_nlattr_to_obj+0x46")
int BPF_KPROBE(do_mov_274)
{
    u64 addr = ctx->dx + ctx->ax * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_timeout_nlattr_to_obj+0x56")
int BPF_KPROBE(do_mov_275)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_sctp+0x80")
int BPF_KPROBE(do_mov_276)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nlattr_to_sctp+0x9a")
int BPF_KPROBE(do_mov_277)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x68")
int BPF_KPROBE(do_mov_278)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sctp_new+0x62")
int BPF_KPROBE(do_mov_279)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x41f")
int BPF_KPROBE(do_mov_280)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x593")
int BPF_KPROBE(do_mov_281)
{
    u64 addr = ctx->bx + ctx->ax * 0x4 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x651")
int BPF_KPROBE(do_mov_282)
{
    u64 addr = ctx->bx + ctx->cx * 0x4 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x7f7")
int BPF_KPROBE(do_mov_283)
{
    u64 addr = ctx->bx + 0xc4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x84d")
int BPF_KPROBE(do_mov_284)
{
    u64 addr = ctx->bx + 0xc5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x85d")
int BPF_KPROBE(do_mov_285)
{
    u64 addr = ctx->bx + ctx->di * 0x4 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x86d")
int BPF_KPROBE(do_mov_286)
{
    u64 addr = ctx->bx + ctx->ax * 0x4 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_packet+0x8d3")
int BPF_KPROBE(do_mov_287)
{
    u64 addr = ctx->bx + 0xc5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x10")
int BPF_KPROBE(do_mov_288)
{
    u64 addr = ctx->di + 0xbd4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_sctp_init_net+0x58")
int BPF_KPROBE(do_mov_289)
{
    u64 addr = ctx->di + 0xbf4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_timeout_nlattr_to_obj+0x1a")
int BPF_KPROBE(do_mov_290)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_timeout_nlattr_to_obj+0x25")
int BPF_KPROBE(do_mov_291)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_destroy+0x77")
int BPF_KPROBE(do_mov_292)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_destroy+0x94")
int BPF_KPROBE(do_mov_293)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x15f")
int BPF_KPROBE(do_mov_294)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x17a")
int BPF_KPROBE(do_mov_295)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x1ae")
int BPF_KPROBE(do_mov_296)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_gre_keymap_add+0x1b5")
int BPF_KPROBE(do_mov_297)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_pkt_to_tuple+0x64")
int BPF_KPROBE(do_mov_298)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/gre_pkt_to_tuple+0x60")
int BPF_KPROBE(do_mov_299)
{
    u64 addr = ctx->bx + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_init_net+0xd")
int BPF_KPROBE(do_mov_300)
{
    u64 addr = ctx->di + 0xc00;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_gre_init_net+0x28")
int BPF_KPROBE(do_mov_301)
{
    u64 addr = ctx->di + 0xc10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x46")
int BPF_KPROBE(do_mov_302)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0x65")
int BPF_KPROBE(do_mov_303)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xaa")
int BPF_KPROBE(do_mov_304)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xb6")
int BPF_KPROBE(do_mov_305)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xce")
int BPF_KPROBE(do_mov_306)
{
    u64 addr = ctx->r8 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xc3")
int BPF_KPROBE(do_mov_307)
{
    u64 addr = ctx->r8 + 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xdd")
int BPF_KPROBE(do_mov_308)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_nf_ct_tuple_parse+0xe4")
int BPF_KPROBE(do_mov_309)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/change_seq_adj+0x57")
int BPF_KPROBE(do_mov_310)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x4f")
int BPF_KPROBE(do_mov_311)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x56")
int BPF_KPROBE(do_mov_312)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x6e")
int BPF_KPROBE(do_mov_313)
{
    u64 addr = ctx->si + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0xaf")
int BPF_KPROBE(do_mov_314)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x180")
int BPF_KPROBE(do_mov_315)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x1d8")
int BPF_KPROBE(do_mov_316)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x28c")
int BPF_KPROBE(do_mov_317)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_parse_tuple_filter+0x2aa")
int BPF_KPROBE(do_mov_318)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x47")
int BPF_KPROBE(do_mov_319)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0x12c")
int BPF_KPROBE(do_mov_320)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_filter+0xa5")
int BPF_KPROBE(do_mov_321)
{
    u64 addr = ctx->r12 + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_stat_cpu_dump+0x19f")
int BPF_KPROBE(do_mov_322)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_tuples_proto+0x94")
int BPF_KPROBE(do_mov_323)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_protoinfo+0x79")
int BPF_KPROBE(do_mov_324)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_ct_seq_adj+0xd2")
int BPF_KPROBE(do_mov_325)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dump_counters+0xd5")
int BPF_KPROBE(do_mov_326)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_tuples_ip+0x78")
int BPF_KPROBE(do_mov_327)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_ct_stat_cpu_dump+0x2a1")
int BPF_KPROBE(do_mov_328)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_stat_ct+0x117")
int BPF_KPROBE(do_mov_329)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_change_synproxy+0x9a")
int BPF_KPROBE(do_mov_330)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_ct_synproxy+0x104")
int BPF_KPROBE(do_mov_331)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_change_helper+0x11e")
int BPF_KPROBE(do_mov_332)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x12e")
int BPF_KPROBE(do_mov_333)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_alloc_expect+0x240")
int BPF_KPROBE(do_mov_334)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_master+0xb9")
int BPF_KPROBE(do_mov_335)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_helpinfo+0xea")
int BPF_KPROBE(do_mov_336)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_secctx.isra.0+0xb9")
int BPF_KPROBE(do_mov_337)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_build+0x11e")
int BPF_KPROBE(do_mov_338)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_build+0x1b6")
int BPF_KPROBE(do_mov_339)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_glue_build+0x34b")
int BPF_KPROBE(do_mov_340)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_expect+0x1ba")
int BPF_KPROBE(do_mov_341)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_expect+0x3fd")
int BPF_KPROBE(do_mov_342)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_expect_event+0x15c")
int BPF_KPROBE(do_mov_343)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_fill_info.constprop.0+0x8d")
int BPF_KPROBE(do_mov_344)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_ct_dump_table+0xef")
int BPF_KPROBE(do_mov_345)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_ct_dump_table+0xdc")
int BPF_KPROBE(do_mov_346)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_table+0x154")
int BPF_KPROBE(do_mov_347)
{
    u64 addr = ctx->r14 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_exp_dump_table+0xa2")
int BPF_KPROBE(do_mov_348)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x16e")
int BPF_KPROBE(do_mov_349)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x20a")
int BPF_KPROBE(do_mov_350)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_fill_info+0x301")
int BPF_KPROBE(do_mov_351)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_dying+0x120")
int BPF_KPROBE(do_mov_352)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_dump_dying+0xe7")
int BPF_KPROBE(do_mov_353)
{
    u64 addr = ctx->r15 + 0x5c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x13a")
int BPF_KPROBE(do_mov_354)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x376")
int BPF_KPROBE(do_mov_355)
{
    u64 addr = ctx->bx + 0xa0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_create_conntrack+0x276")
int BPF_KPROBE(do_mov_356)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x191")
int BPF_KPROBE(do_mov_357)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x19c")
int BPF_KPROBE(do_mov_358)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x376")
int BPF_KPROBE(do_mov_359)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnetlink_conntrack_event+0x4d6")
int BPF_KPROBE(do_mov_360)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_fill_info.constprop.0+0x17a")
int BPF_KPROBE(do_mov_361)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ctnl_timeout_fill_info.constprop.0+0x191")
int BPF_KPROBE(do_mov_362)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x1b6")
int BPF_KPROBE(do_mov_363)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_new_timeout+0x19a")
int BPF_KPROBE(do_mov_364)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/untimeout+0x28")
int BPF_KPROBE(do_mov_365)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/untimeout+0x45")
int BPF_KPROBE(do_mov_366)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_default_get+0x1da")
int BPF_KPROBE(do_mov_367)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_default_get+0x1ef")
int BPF_KPROBE(do_mov_368)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x2f")
int BPF_KPROBE(do_mov_369)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x32")
int BPF_KPROBE(do_mov_370)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_init+0x3a")
int BPF_KPROBE(do_mov_371)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_pre_exit+0x4c")
int BPF_KPROBE(do_mov_372)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_net_exit+0xa1")
int BPF_KPROBE(do_mov_373)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0xa2")
int BPF_KPROBE(do_mov_374)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cttimeout_del_timeout+0x110")
int BPF_KPROBE(do_mov_375)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x6b")
int BPF_KPROBE(do_mov_376)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_parse_tuple+0x92")
int BPF_KPROBE(do_mov_377)
{
    u64 addr = ctx->bx + 0x26;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_del+0x128")
int BPF_KPROBE(do_mov_378)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_del+0x12b")
int BPF_KPROBE(do_mov_379)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x186")
int BPF_KPROBE(do_mov_380)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x2ae")
int BPF_KPROBE(do_mov_381)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x355")
int BPF_KPROBE(do_mov_382)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_fill_info.constprop.0+0x3b9")
int BPF_KPROBE(do_mov_383)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_dump_table+0xb1")
int BPF_KPROBE(do_mov_384)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_dump_table+0x3c")
int BPF_KPROBE(do_mov_385)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x3fc")
int BPF_KPROBE(do_mov_386)
{
    u64 addr = ctx->bx - 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x49b")
int BPF_KPROBE(do_mov_387)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x65d")
int BPF_KPROBE(do_mov_388)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nfnl_cthelper_new+0x587")
int BPF_KPROBE(do_mov_389)
{
    u64 addr = ctx->r12 + 0x9c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0x7c")
int BPF_KPROBE(do_mov_390)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_number+0x1e")
int BPF_KPROBE(do_mov_391)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_number+0x7f")
int BPF_KPROBE(do_mov_392)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_rfc959+0x57")
int BPF_KPROBE(do_mov_393)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/try_eprt+0x1e1")
int BPF_KPROBE(do_mov_394)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xba")
int BPF_KPROBE(do_mov_395)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xdf")
int BPF_KPROBE(do_mov_396)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xef")
int BPF_KPROBE(do_mov_397)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0xfd")
int BPF_KPROBE(do_mov_398)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x137")
int BPF_KPROBE(do_mov_399)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x143")
int BPF_KPROBE(do_mov_400)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x149")
int BPF_KPROBE(do_mov_401)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x158")
int BPF_KPROBE(do_mov_402)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_h225_addr+0x164")
int BPF_KPROBE(do_mov_403)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x187")
int BPF_KPROBE(do_mov_404)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x20b")
int BPF_KPROBE(do_mov_405)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x20e")
int BPF_KPROBE(do_mov_406)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_tpkt_data.isra.0+0x216")
int BPF_KPROBE(do_mov_407)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x603")
int BPF_KPROBE(do_mov_408)
{
    u64 addr = ctx->r15 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x71e")
int BPF_KPROBE(do_mov_409)
{
    u64 addr = ctx->r15 + ctx->bx * 0x2 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x727")
int BPF_KPROBE(do_mov_410)
{
    u64 addr = ctx->r15 + ctx->ax * 0x2 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x8c7")
int BPF_KPROBE(do_mov_411)
{
    u64 addr = ctx->r13 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ras_help+0x8ba")
int BPF_KPROBE(do_mov_412)
{
    u64 addr = ctx->r13 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x3f")
int BPF_KPROBE(do_mov_413)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x2d")
int BPF_KPROBE(do_mov_414)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bool+0x2d")
int BPF_KPROBE(do_mov_415)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bool+0x13")
int BPF_KPROBE(do_mov_416)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_oid+0x1f")
int BPF_KPROBE(do_mov_417)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_oid+0x18")
int BPF_KPROBE(do_mov_418)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x5d")
int BPF_KPROBE(do_mov_419)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_enum+0x21")
int BPF_KPROBE(do_mov_420)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_numstr+0x79")
int BPF_KPROBE(do_mov_421)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_numstr+0x65")
int BPF_KPROBE(do_mov_422)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0x6a")
int BPF_KPROBE(do_mov_423)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bmpstr+0x7c")
int BPF_KPROBE(do_mov_424)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x69")
int BPF_KPROBE(do_mov_425)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_bitstr+0x3c")
int BPF_KPROBE(do_mov_426)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0xa7")
int BPF_KPROBE(do_mov_427)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0xa0")
int BPF_KPROBE(do_mov_428)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x16b")
int BPF_KPROBE(do_mov_429)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_octstr+0x16b")
int BPF_KPROBE(do_mov_430)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x50")
int BPF_KPROBE(do_mov_431)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x47")
int BPF_KPROBE(do_mov_432)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x7e")
int BPF_KPROBE(do_mov_433)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0xb0")
int BPF_KPROBE(do_mov_434)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x17f")
int BPF_KPROBE(do_mov_435)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_int+0x179")
int BPF_KPROBE(do_mov_436)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0xf3")
int BPF_KPROBE(do_mov_437)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seqof+0xec")
int BPF_KPROBE(do_mov_438)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0xdf")
int BPF_KPROBE(do_mov_439)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_choice+0xd2")
int BPF_KPROBE(do_mov_440)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x133")
int BPF_KPROBE(do_mov_441)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x1b0")
int BPF_KPROBE(do_mov_442)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x3e0")
int BPF_KPROBE(do_mov_443)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decode_seq+0x390")
int BPF_KPROBE(do_mov_444)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x123")
int BPF_KPROBE(do_mov_445)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conntrack_broadcast_help+0x178")
int BPF_KPROBE(do_mov_446)
{
    u64 addr = ctx->r15 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x35b")
int BPF_KPROBE(do_mov_447)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/conntrack_pptp_help+0x3a3")
int BPF_KPROBE(do_mov_448)
{
    u64 addr = ctx->ax + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0xfc")
int BPF_KPROBE(do_mov_449)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0xfc")
int BPF_KPROBE(do_mov_450)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skp_epaddr_len+0x49")
int BPF_KPROBE(do_mov_451)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/skp_epaddr_len+0x63")
int BPF_KPROBE(do_mov_452)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x161")
int BPF_KPROBE(do_mov_453)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x173")
int BPF_KPROBE(do_mov_454)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x18c")
int BPF_KPROBE(do_mov_455)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_request+0x192")
int BPF_KPROBE(do_mov_456)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sdp_parse_addr+0x2c")
int BPF_KPROBE(do_mov_457)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sdp_parse_addr+0x6e")
int BPF_KPROBE(do_mov_458)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_numerical_param+0xa5")
int BPF_KPROBE(do_mov_459)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_numerical_param+0xc7")
int BPF_KPROBE(do_mov_460)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_numerical_param+0xcb")
int BPF_KPROBE(do_mov_461)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_address_param+0xcb")
int BPF_KPROBE(do_mov_462)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_address_param+0xd8")
int BPF_KPROBE(do_mov_463)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_sdp_header+0x106")
int BPF_KPROBE(do_mov_464)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_sdp_header+0x16e")
int BPF_KPROBE(do_mov_465)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_sdp_header+0x183")
int BPF_KPROBE(do_mov_466)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_transport+0xad")
int BPF_KPROBE(do_mov_467)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_transport+0xd3")
int BPF_KPROBE(do_mov_468)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_header+0x1da")
int BPF_KPROBE(do_mov_469)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_header+0x241")
int BPF_KPROBE(do_mov_470)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_get_header+0x256")
int BPF_KPROBE(do_mov_471)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x10f")
int BPF_KPROBE(do_mov_472)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x11a")
int BPF_KPROBE(do_mov_473)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x12d")
int BPF_KPROBE(do_mov_474)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x179")
int BPF_KPROBE(do_mov_475)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x1c4")
int BPF_KPROBE(do_mov_476)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x1dc")
int BPF_KPROBE(do_mov_477)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ct_sip_parse_header_uri+0x21d")
int BPF_KPROBE(do_mov_478)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_register_request+0x2c7")
int BPF_KPROBE(do_mov_479)
{
    u64 addr = ctx->r11 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/process_register_request+0x2d9")
int BPF_KPROBE(do_mov_480)
{
    u64 addr = ctx->r11 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_cleanup_conntrack+0x46")
int BPF_KPROBE(do_mov_481)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x6d")
int BPF_KPROBE(do_mov_482)
{
    u64 addr = ctx->r10 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_nat_decode_session+0x127")
int BPF_KPROBE(do_mov_483)
{
    u64 addr = ctx->r10 + 0x56;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_proto_clean+0x89")
int BPF_KPROBE(do_mov_484)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_register_fn+0x167")
int BPF_KPROBE(do_mov_485)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_unregister_fn+0x116")
int BPF_KPROBE(do_mov_486)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0xa0")
int BPF_KPROBE(do_mov_487)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x18a")
int BPF_KPROBE(do_mov_488)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x28a")
int BPF_KPROBE(do_mov_489)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/l4proto_manip_pkt+0x46f")
int BPF_KPROBE(do_mov_490)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_manip_pkt+0xc8")
int BPF_KPROBE(do_mov_491)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv6_manip_pkt+0xeb")
int BPF_KPROBE(do_mov_492)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_manip_pkt+0xa2")
int BPF_KPROBE(do_mov_493)
{
    u64 addr = ctx->dx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ipv4_manip_pkt+0xe4")
int BPF_KPROBE(do_mov_494)
{
    u64 addr = ctx->dx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x53")
int BPF_KPROBE(do_mov_495)
{
    u64 addr = ctx->r10 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x7a")
int BPF_KPROBE(do_mov_496)
{
    u64 addr = ctx->r10 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0xd2")
int BPF_KPROBE(do_mov_497)
{
    u64 addr = ctx->r10 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_csum_recalc+0x100")
int BPF_KPROBE(do_mov_498)
{
    u64 addr = ctx->r10 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x59")
int BPF_KPROBE(do_mov_499)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x4b")
int BPF_KPROBE(do_mov_500)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ftp+0xa0")
int BPF_KPROBE(do_mov_501)
{
    u64 addr = ctx->r13 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_ftp+0x96")
int BPF_KPROBE(do_mov_502)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x74")
int BPF_KPROBE(do_mov_503)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x66")
int BPF_KPROBE(do_mov_504)
{
    u64 addr = ctx->r9 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x9a")
int BPF_KPROBE(do_mov_505)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xc5")
int BPF_KPROBE(do_mov_506)
{
    u64 addr = ctx->r15 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0xbe")
int BPF_KPROBE(do_mov_507)
{
    u64 addr = ctx->r15 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x111")
int BPF_KPROBE(do_mov_508)
{
    u64 addr = ctx->r12 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x109")
int BPF_KPROBE(do_mov_509)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sdp_media+0x20a")
int BPF_KPROBE(do_mov_510)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x155")
int BPF_KPROBE(do_mov_511)
{
    u64 addr = ctx->r13 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_nat_sip_expect+0x165")
int BPF_KPROBE(do_mov_512)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x21")
int BPF_KPROBE(do_mov_513)
{
    u64 addr = ctx->dx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/help+0x29")
int BPF_KPROBE(do_mov_514)
{
    u64 addr = ctx->dx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_init_timestamp_cookie+0x47")
int BPF_KPROBE(do_mov_515)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_init_timestamp_cookie+0x3e")
int BPF_KPROBE(do_mov_516)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x42")
int BPF_KPROBE(do_mov_517)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_build_options.constprop.0+0x73")
int BPF_KPROBE(do_mov_518)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0x9e")
int BPF_KPROBE(do_mov_519)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp.isra.0+0xad")
int BPF_KPROBE(do_mov_520)
{
    u64 addr = ctx->r12 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0x16c")
int BPF_KPROBE(do_mov_521)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_tcp_ipv6+0xa1")
int BPF_KPROBE(do_mov_522)
{
    u64 addr = ctx->r12 + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0x61")
int BPF_KPROBE(do_mov_523)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_parse_options+0xf2")
int BPF_KPROBE(do_mov_524)
{
    u64 addr = ctx->r12 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_cpu_seq_next+0x58")
int BPF_KPROBE(do_mov_525)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_cpu_seq_next+0x86")
int BPF_KPROBE(do_mov_526)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_net_init+0x85")
int BPF_KPROBE(do_mov_527)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x86")
int BPF_KPROBE(do_mov_528)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x18d")
int BPF_KPROBE(do_mov_529)
{
    u64 addr = ctx->r9 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1b5")
int BPF_KPROBE(do_mov_530)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1e9")
int BPF_KPROBE(do_mov_531)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x1f9")
int BPF_KPROBE(do_mov_532)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x23d")
int BPF_KPROBE(do_mov_533)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack_ipv6+0x2bc")
int BPF_KPROBE(do_mov_534)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x258")
int BPF_KPROBE(do_mov_535)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3d0")
int BPF_KPROBE(do_mov_536)
{
    u64 addr = ctx->r9 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x3fc")
int BPF_KPROBE(do_mov_537)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x435")
int BPF_KPROBE(do_mov_538)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x43c")
int BPF_KPROBE(do_mov_539)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x470")
int BPF_KPROBE(do_mov_540)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x5e6")
int BPF_KPROBE(do_mov_541)
{
    u64 addr = ctx->r13 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x60b")
int BPF_KPROBE(do_mov_542)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x641")
int BPF_KPROBE(do_mov_543)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x649")
int BPF_KPROBE(do_mov_544)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_synproxy_hook+0x679")
int BPF_KPROBE(do_mov_545)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0xfe")
int BPF_KPROBE(do_mov_546)
{
    u64 addr = ctx->r13 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x123")
int BPF_KPROBE(do_mov_547)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x158")
int BPF_KPROBE(do_mov_548)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x160")
int BPF_KPROBE(do_mov_549)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack_ipv6+0x17b")
int BPF_KPROBE(do_mov_550)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0xf6")
int BPF_KPROBE(do_mov_551)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x116")
int BPF_KPROBE(do_mov_552)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x15c")
int BPF_KPROBE(do_mov_553)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x164")
int BPF_KPROBE(do_mov_554)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_send_client_synack+0x183")
int BPF_KPROBE(do_mov_555)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x85")
int BPF_KPROBE(do_mov_556)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x169")
int BPF_KPROBE(do_mov_557)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x186")
int BPF_KPROBE(do_mov_558)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1c0")
int BPF_KPROBE(do_mov_559)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x1c9")
int BPF_KPROBE(do_mov_560)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x21b")
int BPF_KPROBE(do_mov_561)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/synproxy_recv_client_ack+0x2a1")
int BPF_KPROBE(do_mov_562)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x204")
int BPF_KPROBE(do_mov_563)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3cd")
int BPF_KPROBE(do_mov_564)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x3c5")
int BPF_KPROBE(do_mov_565)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x418")
int BPF_KPROBE(do_mov_566)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x41f")
int BPF_KPROBE(do_mov_567)
{
    u64 addr = ctx->ax + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x454")
int BPF_KPROBE(do_mov_568)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5d9")
int BPF_KPROBE(do_mov_569)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x5d5")
int BPF_KPROBE(do_mov_570)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x615")
int BPF_KPROBE(do_mov_571)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x61f")
int BPF_KPROBE(do_mov_572)
{
    u64 addr = ctx->r13 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv4_synproxy_hook+0x654")
int BPF_KPROBE(do_mov_573)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0xe")
int BPF_KPROBE(do_mov_574)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0x2a")
int BPF_KPROBE(do_mov_575)
{
    u64 addr = ctx->di + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_list_init+0x22")
int BPF_KPROBE(do_mov_576)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xb6")
int BPF_KPROBE(do_mov_577)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_init+0xec")
int BPF_KPROBE(do_mov_578)
{
    u64 addr = ctx->r12 + 0x828;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x2b7")
int BPF_KPROBE(do_mov_579)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x2cb")
int BPF_KPROBE(do_mov_580)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x36d")
int BPF_KPROBE(do_mov_581)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x366")
int BPF_KPROBE(do_mov_582)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_conncount_add+0x378")
int BPF_KPROBE(do_mov_583)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x426")
int BPF_KPROBE(do_mov_584)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x453")
int BPF_KPROBE(do_mov_585)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x494")
int BPF_KPROBE(do_mov_586)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4a9")
int BPF_KPROBE(do_mov_587)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x49d")
int BPF_KPROBE(do_mov_588)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4d2")
int BPF_KPROBE(do_mov_589)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x4c9")
int BPF_KPROBE(do_mov_590)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_conncount_count+0x53c")
int BPF_KPROBE(do_mov_591)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_do_chain+0x2c0")
int BPF_KPROBE(do_mov_592)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_do_chain+0x402")
int BPF_KPROBE(do_mov_593)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x37")
int BPF_KPROBE(do_mov_594)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x76")
int BPF_KPROBE(do_mov_595)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_reg_track_cancel+0x16")
int BPF_KPROBE(do_mov_596)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_expr+0x28")
int BPF_KPROBE(do_mov_597)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_obj+0x28")
int BPF_KPROBE(do_mov_598)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x1e")
int BPF_KPROBE(do_mov_599)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x29")
int BPF_KPROBE(do_mov_600)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_unregister_flowtable_type+0x27")
int BPF_KPROBE(do_mov_601)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_destroy+0x70")
int BPF_KPROBE(do_mov_602)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x41")
int BPF_KPROBE(do_mov_603)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x44")
int BPF_KPROBE(do_mov_604)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x40")
int BPF_KPROBE(do_mov_605)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x5b")
int BPF_KPROBE(do_mov_606)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x7d")
int BPF_KPROBE(do_mov_607)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x9b")
int BPF_KPROBE(do_mov_608)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_u32_check+0x12")
int BPF_KPROBE(do_mov_609)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x51")
int BPF_KPROBE(do_mov_610)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x54")
int BPF_KPROBE(do_mov_611)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit_audit_log+0x5e")
int BPF_KPROBE(do_mov_612)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa0")
int BPF_KPROBE(do_mov_613)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa7")
int BPF_KPROBE(do_mov_614)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x106")
int BPF_KPROBE(do_mov_615)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x109")
int BPF_KPROBE(do_mov_616)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x36")
int BPF_KPROBE(do_mov_617)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x72")
int BPF_KPROBE(do_mov_618)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_register_load+0x30")
int BPF_KPROBE(do_mov_619)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_register_flowtable_net_hooks+0x112")
int BPF_KPROBE(do_mov_620)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_gc+0x68")
int BPF_KPROBE(do_mov_621)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj_start+0x52")
int BPF_KPROBE(do_mov_622)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_rules_start+0x52")
int BPF_KPROBE(do_mov_623)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable_start+0x4f")
int BPF_KPROBE(do_mov_624)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xb9")
int BPF_KPROBE(do_mov_625)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0x4b")
int BPF_KPROBE(do_mov_626)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xff")
int BPF_KPROBE(do_mov_627)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xf0")
int BPF_KPROBE(do_mov_628)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x5f")
int BPF_KPROBE(do_mov_629)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x107")
int BPF_KPROBE(do_mov_630)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x10a")
int BPF_KPROBE(do_mov_631)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x3d")
int BPF_KPROBE(do_mov_632)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x44")
int BPF_KPROBE(do_mov_633)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x76")
int BPF_KPROBE(do_mov_634)
{
    u64 addr = ctx->bx + 0x6c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_init+0x12c")
int BPF_KPROBE(do_mov_635)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x76")
int BPF_KPROBE(do_mov_636)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x79")
int BPF_KPROBE(do_mov_637)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_register_store+0x48")
int BPF_KPROBE(do_mov_638)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_parse_register_store+0x8f")
int BPF_KPROBE(do_mov_639)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_remove+0x6e")
int BPF_KPROBE(do_mov_640)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_del+0xa6")
int BPF_KPROBE(do_mov_641)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_event+0x108")
int BPF_KPROBE(do_mov_642)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x14d")
int BPF_KPROBE(do_mov_643)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_request_module+0x154")
int BPF_KPROBE(do_mov_644)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_expr_parse+0x175")
int BPF_KPROBE(do_mov_645)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x27")
int BPF_KPROBE(do_mov_646)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x36")
int BPF_KPROBE(do_mov_647)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x5a")
int BPF_KPROBE(do_mov_648)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x64")
int BPF_KPROBE(do_mov_649)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x6d")
int BPF_KPROBE(do_mov_650)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x68")
int BPF_KPROBE(do_mov_651)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delset+0x6f")
int BPF_KPROBE(do_mov_652)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x64")
int BPF_KPROBE(do_mov_653)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delobj+0x6b")
int BPF_KPROBE(do_mov_654)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x150")
int BPF_KPROBE(do_mov_655)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x154")
int BPF_KPROBE(do_mov_656)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0x5f")
int BPF_KPROBE(do_mov_657)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delchain+0x66")
int BPF_KPROBE(do_mov_658)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x47")
int BPF_KPROBE(do_mov_659)
{
    u64 addr = ctx->bx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x4b")
int BPF_KPROBE(do_mov_660)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x74")
int BPF_KPROBE(do_mov_661)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x7b")
int BPF_KPROBE(do_mov_662)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xd8")
int BPF_KPROBE(do_mov_663)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xe1")
int BPF_KPROBE(do_mov_664)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x1de")
int BPF_KPROBE(do_mov_665)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x1e6")
int BPF_KPROBE(do_mov_666)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_init+0xa3")
int BPF_KPROBE(do_mov_667)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_init+0xc6")
int BPF_KPROBE(do_mov_668)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x223")
int BPF_KPROBE(do_mov_669)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x227")
int BPF_KPROBE(do_mov_670)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x305")
int BPF_KPROBE(do_mov_671)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x313")
int BPF_KPROBE(do_mov_672)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x316")
int BPF_KPROBE(do_mov_673)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x34c")
int BPF_KPROBE(do_mov_674)
{
    u64 addr = ctx->ax + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x37f")
int BPF_KPROBE(do_mov_675)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3ae")
int BPF_KPROBE(do_mov_676)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3b1")
int BPF_KPROBE(do_mov_677)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3f4")
int BPF_KPROBE(do_mov_678)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3fc")
int BPF_KPROBE(do_mov_679)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x430")
int BPF_KPROBE(do_mov_680)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x463")
int BPF_KPROBE(do_mov_681)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x466")
int BPF_KPROBE(do_mov_682)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0x168")
int BPF_KPROBE(do_mov_683)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0xc3")
int BPF_KPROBE(do_mov_684)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x67")
int BPF_KPROBE(do_mov_685)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x70")
int BPF_KPROBE(do_mov_686)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x10a")
int BPF_KPROBE(do_mov_687)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x117")
int BPF_KPROBE(do_mov_688)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x14f")
int BPF_KPROBE(do_mov_689)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_delrule+0x15c")
int BPF_KPROBE(do_mov_690)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b0")
int BPF_KPROBE(do_mov_691)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b9")
int BPF_KPROBE(do_mov_692)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x1eb")
int BPF_KPROBE(do_mov_693)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x1e3")
int BPF_KPROBE(do_mov_694)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_table_info+0x1c4")
int BPF_KPROBE(do_mov_695)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_table_info+0xc0")
int BPF_KPROBE(do_mov_696)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xc3")
int BPF_KPROBE(do_mov_697)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xcc")
int BPF_KPROBE(do_mov_698)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0x169")
int BPF_KPROBE(do_mov_699)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xd7")
int BPF_KPROBE(do_mov_700)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0xcd")
int BPF_KPROBE(do_mov_701)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0xc8")
int BPF_KPROBE(do_mov_702)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0x247")
int BPF_KPROBE(do_mov_703)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x108")
int BPF_KPROBE(do_mov_704)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x10f")
int BPF_KPROBE(do_mov_705)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x148")
int BPF_KPROBE(do_mov_706)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x1a1")
int BPF_KPROBE(do_mov_707)
{
    u64 addr = ctx->r15 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x191")
int BPF_KPROBE(do_mov_708)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x189")
int BPF_KPROBE(do_mov_709)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xcc")
int BPF_KPROBE(do_mov_710)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xc7")
int BPF_KPROBE(do_mov_711)
{
    u64 addr = ctx->r13 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x322")
int BPF_KPROBE(do_mov_712)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x338")
int BPF_KPROBE(do_mov_713)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xd5")
int BPF_KPROBE(do_mov_714)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xdc")
int BPF_KPROBE(do_mov_715)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x1a1")
int BPF_KPROBE(do_mov_716)
{
    u64 addr = ctx->r14 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x115")
int BPF_KPROBE(do_mov_717)
{
    u64 addr = ctx->r14 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x1fb")
int BPF_KPROBE(do_mov_718)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x200")
int BPF_KPROBE(do_mov_719)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x22a")
int BPF_KPROBE(do_mov_720)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x233")
int BPF_KPROBE(do_mov_721)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x3ff")
int BPF_KPROBE(do_mov_722)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x43e")
int BPF_KPROBE(do_mov_723)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x4fc")
int BPF_KPROBE(do_mov_724)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x504")
int BPF_KPROBE(do_mov_725)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x58a")
int BPF_KPROBE(do_mov_726)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x596")
int BPF_KPROBE(do_mov_727)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x1c4")
int BPF_KPROBE(do_mov_728)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0xc6")
int BPF_KPROBE(do_mov_729)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x407")
int BPF_KPROBE(do_mov_730)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x54f")
int BPF_KPROBE(do_mov_731)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x57b")
int BPF_KPROBE(do_mov_732)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xc8")
int BPF_KPROBE(do_mov_733)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xd1")
int BPF_KPROBE(do_mov_734)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0x195")
int BPF_KPROBE(do_mov_735)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xfa")
int BPF_KPROBE(do_mov_736)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x22a")
int BPF_KPROBE(do_mov_737)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x233")
int BPF_KPROBE(do_mov_738)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x391")
int BPF_KPROBE(do_mov_739)
{
    u64 addr = ctx->r15 + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x32f")
int BPF_KPROBE(do_mov_740)
{
    u64 addr = ctx->r15 + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x4fc")
int BPF_KPROBE(do_mov_741)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x503")
int BPF_KPROBE(do_mov_742)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x50a")
int BPF_KPROBE(do_mov_743)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x511")
int BPF_KPROBE(do_mov_744)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x687")
int BPF_KPROBE(do_mov_745)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x694")
int BPF_KPROBE(do_mov_746)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1d3")
int BPF_KPROBE(do_mov_747)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1c6")
int BPF_KPROBE(do_mov_748)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x372")
int BPF_KPROBE(do_mov_749)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x37f")
int BPF_KPROBE(do_mov_750)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x420")
int BPF_KPROBE(do_mov_751)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x424")
int BPF_KPROBE(do_mov_752)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x44c")
int BPF_KPROBE(do_mov_753)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x47f")
int BPF_KPROBE(do_mov_754)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x488")
int BPF_KPROBE(do_mov_755)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x4b9")
int BPF_KPROBE(do_mov_756)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x54c")
int BPF_KPROBE(do_mov_757)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x544")
int BPF_KPROBE(do_mov_758)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5d7")
int BPF_KPROBE(do_mov_759)
{
    u64 addr = ctx->r15 + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5e5")
int BPF_KPROBE(do_mov_760)
{
    u64 addr = ctx->r15 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x672")
int BPF_KPROBE(do_mov_761)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x69b")
int BPF_KPROBE(do_mov_762)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x691")
int BPF_KPROBE(do_mov_763)
{
    u64 addr = ctx->r15 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x719")
int BPF_KPROBE(do_mov_764)
{
    u64 addr = ctx->r12 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x71e")
int BPF_KPROBE(do_mov_765)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x74b")
int BPF_KPROBE(do_mov_766)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x754")
int BPF_KPROBE(do_mov_767)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x75e")
int BPF_KPROBE(do_mov_768)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x768")
int BPF_KPROBE(do_mov_769)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x7a1")
int BPF_KPROBE(do_mov_770)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x8a5")
int BPF_KPROBE(do_mov_771)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_chain_destroy+0x9d")
int BPF_KPROBE(do_mov_772)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x14a")
int BPF_KPROBE(do_mov_773)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x135")
int BPF_KPROBE(do_mov_774)
{
    u64 addr = ctx->dx + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1a0")
int BPF_KPROBE(do_mov_775)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1f6")
int BPF_KPROBE(do_mov_776)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1e6")
int BPF_KPROBE(do_mov_777)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x209")
int BPF_KPROBE(do_mov_778)
{
    u64 addr = ctx->dx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x24c")
int BPF_KPROBE(do_mov_779)
{
    u64 addr = ctx->dx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x317")
int BPF_KPROBE(do_mov_780)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x30f")
int BPF_KPROBE(do_mov_781)
{
    u64 addr = ctx->r8 + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x3e0")
int BPF_KPROBE(do_mov_782)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x399")
int BPF_KPROBE(do_mov_783)
{
    u64 addr = ctx->r8 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x557")
int BPF_KPROBE(do_mov_784)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x55e")
int BPF_KPROBE(do_mov_785)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5ca")
int BPF_KPROBE(do_mov_786)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5ba")
int BPF_KPROBE(do_mov_787)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x64b")
int BPF_KPROBE(do_mov_788)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x68f")
int BPF_KPROBE(do_mov_789)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x692")
int BPF_KPROBE(do_mov_790)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x75a")
int BPF_KPROBE(do_mov_791)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x75d")
int BPF_KPROBE(do_mov_792)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d6")
int BPF_KPROBE(do_mov_793)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d9")
int BPF_KPROBE(do_mov_794)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3e6")
int BPF_KPROBE(do_mov_795)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3f3")
int BPF_KPROBE(do_mov_796)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x624")
int BPF_KPROBE(do_mov_797)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x62b")
int BPF_KPROBE(do_mov_798)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x82c")
int BPF_KPROBE(do_mov_799)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x82f")
int BPF_KPROBE(do_mov_800)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x8a3")
int BPF_KPROBE(do_mov_801)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x8a6")
int BPF_KPROBE(do_mov_802)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_dump+0x53")
int BPF_KPROBE(do_mov_803)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0xcf")
int BPF_KPROBE(do_mov_804)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0xd6")
int BPF_KPROBE(do_mov_805)
{
    u64 addr = ctx->bx + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_rule_info+0x2c6")
int BPF_KPROBE(do_mov_806)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xf2")
int BPF_KPROBE(do_mov_807)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xfb")
int BPF_KPROBE(do_mov_808)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x1f0")
int BPF_KPROBE(do_mov_809)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x1e8")
int BPF_KPROBE(do_mov_810)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x105")
int BPF_KPROBE(do_mov_811)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x72")
int BPF_KPROBE(do_mov_812)
{
    u64 addr = ctx->r12 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x146")
int BPF_KPROBE(do_mov_813)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x29e")
int BPF_KPROBE(do_mov_814)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x2cf")
int BPF_KPROBE(do_mov_815)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x370")
int BPF_KPROBE(do_mov_816)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x4a5")
int BPF_KPROBE(do_mov_817)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x61e")
int BPF_KPROBE(do_mov_818)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x240")
int BPF_KPROBE(do_mov_819)
{
    u64 addr = ctx->r9 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x244")
int BPF_KPROBE(do_mov_820)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc0")
int BPF_KPROBE(do_mov_821)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc7")
int BPF_KPROBE(do_mov_822)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x1e")
int BPF_KPROBE(do_mov_823)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x51")
int BPF_KPROBE(do_mov_824)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_expr_clone+0x17")
int BPF_KPROBE(do_mov_825)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x465")
int BPF_KPROBE(do_mov_826)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x485")
int BPF_KPROBE(do_mov_827)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x4b2")
int BPF_KPROBE(do_mov_828)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x6e9")
int BPF_KPROBE(do_mov_829)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x66b")
int BPF_KPROBE(do_mov_830)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d6")
int BPF_KPROBE(do_mov_831)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d9")
int BPF_KPROBE(do_mov_832)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x838")
int BPF_KPROBE(do_mov_833)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8a3")
int BPF_KPROBE(do_mov_834)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x862")
int BPF_KPROBE(do_mov_835)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x93f")
int BPF_KPROBE(do_mov_836)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x91f")
int BPF_KPROBE(do_mov_837)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x972")
int BPF_KPROBE(do_mov_838)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x96a")
int BPF_KPROBE(do_mov_839)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa05")
int BPF_KPROBE(do_mov_840)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa1b")
int BPF_KPROBE(do_mov_841)
{
    u64 addr = ctx->di + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc44")
int BPF_KPROBE(do_mov_842)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc4b")
int BPF_KPROBE(do_mov_843)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc55")
int BPF_KPROBE(do_mov_844)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc5c")
int BPF_KPROBE(do_mov_845)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xdfc")
int BPF_KPROBE(do_mov_846)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x65")
int BPF_KPROBE(do_mov_847)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x6e")
int BPF_KPROBE(do_mov_848)
{
    u64 addr = ctx->bx + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x108")
int BPF_KPROBE(do_mov_849)
{
    u64 addr = ctx->bx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x11e")
int BPF_KPROBE(do_mov_850)
{
    u64 addr = ctx->bx + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_chain_del+0xa9")
int BPF_KPROBE(do_mov_851)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x7d8")
int BPF_KPROBE(do_mov_852)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x95d")
int BPF_KPROBE(do_mov_853)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xdf8")
int BPF_KPROBE(do_mov_854)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf26")
int BPF_KPROBE(do_mov_855)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf5b")
int BPF_KPROBE(do_mov_856)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf62")
int BPF_KPROBE(do_mov_857)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x107f")
int BPF_KPROBE(do_mov_858)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x1f3")
int BPF_KPROBE(do_mov_859)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x1eb")
int BPF_KPROBE(do_mov_860)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0x7f")
int BPF_KPROBE(do_mov_861)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xa6")
int BPF_KPROBE(do_mov_862)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xaf")
int BPF_KPROBE(do_mov_863)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xda")
int BPF_KPROBE(do_mov_864)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xe1")
int BPF_KPROBE(do_mov_865)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x49a")
int BPF_KPROBE(do_mov_866)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4c8")
int BPF_KPROBE(do_mov_867)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4cf")
int BPF_KPROBE(do_mov_868)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_set_destroy+0xb6")
int BPF_KPROBE(do_mov_869)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x66")
int BPF_KPROBE(do_mov_870)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xcd")
int BPF_KPROBE(do_mov_871)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xd5")
int BPF_KPROBE(do_mov_872)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x141")
int BPF_KPROBE(do_mov_873)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x5d")
int BPF_KPROBE(do_mov_874)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x6a")
int BPF_KPROBE(do_mov_875)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xcb")
int BPF_KPROBE(do_mov_876)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xd8")
int BPF_KPROBE(do_mov_877)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x12a")
int BPF_KPROBE(do_mov_878)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x197")
int BPF_KPROBE(do_mov_879)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x312")
int BPF_KPROBE(do_mov_880)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x40d")
int BPF_KPROBE(do_mov_881)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x5df")
int BPF_KPROBE(do_mov_882)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6d0")
int BPF_KPROBE(do_mov_883)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6f6")
int BPF_KPROBE(do_mov_884)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x798")
int BPF_KPROBE(do_mov_885)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x810")
int BPF_KPROBE(do_mov_886)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0xb5")
int BPF_KPROBE(do_mov_887)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0xc2")
int BPF_KPROBE(do_mov_888)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1a5")
int BPF_KPROBE(do_mov_889)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1ac")
int BPF_KPROBE(do_mov_890)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x204")
int BPF_KPROBE(do_mov_891)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_release_table+0x20b")
int BPF_KPROBE(do_mov_892)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xbf")
int BPF_KPROBE(do_mov_893)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xc2")
int BPF_KPROBE(do_mov_894)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rcv_nl_event+0xec")
int BPF_KPROBE(do_mov_895)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_verdict_dump+0x93")
int BPF_KPROBE(do_mov_896)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_data_dump+0x6c")
int BPF_KPROBE(do_mov_897)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x243")
int BPF_KPROBE(do_mov_898)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x351")
int BPF_KPROBE(do_mov_899)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x17f")
int BPF_KPROBE(do_mov_900)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x187")
int BPF_KPROBE(do_mov_901)
{
    u64 addr = ctx->r13 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x2a9")
int BPF_KPROBE(do_mov_902)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb0")
int BPF_KPROBE(do_mov_903)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb8")
int BPF_KPROBE(do_mov_904)
{
    u64 addr = ctx->ax + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0x188")
int BPF_KPROBE(do_mov_905)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xd2")
int BPF_KPROBE(do_mov_906)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xdb")
int BPF_KPROBE(do_mov_907)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x122")
int BPF_KPROBE(do_mov_908)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x1e5")
int BPF_KPROBE(do_mov_909)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x131")
int BPF_KPROBE(do_mov_910)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x2c5")
int BPF_KPROBE(do_mov_911)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x3dd")
int BPF_KPROBE(do_mov_912)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x493")
int BPF_KPROBE(do_mov_913)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5e2")
int BPF_KPROBE(do_mov_914)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5ef")
int BPF_KPROBE(do_mov_915)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x613")
int BPF_KPROBE(do_mov_916)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6d1")
int BPF_KPROBE(do_mov_917)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6de")
int BPF_KPROBE(do_mov_918)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x750")
int BPF_KPROBE(do_mov_919)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x75d")
int BPF_KPROBE(do_mov_920)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x900")
int BPF_KPROBE(do_mov_921)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x903")
int BPF_KPROBE(do_mov_922)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x9e6")
int BPF_KPROBE(do_mov_923)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb2f")
int BPF_KPROBE(do_mov_924)
{
    u64 addr = ctx->r13 - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb96")
int BPF_KPROBE(do_mov_925)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xc3e")
int BPF_KPROBE(do_mov_926)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xcf9")
int BPF_KPROBE(do_mov_927)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xde4")
int BPF_KPROBE(do_mov_928)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xe69")
int BPF_KPROBE(do_mov_929)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf44")
int BPF_KPROBE(do_mov_930)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf51")
int BPF_KPROBE(do_mov_931)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10c4")
int BPF_KPROBE(do_mov_932)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10e3")
int BPF_KPROBE(do_mov_933)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x25c")
int BPF_KPROBE(do_mov_934)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x254")
int BPF_KPROBE(do_mov_935)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_tables_netdev_event+0x1b0")
int BPF_KPROBE(do_mov_936)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_notify+0x51e")
int BPF_KPROBE(do_mov_937)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x2f")
int BPF_KPROBE(do_mov_938)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x4e")
int BPF_KPROBE(do_mov_939)
{
    u64 addr = ctx->di + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_trace_init+0x47")
int BPF_KPROBE(do_mov_940)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x43")
int BPF_KPROBE(do_mov_941)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x58")
int BPF_KPROBE(do_mov_942)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x70")
int BPF_KPROBE(do_mov_943)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_eval+0x78")
int BPF_KPROBE(do_mov_944)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x29")
int BPF_KPROBE(do_mov_945)
{
    u64 addr = ctx->cx + ctx->dx * 0x8 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x2e")
int BPF_KPROBE(do_mov_946)
{
    u64 addr = ctx->cx + ctx->dx * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_immediate_offload+0x42")
int BPF_KPROBE(do_mov_947)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_fast_init+0x97")
int BPF_KPROBE(do_mov_948)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp_fast_init+0x87")
int BPF_KPROBE(do_mov_949)
{
    u64 addr = ctx->bx + 0x11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x122")
int BPF_KPROBE(do_mov_950)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x190")
int BPF_KPROBE(do_mov_951)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_cmp16_fast_init+0x1c9")
int BPF_KPROBE(do_mov_952)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_range_eval+0x5c")
int BPF_KPROBE(do_mov_953)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_fast_reduce+0x4b")
int BPF_KPROBE(do_mov_954)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_init+0x92")
int BPF_KPROBE(do_mov_955)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_init+0x4b")
int BPF_KPROBE(do_mov_956)
{
    u64 addr = ctx->bx + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_eval+0x4a")
int BPF_KPROBE(do_mov_957)
{
    u64 addr = ctx->r8 + ctx->dx * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_eval+0x9f")
int BPF_KPROBE(do_mov_958)
{
    u64 addr = ctx->r8 + ctx->si * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitwise_eval+0xfc")
int BPF_KPROBE(do_mov_959)
{
    u64 addr = ctx->r8 + ctx->ax * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x5e")
int BPF_KPROBE(do_mov_960)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x9d")
int BPF_KPROBE(do_mov_961)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0xdf")
int BPF_KPROBE(do_mov_962)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x10f")
int BPF_KPROBE(do_mov_963)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x13d")
int BPF_KPROBE(do_mov_964)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_byteorder_eval+0x16d")
int BPF_KPROBE(do_mov_965)
{
    u64 addr = ctx->cx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x71")
int BPF_KPROBE(do_mov_966)
{
    u64 addr = ctx->dx - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_mask+0x79")
int BPF_KPROBE(do_mov_967)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_init+0x1a")
int BPF_KPROBE(do_mov_968)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_init+0x38")
int BPF_KPROBE(do_mov_969)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x31")
int BPF_KPROBE(do_mov_970)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x49")
int BPF_KPROBE(do_mov_971)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0xb6")
int BPF_KPROBE(do_mov_972)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_init+0x96")
int BPF_KPROBE(do_mov_973)
{
    u64 addr = ctx->bx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0x5b")
int BPF_KPROBE(do_mov_974)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload_tcp.constprop.0.isra.0+0x6d")
int BPF_KPROBE(do_mov_975)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x15a")
int BPF_KPROBE(do_mov_976)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_offload+0x16c")
int BPF_KPROBE(do_mov_977)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0xb9")
int BPF_KPROBE(do_mov_978)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x1eb")
int BPF_KPROBE(do_mov_979)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x305")
int BPF_KPROBE(do_mov_980)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x336")
int BPF_KPROBE(do_mov_981)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x351")
int BPF_KPROBE(do_mov_982)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x361")
int BPF_KPROBE(do_mov_983)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x37b")
int BPF_KPROBE(do_mov_984)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x385")
int BPF_KPROBE(do_mov_985)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_eval+0x39d")
int BPF_KPROBE(do_mov_986)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_payload_set_eval+0x28a")
int BPF_KPROBE(do_mov_987)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x128")
int BPF_KPROBE(do_mov_988)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x15c")
int BPF_KPROBE(do_mov_989)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x173")
int BPF_KPROBE(do_mov_990)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x190")
int BPF_KPROBE(do_mov_991)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_eval+0x1a8")
int BPF_KPROBE(do_mov_992)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_init+0xdf")
int BPF_KPROBE(do_mov_993)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_lookup_init+0xd3")
int BPF_KPROBE(do_mov_994)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_new+0xcb")
int BPF_KPROBE(do_mov_995)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_dump+0x1d8")
int BPF_KPROBE(do_mov_996)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x21d")
int BPF_KPROBE(do_mov_997)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x1f1")
int BPF_KPROBE(do_mov_998)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x336")
int BPF_KPROBE(do_mov_999)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x35e")
int BPF_KPROBE(do_mov_1000)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x42a")
int BPF_KPROBE(do_mov_1001)
{
    u64 addr = ctx->r13 + ctx->cx * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x437")
int BPF_KPROBE(do_mov_1002)
{
    u64 addr = ctx->r13 + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x500")
int BPF_KPROBE(do_mov_1003)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x517")
int BPF_KPROBE(do_mov_1004)
{
    u64 addr = ctx->r13 + 0x19;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x51f")
int BPF_KPROBE(do_mov_1005)
{
    u64 addr = ctx->r13 + 0x22;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x528")
int BPF_KPROBE(do_mov_1006)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x550")
int BPF_KPROBE(do_mov_1007)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x565")
int BPF_KPROBE(do_mov_1008)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x569")
int BPF_KPROBE(do_mov_1009)
{
    u64 addr = ctx->r13 + 0x1d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x572")
int BPF_KPROBE(do_mov_1010)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_dynset_init+0x5fb")
int BPF_KPROBE(do_mov_1011)
{
    u64 addr = ctx->r13 + 0x29;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x54")
int BPF_KPROBE(do_mov_1012)
{
    u64 addr = ctx->dx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_set_eval+0x37")
int BPF_KPROBE(do_mov_1013)
{
    u64 addr = ctx->dx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_skugid+0xdb")
int BPF_KPROBE(do_mov_1014)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_skugid+0x108")
int BPF_KPROBE(do_mov_1015)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0x54")
int BPF_KPROBE(do_mov_1016)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0x98")
int BPF_KPROBE(do_mov_1017)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0xa3")
int BPF_KPROBE(do_mov_1018)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_time+0xcb")
int BPF_KPROBE(do_mov_1019)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x4d")
int BPF_KPROBE(do_mov_1020)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x5f")
int BPF_KPROBE(do_mov_1021)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x9e")
int BPF_KPROBE(do_mov_1022)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0xb5")
int BPF_KPROBE(do_mov_1023)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0xfd")
int BPF_KPROBE(do_mov_1024)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x10e")
int BPF_KPROBE(do_mov_1025)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x14a")
int BPF_KPROBE(do_mov_1026)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_offload+0x15c")
int BPF_KPROBE(do_mov_1027)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_secmark_compute_secid+0x5a")
int BPF_KPROBE(do_mov_1028)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_rtclassid.isra.0+0x13")
int BPF_KPROBE(do_mov_1029)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0x60")
int BPF_KPROBE(do_mov_1030)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0x8b")
int BPF_KPROBE(do_mov_1031)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0xd3")
int BPF_KPROBE(do_mov_1032)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval_pkttype_lo.isra.0+0xe9")
int BPF_KPROBE(do_mov_1033)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x53")
int BPF_KPROBE(do_mov_1034)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_meta_get_eval+0x115")
int BPF_KPROBE(do_mov_1035)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x47")
int BPF_KPROBE(do_mov_1036)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x65")
int BPF_KPROBE(do_mov_1037)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x7a")
int BPF_KPROBE(do_mov_1038)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0x95")
int BPF_KPROBE(do_mov_1039)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rt_get_eval+0xc9")
int BPF_KPROBE(do_mov_1040)
{
    u64 addr = ctx->bx + ctx->r12 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0xf1")
int BPF_KPROBE(do_mov_1041)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_init+0xfd")
int BPF_KPROBE(do_mov_1042)
{
    u64 addr = ctx->bx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0xfe")
int BPF_KPROBE(do_mov_1043)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_init+0xf8")
int BPF_KPROBE(do_mov_1044)
{
    u64 addr = ctx->r12 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv6_eval+0xd0")
int BPF_KPROBE(do_mov_1045)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0xd7")
int BPF_KPROBE(do_mov_1046)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0x120")
int BPF_KPROBE(do_mov_1047)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_sctp_eval+0x174")
int BPF_KPROBE(do_mov_1048)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv4_eval+0x3c")
int BPF_KPROBE(do_mov_1049)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_ipv4_eval+0x1ae")
int BPF_KPROBE(do_mov_1050)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_eval+0xc5")
int BPF_KPROBE(do_mov_1051)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_eval+0x149")
int BPF_KPROBE(do_mov_1052)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_set_eval+0x189")
int BPF_KPROBE(do_mov_1053)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x102")
int BPF_KPROBE(do_mov_1054)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x11f")
int BPF_KPROBE(do_mov_1055)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_eval+0x199")
int BPF_KPROBE(do_mov_1056)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x63")
int BPF_KPROBE(do_mov_1057)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x79")
int BPF_KPROBE(do_mov_1058)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x18e")
int BPF_KPROBE(do_mov_1059)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1c4")
int BPF_KPROBE(do_mov_1060)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_exthdr_tcp_strip_eval+0x1ee")
int BPF_KPROBE(do_mov_1061)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_eval+0x23")
int BPF_KPROBE(do_mov_1062)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_last_init+0x7d")
int BPF_KPROBE(do_mov_1063)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_do_init+0x9d")
int BPF_KPROBE(do_mov_1064)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_do_init+0xaa")
int BPF_KPROBE(do_mov_1065)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_fetch+0x1d")
int BPF_KPROBE(do_mov_1066)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_counter_clone+0x64")
int BPF_KPROBE(do_mov_1067)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x63")
int BPF_KPROBE(do_mov_1068)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_cmd+0x77")
int BPF_KPROBE(do_mov_1069)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_offload_unbind+0x11f")
int BPF_KPROBE(do_mov_1070)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_block_offload_cmd+0xef")
int BPF_KPROBE(do_mov_1071)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0xdc")
int BPF_KPROBE(do_mov_1072)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0xf1")
int BPF_KPROBE(do_mov_1073)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_cleanup+0x104")
int BPF_KPROBE(do_mov_1074)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_indr_block_offload_cmd+0x12d")
int BPF_KPROBE(do_mov_1075)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_set_addr_type+0x28")
int BPF_KPROBE(do_mov_1076)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_set_addr_type+0x21")
int BPF_KPROBE(do_mov_1077)
{
    u64 addr = ctx->di + 0xae;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0xcc")
int BPF_KPROBE(do_mov_1078)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x111")
int BPF_KPROBE(do_mov_1079)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0xec")
int BPF_KPROBE(do_mov_1080)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1e6")
int BPF_KPROBE(do_mov_1081)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_flow_rule_create+0x1cf")
int BPF_KPROBE(do_mov_1082)
{
    u64 addr = ctx->bx + 0xe4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_update_dependency+0x20")
int BPF_KPROBE(do_mov_1083)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_offload_update_dependency+0x31")
int BPF_KPROBE(do_mov_1084)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_estimate+0x19")
int BPF_KPROBE(do_mov_1085)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_remove+0x17")
int BPF_KPROBE(do_mov_1086)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_destroy+0x5b")
int BPF_KPROBE(do_mov_1087)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_lookup+0xa4")
int BPF_KPROBE(do_mov_1088)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_fast_estimate+0x73")
int BPF_KPROBE(do_mov_1089)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xc1")
int BPF_KPROBE(do_mov_1090)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xc8")
int BPF_KPROBE(do_mov_1091)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_insert+0xe9")
int BPF_KPROBE(do_mov_1092)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_init+0x91")
int BPF_KPROBE(do_mov_1093)
{
    u64 addr = ctx->r12 + 0x178;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_init+0xb5")
int BPF_KPROBE(do_mov_1094)
{
    u64 addr = ctx->r12 + 0x190;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_walk+0x5f")
int BPF_KPROBE(do_mov_1095)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_walk+0xb6")
int BPF_KPROBE(do_mov_1096)
{
    u64 addr = ctx->r13 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x1f8")
int BPF_KPROBE(do_mov_1097)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x1fb")
int BPF_KPROBE(do_mov_1098)
{
    u64 addr = ctx->cx + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x289")
int BPF_KPROBE(do_mov_1099)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_gc+0x28c")
int BPF_KPROBE(do_mov_1100)
{
    u64 addr = ctx->cx + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_lookup+0x185")
int BPF_KPROBE(do_mov_1101)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_hash_estimate+0x73")
int BPF_KPROBE(do_mov_1102)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_update+0x1fe")
int BPF_KPROBE(do_mov_1103)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rhash_insert+0x97")
int BPF_KPROBE(do_mov_1104)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_remove+0x5c")
int BPF_KPROBE(do_mov_1105)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_init+0x12")
int BPF_KPROBE(do_mov_1106)
{
    u64 addr = ctx->di + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_init+0x41")
int BPF_KPROBE(do_mov_1107)
{
    u64 addr = ctx->di + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_estimate+0x37")
int BPF_KPROBE(do_mov_1108)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0x7c")
int BPF_KPROBE(do_mov_1109)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0x85")
int BPF_KPROBE(do_mov_1110)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_bitmap_insert+0xa3")
int BPF_KPROBE(do_mov_1111)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_estimate+0x35")
int BPF_KPROBE(do_mov_1112)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x3d")
int BPF_KPROBE(do_mov_1113)
{
    u64 addr = ctx->di - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x41")
int BPF_KPROBE(do_mov_1114)
{
    u64 addr = ctx->di - 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x49")
int BPF_KPROBE(do_mov_1115)
{
    u64 addr = ctx->di - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x51")
int BPF_KPROBE(do_mov_1116)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x58")
int BPF_KPROBE(do_mov_1117)
{
    u64 addr = ctx->di - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_init+0x5c")
int BPF_KPROBE(do_mov_1118)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0xef")
int BPF_KPROBE(do_mov_1119)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0xf4")
int BPF_KPROBE(do_mov_1120)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x114")
int BPF_KPROBE(do_mov_1121)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x119")
int BPF_KPROBE(do_mov_1122)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x24f")
int BPF_KPROBE(do_mov_1123)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_gc+0x25e")
int BPF_KPROBE(do_mov_1124)
{
    u64 addr = ctx->r12 + ctx->ax * 0x8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x215")
int BPF_KPROBE(do_mov_1125)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x220")
int BPF_KPROBE(do_mov_1126)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_rbtree_insert+0x455")
int BPF_KPROBE(do_mov_1127)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_lookup+0x16c")
int BPF_KPROBE(do_mov_1128)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_lookup+0x1e9")
int BPF_KPROBE(do_mov_1129)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_get.constprop.0+0x16e")
int BPF_KPROBE(do_mov_1130)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nft_rbtree_get.constprop.0+0x17a")
int BPF_KPROBE(do_mov_1131)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xb8")
int BPF_KPROBE(do_mov_1132)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xbd")
int BPF_KPROBE(do_mov_1133)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_lt_bits_adjust+0xd4")
int BPF_KPROBE(do_mov_1134)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_resize+0x199")
int BPF_KPROBE(do_mov_1135)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_resize+0x1b2")
int BPF_KPROBE(do_mov_1136)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_estimate+0xa1")
int BPF_KPROBE(do_mov_1137)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_estimate+0xc0")
int BPF_KPROBE(do_mov_1138)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x4f")
int BPF_KPROBE(do_mov_1139)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x7b")
int BPF_KPROBE(do_mov_1140)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x56")
int BPF_KPROBE(do_mov_1141)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x106")
int BPF_KPROBE(do_mov_1142)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x10d")
int BPF_KPROBE(do_mov_1143)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_clone+0x1a2")
int BPF_KPROBE(do_mov_1144)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x6e")
int BPF_KPROBE(do_mov_1145)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x72")
int BPF_KPROBE(do_mov_1146)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x14b")
int BPF_KPROBE(do_mov_1147)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x15b")
int BPF_KPROBE(do_mov_1148)
{
    u64 addr = ctx->dx - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x166")
int BPF_KPROBE(do_mov_1149)
{
    u64 addr = ctx->dx - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x16e")
int BPF_KPROBE(do_mov_1150)
{
    u64 addr = ctx->dx - 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x176")
int BPF_KPROBE(do_mov_1151)
{
    u64 addr = ctx->dx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x17e")
int BPF_KPROBE(do_mov_1152)
{
    u64 addr = ctx->dx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x186")
int BPF_KPROBE(do_mov_1153)
{
    u64 addr = ctx->dx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x1b8")
int BPF_KPROBE(do_mov_1154)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_init+0x1b1")
int BPF_KPROBE(do_mov_1155)
{
    u64 addr = ctx->bx + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_commit+0x83")
int BPF_KPROBE(do_mov_1156)
{
    u64 addr = ctx->bx + 0xf0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_commit+0x6e")
int BPF_KPROBE(do_mov_1157)
{
    u64 addr = ctx->bx + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pipapo_refill+0xba")
int BPF_KPROBE(do_mov_1158)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_lookup+0x17a")
int BPF_KPROBE(do_mov_1159)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


// SEC("kprobe/nft_pipapo_lookup+0x1a3")
// int BPF_KPROBE(do_mov_1160)
// {
//     u64 addr = ctx->gs + 0x30798;
//     sampling(addr, ctx->ip);
//     return 0;
// }


// SEC("kprobe/nft_pipapo_lookup+0x2b1")
// int BPF_KPROBE(do_mov_1161)
// {
//     u64 addr = ctx->gs + 0x30798;
//     sampling(addr, ctx->ip);
//     return 0;
// }


SEC("kprobe/nft_pipapo_insert+0x10c")
int BPF_KPROBE(do_mov_1162)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x1fc")
int BPF_KPROBE(do_mov_1163)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_insert+0x57b")
int BPF_KPROBE(do_mov_1164)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_remove+0x2b3")
int BPF_KPROBE(do_mov_1165)
{
    u64 addr = ctx->si - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_fill+0x79")
int BPF_KPROBE(do_mov_1166)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_fill+0x95")
int BPF_KPROBE(do_mov_1167)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0x8f")
int BPF_KPROBE(do_mov_1168)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0xf3")
int BPF_KPROBE(do_mov_1169)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_refill+0x1bf")
int BPF_KPROBE(do_mov_1170)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_estimate+0xd4")
int BPF_KPROBE(do_mov_1171)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_pipapo_avx2_estimate+0x106")
int BPF_KPROBE(do_mov_1172)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


// SEC("kprobe/nft_pipapo_avx2_lookup+0x3ea")
// int BPF_KPROBE(do_mov_1173)
// {
//     u64 addr = ctx->gs + 0x30799;
//     sampling(addr, ctx->ip);
//     return 0;
// }


SEC("kprobe/nft_pipapo_avx2_lookup+0x583")
int BPF_KPROBE(do_mov_1174)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_clone+0x28")
int BPF_KPROBE(do_mov_1175)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_clone+0x47")
int BPF_KPROBE(do_mov_1176)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_do_init+0x61")
int BPF_KPROBE(do_mov_1177)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_do_init+0x75")
int BPF_KPROBE(do_mov_1178)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_connlimit_eval+0x8b")
int BPF_KPROBE(do_mov_1179)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x2d")
int BPF_KPROBE(do_mov_1180)
{
    u64 addr = ctx->dx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_init+0x73")
int BPF_KPROBE(do_mov_1181)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_init+0x147")
int BPF_KPROBE(do_mov_1182)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_set_zone_eval+0xe1")
int BPF_KPROBE(do_mov_1183)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_helper_obj_eval+0x7f")
int BPF_KPROBE(do_mov_1184)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_eval+0x31")
int BPF_KPROBE(do_mov_1185)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_expect_obj_eval+0x127")
int BPF_KPROBE(do_mov_1186)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_eval+0x86")
int BPF_KPROBE(do_mov_1187)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_eval+0xca")
int BPF_KPROBE(do_mov_1188)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_timeout_obj_eval+0xdb")
int BPF_KPROBE(do_mov_1189)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x94")
int BPF_KPROBE(do_mov_1190)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x116")
int BPF_KPROBE(do_mov_1191)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x128")
int BPF_KPROBE(do_mov_1192)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x145")
int BPF_KPROBE(do_mov_1193)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x16d")
int BPF_KPROBE(do_mov_1194)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x17c")
int BPF_KPROBE(do_mov_1195)
{
    u64 addr = ctx->r12 + ctx->r13 * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1bd")
int BPF_KPROBE(do_mov_1196)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x1e1")
int BPF_KPROBE(do_mov_1197)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x288")
int BPF_KPROBE(do_mov_1198)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x31c")
int BPF_KPROBE(do_mov_1199)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x348")
int BPF_KPROBE(do_mov_1200)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x36e")
int BPF_KPROBE(do_mov_1201)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x395")
int BPF_KPROBE(do_mov_1202)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x3da")
int BPF_KPROBE(do_mov_1203)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x455")
int BPF_KPROBE(do_mov_1204)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x4ed")
int BPF_KPROBE(do_mov_1205)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x4f4")
int BPF_KPROBE(do_mov_1206)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x54c")
int BPF_KPROBE(do_mov_1207)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x55c")
int BPF_KPROBE(do_mov_1208)
{
    u64 addr = ctx->r14 + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x5a9")
int BPF_KPROBE(do_mov_1209)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_ct_get_eval+0x5b0")
int BPF_KPROBE(do_mov_1210)
{
    u64 addr = ctx->r14 + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0xe2")
int BPF_KPROBE(do_mov_1211)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0xa9")
int BPF_KPROBE(do_mov_1212)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_init+0x118")
int BPF_KPROBE(do_mov_1213)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_bytes_eval+0x90")
int BPF_KPROBE(do_mov_1214)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x25")
int BPF_KPROBE(do_mov_1215)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x1d")
int BPF_KPROBE(do_mov_1216)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_clone+0x60")
int BPF_KPROBE(do_mov_1217)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x1d")
int BPF_KPROBE(do_mov_1218)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x40")
int BPF_KPROBE(do_mov_1219)
{
    u64 addr = ctx->di + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_clone+0x58")
int BPF_KPROBE(do_mov_1220)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_pkts_eval+0x68")
int BPF_KPROBE(do_mov_1221)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_obj_pkts_eval+0x7d")
int BPF_KPROBE(do_mov_1222)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_limit_bytes_eval+0x78")
int BPF_KPROBE(do_mov_1223)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x195")
int BPF_KPROBE(do_mov_1224)
{
    u64 addr = ctx->r12 + 0x9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_nat_init+0x13c")
int BPF_KPROBE(do_mov_1225)
{
    u64 addr = ctx->r12 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_sreg_eval+0x25")
int BPF_KPROBE(do_mov_1226)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_init+0x2d")
int BPF_KPROBE(do_mov_1227)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_init+0x58")
int BPF_KPROBE(do_mov_1228)
{
    u64 addr = ctx->cx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_queue_eval+0x60")
int BPF_KPROBE(do_mov_1229)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_clone+0x2c")
int BPF_KPROBE(do_mov_1230)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_do_init+0xb3")
int BPF_KPROBE(do_mov_1231)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_do_init+0xa4")
int BPF_KPROBE(do_mov_1232)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_obj_eval+0x3e")
int BPF_KPROBE(do_mov_1233)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_quota_eval+0x33")
int BPF_KPROBE(do_mov_1234)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_reject_netdev_eval+0xa8")
int BPF_KPROBE(do_mov_1235)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_init+0x1d")
int BPF_KPROBE(do_mov_1236)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_init+0x51")
int BPF_KPROBE(do_mov_1237)
{
    u64 addr = ctx->si + 0xb;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0x93")
int BPF_KPROBE(do_mov_1238)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0xbc")
int BPF_KPROBE(do_mov_1239)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_get_eval+0xd8")
int BPF_KPROBE(do_mov_1240)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x1e0")
int BPF_KPROBE(do_mov_1241)
{
    u64 addr = ctx->ax + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x240")
int BPF_KPROBE(do_mov_1242)
{
    u64 addr = ctx->ax + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x28c")
int BPF_KPROBE(do_mov_1243)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x419")
int BPF_KPROBE(do_mov_1244)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x561")
int BPF_KPROBE(do_mov_1245)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x640")
int BPF_KPROBE(do_mov_1246)
{
    u64 addr = ctx->bx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_init+0x579")
int BPF_KPROBE(do_mov_1247)
{
    u64 addr = ctx->bx + 0x194;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x26c")
int BPF_KPROBE(do_mov_1248)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x39f")
int BPF_KPROBE(do_mov_1249)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tunnel_obj_dump+0x494")
int BPF_KPROBE(do_mov_1250)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x81")
int BPF_KPROBE(do_mov_1251)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x45")
int BPF_KPROBE(do_mov_1252)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0x13e")
int BPF_KPROBE(do_mov_1253)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_log_init+0xfd")
int BPF_KPROBE(do_mov_1254)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_masq_ipv4_eval+0x85")
int BPF_KPROBE(do_mov_1255)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_masq_ipv6_eval+0x82")
int BPF_KPROBE(do_mov_1256)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_redir_ipv6_eval+0x8b")
int BPF_KPROBE(do_mov_1257)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_jhash_init+0x8a")
int BPF_KPROBE(do_mov_1258)
{
    u64 addr = ctx->r13 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_jhash_init+0xca")
int BPF_KPROBE(do_mov_1259)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_store_result+0x35")
int BPF_KPROBE(do_mov_1260)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_store_result+0x46")
int BPF_KPROBE(do_mov_1261)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib_netdev_eval+0x66")
int BPF_KPROBE(do_mov_1262)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_init+0x31")
int BPF_KPROBE(do_mov_1263)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_init+0x55")
int BPF_KPROBE(do_mov_1264)
{
    u64 addr = ctx->si + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0xfc")
int BPF_KPROBE(do_mov_1265)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x142")
int BPF_KPROBE(do_mov_1266)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_socket_eval+0x185")
int BPF_KPROBE(do_mov_1267)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_eval+0x37")
int BPF_KPROBE(do_mov_1268)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_osf_eval+0xc3")
int BPF_KPROBE(do_mov_1269)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_tproxy_eval+0x61")
int BPF_KPROBE(do_mov_1270)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_init+0x3e")
int BPF_KPROBE(do_mov_1271)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_init+0x89")
int BPF_KPROBE(do_mov_1272)
{
    u64 addr = ctx->si + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x77")
int BPF_KPROBE(do_mov_1273)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x86")
int BPF_KPROBE(do_mov_1274)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x8e")
int BPF_KPROBE(do_mov_1275)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_state_get_key.isra.0+0x96")
int BPF_KPROBE(do_mov_1276)
{
    u64 addr = ctx->dx + ctx->di * 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_xfrm_get_eval+0x1b")
int BPF_KPROBE(do_mov_1277)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_init+0x82")
int BPF_KPROBE(do_mov_1278)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_init+0x4f")
int BPF_KPROBE(do_mov_1279)
{
    u64 addr = ctx->r15 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x91")
int BPF_KPROBE(do_mov_1280)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x168")
int BPF_KPROBE(do_mov_1281)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x261")
int BPF_KPROBE(do_mov_1282)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_synproxy_do_eval+0x2bf")
int BPF_KPROBE(do_mov_1283)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_netdev_eval+0x63")
int BPF_KPROBE(do_mov_1284)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_netdev_eval+0x2f")
int BPF_KPROBE(do_mov_1285)
{
    u64 addr = ctx->dx + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fwd_neigh_eval+0x4d")
int BPF_KPROBE(do_mov_1286)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x5e")
int BPF_KPROBE(do_mov_1287)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_dir+0x2e")
int BPF_KPROBE(do_mov_1288)
{
    u64 addr = ctx->r9 + 0x3a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_teardown+0x6a")
int BPF_KPROBE(do_mov_1289)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_teardown+0x80")
int BPF_KPROBE(do_mov_1290)
{
    u64 addr = ctx->dx + 0xd4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_dnat_port+0x31")
int BPF_KPROBE(do_mov_1291)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x3d")
int BPF_KPROBE(do_mov_1292)
{
    u64 addr = ctx->di - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x41")
int BPF_KPROBE(do_mov_1293)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0x49")
int BPF_KPROBE(do_mov_1294)
{
    u64 addr = ctx->di - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_init+0xd0")
int BPF_KPROBE(do_mov_1295)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0xe3")
int BPF_KPROBE(do_mov_1296)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x112")
int BPF_KPROBE(do_mov_1297)
{
    u64 addr = ctx->ax + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1a1")
int BPF_KPROBE(do_mov_1298)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_fill_route+0x1b8")
int BPF_KPROBE(do_mov_1299)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_snat_port+0xa5")
int BPF_KPROBE(do_mov_1300)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_free+0x48")
int BPF_KPROBE(do_mov_1301)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_free+0x55")
int BPF_KPROBE(do_mov_1302)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0xe1")
int BPF_KPROBE(do_mov_1303)
{
    u64 addr = ctx->bx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_encap_pop+0xed")
int BPF_KPROBE(do_mov_1304)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_xmit_xfrm+0x2b")
int BPF_KPROBE(do_mov_1305)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_xmit_xfrm+0x60")
int BPF_KPROBE(do_mov_1306)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x4fd")
int BPF_KPROBE(do_mov_1307)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x549")
int BPF_KPROBE(do_mov_1308)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x5e7")
int BPF_KPROBE(do_mov_1309)
{
    u64 addr = ctx->ax + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x686")
int BPF_KPROBE(do_mov_1310)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x71a")
int BPF_KPROBE(do_mov_1311)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ip_hook+0x74a")
int BPF_KPROBE(do_mov_1312)
{
    u64 addr = ctx->r12 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x4a7")
int BPF_KPROBE(do_mov_1313)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x50c")
int BPF_KPROBE(do_mov_1314)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x575")
int BPF_KPROBE(do_mov_1315)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x633")
int BPF_KPROBE(do_mov_1316)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6c3")
int BPF_KPROBE(do_mov_1317)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_ipv6_hook+0x6cc")
int BPF_KPROBE(do_mov_1318)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_redirect+0x48")
int BPF_KPROBE(do_mov_1319)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_redirect+0x68")
int BPF_KPROBE(do_mov_1320)
{
    u64 addr = ctx->dx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0x5")
int BPF_KPROBE(do_mov_1321)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/flow_offload_mangle+0x1d")
int BPF_KPROBE(do_mov_1322)
{
    u64 addr = ctx->di + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x110")
int BPF_KPROBE(do_mov_1323)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_tuple+0x135")
int BPF_KPROBE(do_mov_1324)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x47")
int BPF_KPROBE(do_mov_1325)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_work_alloc+0x69")
int BPF_KPROBE(do_mov_1326)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x40")
int BPF_KPROBE(do_mov_1327)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x6e")
int BPF_KPROBE(do_mov_1328)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_indr_cleanup+0x71")
int BPF_KPROBE(do_mov_1329)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x61")
int BPF_KPROBE(do_mov_1330)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x208")
int BPF_KPROBE(do_mov_1331)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x2d8")
int BPF_KPROBE(do_mov_1332)
{
    u64 addr = ctx->r12 + 0x130;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x529")
int BPF_KPROBE(do_mov_1333)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_offload_rule_alloc+0x517")
int BPF_KPROBE(do_mov_1334)
{
    u64 addr = ctx->r12 + 0x136;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x3be")
int BPF_KPROBE(do_mov_1335)
{
    u64 addr = ctx->r9 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x3d7")
int BPF_KPROBE(do_mov_1336)
{
    u64 addr = ctx->r9 + 0x42;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x54c")
int BPF_KPROBE(do_mov_1337)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_common+0x59f")
int BPF_KPROBE(do_mov_1338)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0x81")
int BPF_KPROBE(do_mov_1339)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_rule_route_ipv4+0xb6")
int BPF_KPROBE(do_mov_1340)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x176")
int BPF_KPROBE(do_mov_1341)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_flow_table_offload_setup+0x299")
int BPF_KPROBE(do_mov_1342)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_target+0x46")
int BPF_KPROBE(do_mov_1343)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_target+0x48")
int BPF_KPROBE(do_mov_1344)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_target+0x55")
int BPF_KPROBE(do_mov_1345)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_match+0x46")
int BPF_KPROBE(do_mov_1346)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_match+0x48")
int BPF_KPROBE(do_mov_1347)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_match+0x55")
int BPF_KPROBE(do_mov_1348)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/target_revfn+0x85")
int BPF_KPROBE(do_mov_1349)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/match_revfn+0x85")
int BPF_KPROBE(do_mov_1350)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_find_revision+0x48")
int BPF_KPROBE(do_mov_1351)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_find_revision+0x64")
int BPF_KPROBE(do_mov_1352)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_find_revision+0x7e")
int BPF_KPROBE(do_mov_1353)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0x63")
int BPF_KPROBE(do_mov_1354)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_from_user+0x82")
int BPF_KPROBE(do_mov_1355)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0x63")
int BPF_KPROBE(do_mov_1356)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_from_user+0x82")
int BPF_KPROBE(do_mov_1357)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_net_init+0x35")
int BPF_KPROBE(do_mov_1358)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_table+0x41")
int BPF_KPROBE(do_mov_1359)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_table+0x4e")
int BPF_KPROBE(do_mov_1360)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_template+0xa4")
int BPF_KPROBE(do_mov_1361)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_template+0xb1")
int BPF_KPROBE(do_mov_1362)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x29")
int BPF_KPROBE(do_mov_1363)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x32")
int BPF_KPROBE(do_mov_1364)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_percpu_counter_alloc+0x4d")
int BPF_KPROBE(do_mov_1365)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/textify_hooks.constprop.0+0x45")
int BPF_KPROBE(do_mov_1366)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x89")
int BPF_KPROBE(do_mov_1367)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_mttg_seq_next.constprop.0.isra.0+0x62")
int BPF_KPROBE(do_mov_1368)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_match_to_user+0xbc")
int BPF_KPROBE(do_mov_1369)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_compat_target_to_user+0xbc")
int BPF_KPROBE(do_mov_1370)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x150")
int BPF_KPROBE(do_mov_1371)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_template+0x153")
int BPF_KPROBE(do_mov_1372)
{
    u64 addr = ctx->bx - 0x7c6ee740;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x76")
int BPF_KPROBE(do_mov_1373)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x79")
int BPF_KPROBE(do_mov_1374)
{
    u64 addr = ctx->dx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_hook_ops_alloc+0x88")
int BPF_KPROBE(do_mov_1375)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_matches+0x87")
int BPF_KPROBE(do_mov_1376)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_matches+0x5c")
int BPF_KPROBE(do_mov_1377)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_unregister_targets+0x87")
int BPF_KPROBE(do_mov_1378)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_targets+0x5c")
int BPF_KPROBE(do_mov_1379)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x96")
int BPF_KPROBE(do_mov_1380)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x1bd")
int BPF_KPROBE(do_mov_1381)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_replace_table+0x1df")
int BPF_KPROBE(do_mov_1382)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x17c")
int BPF_KPROBE(do_mov_1383)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_register_table+0x180")
int BPF_KPROBE(do_mov_1384)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xc8")
int BPF_KPROBE(do_mov_1385)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0x110")
int BPF_KPROBE(do_mov_1386)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_copy_counters+0xf9")
int BPF_KPROBE(do_mov_1387)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_target_v3+0x1ce")
int BPF_KPROBE(do_mov_1388)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_target_v3+0x192")
int BPF_KPROBE(do_mov_1389)
{
    u64 addr = ctx->r13 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_destroy+0x39")
int BPF_KPROBE(do_mov_1390)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_destroy+0x46")
int BPF_KPROBE(do_mov_1391)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0xfa")
int BPF_KPROBE(do_mov_1392)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/led_tg_check+0xca")
int BPF_KPROBE(do_mov_1393)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_put+0x46")
int BPF_KPROBE(do_mov_1394)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x189")
int BPF_KPROBE(do_mov_1395)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1a2")
int BPF_KPROBE(do_mov_1396)
{
    u64 addr = ctx->r12 + 0x39;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xt_rateest_tg_checkentry+0x1f3")
int BPF_KPROBE(do_mov_1397)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/secmark_tg_check_v0+0x65")
int BPF_KPROBE(do_mov_1398)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x13a")
int BPF_KPROBE(do_mov_1399)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x142")
int BPF_KPROBE(do_mov_1400)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x293")
int BPF_KPROBE(do_mov_1401)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcpmss_mangle_packet+0x268")
int BPF_KPROBE(do_mov_1402)
{
    u64 addr = ctx->bx + 0x16;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy_v1+0x4e")
int BPF_KPROBE(do_mov_1403)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy_v1+0x5b")
int BPF_KPROBE(do_mov_1404)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy+0x4e")
int BPF_KPROBE(do_mov_1405)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_destroy+0x5b")
int BPF_KPROBE(do_mov_1406)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x8e")
int BPF_KPROBE(do_mov_1407)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x8e")
int BPF_KPROBE(do_mov_1408)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x244")
int BPF_KPROBE(do_mov_1409)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x247")
int BPF_KPROBE(do_mov_1410)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry_v1+0x270")
int BPF_KPROBE(do_mov_1411)
{
    u64 addr = ctx->ax + 0xfc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x73")
int BPF_KPROBE(do_mov_1412)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x73")
int BPF_KPROBE(do_mov_1413)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1c3")
int BPF_KPROBE(do_mov_1414)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1c8")
int BPF_KPROBE(do_mov_1415)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/idletimer_tg_checkentry+0x1f5")
int BPF_KPROBE(do_mov_1416)
{
    u64 addr = ctx->ax + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xbc")
int BPF_KPROBE(do_mov_1417)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/bpf_mt_v1+0xcb")
int BPF_KPROBE(do_mov_1418)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x47")
int BPF_KPROBE(do_mov_1419)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x51")
int BPF_KPROBE(do_mov_1420)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_compat_from_user+0x69")
int BPF_KPROBE(do_mov_1421)
{
    u64 addr = ctx->di + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/limit_mt_check+0x8d")
int BPF_KPROBE(do_mov_1422)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v2+0x3f")
int BPF_KPROBE(do_mov_1423)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v2+0x3f")
int BPF_KPROBE(do_mov_1424)
{
    u64 addr = ctx->bx + 0x208;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v1+0x3f")
int BPF_KPROBE(do_mov_1425)
{
    u64 addr = ctx->bx + 0x1008;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cgroup_mt_check_v1+0x3f")
int BPF_KPROBE(do_mov_1426)
{
    u64 addr = ctx->bx + 0x1008;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/quota_mt_check+0x35")
int BPF_KPROBE(do_mov_1427)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_seq_open+0x2d")
int BPF_KPROBE(do_mov_1428)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_net_init+0x2b")
int BPF_KPROBE(do_mov_1429)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x67")
int BPF_KPROBE(do_mov_1430)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x72")
int BPF_KPROBE(do_mov_1431)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_table_flush+0x7d")
int BPF_KPROBE(do_mov_1432)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x2bc")
int BPF_KPROBE(do_mov_1433)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x2dc")
int BPF_KPROBE(do_mov_1434)
{
    u64 addr = ctx->r15 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x39c")
int BPF_KPROBE(do_mov_1435)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x3a3")
int BPF_KPROBE(do_mov_1436)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_check.isra.0+0x40d")
int BPF_KPROBE(do_mov_1437)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_destroy+0xb5")
int BPF_KPROBE(do_mov_1438)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_destroy+0xc2")
int BPF_KPROBE(do_mov_1439)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x92")
int BPF_KPROBE(do_mov_1440)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x74")
int BPF_KPROBE(do_mov_1441)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x119")
int BPF_KPROBE(do_mov_1442)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x120")
int BPF_KPROBE(do_mov_1443)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x224")
int BPF_KPROBE(do_mov_1444)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x239")
int BPF_KPROBE(do_mov_1445)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x258")
int BPF_KPROBE(do_mov_1446)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x277")
int BPF_KPROBE(do_mov_1447)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_entry_init+0x282")
int BPF_KPROBE(do_mov_1448)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x18c")
int BPF_KPROBE(do_mov_1449)
{
    u64 addr = ctx->di + 0x33;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x192")
int BPF_KPROBE(do_mov_1450)
{
    u64 addr = ctx->di + ctx->ax * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x19d")
int BPF_KPROBE(do_mov_1451)
{
    u64 addr = ctx->di + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1b8")
int BPF_KPROBE(do_mov_1452)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x1e3")
int BPF_KPROBE(do_mov_1453)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x22c")
int BPF_KPROBE(do_mov_1454)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x24b")
int BPF_KPROBE(do_mov_1455)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt_proc_write+0x256")
int BPF_KPROBE(do_mov_1456)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x1c1")
int BPF_KPROBE(do_mov_1457)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x2ec")
int BPF_KPROBE(do_mov_1458)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x30a")
int BPF_KPROBE(do_mov_1459)
{
    u64 addr = ctx->ax - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x30e")
int BPF_KPROBE(do_mov_1460)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x316")
int BPF_KPROBE(do_mov_1461)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x319")
int BPF_KPROBE(do_mov_1462)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x33f")
int BPF_KPROBE(do_mov_1463)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x362")
int BPF_KPROBE(do_mov_1464)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/recent_mt+0x369")
int BPF_KPROBE(do_mov_1465)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/statistic_mt_check+0x44")
int BPF_KPROBE(do_mov_1466)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_set_and_id+0x1b")
int BPF_KPROBE(do_mov_1467)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/find_set_and_id+0x76")
int BPF_KPROBE(do_mov_1468)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_register+0x5e")
int BPF_KPROBE(do_mov_1469)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type_unregister+0x4e")
int BPF_KPROBE(do_mov_1470)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_init_comment+0x8a")
int BPF_KPROBE(do_mov_1471)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_init_comment+0xc9")
int BPF_KPROBE(do_mov_1472)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_comment_free+0x43")
int BPF_KPROBE(do_mov_1473)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_elem_len+0x6a")
int BPF_KPROBE(do_mov_1474)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0x181")
int BPF_KPROBE(do_mov_1475)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_extensions+0xd7")
int BPF_KPROBE(do_mov_1476)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0x44")
int BPF_KPROBE(do_mov_1477)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0x93")
int BPF_KPROBE(do_mov_1478)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_minmax+0xa3")
int BPF_KPROBE(do_mov_1479)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_set_type_get+0x53")
int BPF_KPROBE(do_mov_1480)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_match_extensions+0x49")
int BPF_KPROBE(do_mov_1481)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ipaddr4+0x65")
int BPF_KPROBE(do_mov_1482)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x73")
int BPF_KPROBE(do_mov_1483)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_init+0x6f")
int BPF_KPROBE(do_mov_1484)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_net_exit+0x59")
int BPF_KPROBE(do_mov_1485)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_byname+0xbd")
int BPF_KPROBE(do_mov_1486)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ipaddr6+0x6c")
int BPF_KPROBE(do_mov_1487)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_start+0xdb")
int BPF_KPROBE(do_mov_1488)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_start+0xc2")
int BPF_KPROBE(do_mov_1489)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_destroy+0x162")
int BPF_KPROBE(do_mov_1490)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_protocol+0x102")
int BPF_KPROBE(do_mov_1491)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_byname+0x1b9")
int BPF_KPROBE(do_mov_1492)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x219")
int BPF_KPROBE(do_mov_1493)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_sockfn_get+0x27f")
int BPF_KPROBE(do_mov_1494)
{
    u64 addr = ctx->r13 + 0x2b;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_create+0x43b")
int BPF_KPROBE(do_mov_1495)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_byindex+0x19e")
int BPF_KPROBE(do_mov_1496)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_header+0x203")
int BPF_KPROBE(do_mov_1497)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_type+0x1dc")
int BPF_KPROBE(do_mov_1498)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x1f6")
int BPF_KPROBE(do_mov_1499)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x2de")
int BPF_KPROBE(do_mov_1500)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x2b6")
int BPF_KPROBE(do_mov_1501)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x435")
int BPF_KPROBE(do_mov_1502)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_dump_do+0x435")
int BPF_KPROBE(do_mov_1503)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0x6c")
int BPF_KPROBE(do_mov_1504)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_port+0xc7")
int BPF_KPROBE(do_mov_1505)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_get_ip4_port+0x5f")
int BPF_KPROBE(do_mov_1506)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_range_to_cidr+0x4e")
int BPF_KPROBE(do_mov_1507)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip_set_range_to_cidr+0x55")
int BPF_KPROBE(do_mov_1508)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x166")
int BPF_KPROBE(do_mov_1509)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_resolve_clash+0x18f")
int BPF_KPROBE(do_mov_1510)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x4c")
int BPF_KPROBE(do_mov_1511)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/get_bits+0x55")
int BPF_KPROBE(do_mov_1512)
{
    u64 addr = ctx->bx + 0xa094;
    sampling(addr, ctx->ip);
    return 0;
}


