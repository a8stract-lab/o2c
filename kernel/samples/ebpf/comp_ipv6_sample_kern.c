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



SEC("kprobe/copy_group_source_from_sockptr+0x80")
int BPF_KPROBE(do_mov_0)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0xbd")
int BPF_KPROBE(do_mov_1)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0xc4")
int BPF_KPROBE(do_mov_2)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0xcd")
int BPF_KPROBE(do_mov_3)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0x266")
int BPF_KPROBE(do_mov_4)
{
    u64 addr = ctx->r12 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x11e")
int BPF_KPROBE(do_mov_5)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x125")
int BPF_KPROBE(do_mov_6)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x135")
int BPF_KPROBE(do_mov_7)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x143")
int BPF_KPROBE(do_mov_8)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x36")
int BPF_KPROBE(do_mov_9)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x39")
int BPF_KPROBE(do_mov_10)
{
    u64 addr = ctx->ax + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x45")
int BPF_KPROBE(do_mov_11)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x69")
int BPF_KPROBE(do_mov_12)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grec+0x22e")
int BPF_KPROBE(do_mov_13)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grec+0x3b1")
int BPF_KPROBE(do_mov_14)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grec+0x4af")
int BPF_KPROBE(do_mov_15)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/reg_vif_setup+0x2b")
int BPF_KPROBE(do_mov_16)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/reg_vif_setup+0x40")
int BPF_KPROBE(do_mov_17)
{
    u64 addr = ctx->di + 0x524;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start+0x37")
int BPF_KPROBE(do_mov_18)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start+0x48")
int BPF_KPROBE(do_mov_19)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipmr_expire_process+0x80")
int BPF_KPROBE(do_mov_20)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mroute_clean_tables+0x161")
int BPF_KPROBE(do_mov_21)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mroute_clean_tables+0x344")
int BPF_KPROBE(do_mov_22)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_getname+0x4a")
int BPF_KPROBE(do_mov_23)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_getname+0x8b")
int BPF_KPROBE(do_mov_24)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_getname+0x4d")
int BPF_KPROBE(do_mov_25)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_register_protosw+0x6e")
int BPF_KPROBE(do_mov_26)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_register_protosw+0x71")
int BPF_KPROBE(do_mov_27)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_create+0x155")
int BPF_KPROBE(do_mov_28)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_create+0x124")
int BPF_KPROBE(do_mov_29)
{
    u64 addr = ctx->r8 + 0x328;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_create+0x196")
int BPF_KPROBE(do_mov_30)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_create+0x1a7")
int BPF_KPROBE(do_mov_31)
{
    u64 addr = ctx->ax + 0x4e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_create+0x3bb")
int BPF_KPROBE(do_mov_32)
{
    u64 addr = ctx->r8 + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_create+0x20c")
int BPF_KPROBE(do_mov_33)
{
    u64 addr = ctx->r8 + 0x338;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header+0x1a4")
int BPF_KPROBE(do_mov_34)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header+0x195")
int BPF_KPROBE(do_mov_35)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_net_init+0x1f")
int BPF_KPROBE(do_mov_36)
{
    u64 addr = ctx->di + 0x6cd;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_net_init+0x37")
int BPF_KPROBE(do_mov_37)
{
    u64 addr = ctx->di + 0x6d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_net_init+0x9d")
int BPF_KPROBE(do_mov_38)
{
    u64 addr = ctx->di + 0x6ce;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_net_init+0xb2")
int BPF_KPROBE(do_mov_39)
{
    u64 addr = ctx->di + 0x8a4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_net_init+0x115")
int BPF_KPROBE(do_mov_40)
{
    u64 addr = ctx->bx + 0x180;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_net_init+0x180")
int BPF_KPROBE(do_mov_41)
{
    u64 addr = ctx->bx + 0x1e8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_unregister_protosw+0x35")
int BPF_KPROBE(do_mov_42)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_bind+0x17e")
int BPF_KPROBE(do_mov_43)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_bind+0x193")
int BPF_KPROBE(do_mov_44)
{
    u64 addr = ctx->r12 + 0x320;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_bind+0x4ee")
int BPF_KPROBE(do_mov_45)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_bind+0x4f7")
int BPF_KPROBE(do_mov_46)
{
    u64 addr = ctx->r12 + 0x310;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0+0x20")
int BPF_KPROBE(do_mov_47)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0+0x30")
int BPF_KPROBE(do_mov_48)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ac6_seq_start+0x49")
int BPF_KPROBE(do_mov_49)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ac6_seq_start+0x2b")
int BPF_KPROBE(do_mov_50)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc+0x102")
int BPF_KPROBE(do_mov_51)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc+0x13e")
int BPF_KPROBE(do_mov_52)
{
    u64 addr = ctx->r8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join+0xf3")
int BPF_KPROBE(do_mov_53)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join+0xf6")
int BPF_KPROBE(do_mov_54)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join+0x1de")
int BPF_KPROBE(do_mov_55)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec+0xc0")
int BPF_KPROBE(do_mov_56)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_ac_destroy_dev+0x49")
int BPF_KPROBE(do_mov_57)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_frag_init+0x10")
int BPF_KPROBE(do_mov_58)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_frag_init+0x17")
int BPF_KPROBE(do_mov_59)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_frag_init+0x1a")
int BPF_KPROBE(do_mov_60)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_cork_release+0x4c")
int BPF_KPROBE(do_mov_61)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames+0x42")
int BPF_KPROBE(do_mov_62)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames+0x4d")
int BPF_KPROBE(do_mov_63)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x12f")
int BPF_KPROBE(do_mov_64)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xac")
int BPF_KPROBE(do_mov_65)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xde")
int BPF_KPROBE(do_mov_66)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x201")
int BPF_KPROBE(do_mov_67)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x229")
int BPF_KPROBE(do_mov_68)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x2b")
int BPF_KPROBE(do_mov_69)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x4a")
int BPF_KPROBE(do_mov_70)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x86")
int BPF_KPROBE(do_mov_71)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x96")
int BPF_KPROBE(do_mov_72)
{
    u64 addr = ctx->r14 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xb5")
int BPF_KPROBE(do_mov_73)
{
    u64 addr = ctx->bx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xc3")
int BPF_KPROBE(do_mov_74)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xf6")
int BPF_KPROBE(do_mov_75)
{
    u64 addr = ctx->r15 - 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xfb")
int BPF_KPROBE(do_mov_76)
{
    u64 addr = ctx->r15 - 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x100")
int BPF_KPROBE(do_mov_77)
{
    u64 addr = ctx->r15 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_xmit+0x1be")
int BPF_KPROBE(do_mov_78)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_xmit+0x1eb")
int BPF_KPROBE(do_mov_79)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_xmit+0x518")
int BPF_KPROBE(do_mov_80)
{
    u64 addr = ctx->r12 + 0x81;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_xmit+0x200")
int BPF_KPROBE(do_mov_81)
{
    u64 addr = ctx->r12 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_xmit+0x556")
int BPF_KPROBE(do_mov_82)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x269")
int BPF_KPROBE(do_mov_83)
{
    u64 addr = ctx->cx - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x26d")
int BPF_KPROBE(do_mov_84)
{
    u64 addr = ctx->cx - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0xb5")
int BPF_KPROBE(do_mov_85)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0xc1")
int BPF_KPROBE(do_mov_86)
{
    u64 addr = ctx->r10 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x14b")
int BPF_KPROBE(do_mov_87)
{
    u64 addr = ctx->r10 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x23f")
int BPF_KPROBE(do_mov_88)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x255")
int BPF_KPROBE(do_mov_89)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x37b")
int BPF_KPROBE(do_mov_90)
{
    u64 addr = ctx->r10 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x367")
int BPF_KPROBE(do_mov_91)
{
    u64 addr = ctx->r10 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x2a")
int BPF_KPROBE(do_mov_92)
{
    u64 addr = ctx->di + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x43")
int BPF_KPROBE(do_mov_93)
{
    u64 addr = ctx->di + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0xaa")
int BPF_KPROBE(do_mov_94)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x1ef")
int BPF_KPROBE(do_mov_95)
{
    u64 addr = ctx->bx + 0xe0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0x46")
int BPF_KPROBE(do_mov_96)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0x59")
int BPF_KPROBE(do_mov_97)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0x9d")
int BPF_KPROBE(do_mov_98)
{
    u64 addr = ctx->r13 - 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xa2")
int BPF_KPROBE(do_mov_99)
{
    u64 addr = ctx->r13 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xae")
int BPF_KPROBE(do_mov_100)
{
    u64 addr = ctx->r13 - 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xbd")
int BPF_KPROBE(do_mov_101)
{
    u64 addr = ctx->r13 - 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xcb")
int BPF_KPROBE(do_mov_102)
{
    u64 addr = ctx->r13 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x14a")
int BPF_KPROBE(do_mov_103)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x248")
int BPF_KPROBE(do_mov_104)
{
    u64 addr = ctx->si + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x3dd")
int BPF_KPROBE(do_mov_105)
{
    u64 addr = ctx->si + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xc87")
int BPF_KPROBE(do_mov_106)
{
    u64 addr = ctx->r9 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xceb")
int BPF_KPROBE(do_mov_107)
{
    u64 addr = ctx->r9 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xe63")
int BPF_KPROBE(do_mov_108)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xf2c")
int BPF_KPROBE(do_mov_109)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xf31")
int BPF_KPROBE(do_mov_110)
{
    u64 addr = ctx->r12 + 0xbc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_append_data+0x120")
int BPF_KPROBE(do_mov_111)
{
    u64 addr = ctx->di + 0x378;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_append_data+0x199")
int BPF_KPROBE(do_mov_112)
{
    u64 addr = ctx->di + 0x3d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fragment+0x75f")
int BPF_KPROBE(do_mov_113)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fragment+0x6b4")
int BPF_KPROBE(do_mov_114)
{
    u64 addr = ctx->r15 + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x95")
int BPF_KPROBE(do_mov_115)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0xaa")
int BPF_KPROBE(do_mov_116)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x10f")
int BPF_KPROBE(do_mov_117)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x122")
int BPF_KPROBE(do_mov_118)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x151")
int BPF_KPROBE(do_mov_119)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x220")
int BPF_KPROBE(do_mov_120)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x2a4")
int BPF_KPROBE(do_mov_121)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x30d")
int BPF_KPROBE(do_mov_122)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x342")
int BPF_KPROBE(do_mov_123)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x364")
int BPF_KPROBE(do_mov_124)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x358")
int BPF_KPROBE(do_mov_125)
{
    u64 addr = ctx->r12 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x383")
int BPF_KPROBE(do_mov_126)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x41d")
int BPF_KPROBE(do_mov_127)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv_finish+0x22")
int BPF_KPROBE(do_mov_128)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv_finish+0x29")
int BPF_KPROBE(do_mov_129)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv+0x192")
int BPF_KPROBE(do_mov_130)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv+0x108")
int BPF_KPROBE(do_mov_131)
{
    u64 addr = ctx->r14 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv+0x1b4")
int BPF_KPROBE(do_mov_132)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv+0x1bb")
int BPF_KPROBE(do_mov_133)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rcv_core+0x2e2")
int BPF_KPROBE(do_mov_134)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rcv_core+0x271")
int BPF_KPROBE(do_mov_135)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_list_rcv+0x8f")
int BPF_KPROBE(do_mov_136)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_list_rcv+0x92")
int BPF_KPROBE(do_mov_137)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu+0xe5")
int BPF_KPROBE(do_mov_138)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu+0x30f")
int BPF_KPROBE(do_mov_139)
{
    u64 addr = ctx->r15 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid+0x9d")
int BPF_KPROBE(do_mov_140)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid+0xa4")
int BPF_KPROBE(do_mov_141)
{
    u64 addr = ctx->cx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64+0x58")
int BPF_KPROBE(do_mov_142)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64+0x8f")
int BPF_KPROBE(do_mov_143)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64+0x95")
int BPF_KPROBE(do_mov_144)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64+0xab")
int BPF_KPROBE(do_mov_145)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64+0xf4")
int BPF_KPROBE(do_mov_146)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64+0xca")
int BPF_KPROBE(do_mov_147)
{
    u64 addr = ctx->di + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_leave_anycast+0x72")
int BPF_KPROBE(do_mov_148)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_leave_anycast+0x85")
int BPF_KPROBE(do_mov_149)
{
    u64 addr = ctx->r8 + ctx->si * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_leave_anycast+0x98")
int BPF_KPROBE(do_mov_150)
{
    u64 addr = ctx->r8 + ctx->si * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_saddr_eval+0x104")
int BPF_KPROBE(do_mov_151)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_saddr_eval+0x8c")
int BPF_KPROBE(do_mov_152)
{
    u64 addr = ctx->r12 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr+0x86")
int BPF_KPROBE(do_mov_153)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr+0x91")
int BPF_KPROBE(do_mov_154)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr+0xc9")
int BPF_KPROBE(do_mov_155)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs+0x119")
int BPF_KPROBE(do_mov_156)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs+0x3dd")
int BPF_KPROBE(do_mov_157)
{
    u64 addr = ctx->r12 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/if6_seq_next+0x3b")
int BPF_KPROBE(do_mov_158)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/if6_seq_next+0x2e")
int BPF_KPROBE(do_mov_159)
{
    u64 addr = ctx->cx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/if6_seq_start+0x25")
int BPF_KPROBE(do_mov_160)
{
    u64 addr = ctx->dx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/if6_seq_start+0x84")
int BPF_KPROBE(do_mov_161)
{
    u64 addr = ctx->dx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address+0x1d5")
int BPF_KPROBE(do_mov_162)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address+0x26c")
int BPF_KPROBE(do_mov_163)
{
    u64 addr = ctx->ax - 0x7c6e8b4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address+0x27c")
int BPF_KPROBE(do_mov_164)
{
    u64 addr = ctx->ax - 0x7c6e8b4a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/check_cleanup_prefix_route+0x20")
int BPF_KPROBE(do_mov_165)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/check_cleanup_prefix_route+0xcd")
int BPF_KPROBE(do_mov_166)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/modify_prefix_route+0x77")
int BPF_KPROBE(do_mov_167)
{
    u64 addr = ctx->si + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/modify_prefix_route+0x7b")
int BPF_KPROBE(do_mov_168)
{
    u64 addr = ctx->si + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0xc9")
int BPF_KPROBE(do_mov_169)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x130")
int BPF_KPROBE(do_mov_170)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x14f")
int BPF_KPROBE(do_mov_171)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x171")
int BPF_KPROBE(do_mov_172)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x1aa")
int BPF_KPROBE(do_mov_173)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_valid_dump_ifaddr_req.constprop.0+0x1de")
int BPF_KPROBE(do_mov_174)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo+0x74")
int BPF_KPROBE(do_mov_175)
{
    u64 addr = ctx->r13 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo+0x94")
int BPF_KPROBE(do_mov_176)
{
    u64 addr = ctx->r13 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo+0x1bf")
int BPF_KPROBE(do_mov_177)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo+0x17b")
int BPF_KPROBE(do_mov_178)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo+0x19e")
int BPF_KPROBE(do_mov_179)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr+0x279")
int BPF_KPROBE(do_mov_180)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr+0xba")
int BPF_KPROBE(do_mov_181)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret+0x182")
int BPF_KPROBE(do_mov_182)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf+0x103")
int BPF_KPROBE(do_mov_183)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf+0x11a")
int BPF_KPROBE(do_mov_184)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf+0x1e3")
int BPF_KPROBE(do_mov_185)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf+0x247")
int BPF_KPROBE(do_mov_186)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy+0x95")
int BPF_KPROBE(do_mov_187)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy+0xc4")
int BPF_KPROBE(do_mov_188)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/in6_dump_addrs+0x211")
int BPF_KPROBE(do_mov_189)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/in6_dump_addrs+0x16a")
int BPF_KPROBE(do_mov_190)
{
    u64 addr = ctx->r12 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/in6_dump_addrs+0x28b")
int BPF_KPROBE(do_mov_191)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/in6_dump_addrs+0x2f5")
int BPF_KPROBE(do_mov_192)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/in6_dump_addrs+0x478")
int BPF_KPROBE(do_mov_193)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/in6_dump_addrs+0x3d6")
int BPF_KPROBE(do_mov_194)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_addr+0xd5")
int BPF_KPROBE(do_mov_195)
{
    u64 addr = ctx->r13 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_addr+0x1c8")
int BPF_KPROBE(do_mov_196)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf+0x2fd")
int BPF_KPROBE(do_mov_197)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf+0x3ab")
int BPF_KPROBE(do_mov_198)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_add_addr+0x137")
int BPF_KPROBE(do_mov_199)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_add_addr+0x13f")
int BPF_KPROBE(do_mov_200)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_add_addr+0x150")
int BPF_KPROBE(do_mov_201)
{
    u64 addr = ctx->r12 + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register+0x88")
int BPF_KPROBE(do_mov_202)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register+0x99")
int BPF_KPROBE(do_mov_203)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_add_dev+0x66")
int BPF_KPROBE(do_mov_204)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_add_dev+0x1de")
int BPF_KPROBE(do_mov_205)
{
    u64 addr = ctx->r12 + 0x270;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_add_dev+0xdd")
int BPF_KPROBE(do_mov_206)
{
    u64 addr = ctx->r12 + 0x408;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x45")
int BPF_KPROBE(do_mov_207)
{
    u64 addr = ctx->di - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x49")
int BPF_KPROBE(do_mov_208)
{
    u64 addr = ctx->di - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x50")
int BPF_KPROBE(do_mov_209)
{
    u64 addr = ctx->di - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x54")
int BPF_KPROBE(do_mov_210)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x11d")
int BPF_KPROBE(do_mov_211)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x13c")
int BPF_KPROBE(do_mov_212)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x162")
int BPF_KPROBE(do_mov_213)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x17f")
int BPF_KPROBE(do_mov_214)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x19f")
int BPF_KPROBE(do_mov_215)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_init_net+0x190")
int BPF_KPROBE(do_mov_216)
{
    u64 addr = ctx->r14 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown+0xce")
int BPF_KPROBE(do_mov_217)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown+0xfb")
int BPF_KPROBE(do_mov_218)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_forward_change+0x13b")
int BPF_KPROBE(do_mov_219)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_forward_change+0x1b0")
int BPF_KPROBE(do_mov_220)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/dev_forward_change+0x1b3")
int BPF_KPROBE(do_mov_221)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward+0xcd")
int BPF_KPROBE(do_mov_222)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward+0x12d")
int BPF_KPROBE(do_mov_223)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward+0x138")
int BPF_KPROBE(do_mov_224)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_exit_net+0xcb")
int BPF_KPROBE(do_mov_225)
{
    u64 addr = ctx->bx + 0x738;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_exit_net+0x10f")
int BPF_KPROBE(do_mov_226)
{
    u64 addr = ctx->bx + 0x820;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x159")
int BPF_KPROBE(do_mov_227)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x251")
int BPF_KPROBE(do_mov_228)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x258")
int BPF_KPROBE(do_mov_229)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x3ad")
int BPF_KPROBE(do_mov_230)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x3f1")
int BPF_KPROBE(do_mov_231)
{
    u64 addr = ctx->r13 - 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x441")
int BPF_KPROBE(do_mov_232)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x44e")
int BPF_KPROBE(do_mov_233)
{
    u64 addr = ctx->r13 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x550")
int BPF_KPROBE(do_mov_234)
{
    u64 addr = ctx->r13 - 0xac;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0+0x55b")
int BPF_KPROBE(do_mov_235)
{
    u64 addr = ctx->r13 - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_del_addr+0x97")
int BPF_KPROBE(do_mov_236)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_del_addr+0xff")
int BPF_KPROBE(do_mov_237)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_del_addr+0x1d3")
int BPF_KPROBE(do_mov_238)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_del_addr+0x1e8")
int BPF_KPROBE(do_mov_239)
{
    u64 addr = ctx->r12 + 0xe8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_del_addr+0x220")
int BPF_KPROBE(do_mov_240)
{
    u64 addr = ctx->r12 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode+0xd2")
int BPF_KPROBE(do_mov_241)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode+0x114")
int BPF_KPROBE(do_mov_242)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0+0x2bd")
int BPF_KPROBE(do_mov_243)
{
    u64 addr = ctx->r14 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0+0x2b1")
int BPF_KPROBE(do_mov_244)
{
    u64 addr = ctx->r14 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0+0x393")
int BPF_KPROBE(do_mov_245)
{
    u64 addr = ctx->r13 + 0x27c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0+0x4da")
int BPF_KPROBE(do_mov_246)
{
    u64 addr = ctx->r13 + 0x2e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/manage_tempaddrs+0xe3")
int BPF_KPROBE(do_mov_247)
{
    u64 addr = ctx->r14 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/manage_tempaddrs+0xf5")
int BPF_KPROBE(do_mov_248)
{
    u64 addr = ctx->r14 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl+0x213")
int BPF_KPROBE(do_mov_249)
{
    u64 addr = ctx->r12 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl+0x415")
int BPF_KPROBE(do_mov_250)
{
    u64 addr = ctx->r12 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_deladdr+0xfe")
int BPF_KPROBE(do_mov_251)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_addr_add+0xf3")
int BPF_KPROBE(do_mov_252)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_addr_add+0xb2")
int BPF_KPROBE(do_mov_253)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_lladdr+0x7f")
int BPF_KPROBE(do_mov_254)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_dad_work+0x5b")
int BPF_KPROBE(do_mov_255)
{
    u64 addr = ctx->r14 - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_dad_work+0x140")
int BPF_KPROBE(do_mov_256)
{
    u64 addr = ctx->r14 - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_dad_work+0x1f1")
int BPF_KPROBE(do_mov_257)
{
    u64 addr = ctx->r14 - 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_dad_work+0x274")
int BPF_KPROBE(do_mov_258)
{
    u64 addr = ctx->r14 - 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_dad_work+0x2a8")
int BPF_KPROBE(do_mov_259)
{
    u64 addr = ctx->r14 - 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_dad_work+0x34b")
int BPF_KPROBE(do_mov_260)
{
    u64 addr = ctx->r14 - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr+0x117")
int BPF_KPROBE(do_mov_261)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr+0x3b1")
int BPF_KPROBE(do_mov_262)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr+0x3d9")
int BPF_KPROBE(do_mov_263)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr+0x408")
int BPF_KPROBE(do_mov_264)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr+0x226")
int BPF_KPROBE(do_mov_265)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr+0x10f")
int BPF_KPROBE(do_mov_266)
{
    u64 addr = ctx->r13 + 0x104;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr+0x3a5")
int BPF_KPROBE(do_mov_267)
{
    u64 addr = ctx->r15 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr+0x4f2")
int BPF_KPROBE(do_mov_268)
{
    u64 addr = ctx->r15 + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv+0x3b9")
int BPF_KPROBE(do_mov_269)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv+0x329")
int BPF_KPROBE(do_mov_270)
{
    u64 addr = ctx->r15 + 0x1a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable+0x8c")
int BPF_KPROBE(do_mov_271)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable+0xca")
int BPF_KPROBE(do_mov_272)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_set_link_af+0x20f")
int BPF_KPROBE(do_mov_273)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_set_link_af+0x3a2")
int BPF_KPROBE(do_mov_274)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_set_link_af+0x3c5")
int BPF_KPROBE(do_mov_275)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_net_exit+0x65")
int BPF_KPROBE(do_mov_276)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0+0xdb")
int BPF_KPROBE(do_mov_277)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0+0x9a")
int BPF_KPROBE(do_mov_278)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_dump+0x11e")
int BPF_KPROBE(do_mov_279)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_dump+0x13d")
int BPF_KPROBE(do_mov_280)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_dump+0x15f")
int BPF_KPROBE(do_mov_281)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_get+0x1d9")
int BPF_KPROBE(do_mov_282)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_get+0x251")
int BPF_KPROBE(do_mov_283)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_get+0x278")
int BPF_KPROBE(do_mov_284)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_get+0x29f")
int BPF_KPROBE(do_mov_285)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0x78")
int BPF_KPROBE(do_mov_286)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0x82")
int BPF_KPROBE(do_mov_287)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xb6")
int BPF_KPROBE(do_mov_288)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xba")
int BPF_KPROBE(do_mov_289)
{
    u64 addr = ctx->r8 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xbe")
int BPF_KPROBE(do_mov_290)
{
    u64 addr = ctx->r8 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xc2")
int BPF_KPROBE(do_mov_291)
{
    u64 addr = ctx->r8 + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xc6")
int BPF_KPROBE(do_mov_292)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xce")
int BPF_KPROBE(do_mov_293)
{
    u64 addr = ctx->r8 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc+0xf7")
int BPF_KPROBE(do_mov_294)
{
    u64 addr = ctx->r8 + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel+0x135")
int BPF_KPROBE(do_mov_295)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel+0x148")
int BPF_KPROBE(do_mov_296)
{
    u64 addr = ctx->r8 + ctx->di * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel+0x15b")
int BPF_KPROBE(do_mov_297)
{
    u64 addr = ctx->r8 + ctx->di * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel+0x30d")
int BPF_KPROBE(do_mov_298)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init+0xf0")
int BPF_KPROBE(do_mov_299)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_nh_nlmsg_size+0x24")
int BPF_KPROBE(do_mov_300)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x37")
int BPF_KPROBE(do_mov_301)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x63")
int BPF_KPROBE(do_mov_302)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0xb4")
int BPF_KPROBE(do_mov_303)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0xda")
int BPF_KPROBE(do_mov_304)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0xfe")
int BPF_KPROBE(do_mov_305)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x139")
int BPF_KPROBE(do_mov_306)
{
    u64 addr = ctx->ax + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x161")
int BPF_KPROBE(do_mov_307)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x191")
int BPF_KPROBE(do_mov_308)
{
    u64 addr = ctx->ax + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x1b2")
int BPF_KPROBE(do_mov_309)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x1d6")
int BPF_KPROBE(do_mov_310)
{
    u64 addr = ctx->ax + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x1e7")
int BPF_KPROBE(do_mov_311)
{
    u64 addr = ctx->bx + 0x6a8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_net_init+0x209")
int BPF_KPROBE(do_mov_312)
{
    u64 addr = ctx->bx + 0x7d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__rt6_find_exception_spinlock+0x40")
int BPF_KPROBE(do_mov_313)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__rt6_find_exception_rcu+0x40")
int BPF_KPROBE(do_mov_314)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x7a")
int BPF_KPROBE(do_mov_315)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0+0x68")
int BPF_KPROBE(do_mov_316)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_redirect_nh_match+0x8c")
int BPF_KPROBE(do_mov_317)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_redirect_match+0xc")
int BPF_KPROBE(do_mov_318)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu+0x86")
int BPF_KPROBE(do_mov_319)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu+0x53")
int BPF_KPROBE(do_mov_320)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config+0xc3")
int BPF_KPROBE(do_mov_321)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config+0x25e")
int BPF_KPROBE(do_mov_322)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config+0x2d9")
int BPF_KPROBE(do_mov_323)
{
    u64 addr = ctx->bx + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config+0x3d4")
int BPF_KPROBE(do_mov_324)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config+0x3fe")
int BPF_KPROBE(do_mov_325)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config+0x421")
int BPF_KPROBE(do_mov_326)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_probe+0x1ce")
int BPF_KPROBE(do_mov_327)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_probe+0x1d5")
int BPF_KPROBE(do_mov_328)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_probe+0x1f8")
int BPF_KPROBE(do_mov_329)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_nh_find_match+0x81")
int BPF_KPROBE(do_mov_330)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_nh_find_match+0x8a")
int BPF_KPROBE(do_mov_331)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_insert_exception+0x114")
int BPF_KPROBE(do_mov_332)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_insert_exception+0x105")
int BPF_KPROBE(do_mov_333)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init+0x146")
int BPF_KPROBE(do_mov_334)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init+0xf8")
int BPF_KPROBE(do_mov_335)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init+0x1e4")
int BPF_KPROBE(do_mov_336)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init+0x1d0")
int BPF_KPROBE(do_mov_337)
{
    u64 addr = ctx->di + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init+0x20e")
int BPF_KPROBE(do_mov_338)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init+0x206")
int BPF_KPROBE(do_mov_339)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_destroy+0x78")
int BPF_KPROBE(do_mov_340)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_destroy+0x9a")
int BPF_KPROBE(do_mov_341)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_dst_destroy+0x82")
int BPF_KPROBE(do_mov_342)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_rr_leaf+0xf2")
int BPF_KPROBE(do_mov_343)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_rr_leaf+0xf8")
int BPF_KPROBE(do_mov_344)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_rr_leaf+0x248")
int BPF_KPROBE(do_mov_345)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__find_rr_leaf+0x243")
int BPF_KPROBE(do_mov_346)
{
    u64 addr = ctx->r14 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_dev_notify+0x83")
int BPF_KPROBE(do_mov_347)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_dev_notify+0x83")
int BPF_KPROBE(do_mov_348)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_dev_notify+0x136")
int BPF_KPROBE(do_mov_349)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_dev_notify+0x18e")
int BPF_KPROBE(do_mov_350)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_dev_notify+0x1e6")
int BPF_KPROBE(do_mov_351)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_fill_node+0x319")
int BPF_KPROBE(do_mov_352)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_fill_node+0x11b")
int BPF_KPROBE(do_mov_353)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_fill_node+0x867")
int BPF_KPROBE(do_mov_354)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_info_hw_flags_set+0x24")
int BPF_KPROBE(do_mov_355)
{
    u64 addr = ctx->r12 + 0x86;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_info_hw_flags_set+0x42")
int BPF_KPROBE(do_mov_356)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getroute+0x596")
int BPF_KPROBE(do_mov_357)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getroute+0x5b9")
int BPF_KPROBE(do_mov_358)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getroute+0x5dc")
int BPF_KPROBE(do_mov_359)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_getroute+0x603")
int BPF_KPROBE(do_mov_360)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc+0xcd")
int BPF_KPROBE(do_mov_361)
{
    u64 addr = ctx->r12 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc+0xb1")
int BPF_KPROBE(do_mov_362)
{
    u64 addr = ctx->r12 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_do_redirect+0x320")
int BPF_KPROBE(do_mov_363)
{
    u64 addr = ctx->r13 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_do_redirect+0x309")
int BPF_KPROBE(do_mov_364)
{
    u64 addr = ctx->r13 + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_del+0x92")
int BPF_KPROBE(do_mov_365)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_del+0x149")
int BPF_KPROBE(do_mov_366)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_rtm_delroute+0x99")
int BPF_KPROBE(do_mov_367)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_uncached_list_del+0x48")
int BPF_KPROBE(do_mov_368)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_table_lookup+0xac")
int BPF_KPROBE(do_mov_369)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_table_lookup+0xbe")
int BPF_KPROBE(do_mov_370)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_select_path+0x60")
int BPF_KPROBE(do_mov_371)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_select_path+0x114")
int BPF_KPROBE(do_mov_372)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_select_path+0x1ad")
int BPF_KPROBE(do_mov_373)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_check_nh+0x18e")
int BPF_KPROBE(do_mov_374)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_check_nh+0x1dd")
int BPF_KPROBE(do_mov_375)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_input+0x1be")
int BPF_KPROBE(do_mov_376)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_input+0x1c7")
int BPF_KPROBE(do_mov_377)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_blackhole_route+0x66")
int BPF_KPROBE(do_mov_378)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_blackhole_route+0x5c")
int BPF_KPROBE(do_mov_379)
{
    u64 addr = ctx->bx + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_blackhole_route+0xa1")
int BPF_KPROBE(do_mov_380)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_blackhole_route+0xdf")
int BPF_KPROBE(do_mov_381)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_blackhole_route+0x160")
int BPF_KPROBE(do_mov_382)
{
    u64 addr = ctx->bx + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_blackhole_route+0x155")
int BPF_KPROBE(do_mov_383)
{
    u64 addr = ctx->bx + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow+0xb3")
int BPF_KPROBE(do_mov_384)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow+0xa0")
int BPF_KPROBE(do_mov_385)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp6_dst_alloc+0xa1")
int BPF_KPROBE(do_mov_386)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmp6_dst_alloc+0xd8")
int BPF_KPROBE(do_mov_387)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x134")
int BPF_KPROBE(do_mov_388)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x123")
int BPF_KPROBE(do_mov_389)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x305")
int BPF_KPROBE(do_mov_390)
{
    u64 addr = ctx->si + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x309")
int BPF_KPROBE(do_mov_391)
{
    u64 addr = ctx->si + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x531")
int BPF_KPROBE(do_mov_392)
{
    u64 addr = ctx->bx + 0xe;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x539")
int BPF_KPROBE(do_mov_393)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x6a1")
int BPF_KPROBE(do_mov_394)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x6d4")
int BPF_KPROBE(do_mov_395)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x7f5")
int BPF_KPROBE(do_mov_396)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x87f")
int BPF_KPROBE(do_mov_397)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x8b4")
int BPF_KPROBE(do_mov_398)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x8de")
int BPF_KPROBE(do_mov_399)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x90d")
int BPF_KPROBE(do_mov_400)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_nh_init+0x945")
int BPF_KPROBE(do_mov_401)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_info_create+0x2e5")
int BPF_KPROBE(do_mov_402)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_info_create+0x313")
int BPF_KPROBE(do_mov_403)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_info_create+0x34c")
int BPF_KPROBE(do_mov_404)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_info_create+0x37e")
int BPF_KPROBE(do_mov_405)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_info_create+0x3d7")
int BPF_KPROBE(do_mov_406)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_info_create+0x576")
int BPF_KPROBE(do_mov_407)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_route_rcv+0x21f")
int BPF_KPROBE(do_mov_408)
{
    u64 addr = ctx->si + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_route_rcv+0x1f9")
int BPF_KPROBE(do_mov_409)
{
    u64 addr = ctx->si + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_route_rcv+0x2b6")
int BPF_KPROBE(do_mov_410)
{
    u64 addr = ctx->r8 + ctx->r11 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_route_rcv+0x2cc")
int BPF_KPROBE(do_mov_411)
{
    u64 addr = ctx->r8 + ctx->r11 * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_route_rcv+0x2e4")
int BPF_KPROBE(do_mov_412)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rt6_disable_ip+0x160")
int BPF_KPROBE(do_mov_413)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0xc4")
int BPF_KPROBE(do_mov_414)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x203")
int BPF_KPROBE(do_mov_415)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x2e6")
int BPF_KPROBE(do_mov_416)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x4c3")
int BPF_KPROBE(do_mov_417)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x50f")
int BPF_KPROBE(do_mov_418)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x676")
int BPF_KPROBE(do_mov_419)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x8ae")
int BPF_KPROBE(do_mov_420)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x8ca")
int BPF_KPROBE(do_mov_421)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add+0x93c")
int BPF_KPROBE(do_mov_422)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init+0x41")
int BPF_KPROBE(do_mov_423)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init+0xb9")
int BPF_KPROBE(do_mov_424)
{
    u64 addr = ctx->ax + 0x288;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_walk_continue+0x5a")
int BPF_KPROBE(do_mov_425)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_walk_continue+0x3b")
int BPF_KPROBE(do_mov_426)
{
    u64 addr = ctx->bx + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_node+0x5b")
int BPF_KPROBE(do_mov_427)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_node+0x1d")
int BPF_KPROBE(do_mov_428)
{
    u64 addr = ctx->r12 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_exit+0x56")
int BPF_KPROBE(do_mov_429)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_exit+0x7d")
int BPF_KPROBE(do_mov_430)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_exit+0x85")
int BPF_KPROBE(do_mov_431)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk+0x6c")
int BPF_KPROBE(do_mov_432)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk+0x70")
int BPF_KPROBE(do_mov_433)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_new_table+0x96")
int BPF_KPROBE(do_mov_434)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_new_table+0x67")
int BPF_KPROBE(do_mov_435)
{
    u64 addr = ctx->ax + 0x42;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop+0x5f")
int BPF_KPROBE(do_mov_436)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_clean_tree+0xdf")
int BPF_KPROBE(do_mov_437)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x53")
int BPF_KPROBE(do_mov_438)
{
    u64 addr = ctx->r12 + 0x6c8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x6b")
int BPF_KPROBE(do_mov_439)
{
    u64 addr = ctx->r12 + 0x7c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0xf1")
int BPF_KPROBE(do_mov_440)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x119")
int BPF_KPROBE(do_mov_441)
{
    u64 addr = ctx->ax + 0x42;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x1b8")
int BPF_KPROBE(do_mov_442)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x17d")
int BPF_KPROBE(do_mov_443)
{
    u64 addr = ctx->ax + 0x42;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x1ed")
int BPF_KPROBE(do_mov_444)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_net_init+0x1cf")
int BPF_KPROBE(do_mov_445)
{
    u64 addr = ctx->ax + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_done+0x43")
int BPF_KPROBE(do_mov_446)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_done+0x22")
int BPF_KPROBE(do_mov_447)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_done+0x8b")
int BPF_KPROBE(do_mov_448)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_done+0x98")
int BPF_KPROBE(do_mov_449)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next+0x51")
int BPF_KPROBE(do_mov_450)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next+0x59")
int BPF_KPROBE(do_mov_451)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next+0xc0")
int BPF_KPROBE(do_mov_452)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next+0xcd")
int BPF_KPROBE(do_mov_453)
{
    u64 addr = ctx->r14 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next+0x125")
int BPF_KPROBE(do_mov_454)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next+0x180")
int BPF_KPROBE(do_mov_455)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_start+0x63")
int BPF_KPROBE(do_mov_456)
{
    u64 addr = ctx->di + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_route_seq_start+0x58")
int BPF_KPROBE(do_mov_457)
{
    u64 addr = ctx->di + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0x4d")
int BPF_KPROBE(do_mov_458)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0x54")
int BPF_KPROBE(do_mov_459)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0xe5")
int BPF_KPROBE(do_mov_460)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0x152")
int BPF_KPROBE(do_mov_461)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0x15f")
int BPF_KPROBE(do_mov_462)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0x194")
int BPF_KPROBE(do_mov_463)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0+0x1a1")
int BPF_KPROBE(do_mov_464)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_fib+0x21f")
int BPF_KPROBE(do_mov_465)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_fib+0x1bd")
int BPF_KPROBE(do_mov_466)
{
    u64 addr = ctx->r15 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_fib+0x2e8")
int BPF_KPROBE(do_mov_467)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_dump_fib+0x2eb")
int BPF_KPROBE(do_mov_468)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_purge_rt+0x8c")
int BPF_KPROBE(do_mov_469)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x212")
int BPF_KPROBE(do_mov_470)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x223")
int BPF_KPROBE(do_mov_471)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x2cf")
int BPF_KPROBE(do_mov_472)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x2e8")
int BPF_KPROBE(do_mov_473)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x322")
int BPF_KPROBE(do_mov_474)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x357")
int BPF_KPROBE(do_mov_475)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0+0x364")
int BPF_KPROBE(do_mov_476)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_info_alloc+0x35")
int BPF_KPROBE(do_mov_477)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_info_alloc+0x3d")
int BPF_KPROBE(do_mov_478)
{
    u64 addr = ctx->ax + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_tables_dump+0xaf")
int BPF_KPROBE(do_mov_479)
{
    u64 addr = ctx->r15 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_tables_dump+0x68")
int BPF_KPROBE(do_mov_480)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_tables_dump+0xe5")
int BPF_KPROBE(do_mov_481)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_tables_dump+0x166")
int BPF_KPROBE(do_mov_482)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_tables_dump+0x169")
int BPF_KPROBE(do_mov_483)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add+0x72f")
int BPF_KPROBE(do_mov_484)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add+0x8d3")
int BPF_KPROBE(do_mov_485)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_add+0x89d")
int BPF_KPROBE(do_mov_486)
{
    u64 addr = ctx->r13 + 0x2a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_del+0xd2")
int BPF_KPROBE(do_mov_487)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_del+0x158")
int BPF_KPROBE(do_mov_488)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_del+0x316")
int BPF_KPROBE(do_mov_489)
{
    u64 addr = ctx->r14 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_del+0x31f")
int BPF_KPROBE(do_mov_490)
{
    u64 addr = ctx->r14 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_clean_node+0xbc")
int BPF_KPROBE(do_mov_491)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_clean_node+0xbc")
int BPF_KPROBE(do_mov_492)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/compat_ipv6_mcast_join_leave+0x6c")
int BPF_KPROBE(do_mov_493)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mcast_join_leave+0x47")
int BPF_KPROBE(do_mov_494)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0x80")
int BPF_KPROBE(do_mov_495)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0xbd")
int BPF_KPROBE(do_mov_496)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0xc4")
int BPF_KPROBE(do_mov_497)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0xcd")
int BPF_KPROBE(do_mov_498)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr+0x266")
int BPF_KPROBE(do_mov_499)
{
    u64 addr = ctx->r12 + 0x100;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter+0x21e")
int BPF_KPROBE(do_mov_500)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_msfilter+0x68")
int BPF_KPROBE(do_mov_501)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_msfilter+0x115")
int BPF_KPROBE(do_mov_502)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_msfilter+0x12f")
int BPF_KPROBE(do_mov_503)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_get_msfilter+0x157")
int BPF_KPROBE(do_mov_504)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_ra_control+0x85")
int BPF_KPROBE(do_mov_505)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_ra_control+0xe3")
int BPF_KPROBE(do_mov_506)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_ra_control+0xdf")
int BPF_KPROBE(do_mov_507)
{
    u64 addr = ctx->r14 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x32c")
int BPF_KPROBE(do_mov_508)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x6fd")
int BPF_KPROBE(do_mov_509)
{
    u64 addr = ctx->r9 + 0x3c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x640")
int BPF_KPROBE(do_mov_510)
{
    u64 addr = ctx->r9 + 0x4f;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x7d9")
int BPF_KPROBE(do_mov_511)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x929")
int BPF_KPROBE(do_mov_512)
{
    u64 addr = ctx->r9 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x8f1")
int BPF_KPROBE(do_mov_513)
{
    u64 addr = ctx->r9 + 0x4d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0xb31")
int BPF_KPROBE(do_mov_514)
{
    u64 addr = ctx->r9 + 0x4d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0xb8e")
int BPF_KPROBE(do_mov_515)
{
    u64 addr = ctx->r9 + 0x51;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0xd99")
int BPF_KPROBE(do_mov_516)
{
    u64 addr = ctx->r9 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0xc61")
int BPF_KPROBE(do_mov_517)
{
    u64 addr = ctx->r9 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x10ce")
int BPF_KPROBE(do_mov_518)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x10ee")
int BPF_KPROBE(do_mov_519)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x11ac")
int BPF_KPROBE(do_mov_520)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x11fb")
int BPF_KPROBE(do_mov_521)
{
    u64 addr = ctx->r9 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x14b9")
int BPF_KPROBE(do_mov_522)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x14c4")
int BPF_KPROBE(do_mov_523)
{
    u64 addr = ctx->r15 + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt+0x14e1")
int BPF_KPROBE(do_mov_524)
{
    u64 addr = ctx->r15 + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0x1ac")
int BPF_KPROBE(do_mov_525)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0x1e6")
int BPF_KPROBE(do_mov_526)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0x22e")
int BPF_KPROBE(do_mov_527)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0x59c")
int BPF_KPROBE(do_mov_528)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0x7ce")
int BPF_KPROBE(do_mov_529)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0xa0d")
int BPF_KPROBE(do_mov_530)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0xa27")
int BPF_KPROBE(do_mov_531)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt+0xcf2")
int BPF_KPROBE(do_mov_532)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_mc_map+0xd6")
int BPF_KPROBE(do_mov_533)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_mc_map+0xe5")
int BPF_KPROBE(do_mov_534)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_mc_map+0xf3")
int BPF_KPROBE(do_mov_535)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_mc_map+0x13d")
int BPF_KPROBE(do_mov_536)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_mc_map+0x12f")
int BPF_KPROBE(do_mov_537)
{
    u64 addr = ctx->si + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_mc_map+0x187")
int BPF_KPROBE(do_mov_538)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ndisc_fill_addr_option+0x47")
int BPF_KPROBE(do_mov_539)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_alloc_skb+0x61")
int BPF_KPROBE(do_mov_540)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_alloc_skb+0x8b")
int BPF_KPROBE(do_mov_541)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_allow_add+0x46")
int BPF_KPROBE(do_mov_542)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_skb+0x1a4")
int BPF_KPROBE(do_mov_543)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_skb+0x1b5")
int BPF_KPROBE(do_mov_544)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_skb+0x1d6")
int BPF_KPROBE(do_mov_545)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_ns_create+0x92")
int BPF_KPROBE(do_mov_546)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_ns_create+0xcb")
int BPF_KPROBE(do_mov_547)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_ns_create+0x99")
int BPF_KPROBE(do_mov_548)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_constructor+0xb4")
int BPF_KPROBE(do_mov_549)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_constructor+0x18d")
int BPF_KPROBE(do_mov_550)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_constructor+0x27e")
int BPF_KPROBE(do_mov_551)
{
    u64 addr = ctx->bx + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_constructor+0x26a")
int BPF_KPROBE(do_mov_552)
{
    u64 addr = ctx->bx + 0x150;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_constructor+0x2f7")
int BPF_KPROBE(do_mov_553)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_constructor+0x396")
int BPF_KPROBE(do_mov_554)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x39")
int BPF_KPROBE(do_mov_555)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x137")
int BPF_KPROBE(do_mov_556)
{
    u64 addr = ctx->r14 + ctx->di * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x15a")
int BPF_KPROBE(do_mov_557)
{
    u64 addr = ctx->r14 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x167")
int BPF_KPROBE(do_mov_558)
{
    u64 addr = ctx->r14 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x170")
int BPF_KPROBE(do_mov_559)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x183")
int BPF_KPROBE(do_mov_560)
{
    u64 addr = ctx->r14 + ctx->ax * 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x1b5")
int BPF_KPROBE(do_mov_561)
{
    u64 addr = ctx->r14 + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_parse_options+0x1c2")
int BPF_KPROBE(do_mov_562)
{
    u64 addr = ctx->r14 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_router_discovery+0x358")
int BPF_KPROBE(do_mov_563)
{
    u64 addr = ctx->cx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_router_discovery+0x3d5")
int BPF_KPROBE(do_mov_564)
{
    u64 addr = ctx->cx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_router_discovery+0x777")
int BPF_KPROBE(do_mov_565)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_router_discovery+0x706")
int BPF_KPROBE(do_mov_566)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_router_discovery+0xa21")
int BPF_KPROBE(do_mov_567)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_na+0xff")
int BPF_KPROBE(do_mov_568)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_na+0x109")
int BPF_KPROBE(do_mov_569)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_na+0x239")
int BPF_KPROBE(do_mov_570)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_na+0x114")
int BPF_KPROBE(do_mov_571)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_rs+0xcc")
int BPF_KPROBE(do_mov_572)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_redirect+0x3a6")
int BPF_KPROBE(do_mov_573)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_redirect+0x3b1")
int BPF_KPROBE(do_mov_574)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_redirect+0x49a")
int BPF_KPROBE(do_mov_575)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_send_redirect+0x48f")
int BPF_KPROBE(do_mov_576)
{
    u64 addr = ctx->ax + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_rcv+0xcb")
int BPF_KPROBE(do_mov_577)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ndisc_rcv+0x67")
int BPF_KPROBE(do_mov_578)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_init_sock+0x30")
int BPF_KPROBE(do_mov_579)
{
    u64 addr = ctx->di + 0x2d0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_init_sock+0x22")
int BPF_KPROBE(do_mov_580)
{
    u64 addr = ctx->di + 0x450;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_v6_send_skb+0x4f")
int BPF_KPROBE(do_mov_581)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_v6_send_skb+0x6b")
int BPF_KPROBE(do_mov_582)
{
    u64 addr = ctx->r13 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_recvmsg+0x2a5")
int BPF_KPROBE(do_mov_583)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_recvmsg+0x339")
int BPF_KPROBE(do_mov_584)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_recvmsg+0x691")
int BPF_KPROBE(do_mov_585)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_recvmsg+0x6a2")
int BPF_KPROBE(do_mov_586)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb+0x3b1")
int BPF_KPROBE(do_mov_587)
{
    u64 addr = ctx->bx + 0x7a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb+0x3a6")
int BPF_KPROBE(do_mov_588)
{
    u64 addr = ctx->bx + 0x114;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb+0x12d")
int BPF_KPROBE(do_mov_589)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb+0x123")
int BPF_KPROBE(do_mov_590)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_sendmsg+0x1bd")
int BPF_KPROBE(do_mov_591)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_sendmsg+0x1e9")
int BPF_KPROBE(do_mov_592)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_sendmsg+0x74d")
int BPF_KPROBE(do_mov_593)
{
    u64 addr = ctx->r12 + 0x3d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udpv6_sendmsg+0x75d")
int BPF_KPROBE(do_mov_594)
{
    u64 addr = ctx->r12 + 0x3e2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_v6_early_demux+0x18e")
int BPF_KPROBE(do_mov_595)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp_v6_early_demux+0x192")
int BPF_KPROBE(do_mov_596)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_bind+0xc4")
int BPF_KPROBE(do_mov_597)
{
    u64 addr = ctx->r14 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_bind+0xba")
int BPF_KPROBE(do_mov_598)
{
    u64 addr = ctx->r14 + 0x310;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_bind+0x119")
int BPF_KPROBE(do_mov_599)
{
    u64 addr = ctx->r14 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_bind+0x10b")
int BPF_KPROBE(do_mov_600)
{
    u64 addr = ctx->r14 + 0x310;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_recvmsg+0x154")
int BPF_KPROBE(do_mov_601)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_recvmsg+0x175")
int BPF_KPROBE(do_mov_602)
{
    u64 addr = ctx->si + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_recvmsg+0x180")
int BPF_KPROBE(do_mov_603)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_recvmsg+0x1cb")
int BPF_KPROBE(do_mov_604)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_setsockopt+0x1cf")
int BPF_KPROBE(do_mov_605)
{
    u64 addr = ctx->r14 + 0x3d8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_setsockopt+0x1ea")
int BPF_KPROBE(do_mov_606)
{
    u64 addr = ctx->r14 + 0x3e0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_sendmsg+0x854")
int BPF_KPROBE(do_mov_607)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_sendmsg+0x86e")
int BPF_KPROBE(do_mov_608)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_rcv+0x2d0")
int BPF_KPROBE(do_mov_609)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/rawv6_rcv+0xf7")
int BPF_KPROBE(do_mov_610)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_err_convert+0x6")
int BPF_KPROBE(do_mov_611)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_err_convert+0x23")
int BPF_KPROBE(do_mov_612)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_err_convert+0x38")
int BPF_KPROBE(do_mov_613)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_err_convert+0x59")
int BPF_KPROBE(do_mov_614)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames+0x59")
int BPF_KPROBE(do_mov_615)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach+0xdf")
int BPF_KPROBE(do_mov_616)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach+0x137")
int BPF_KPROBE(do_mov_617)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_rcv+0x184")
int BPF_KPROBE(do_mov_618)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_rcv+0x320")
int BPF_KPROBE(do_mov_619)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_flow_init+0x1c")
int BPF_KPROBE(do_mov_620)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/icmpv6_flow_init+0x26")
int BPF_KPROBE(do_mov_621)
{
    u64 addr = ctx->si + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init+0x2f")
int BPF_KPROBE(do_mov_622)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init+0x61")
int BPF_KPROBE(do_mov_623)
{
    u64 addr = ctx->ax + 0x108;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_stop+0x2b")
int BPF_KPROBE(do_mov_624)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_stop+0x14")
int BPF_KPROBE(do_mov_625)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x14e")
int BPF_KPROBE(do_mov_626)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x18e")
int BPF_KPROBE(do_mov_627)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/sf_setstate+0x185")
int BPF_KPROBE(do_mov_628)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0+0x43")
int BPF_KPROBE(do_mov_629)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0+0x47")
int BPF_KPROBE(do_mov_630)
{
    u64 addr = ctx->si + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0+0x6b")
int BPF_KPROBE(do_mov_631)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0+0xb1")
int BPF_KPROBE(do_mov_632)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0+0x1f")
int BPF_KPROBE(do_mov_633)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0+0x3c")
int BPF_KPROBE(do_mov_634)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start+0x5a")
int BPF_KPROBE(do_mov_635)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start+0x40")
int BPF_KPROBE(do_mov_636)
{
    u64 addr = ctx->ax + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next+0x34")
int BPF_KPROBE(do_mov_637)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next+0x44")
int BPF_KPROBE(do_mov_638)
{
    u64 addr = ctx->di + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_sendpack+0x167")
int BPF_KPROBE(do_mov_639)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_sendpack+0x185")
int BPF_KPROBE(do_mov_640)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start+0x3c")
int BPF_KPROBE(do_mov_641)
{
    u64 addr = ctx->r8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start+0x22")
int BPF_KPROBE(do_mov_642)
{
    u64 addr = ctx->r8 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start+0xaa")
int BPF_KPROBE(do_mov_643)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start+0xba")
int BPF_KPROBE(do_mov_644)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_send+0x16c")
int BPF_KPROBE(do_mov_645)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_send+0x180")
int BPF_KPROBE(do_mov_646)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_send+0x192")
int BPF_KPROBE(do_mov_647)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_send+0x1db")
int BPF_KPROBE(do_mov_648)
{
    u64 addr = ctx->r9 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_send+0x1ad")
int BPF_KPROBE(do_mov_649)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next+0x4b")
int BPF_KPROBE(do_mov_650)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next+0x31")
int BPF_KPROBE(do_mov_651)
{
    u64 addr = ctx->di + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_clear_delrec+0x8e")
int BPF_KPROBE(do_mov_652)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_clear_delrec+0xa0")
int BPF_KPROBE(do_mov_653)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x30")
int BPF_KPROBE(do_mov_654)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x33")
int BPF_KPROBE(do_mov_655)
{
    u64 addr = ctx->ax + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x46")
int BPF_KPROBE(do_mov_656)
{
    u64 addr = ctx->ax + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grhead+0x6b")
int BPF_KPROBE(do_mov_657)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grec+0x256")
int BPF_KPROBE(do_mov_658)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grec+0x40a")
int BPF_KPROBE(do_mov_659)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/add_grec+0x4d7")
int BPF_KPROBE(do_mov_660)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_gq_work+0x2e")
int BPF_KPROBE(do_mov_661)
{
    u64 addr = ctx->bx - 0x27;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_del_delrec+0xef")
int BPF_KPROBE(do_mov_662)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_del_delrec+0x10a")
int BPF_KPROBE(do_mov_663)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_report_work+0x7d")
int BPF_KPROBE(do_mov_664)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_report_work+0x88")
int BPF_KPROBE(do_mov_665)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_report_work+0x90")
int BPF_KPROBE(do_mov_666)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_report_work+0x9c")
int BPF_KPROBE(do_mov_667)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_report_work+0x111")
int BPF_KPROBE(do_mov_668)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_report_work+0x11c")
int BPF_KPROBE(do_mov_669)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_dad_work+0x79")
int BPF_KPROBE(do_mov_670)
{
    u64 addr = ctx->bx - 0xd5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_ifc_work+0x1a9")
int BPF_KPROBE(do_mov_671)
{
    u64 addr = ctx->cx - 0x7e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_ifc_work+0x245")
int BPF_KPROBE(do_mov_672)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_ifc_work+0x283")
int BPF_KPROBE(do_mov_673)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_del1_src+0x79")
int BPF_KPROBE(do_mov_674)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_del1_src+0xf4")
int BPF_KPROBE(do_mov_675)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_add_src+0x1a8")
int BPF_KPROBE(do_mov_676)
{
    u64 addr = ctx->ax + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_add_src+0x151")
int BPF_KPROBE(do_mov_677)
{
    u64 addr = ctx->ax + 0x2a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_add_src+0x1b0")
int BPF_KPROBE(do_mov_678)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_add_src+0x210")
int BPF_KPROBE(do_mov_679)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0+0xff")
int BPF_KPROBE(do_mov_680)
{
    u64 addr = ctx->bx + ctx->ax * 0x8 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0+0x11d")
int BPF_KPROBE(do_mov_681)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0+0x128")
int BPF_KPROBE(do_mov_682)
{
    u64 addr = ctx->bx + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_group_dropped+0x16a")
int BPF_KPROBE(do_mov_683)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_group_dropped+0x16e")
int BPF_KPROBE(do_mov_684)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_group_dropped+0x178")
int BPF_KPROBE(do_mov_685)
{
    u64 addr = ctx->r13 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x152")
int BPF_KPROBE(do_mov_686)
{
    u64 addr = ctx->r9 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x15a")
int BPF_KPROBE(do_mov_687)
{
    u64 addr = ctx->r9 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x162")
int BPF_KPROBE(do_mov_688)
{
    u64 addr = ctx->r9 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x166")
int BPF_KPROBE(do_mov_689)
{
    u64 addr = ctx->r9 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x17e")
int BPF_KPROBE(do_mov_690)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x188")
int BPF_KPROBE(do_mov_691)
{
    u64 addr = ctx->r9 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x196")
int BPF_KPROBE(do_mov_692)
{
    u64 addr = ctx->r9 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x19d")
int BPF_KPROBE(do_mov_693)
{
    u64 addr = ctx->r9 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x1a4")
int BPF_KPROBE(do_mov_694)
{
    u64 addr = ctx->r9 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x1a8")
int BPF_KPROBE(do_mov_695)
{
    u64 addr = ctx->r9 + 0xa4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x1b3")
int BPF_KPROBE(do_mov_696)
{
    u64 addr = ctx->r9 + 0xa8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x1be")
int BPF_KPROBE(do_mov_697)
{
    u64 addr = ctx->r9 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x1c2")
int BPF_KPROBE(do_mov_698)
{
    u64 addr = ctx->r9 + ctx->r12 * 0x8 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc+0x1e8")
int BPF_KPROBE(do_mov_699)
{
    u64 addr = ctx->r9 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join+0xd7")
int BPF_KPROBE(do_mov_700)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join+0xdb")
int BPF_KPROBE(do_mov_701)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join+0x10a")
int BPF_KPROBE(do_mov_702)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_query_work+0x82")
int BPF_KPROBE(do_mov_703)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_query_work+0x8d")
int BPF_KPROBE(do_mov_704)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_query_work+0x95")
int BPF_KPROBE(do_mov_705)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mld_query_work+0xa1")
int BPF_KPROBE(do_mov_706)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_msfget+0x115")
int BPF_KPROBE(do_mov_707)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_msfget+0x19b")
int BPF_KPROBE(do_mov_708)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_dec+0x98")
int BPF_KPROBE(do_mov_709)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_dec+0xf2")
int BPF_KPROBE(do_mov_710)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_dec+0x107")
int BPF_KPROBE(do_mov_711)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_source+0x30a")
int BPF_KPROBE(do_mov_712)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_source+0x30c")
int BPF_KPROBE(do_mov_713)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_source+0x334")
int BPF_KPROBE(do_mov_714)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_source+0x339")
int BPF_KPROBE(do_mov_715)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_source+0x4c9")
int BPF_KPROBE(do_mov_716)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mc_msfilter+0x115")
int BPF_KPROBE(do_mov_717)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_event_query+0x76")
int BPF_KPROBE(do_mov_718)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_event_query+0x94")
int BPF_KPROBE(do_mov_719)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_event_report+0x76")
int BPF_KPROBE(do_mov_720)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/igmp6_event_report+0x94")
int BPF_KPROBE(do_mov_721)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_up+0x17")
int BPF_KPROBE(do_mov_722)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_up+0x25")
int BPF_KPROBE(do_mov_723)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x32")
int BPF_KPROBE(do_mov_724)
{
    u64 addr = ctx->di - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x36")
int BPF_KPROBE(do_mov_725)
{
    u64 addr = ctx->di - 0x47;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x3a")
int BPF_KPROBE(do_mov_726)
{
    u64 addr = ctx->di - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x3e")
int BPF_KPROBE(do_mov_727)
{
    u64 addr = ctx->di - 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x42")
int BPF_KPROBE(do_mov_728)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x64")
int BPF_KPROBE(do_mov_729)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev+0x1c0")
int BPF_KPROBE(do_mov_730)
{
    u64 addr = ctx->bx + 0x238;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev+0x7b")
int BPF_KPROBE(do_mov_731)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev+0x8e")
int BPF_KPROBE(do_mov_732)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev+0xf3")
int BPF_KPROBE(do_mov_733)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev+0x106")
int BPF_KPROBE(do_mov_734)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev+0x1ad")
int BPF_KPROBE(do_mov_735)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev+0x1c2")
int BPF_KPROBE(do_mov_736)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frags_init_net+0x34")
int BPF_KPROBE(do_mov_737)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frags_init_net+0x51")
int BPF_KPROBE(do_mov_738)
{
    u64 addr = ctx->ax + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frags_init_net+0x9b")
int BPF_KPROBE(do_mov_739)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frags_init_net+0xd7")
int BPF_KPROBE(do_mov_740)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x13c")
int BPF_KPROBE(do_mov_741)
{
    u64 addr = ctx->r12 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0xea")
int BPF_KPROBE(do_mov_742)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x33e")
int BPF_KPROBE(do_mov_743)
{
    u64 addr = ctx->r14 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x26c")
int BPF_KPROBE(do_mov_744)
{
    u64 addr = ctx->r14 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x3f0")
int BPF_KPROBE(do_mov_745)
{
    u64 addr = ctx->r14 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x489")
int BPF_KPROBE(do_mov_746)
{
    u64 addr = ctx->r14 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x86d")
int BPF_KPROBE(do_mov_747)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x824")
int BPF_KPROBE(do_mov_748)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x964")
int BPF_KPROBE(do_mov_749)
{
    u64 addr = ctx->r14 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv+0x979")
int BPF_KPROBE(do_mov_750)
{
    u64 addr = ctx->r14 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_restore_cb+0xe")
int BPF_KPROBE(do_mov_751)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_restore_cb+0x19")
int BPF_KPROBE(do_mov_752)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_fill_cb+0x2f")
int BPF_KPROBE(do_mov_753)
{
    u64 addr = ctx->ax + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_fill_cb+0x22")
int BPF_KPROBE(do_mov_754)
{
    u64 addr = ctx->ax + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_sk_rx_dst_set+0x2f")
int BPF_KPROBE(do_mov_755)
{
    u64 addr = ctx->di + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_sk_rx_dst_set+0x4b")
int BPF_KPROBE(do_mov_756)
{
    u64 addr = ctx->di + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x3a")
int BPF_KPROBE(do_mov_757)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x3d")
int BPF_KPROBE(do_mov_758)
{
    u64 addr = ctx->si + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x70")
int BPF_KPROBE(do_mov_759)
{
    u64 addr = ctx->si + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x88")
int BPF_KPROBE(do_mov_760)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_headers.isra.0+0x8f")
int BPF_KPROBE(do_mov_761)
{
    u64 addr = ctx->ax + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_skb+0x117")
int BPF_KPROBE(do_mov_762)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_skb+0x11f")
int BPF_KPROBE(do_mov_763)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x329")
int BPF_KPROBE(do_mov_764)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x13d")
int BPF_KPROBE(do_mov_765)
{
    u64 addr = ctx->bx + 0x8f0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x381")
int BPF_KPROBE(do_mov_766)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x36f")
int BPF_KPROBE(do_mov_767)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x3c8")
int BPF_KPROBE(do_mov_768)
{
    u64 addr = ctx->bx + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x3b9")
int BPF_KPROBE(do_mov_769)
{
    u64 addr = ctx->bx + 0x6ba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x5b1")
int BPF_KPROBE(do_mov_770)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_connect+0x50f")
int BPF_KPROBE(do_mov_771)
{
    u64 addr = ctx->bx + 0x8c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x184")
int BPF_KPROBE(do_mov_772)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x1a7")
int BPF_KPROBE(do_mov_773)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x193")
int BPF_KPROBE(do_mov_774)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x23e")
int BPF_KPROBE(do_mov_775)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x2c7")
int BPF_KPROBE(do_mov_776)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x3e2")
int BPF_KPROBE(do_mov_777)
{
    u64 addr = ctx->r12 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x413")
int BPF_KPROBE(do_mov_778)
{
    u64 addr = ctx->r12 + 0x94;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x617")
int BPF_KPROBE(do_mov_779)
{
    u64 addr = ctx->bx + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x630")
int BPF_KPROBE(do_mov_780)
{
    u64 addr = ctx->bx + 0x1c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x7d2")
int BPF_KPROBE(do_mov_781)
{
    u64 addr = ctx->r10 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_response+0x7da")
int BPF_KPROBE(do_mov_782)
{
    u64 addr = ctx->r10 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_synack+0xb6")
int BPF_KPROBE(do_mov_783)
{
    u64 addr = ctx->r15 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_send_synack+0xea")
int BPF_KPROBE(do_mov_784)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_route_req+0xc4")
int BPF_KPROBE(do_mov_785)
{
    u64 addr = ctx->r13 + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_route_req+0x114")
int BPF_KPROBE(do_mov_786)
{
    u64 addr = ctx->r13 + 0xf8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_do_rcv+0xc5")
int BPF_KPROBE(do_mov_787)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_do_rcv+0x299")
int BPF_KPROBE(do_mov_788)
{
    u64 addr = ctx->r12 + 0x90c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_do_rcv+0x455")
int BPF_KPROBE(do_mov_789)
{
    u64 addr = ctx->r12 + 0x7a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_do_rcv+0x42e")
int BPF_KPROBE(do_mov_790)
{
    u64 addr = ctx->r12 + 0x114;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_err+0x44e")
int BPF_KPROBE(do_mov_791)
{
    u64 addr = ctx->r12 + 0x220;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_err+0x303")
int BPF_KPROBE(do_mov_792)
{
    u64 addr = ctx->r12 + 0x878;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0xf2")
int BPF_KPROBE(do_mov_793)
{
    u64 addr = ctx->dx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0xd0")
int BPF_KPROBE(do_mov_794)
{
    u64 addr = ctx->dx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0x117")
int BPF_KPROBE(do_mov_795)
{
    u64 addr = ctx->r12 + 0x308;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0x14f")
int BPF_KPROBE(do_mov_796)
{
    u64 addr = ctx->r12 + 0x950;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0x352")
int BPF_KPROBE(do_mov_797)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0x1d6")
int BPF_KPROBE(do_mov_798)
{
    u64 addr = ctx->r12 + 0x938;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0x6bc")
int BPF_KPROBE(do_mov_799)
{
    u64 addr = ctx->r12 + 0x2c0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock+0x6f8")
int BPF_KPROBE(do_mov_800)
{
    u64 addr = ctx->r12 + 0x938;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_rcv+0xd29")
int BPF_KPROBE(do_mov_801)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_rcv+0x18a")
int BPF_KPROBE(do_mov_802)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_rcv+0xe0d")
int BPF_KPROBE(do_mov_803)
{
    u64 addr = ctx->r13 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_rcv+0xdc7")
int BPF_KPROBE(do_mov_804)
{
    u64 addr = ctx->r13 + 0x584;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_early_demux+0xcc")
int BPF_KPROBE(do_mov_805)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp_v6_early_demux+0xd5")
int BPF_KPROBE(do_mov_806)
{
    u64 addr = ctx->bx + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl6_update_dst+0x54")
int BPF_KPROBE(do_mov_807)
{
    u64 addr = ctx->ax + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl6_update_dst+0x50")
int BPF_KPROBE(do_mov_808)
{
    u64 addr = ctx->ax + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_exthdr+0x65")
int BPF_KPROBE(do_mov_809)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_exthdr+0x68")
int BPF_KPROBE(do_mov_810)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_option+0x2e")
int BPF_KPROBE(do_mov_811)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_option+0x50")
int BPF_KPROBE(do_mov_812)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_option+0x56")
int BPF_KPROBE(do_mov_813)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_option+0x63")
int BPF_KPROBE(do_mov_814)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_dup_options+0x7d")
int BPF_KPROBE(do_mov_815)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_dup_options+0x69")
int BPF_KPROBE(do_mov_816)
{
    u64 addr = ctx->r8 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_fixup_options+0x27")
int BPF_KPROBE(do_mov_817)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ipv6_fixup_options+0x5e")
int BPF_KPROBE(do_mov_818)
{
    u64 addr = ctx->di + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_parse_tlv+0x5f3")
int BPF_KPROBE(do_mov_819)
{
    u64 addr = ctx->r10 + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_parse_tlv+0x6c7")
int BPF_KPROBE(do_mov_820)
{
    u64 addr = ctx->r10 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_destopt_rcv+0x97")
int BPF_KPROBE(do_mov_821)
{
    u64 addr = ctx->r12 + 0x32;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_destopt_rcv+0x157")
int BPF_KPROBE(do_mov_822)
{
    u64 addr = ctx->r12 + 0x36;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x241")
int BPF_KPROBE(do_mov_823)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x647")
int BPF_KPROBE(do_mov_824)
{
    u64 addr = ctx->si + 0x3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x720")
int BPF_KPROBE(do_mov_825)
{
    u64 addr = ctx->si + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x815")
int BPF_KPROBE(do_mov_826)
{
    u64 addr = ctx->r13 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x7db")
int BPF_KPROBE(do_mov_827)
{
    u64 addr = ctx->r13 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x947")
int BPF_KPROBE(do_mov_828)
{
    u64 addr = ctx->r13 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0x962")
int BPF_KPROBE(do_mov_829)
{
    u64 addr = ctx->r13 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0xe15")
int BPF_KPROBE(do_mov_830)
{
    u64 addr = ctx->r13 + 0x2e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv+0xebf")
int BPF_KPROBE(do_mov_831)
{
    u64 addr = ctx->r13 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x69")
int BPF_KPROBE(do_mov_832)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0xe1")
int BPF_KPROBE(do_mov_833)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x11c")
int BPF_KPROBE(do_mov_834)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x11e")
int BPF_KPROBE(do_mov_835)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x179")
int BPF_KPROBE(do_mov_836)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x1f0")
int BPF_KPROBE(do_mov_837)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x1f2")
int BPF_KPROBE(do_mov_838)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x233")
int BPF_KPROBE(do_mov_839)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x24a")
int BPF_KPROBE(do_mov_840)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts+0x265")
int BPF_KPROBE(do_mov_841)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_options+0xd0")
int BPF_KPROBE(do_mov_842)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_options+0x2e9")
int BPF_KPROBE(do_mov_843)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_renew_options+0x19c")
int BPF_KPROBE(do_mov_844)
{
    u64 addr = ctx->r12 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_datagram_send_ctl+0x2b9")
int BPF_KPROBE(do_mov_845)
{
    u64 addr = ctx->r15 + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_datagram_send_ctl+0x2de")
int BPF_KPROBE(do_mov_846)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_datagram_dst_update+0x1ec")
int BPF_KPROBE(do_mov_847)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_datagram_dst_update+0x20d")
int BPF_KPROBE(do_mov_848)
{
    u64 addr = ctx->r12 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_datagram_dst_update+0x220")
int BPF_KPROBE(do_mov_849)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x14a")
int BPF_KPROBE(do_mov_850)
{
    u64 addr = ctx->r14 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x166")
int BPF_KPROBE(do_mov_851)
{
    u64 addr = ctx->r14 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x173")
int BPF_KPROBE(do_mov_852)
{
    u64 addr = ctx->r14 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x1de")
int BPF_KPROBE(do_mov_853)
{
    u64 addr = ctx->r14 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x1f9")
int BPF_KPROBE(do_mov_854)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x208")
int BPF_KPROBE(do_mov_855)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x23c")
int BPF_KPROBE(do_mov_856)
{
    u64 addr = ctx->r14 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x24c")
int BPF_KPROBE(do_mov_857)
{
    u64 addr = ctx->r14 + 0x54;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x363")
int BPF_KPROBE(do_mov_858)
{
    u64 addr = ctx->r14 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect+0x377")
int BPF_KPROBE(do_mov_859)
{
    u64 addr = ctx->r14 + 0x1fc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_icmp_error+0xaf")
int BPF_KPROBE(do_mov_860)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_icmp_error+0x123")
int BPF_KPROBE(do_mov_861)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_local_error+0xb9")
int BPF_KPROBE(do_mov_862)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_local_error+0xbc")
int BPF_KPROBE(do_mov_863)
{
    u64 addr = ctx->cx - 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_local_error+0xd4")
int BPF_KPROBE(do_mov_864)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_local_error+0x138")
int BPF_KPROBE(do_mov_865)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_local_rxpmtu+0xa8")
int BPF_KPROBE(do_mov_866)
{
    u64 addr = ctx->bx + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_local_rxpmtu+0xf5")
int BPF_KPROBE(do_mov_867)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_rxpmtu+0x146")
int BPF_KPROBE(do_mov_868)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_rxpmtu+0x151")
int BPF_KPROBE(do_mov_869)
{
    u64 addr = ctx->r15 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_error+0x11e")
int BPF_KPROBE(do_mov_870)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_error+0x14e")
int BPF_KPROBE(do_mov_871)
{
    u64 addr = ctx->di + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_error+0x15f")
int BPF_KPROBE(do_mov_872)
{
    u64 addr = ctx->di + 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_error+0x16f")
int BPF_KPROBE(do_mov_873)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_error+0x386")
int BPF_KPROBE(do_mov_874)
{
    u64 addr = ctx->cx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_recv_error+0x36e")
int BPF_KPROBE(do_mov_875)
{
    u64 addr = ctx->cx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl6_merge_options+0x51")
int BPF_KPROBE(do_mov_876)
{
    u64 addr = ctx->di + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl6_merge_options+0x42")
int BPF_KPROBE(do_mov_877)
{
    u64 addr = ctx->di + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl_release+0x8c")
int BPF_KPROBE(do_mov_878)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl_release+0x72")
int BPF_KPROBE(do_mov_879)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl6_renew+0x6b")
int BPF_KPROBE(do_mov_880)
{
    u64 addr = ctx->r13 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl6_renew+0x82")
int BPF_KPROBE(do_mov_881)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl_create+0x1ab")
int BPF_KPROBE(do_mov_882)
{
    u64 addr = ctx->r14 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl_create+0x15e")
int BPF_KPROBE(do_mov_883)
{
    u64 addr = ctx->r14 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fl_create+0x23b")
int BPF_KPROBE(do_mov_884)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_fl_gc+0x87")
int BPF_KPROBE(do_mov_885)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_flowlabel_net_exit+0x50")
int BPF_KPROBE(do_mov_886)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt_get+0xb2")
int BPF_KPROBE(do_mov_887)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt_get+0xfb")
int BPF_KPROBE(do_mov_888)
{
    u64 addr = ctx->r13 + 0x1a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt+0x3e4")
int BPF_KPROBE(do_mov_889)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt+0x4f3")
int BPF_KPROBE(do_mov_890)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt+0x4ff")
int BPF_KPROBE(do_mov_891)
{
    u64 addr = ctx->r12 + 0x4e;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt+0x6ee")
int BPF_KPROBE(do_mov_892)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt+0x6e2")
int BPF_KPROBE(do_mov_893)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt+0x737")
int BPF_KPROBE(do_mov_894)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_req+0x5b")
int BPF_KPROBE(do_mov_895)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_req+0xce")
int BPF_KPROBE(do_mov_896)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_req+0x63")
int BPF_KPROBE(do_mov_897)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_addr2sockaddr+0xb")
int BPF_KPROBE(do_mov_898)
{
    u64 addr = ctx->si;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_addr2sockaddr+0x23")
int BPF_KPROBE(do_mov_899)
{
    u64 addr = ctx->si + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_socket+0xc5")
int BPF_KPROBE(do_mov_900)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_socket+0xdd")
int BPF_KPROBE(do_mov_901)
{
    u64 addr = ctx->r12 + 0x56;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_socket+0x1ca")
int BPF_KPROBE(do_mov_902)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/inet6_csk_route_socket+0x1bb")
int BPF_KPROBE(do_mov_903)
{
    u64 addr = ctx->r14 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_ufo_fragment+0x226")
int BPF_KPROBE(do_mov_904)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_gro_receive+0x2b9")
int BPF_KPROBE(do_mov_905)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_gro_receive+0x36f")
int BPF_KPROBE(do_mov_906)
{
    u64 addr = ctx->r12 + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_genl_dumphmac+0x127")
int BPF_KPROBE(do_mov_907)
{
    u64 addr = ctx->bx - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_genl_get_tunsrc+0xa8")
int BPF_KPROBE(do_mov_908)
{
    u64 addr = ctx->r13 - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_genl_sethmac+0x147")
int BPF_KPROBE(do_mov_909)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_genl_sethmac+0x14e")
int BPF_KPROBE(do_mov_910)
{
    u64 addr = ctx->bx + 0x5d;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/call_fib6_notifier+0x6")
int BPF_KPROBE(do_mov_911)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/call_fib6_notifiers+0x6")
int BPF_KPROBE(do_mov_912)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x27")
int BPF_KPROBE(do_mov_913)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x49")
int BPF_KPROBE(do_mov_914)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x93")
int BPF_KPROBE(do_mov_915)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0xf1")
int BPF_KPROBE(do_mov_916)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x108")
int BPF_KPROBE(do_mov_917)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x10e")
int BPF_KPROBE(do_mov_918)
{
    u64 addr = ctx->ax + ctx->cx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x11c")
int BPF_KPROBE(do_mov_919)
{
    u64 addr = ctx->ax + ctx->cx * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x12a")
int BPF_KPROBE(do_mov_920)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress+0x130")
int BPF_KPROBE(do_mov_921)
{
    u64 addr = ctx->ax + ctx->dx * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress+0x3b")
int BPF_KPROBE(do_mov_922)
{
    u64 addr = ctx->di - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress+0x44")
int BPF_KPROBE(do_mov_923)
{
    u64 addr = ctx->di + ctx->ax * 0x1 - 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress+0x6a")
int BPF_KPROBE(do_mov_924)
{
    u64 addr = ctx->di + ctx->dx * 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress+0x7b")
int BPF_KPROBE(do_mov_925)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress+0x81")
int BPF_KPROBE(do_mov_926)
{
    u64 addr = ctx->di + ctx->ax * 0x1 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress+0x8c")
int BPF_KPROBE(do_mov_927)
{
    u64 addr = ctx->di + ctx->ax * 0x1 - 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_decompress+0x40")
int BPF_KPROBE(do_mov_928)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_decompress+0x4e")
int BPF_KPROBE(do_mov_929)
{
    u64 addr = ctx->bx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_compress+0xba")
int BPF_KPROBE(do_mov_930)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_compress+0xf7")
int BPF_KPROBE(do_mov_931)
{
    u64 addr = ctx->r12 + 0x5;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpns+0x15c")
int BPF_KPROBE(do_mov_932)
{
    u64 addr = ctx->bx - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpsc+0x109")
int BPF_KPROBE(do_mov_933)
{
    u64 addr = ctx->r13 - 0x14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_genl_addsc+0x3f4")
int BPF_KPROBE(do_mov_934)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_genl_addsc+0x196")
int BPF_KPROBE(do_mov_935)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_genl_addns+0x3d4")
int BPF_KPROBE(do_mov_936)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_genl_addns+0x194")
int BPF_KPROBE(do_mov_937)
{
    u64 addr = ctx->r14 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0xde")
int BPF_KPROBE(do_mov_938)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x178")
int BPF_KPROBE(do_mov_939)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x1b9")
int BPF_KPROBE(do_mov_940)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x1c9")
int BPF_KPROBE(do_mov_941)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x1e5")
int BPF_KPROBE(do_mov_942)
{
    u64 addr = ctx->r12 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x20f")
int BPF_KPROBE(do_mov_943)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x21f")
int BPF_KPROBE(do_mov_944)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x258")
int BPF_KPROBE(do_mov_945)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x29d")
int BPF_KPROBE(do_mov_946)
{
    u64 addr = ctx->r12 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x2aa")
int BPF_KPROBE(do_mov_947)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x2be")
int BPF_KPROBE(do_mov_948)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x2d2")
int BPF_KPROBE(do_mov_949)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x2e6")
int BPF_KPROBE(do_mov_950)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x2fa")
int BPF_KPROBE(do_mov_951)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x316")
int BPF_KPROBE(do_mov_952)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x32a")
int BPF_KPROBE(do_mov_953)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x33e")
int BPF_KPROBE(do_mov_954)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x352")
int BPF_KPROBE(do_mov_955)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x366")
int BPF_KPROBE(do_mov_956)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x38f")
int BPF_KPROBE(do_mov_957)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x3e4")
int BPF_KPROBE(do_mov_958)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x437")
int BPF_KPROBE(do_mov_959)
{
    u64 addr = ctx->r12 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x480")
int BPF_KPROBE(do_mov_960)
{
    u64 addr = ctx->r12 - 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data+0x55a")
int BPF_KPROBE(do_mov_961)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_sysctl_net_init+0x91")
int BPF_KPROBE(do_mov_962)
{
    u64 addr = ctx->bx + 0x680;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_sysctl_net_init+0xcd")
int BPF_KPROBE(do_mov_963)
{
    u64 addr = ctx->bx + 0x690;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rule_action+0x68")
int BPF_KPROBE(do_mov_964)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/reg_vif_setup+0x2b")
int BPF_KPROBE(do_mov_965)
{
    u64 addr = ctx->di + 0xc0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/reg_vif_setup+0x40")
int BPF_KPROBE(do_mov_966)
{
    u64 addr = ctx->di + 0x524;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_fib_lookup+0x7a")
int BPF_KPROBE(do_mov_967)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_destroy_unres+0x6d")
int BPF_KPROBE(do_mov_968)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds+0x9")
int BPF_KPROBE(do_mov_969)
{
    u64 addr = ctx->si + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds+0x2c")
int BPF_KPROBE(do_mov_970)
{
    u64 addr = ctx->si + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds+0x77")
int BPF_KPROBE(do_mov_971)
{
    u64 addr = ctx->r8 + ctx->ax * 0x1 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds+0x84")
int BPF_KPROBE(do_mov_972)
{
    u64 addr = ctx->r8 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds+0x8e")
int BPF_KPROBE(do_mov_973)
{
    u64 addr = ctx->r8 + 0x24;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds+0xa6")
int BPF_KPROBE(do_mov_974)
{
    u64 addr = ctx->r8 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start+0x37")
int BPF_KPROBE(do_mov_975)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start+0x48")
int BPF_KPROBE(do_mov_976)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pim6_rcv+0x205")
int BPF_KPROBE(do_mov_977)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/pim6_rcv+0x1a3")
int BPF_KPROBE(do_mov_978)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_fill_mroute+0x141")
int BPF_KPROBE(do_mov_979)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_fill_mroute+0xcf")
int BPF_KPROBE(do_mov_980)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipmr_do_expire_process+0x5c")
int BPF_KPROBE(do_mov_981)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0xb7")
int BPF_KPROBE(do_mov_982)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0xd6")
int BPF_KPROBE(do_mov_983)
{
    u64 addr = ctx->dx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0xff")
int BPF_KPROBE(do_mov_984)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x105")
int BPF_KPROBE(do_mov_985)
{
    u64 addr = ctx->ax + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x10e")
int BPF_KPROBE(do_mov_986)
{
    u64 addr = ctx->ax + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x12f")
int BPF_KPROBE(do_mov_987)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x155")
int BPF_KPROBE(do_mov_988)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x180")
int BPF_KPROBE(do_mov_989)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x1a5")
int BPF_KPROBE(do_mov_990)
{
    u64 addr = ctx->r15 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x3de")
int BPF_KPROBE(do_mov_991)
{
    u64 addr = ctx->cx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x429")
int BPF_KPROBE(do_mov_992)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_report+0x514")
int BPF_KPROBE(do_mov_993)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_unresolved+0xfa")
int BPF_KPROBE(do_mov_994)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_cache_unresolved+0x10d")
int BPF_KPROBE(do_mov_995)
{
    u64 addr = ctx->bx + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rtm_getroute+0x307")
int BPF_KPROBE(do_mov_996)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rtm_getroute+0x335")
int BPF_KPROBE(do_mov_997)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rtm_getroute+0x36d")
int BPF_KPROBE(do_mov_998)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rtm_getroute+0x396")
int BPF_KPROBE(do_mov_999)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_delete+0x124")
int BPF_KPROBE(do_mov_1000)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mroute_clean_tables+0x157")
int BPF_KPROBE(do_mov_1001)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/mroute_clean_tables+0x34d")
int BPF_KPROBE(do_mov_1002)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rules_exit+0x64")
int BPF_KPROBE(do_mov_1003)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_rules_exit+0x67")
int BPF_KPROBE(do_mov_1004)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_net_init+0x67")
int BPF_KPROBE(do_mov_1005)
{
    u64 addr = ctx->bx + 0x888;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_net_init+0x38")
int BPF_KPROBE(do_mov_1006)
{
    u64 addr = ctx->bx + 0x8b8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_forward2.isra.0+0xd3")
int BPF_KPROBE(do_mov_1007)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_forward2.isra.0+0xf8")
int BPF_KPROBE(do_mov_1008)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_forward2.isra.0+0x122")
int BPF_KPROBE(do_mov_1009)
{
    u64 addr = ctx->ax + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_forward2.isra.0+0x10f")
int BPF_KPROBE(do_mov_1010)
{
    u64 addr = ctx->ax + 0x90;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mr_forward+0xfc")
int BPF_KPROBE(do_mov_1011)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mr_forward+0x6d")
int BPF_KPROBE(do_mov_1012)
{
    u64 addr = ctx->r13 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x2c5")
int BPF_KPROBE(do_mov_1013)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x10f")
int BPF_KPROBE(do_mov_1014)
{
    u64 addr = ctx->r13 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x569")
int BPF_KPROBE(do_mov_1015)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x5cc")
int BPF_KPROBE(do_mov_1016)
{
    u64 addr = ctx->bx + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x57e")
int BPF_KPROBE(do_mov_1017)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x5e9")
int BPF_KPROBE(do_mov_1018)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x638")
int BPF_KPROBE(do_mov_1019)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x6a6")
int BPF_KPROBE(do_mov_1020)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x77d")
int BPF_KPROBE(do_mov_1021)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add+0x792")
int BPF_KPROBE(do_mov_1022)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mroute_setsockopt+0x64f")
int BPF_KPROBE(do_mov_1023)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mroute_setsockopt+0x492")
int BPF_KPROBE(do_mov_1024)
{
    u64 addr = ctx->r12 + 0xe14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_mroute_getsockopt+0xfa")
int BPF_KPROBE(do_mov_1025)
{
    u64 addr = ctx->r14;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_get_route+0x1c5")
int BPF_KPROBE(do_mov_1026)
{
    u64 addr = ctx->r15 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_get_route+0x1f9")
int BPF_KPROBE(do_mov_1027)
{
    u64 addr = ctx->r15 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_get_route+0x218")
int BPF_KPROBE(do_mov_1028)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6mr_get_route+0x23c")
int BPF_KPROBE(do_mov_1029)
{
    u64 addr = ctx->cx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_net_init+0x60")
int BPF_KPROBE(do_mov_1030)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_net_init+0x46")
int BPF_KPROBE(do_mov_1031)
{
    u64 addr = ctx->di + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_fill_dst+0x1a")
int BPF_KPROBE(do_mov_1032)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_fill_dst+0xe6")
int BPF_KPROBE(do_mov_1033)
{
    u64 addr = ctx->r12 + 0x7c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_fill_dst+0xb9")
int BPF_KPROBE(do_mov_1034)
{
    u64 addr = ctx->r12 + 0x128;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_transport_finish+0x1bb")
int BPF_KPROBE(do_mov_1035)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_transport_finish+0x1f7")
int BPF_KPROBE(do_mov_1036)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_udp_encap_rcv+0xf3")
int BPF_KPROBE(do_mov_1037)
{
    u64 addr = ctx->r12 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_udp_encap_rcv+0x113")
int BPF_KPROBE(do_mov_1038)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_rcv_encap+0xc0")
int BPF_KPROBE(do_mov_1039)
{
    u64 addr = ctx->r14 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_rcv_encap+0x1b8")
int BPF_KPROBE(do_mov_1040)
{
    u64 addr = ctx->r14 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_protocol_register+0x8c")
int BPF_KPROBE(do_mov_1041)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/xfrm6_protocol_deregister+0xa4")
int BPF_KPROBE(do_mov_1042)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__nf_ip6_route+0x32")
int BPF_KPROBE(do_mov_1043)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_me_harder+0x19e")
int BPF_KPROBE(do_mov_1044)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_route_me_harder+0x1be")
int BPF_KPROBE(do_mov_1045)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/br_ip6_fragment+0x23b")
int BPF_KPROBE(do_mov_1046)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/br_ip6_fragment+0x27a")
int BPF_KPROBE(do_mov_1047)
{
    u64 addr = ctx->cx + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_rule_fill+0x18")
int BPF_KPROBE(do_mov_1048)
{
    u64 addr = ctx->dx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_rule_fill+0x2b")
int BPF_KPROBE(do_mov_1049)
{
    u64 addr = ctx->dx + 0x3;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_rule_configure+0x165")
int BPF_KPROBE(do_mov_1050)
{
    u64 addr = ctx->bx + 0x98;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_rule_configure+0x13c")
int BPF_KPROBE(do_mov_1051)
{
    u64 addr = ctx->bx + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/fib6_rule_configure+0x1d3")
int BPF_KPROBE(do_mov_1052)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__cookie_v6_init_sequence+0x56")
int BPF_KPROBE(do_mov_1053)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cookie_v6_check+0x27c")
int BPF_KPROBE(do_mov_1054)
{
    u64 addr = ctx->r15 + 0xc;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/cookie_v6_check+0x3f4")
int BPF_KPROBE(do_mov_1055)
{
    u64 addr = ctx->r15 + 0x120;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_cache_invalidate+0x5f")
int BPF_KPROBE(do_mov_1056)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_genopt+0x118")
int BPF_KPROBE(do_mov_1057)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_genopt+0x11e")
int BPF_KPROBE(do_mov_1058)
{
    u64 addr = ctx->bx + 0x1;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_genopt+0x142")
int BPF_KPROBE(do_mov_1059)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_cache_add+0x90")
int BPF_KPROBE(do_mov_1060)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_cache_add+0xbb")
int BPF_KPROBE(do_mov_1061)
{
    u64 addr = ctx->r12 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_cache_add+0x131")
int BPF_KPROBE(do_mov_1062)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_cache_add+0x13e")
int BPF_KPROBE(do_mov_1063)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_find+0xab")
int BPF_KPROBE(do_mov_1064)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_find+0xb3")
int BPF_KPROBE(do_mov_1065)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_find+0xdb")
int BPF_KPROBE(do_mov_1066)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_find+0xf8")
int BPF_KPROBE(do_mov_1067)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_del+0x95")
int BPF_KPROBE(do_mov_1068)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_del+0x117")
int BPF_KPROBE(do_mov_1069)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_insert+0x11b")
int BPF_KPROBE(do_mov_1070)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_doi_remove+0x7d")
int BPF_KPROBE(do_mov_1071)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/calipso_opt_getattr+0x180")
int BPF_KPROBE(do_mov_1072)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/set_tun_src+0x42")
int BPF_KPROBE(do_mov_1073)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_build_state+0x113")
int BPF_KPROBE(do_mov_1074)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_build_state+0x11d")
int BPF_KPROBE(do_mov_1075)
{
    u64 addr = ctx->r13 + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_build_state+0x153")
int BPF_KPROBE(do_mov_1076)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x14d")
int BPF_KPROBE(do_mov_1077)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x154")
int BPF_KPROBE(do_mov_1078)
{
    u64 addr = ctx->r9 + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x158")
int BPF_KPROBE(do_mov_1079)
{
    u64 addr = ctx->r9 + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x16f")
int BPF_KPROBE(do_mov_1080)
{
    u64 addr = ctx->r9 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x18f")
int BPF_KPROBE(do_mov_1081)
{
    u64 addr = ctx->r9 + ctx->ax * 0x1 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x23a")
int BPF_KPROBE(do_mov_1082)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x1a7")
int BPF_KPROBE(do_mov_1083)
{
    u64 addr = ctx->r9 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x259")
int BPF_KPROBE(do_mov_1084)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap+0x300")
int BPF_KPROBE(do_mov_1085)
{
    u64 addr = ctx->r15 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_inline+0x1c9")
int BPF_KPROBE(do_mov_1086)
{
    u64 addr = ctx->r13 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_inline+0x182")
int BPF_KPROBE(do_mov_1087)
{
    u64 addr = ctx->r13 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_inline+0x234")
int BPF_KPROBE(do_mov_1088)
{
    u64 addr = ctx->bx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_inline+0x25b")
int BPF_KPROBE(do_mov_1089)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x171")
int BPF_KPROBE(do_mov_1090)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x1d7")
int BPF_KPROBE(do_mov_1091)
{
    u64 addr = ctx->r9 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x202")
int BPF_KPROBE(do_mov_1092)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x292")
int BPF_KPROBE(do_mov_1093)
{
    u64 addr = ctx->r9;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x230")
int BPF_KPROBE(do_mov_1094)
{
    u64 addr = ctx->r9 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x2b1")
int BPF_KPROBE(do_mov_1095)
{
    u64 addr = ctx->r15 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x2c1")
int BPF_KPROBE(do_mov_1096)
{
    u64 addr = ctx->r15 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x430")
int BPF_KPROBE(do_mov_1097)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x44e")
int BPF_KPROBE(do_mov_1098)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x45d")
int BPF_KPROBE(do_mov_1099)
{
    u64 addr = ctx->r11;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red+0x47b")
int BPF_KPROBE(do_mov_1100)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh+0x110")
int BPF_KPROBE(do_mov_1101)
{
    u64 addr = ctx->bx + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_do_srh+0x81")
int BPF_KPROBE(do_mov_1102)
{
    u64 addr = ctx->bx + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__seg6_end_dt_vrf_build+0x41")
int BPF_KPROBE(do_mov_1103)
{
    u64 addr = ctx->bx + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__seg6_end_dt_vrf_build+0x3c")
int BPF_KPROBE(do_mov_1104)
{
    u64 addr = ctx->bx + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__seg6_end_dt_vrf_build+0xbd")
int BPF_KPROBE(do_mov_1105)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_end_dt6_build+0x66")
int BPF_KPROBE(do_mov_1106)
{
    u64 addr = ctx->dx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decap_and_validate+0x8f")
int BPF_KPROBE(do_mov_1107)
{
    u64 addr = ctx->bx + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/decap_and_validate+0x92")
int BPF_KPROBE(do_mov_1108)
{
    u64 addr = ctx->bx + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/end_dt_vrf_core+0x18a")
int BPF_KPROBE(do_mov_1109)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/end_dt_vrf_core+0x110")
int BPF_KPROBE(do_mov_1110)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_nla_flavors+0x6e")
int BPF_KPROBE(do_mov_1111)
{
    u64 addr = ctx->r12 + 0x60;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_nla_flavors+0xde")
int BPF_KPROBE(do_mov_1112)
{
    u64 addr = ctx->r12 + 0x65;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/parse_nla_flavors+0x143")
int BPF_KPROBE(do_mov_1113)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/put_nla_flavors+0x94")
int BPF_KPROBE(do_mov_1114)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_dx4_finish+0x93")
int BPF_KPROBE(do_mov_1115)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_dx4_finish+0xeb")
int BPF_KPROBE(do_mov_1116)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_dx2+0x12c")
int BPF_KPROBE(do_mov_1117)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_dx2+0x5d")
int BPF_KPROBE(do_mov_1118)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_dx4+0x94")
int BPF_KPROBE(do_mov_1119)
{
    u64 addr = ctx->r12 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_dx4+0x73")
int BPF_KPROBE(do_mov_1120)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end+0x120")
int BPF_KPROBE(do_mov_1121)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end+0x133")
int BPF_KPROBE(do_mov_1122)
{
    u64 addr = ctx->r8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_b6_encap+0x8a")
int BPF_KPROBE(do_mov_1123)
{
    u64 addr = ctx->r12 + 0xae;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_b6_encap+0xe6")
int BPF_KPROBE(do_mov_1124)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_local_build_state+0x263")
int BPF_KPROBE(do_mov_1125)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_local_build_state+0x22b")
int BPF_KPROBE(do_mov_1126)
{
    u64 addr = ctx->r12 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_bpf+0x9e")
int BPF_KPROBE(do_mov_1127)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_bpf+0xa6")
int BPF_KPROBE(do_mov_1128)
{
    u64 addr = ctx->bx + 0xa;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_bpf+0x233")
int BPF_KPROBE(do_mov_1129)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_bpf+0xeb")
int BPF_KPROBE(do_mov_1130)
{
    u64 addr = ctx->r12 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_bpf+0x272")
int BPF_KPROBE(do_mov_1131)
{
    u64 addr = ctx->r12 + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/input_action_end_bpf+0x285")
int BPF_KPROBE(do_mov_1132)
{
    u64 addr = ctx->r12 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x76")
int BPF_KPROBE(do_mov_1133)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x8f")
int BPF_KPROBE(do_mov_1134)
{
    u64 addr = ctx->r12 + 0x12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0xb5")
int BPF_KPROBE(do_mov_1135)
{
    u64 addr = ctx->ax - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x18f")
int BPF_KPROBE(do_mov_1136)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x1c6")
int BPF_KPROBE(do_mov_1137)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x1d5")
int BPF_KPROBE(do_mov_1138)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x1e1")
int BPF_KPROBE(do_mov_1139)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x1e9")
int BPF_KPROBE(do_mov_1140)
{
    u64 addr = ctx->bx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x20b")
int BPF_KPROBE(do_mov_1141)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x24d")
int BPF_KPROBE(do_mov_1142)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x258")
int BPF_KPROBE(do_mov_1143)
{
    u64 addr = ctx->bx + ctx->ax * 0x1 - 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_compute+0x2b7")
int BPF_KPROBE(do_mov_1144)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_push_hmac+0x7b")
int BPF_KPROBE(do_mov_1145)
{
    u64 addr = ctx->cx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_push_hmac+0x8b")
int BPF_KPROBE(do_mov_1146)
{
    u64 addr = ctx->cx + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_info_add+0x1a2")
int BPF_KPROBE(do_mov_1147)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_info_del+0x162")
int BPF_KPROBE(do_mov_1148)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/seg6_hmac_info_del+0x2ae")
int BPF_KPROBE(do_mov_1149)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x1f7")
int BPF_KPROBE(do_mov_1150)
{
    u64 addr = ctx->r15 + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x1ff")
int BPF_KPROBE(do_mov_1151)
{
    u64 addr = ctx->r15 + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x203")
int BPF_KPROBE(do_mov_1152)
{
    u64 addr = ctx->r15 + 0x44;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x207")
int BPF_KPROBE(do_mov_1153)
{
    u64 addr = ctx->r15 + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x234")
int BPF_KPROBE(do_mov_1154)
{
    u64 addr = ctx->r15 + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x238")
int BPF_KPROBE(do_mov_1155)
{
    u64 addr = ctx->r15 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x23f")
int BPF_KPROBE(do_mov_1156)
{
    u64 addr = ctx->r15 + 0x62;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x246")
int BPF_KPROBE(do_mov_1157)
{
    u64 addr = ctx->r15 + 0x67;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x24f")
int BPF_KPROBE(do_mov_1158)
{
    u64 addr = ctx->r15 + 0x64;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x257")
int BPF_KPROBE(do_mov_1159)
{
    u64 addr = ctx->r15 + 0x61;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x268")
int BPF_KPROBE(do_mov_1160)
{
    u64 addr = ctx->r15 + 0x65;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x271")
int BPF_KPROBE(do_mov_1161)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x28b")
int BPF_KPROBE(do_mov_1162)
{
    u64 addr = ctx->r15 + ctx->ax * 0x1 + 0x70;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x29a")
int BPF_KPROBE(do_mov_1163)
{
    u64 addr = ctx->r15 + ctx->ax * 0x4 + 0x71;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x2ab")
int BPF_KPROBE(do_mov_1164)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x32b")
int BPF_KPROBE(do_mov_1165)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x376")
int BPF_KPROBE(do_mov_1166)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x3a9")
int BPF_KPROBE(do_mov_1167)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_build_state+0x37d")
int BPF_KPROBE(do_mov_1168)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x2dc")
int BPF_KPROBE(do_mov_1169)
{
    u64 addr = ctx->r12 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x2a8")
int BPF_KPROBE(do_mov_1170)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x2ff")
int BPF_KPROBE(do_mov_1171)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x323")
int BPF_KPROBE(do_mov_1172)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x342")
int BPF_KPROBE(do_mov_1173)
{
    u64 addr = ctx->r15;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x37b")
int BPF_KPROBE(do_mov_1174)
{
    u64 addr = ctx->r15 + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x36a")
int BPF_KPROBE(do_mov_1175)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x4b4")
int BPF_KPROBE(do_mov_1176)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x5d7")
int BPF_KPROBE(do_mov_1177)
{
    u64 addr = ctx->r12 + 0xba;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x662")
int BPF_KPROBE(do_mov_1178)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x68c")
int BPF_KPROBE(do_mov_1179)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x7bd")
int BPF_KPROBE(do_mov_1180)
{
    u64 addr = ctx->r12 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ioam6_output+0x77c")
int BPF_KPROBE(do_mov_1181)
{
    u64 addr = ctx->r12 + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x23a")
int BPF_KPROBE(do_mov_1182)
{
    u64 addr = ctx->r13 + 0x18;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x201")
int BPF_KPROBE(do_mov_1183)
{
    u64 addr = ctx->r13 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x5aa")
int BPF_KPROBE(do_mov_1184)
{
    u64 addr = ctx->r15 + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x59a")
int BPF_KPROBE(do_mov_1185)
{
    u64 addr = ctx->r15 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x897")
int BPF_KPROBE(do_mov_1186)
{
    u64 addr = ctx->r15 + 0x68;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x8a7")
int BPF_KPROBE(do_mov_1187)
{
    u64 addr = ctx->r15 + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x8af")
int BPF_KPROBE(do_mov_1188)
{
    u64 addr = ctx->r13 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_frag6_gather+0x999")
int BPF_KPROBE(do_mov_1189)
{
    u64 addr = ctx->r13 + 0xb6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_net_pre_exit+0x2f")
int BPF_KPROBE(do_mov_1190)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_net_init+0x4e")
int BPF_KPROBE(do_mov_1191)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_net_init+0xcc")
int BPF_KPROBE(do_mov_1192)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_ct_net_init+0xfb")
int BPF_KPROBE(do_mov_1193)
{
    u64 addr = ctx->r12 + 0xb0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6hdr_put+0x56")
int BPF_KPROBE(do_mov_1194)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6hdr_put+0x60")
int BPF_KPROBE(do_mov_1195)
{
    u64 addr = ctx->ax + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6hdr_put+0x84")
int BPF_KPROBE(do_mov_1196)
{
    u64 addr = ctx->ax + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6_tcphdr_put+0x4d")
int BPF_KPROBE(do_mov_1197)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6_tcphdr_put+0x55")
int BPF_KPROBE(do_mov_1198)
{
    u64 addr = ctx->bx + 0x2;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6_tcphdr_put+0x80")
int BPF_KPROBE(do_mov_1199)
{
    u64 addr = ctx->bx + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_ip6_tcphdr_get+0x7b")
int BPF_KPROBE(do_mov_1200)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_tcp_reset+0xf4")
int BPF_KPROBE(do_mov_1201)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_tcp_reset+0x10c")
int BPF_KPROBE(do_mov_1202)
{
    u64 addr = ctx->bx + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_tcp_reset+0x125")
int BPF_KPROBE(do_mov_1203)
{
    u64 addr = ctx->bx + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x1ed")
int BPF_KPROBE(do_mov_1204)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x205")
int BPF_KPROBE(do_mov_1205)
{
    u64 addr = ctx->r15 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x21e")
int BPF_KPROBE(do_mov_1206)
{
    u64 addr = ctx->r15 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x25c")
int BPF_KPROBE(do_mov_1207)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x258")
int BPF_KPROBE(do_mov_1208)
{
    u64 addr = ctx->ax + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x29d")
int BPF_KPROBE(do_mov_1209)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x33d")
int BPF_KPROBE(do_mov_1210)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x35e")
int BPF_KPROBE(do_mov_1211)
{
    u64 addr = ctx->di;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_reject_skb_v6_unreach+0x412")
int BPF_KPROBE(do_mov_1212)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x221")
int BPF_KPROBE(do_mov_1213)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x2b2")
int BPF_KPROBE(do_mov_1214)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x2c6")
int BPF_KPROBE(do_mov_1215)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x2cf")
int BPF_KPROBE(do_mov_1216)
{
    u64 addr = ctx->ax + 0x7;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x2de")
int BPF_KPROBE(do_mov_1217)
{
    u64 addr = ctx->r13 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x2f2")
int BPF_KPROBE(do_mov_1218)
{
    u64 addr = ctx->r13 + 0x20;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x35c")
int BPF_KPROBE(do_mov_1219)
{
    u64 addr = ctx->r12 + 0x10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_send_reset6+0x2fd")
int BPF_KPROBE(do_mov_1220)
{
    u64 addr = ctx->r12 + 0xb4;
    sampling(addr, ctx->ip);
    return 0;
}


// SEC("kprobe/nf_dup_ipv6+0x184")
// int BPF_KPROBE(do_mov_1221)
// {
//     u64 addr = ctx->gs + 0x30790;
//     sampling(addr, ctx->ip);
//     return 0;
// }


SEC("kprobe/nf_dup_ipv6+0x148")
int BPF_KPROBE(do_mov_1222)
{
    u64 addr = ctx->r12 + 0x58;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nf_dup_ipv6+0x176")
int BPF_KPROBE(do_mov_1223)
{
    u64 addr = ctx->r12 + 0x84;
    sampling(addr, ctx->ip);
    return 0;
}


// SEC("kprobe/nf_dup_ipv6+0x1a4")
// int BPF_KPROBE(do_mov_1224)
// {
//     u64 addr = ctx->gs + 0x30790;
//     sampling(addr, ctx->ip);
//     return 0;
// }


SEC("kprobe/nft_reject_ipv6_eval+0x5b")
int BPF_KPROBE(do_mov_1225)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib6_flowi_init+0x39")
int BPF_KPROBE(do_mov_1226)
{
    u64 addr = ctx->di + 0x30;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib6_flowi_init+0x4d")
int BPF_KPROBE(do_mov_1227)
{
    u64 addr = ctx->di + 0x48;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib6_flowi_init+0x72")
int BPF_KPROBE(do_mov_1228)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib6_flowi_init+0xb1")
int BPF_KPROBE(do_mov_1229)
{
    u64 addr = ctx->bx + 0x50;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib6_eval+0x220")
int BPF_KPROBE(do_mov_1230)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/nft_fib6_eval_type+0x8d")
int BPF_KPROBE(do_mov_1231)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/eafnosupport_fib6_nh_init+0x1e")
int BPF_KPROBE(do_mov_1232)
{
    u64 addr = ctx->bx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_skip_exthdr+0x41")
int BPF_KPROBE(do_mov_1233)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_skip_exthdr+0x53")
int BPF_KPROBE(do_mov_1234)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_skip_exthdr+0xf8")
int BPF_KPROBE(do_mov_1235)
{
    u64 addr = ctx->r12;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_find_hdr+0x54")
int BPF_KPROBE(do_mov_1236)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_find_hdr+0x10b")
int BPF_KPROBE(do_mov_1237)
{
    u64 addr = ctx->r10;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_find_hdr+0x338")
int BPF_KPROBE(do_mov_1238)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_find_hdr+0x371")
int BPF_KPROBE(do_mov_1239)
{
    u64 addr = ctx->cx;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_set_csum+0x6e")
int BPF_KPROBE(do_mov_1240)
{
    u64 addr = ctx->ax + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_set_csum+0x79")
int BPF_KPROBE(do_mov_1241)
{
    u64 addr = ctx->ax + 0x8a;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_set_csum+0x98")
int BPF_KPROBE(do_mov_1242)
{
    u64 addr = ctx->bx + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_set_csum+0x98")
int BPF_KPROBE(do_mov_1243)
{
    u64 addr = ctx->bx + 0x6;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_csum_init+0x34")
int BPF_KPROBE(do_mov_1244)
{
    u64 addr = ctx->bx + 0x81;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_csum_init+0xa9")
int BPF_KPROBE(do_mov_1245)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_csum_init+0x163")
int BPF_KPROBE(do_mov_1246)
{
    u64 addr = ctx->di + 0x40;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_csum_init+0x175")
int BPF_KPROBE(do_mov_1247)
{
    u64 addr = ctx->di + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_csum_init+0x1ea")
int BPF_KPROBE(do_mov_1248)
{
    u64 addr = ctx->bx + 0x80;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/udp6_csum_init+0x1ad")
int BPF_KPROBE(do_mov_1249)
{
    u64 addr = ctx->bx + 0x88;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ip6_find_1stfragopt+0xa4")
int BPF_KPROBE(do_mov_1250)
{
    u64 addr = ctx->r13;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gro_complete+0x144")
int BPF_KPROBE(do_mov_1251)
{
    u64 addr = ctx->dx + 0x4;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gro_complete+0x15a")
int BPF_KPROBE(do_mov_1252)
{
    u64 addr = ctx->dx + 0x2c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gso_segment+0xa0")
int BPF_KPROBE(do_mov_1253)
{
    u64 addr = ctx->bx + 0x4c;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gso_segment+0x46")
int BPF_KPROBE(do_mov_1254)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gso_segment+0x195")
int BPF_KPROBE(do_mov_1255)
{
    u64 addr = ctx->bx + 0x78;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gso_segment+0x187")
int BPF_KPROBE(do_mov_1256)
{
    u64 addr = ctx->bx + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gro_receive+0x6a")
int BPF_KPROBE(do_mov_1257)
{
    u64 addr = ctx->r12 + 0x34;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gro_receive+0x71")
int BPF_KPROBE(do_mov_1258)
{
    u64 addr = ctx->r12 + 0xb8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gro_receive+0x28e")
int BPF_KPROBE(do_mov_1259)
{
    u64 addr = ctx->r12 + 0x28;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/ipv6_gro_receive+0x286")
int BPF_KPROBE(do_mov_1260)
{
    u64 addr = ctx->r12 + 0xd0;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp6_gro_receive+0xe8")
int BPF_KPROBE(do_mov_1261)
{
    u64 addr = ctx->r12 + 0x38;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/tcp6_gro_receive+0x18c")
int BPF_KPROBE(do_mov_1262)
{
    u64 addr = ctx->r12 + 0x82;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_check_established+0x108")
int BPF_KPROBE(do_mov_1263)
{
    u64 addr = ctx->r12 + 0x8;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_check_established+0xff")
int BPF_KPROBE(do_mov_1264)
{
    u64 addr = ctx->r12 + 0x320;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_check_established+0x17f")
int BPF_KPROBE(do_mov_1265)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}


SEC("kprobe/__inet6_check_established+0x2a9")
int BPF_KPROBE(do_mov_1266)
{
    u64 addr = ctx->ax;
    sampling(addr, ctx->ip);
    return 0;
}
