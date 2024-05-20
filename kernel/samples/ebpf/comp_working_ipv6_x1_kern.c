
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "comp_header.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct visited {
	unsigned long call_site;  // call_site in slab, used ip in buddy.
	unsigned long times;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819);
	__type(key, u64);
	__type(value, u64);
} ml_record SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819);
	__type(key, u64);
	__type(value, u64);
} cfg SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64);
	__type(value, u64);
} private_stk SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819);
	__type(key, u64);
	__type(value, u64);
} slabcaches SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819);
	__type(key, u64);
	__type(value, u64);
} vmalloc_objs SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 819);
	__type(key, u64);
	__type(value, struct visited);
} buddy_objs SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 6 * sizeof(u64));
	__uint(max_entries, 100);
} stackmap SEC(".maps");

struct hmap_elem {
	// int pad; /* unused */
	struct bpf_timer timer;
};

struct inner_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct hmap_elem);
} inner_htab SEC(".maps");

#define ARRAY_KEY 1
#define HASH_KEY 1234

struct outer_arr {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 100);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__array(values, struct inner_map);
} outer_arr SEC(".maps") = {
	.values = { [ARRAY_KEY] = &inner_htab },
};

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

u64 cache4k = 0;
u64 cache8k = 0;

u64 INTERVAL = 60 * (u64)1000000000;
bool initialized = false;
bool ML_enable = true;

static int timer_sweep(void *map, int *key, struct hmap_elem *val)
{
	// bpf_printk("=============ML policy disabled=============\n");
	// ML_enable = false;
	return 0;
}
#define ___GFP_DMA		0x01u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_ACCOUNT		0x400000u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_DIRECT_RECLAIM	0x400u
#define ___GFP_KSWAPD_RECLAIM	0x800u
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
// #define SLAB_KMALLOC		(0x00001000U)
// #define SLAB_HWCACHE_ALIGN	(0x00002000U)
// #define SLAB_CACHE_DMA		(0x00004000U)
// #define SLAB_CACHE_DMA32	(0x00008000U)
/* DEBUG: Store the last owner for bug hunting */

#define GFP_KERNEL  (___GFP_IO|___GFP_FS|___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM)

u32 get_zone(u32 gfp_flags)
{
	u32 ret = 0;
	if (gfp_flags & ___GFP_DMA) {
		ret = 1;
	} else if (gfp_flags & ___GFP_RECLAIMABLE) {
		ret = 2;
	} else if (gfp_flags & ___GFP_ACCOUNT) {
		ret = 3;
	}
	return ret;
}


int init(void)
{
	int err = 0;
    struct hmap_elem init = {};
	struct bpf_map *inner_map;
	struct hmap_elem *val;
	int array_key = ARRAY_KEY;
	int hash_key = HASH_KEY;
	inner_map = bpf_map_lookup_elem(&outer_arr, &array_key);
    if (!inner_map)
        return 0;
    bpf_map_update_elem(inner_map, &hash_key, &init, 0);
    val = bpf_map_lookup_elem(inner_map, &hash_key);
    if (!val)
        return 0;
    bpf_timer_init(&(val->timer), inner_map, CLOCK_REALTIME);
    err = bpf_timer_set_callback(&val->timer, timer_sweep);
    if (err < 0) {
        bpf_printk("bpf_timer_set_callback failed\n");
        return err;
    }
    err = bpf_timer_start(&val->timer, INTERVAL, 0);
    if (err < 0) {
        bpf_printk("bpf_timer_start failed\n");
        return err;
    }
	cache8k = bpf_create_slab_cache(8192, SLAB_KMALLOC|SLAB_HWCACHE_ALIGN, 0);
	u64 v = 1;
	u64 k = 0xffff888101926500;
	bpf_map_update_elem(&slabcaches, &k, &v, BPF_ANY);
	k = 0xffff8881001fa000;
	bpf_map_update_elem(&slabcaches, &k, &v, BPF_ANY);
	k = 0xffff888101926d00;
	bpf_map_update_elem(&slabcaches, &k, &v, BPF_ANY);
	k = 0xffff8881001fa500;
	bpf_map_update_elem(&slabcaches, &k, &v, BPF_ANY);
	k = 0xffff8881001fb300;
	bpf_map_update_elem(&slabcaches, &k, &v, BPF_ANY);

	return 0;
}

u32 getsize(u32 sz) {
	return sz <= 4096 ? 4096 : 8192;
}

u32 getcache(u32 sz) {
	return sz <= 4096 ? cache4k : cache8k;
}

struct page *start_page = (struct page *) 0xffffea0000000000;
SEC("tp/kmem/mm_page_alloc")
int handle_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	struct page *curr = start_page+ctx->pfn;
	u64 k = (u64) bpf_page_to_virt((u64) curr);
	u64 stkid = (u64) bpf_get_stackid(ctx, &stackmap, KERN_STACKID_FLAGS);
	struct visited v = {stkid, 0};
	
	if (stkid == 0xf666 || stkid == 0x57b5 || stkid == 2 || stkid == 3) {
		bpf_map_update_elem(&buddy_objs, &k, &v, BPF_ANY);
	}

	return 0;
}


SEC("tp/kmem/mm_page_free")
int handle_mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	struct event *e;
	struct page *curr = (struct page *) start_page+ctx->pfn;
	u64 k = (u64) bpf_page_to_virt((u64) curr);
	bpf_map_delete_elem(&buddy_objs, &k);

	if (ML_enable) {
		u64 *pv = bpf_map_lookup_elem(&ml_record, &k);
		if (pv == NULL) return 0;
		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
		if (!e)
			return 0;
		e->alloc_addr = k;
		e->cache_addr = *pv;
		e->sz = ((u64) 1 << ctx->order) * (u64) 4096;
		bpf_core_read(e->content, getsize(e->sz), k);
		bpf_ringbuf_submit(e, 0);
		bpf_map_delete_elem(&ml_record, &k);
	}

	return 0;
}



SEC("tp/kmem/kfree")
int handle_mm_kfree(struct trace_event_raw_kfree *ctx)
{
	struct event *e;
	if (ML_enable) {
		// if (++cnt_slab % 1000000 == 0)
		// 	bpf_printk("slab: %lu allocated\n", cnt_slab);
		u64 k = (u64) (ctx->ptr);
		u64 *pv = bpf_map_lookup_elem(&ml_record, &k);
		if (pv == NULL) return 0;
		struct kmem_cache *s = bpf_get_slab_cache(k);
		if (s == NULL) return 0;

		e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
		if (!e)
			return 0;
		e->alloc_addr = k;
		e->cache_addr = (u64) s;
		// u64 name_addr = (u64)BPF_CORE_READ(s, name);
		e->sz = BPF_CORE_READ(s, size);
		// bpf_core_read(e->cache, 32, name_addr);
		bpf_core_read(e->content, getsize(e->sz), k);
		
		bpf_ringbuf_submit(e, 0);
		bpf_map_delete_elem(&ml_record, &k);
	}

	return 0;
}


int check(u64 addr)
{
	u64 val = 1;
    if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {
        struct kmem_cache *s = (struct kmem_cache *)bpf_get_slab_cache(addr);
        if (s) {
            u64 *pv = bpf_map_lookup_elem(&slabcaches, &s);
            if (pv) {}
            else if (ML_enable) {
                u64 start = bpf_get_slab_start(addr);
                bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
            } else { /* error happens */ }
        } else {
            u64 k = bpf_get_slab_start(addr);
            u64 *pv = bpf_map_lookup_elem(&buddy_objs, &k);
            if (pv) {}
            else if (ML_enable) {
                bpf_map_update_elem(&ml_record, &k, &val, BPF_ANY);
            } else { /* error happens */ }
        }
    } else if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {
        
    } else if (addr >= 0xffffc90000000000 && addr <= 0xffffe8ffffffffff) {
        struct vm_struct *vms = (struct vm_struct *)bpf_get_vm_struct(addr);
        u64 caller = BPF_CORE_READ(vms, caller);
        u64 *pv = bpf_map_lookup_elem(&vmalloc_objs, &pv);
        if (pv) {}
        else { /* error happens */ }
    } else { /* error happens */ }
	return 0;
}




SEC("kprobe/kfree")
int BPF_KPROBE(do_bio)
{
	// bpf_printk("ip: %016lx\n", ctx->ip);
	if (!initialized) {
		init();
		initialized = true;
	}
	return 0;
}


// ======================================================================================================================


SEC("kprobe/ip6_frag_init+0x10")
int BPF_KPROBE(do_mov_general_1)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_frag_init+0x17")
int BPF_KPROBE(do_mov_general_2)
{
    u64 addr = ctx->ax + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_frag_init+0x1a")
int BPF_KPROBE(do_mov_general_3)
{
    u64 addr = ctx->ax + 0x28;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_cork_release+0x4c")
int BPF_KPROBE(do_mov_general_4)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_cork_release+0x5d")
int BPF_KPROBE(do_switch_6)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_cork_release+0x62")
int BPF_KPROBE(do_switch_7)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames+0x42")
int BPF_KPROBE(do_mov_general_5)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames+0x4d")
int BPF_KPROBE(do_mov_general_6)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x64")
int BPF_KPROBE(do_switch_11)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x69")
int BPF_KPROBE(do_switch_12)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x12f")
int BPF_KPROBE(do_mov_general_7)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x14d")
int BPF_KPROBE(do_switch_14)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x152")
int BPF_KPROBE(do_switch_15)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x15e")
int BPF_KPROBE(do_switch_16)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel+0x163")
int BPF_KPROBE(do_switch_17)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xa7")
int BPF_KPROBE(do_switch_21)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xac")
int BPF_KPROBE(do_switch_22)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xac")
int BPF_KPROBE(do_mov_general_8)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0xde")
int BPF_KPROBE(do_mov_stk_9)
{
    u64 addr = bpf_get_slab_start(ctx->r12);
    u64 *pv = bpf_map_lookup_elem(&buddy_objs, &addr);
    if (pv) {}
    else {
        if (ML_enable) {
            u64 val = 1;
            bpf_map_update_elem(&ml_record, &addr, &val, BPF_ANY);
        } else { /* error happens */ }
    }
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x1fc")
int BPF_KPROBE(do_switch_28)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x201")
int BPF_KPROBE(do_switch_29)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x201")
int BPF_KPROBE(do_mov_general_10)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x21e")
int BPF_KPROBE(do_switch_30)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x223")
int BPF_KPROBE(do_switch_31)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0+0x229")
int BPF_KPROBE(do_mov_general_11)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x2b")
int BPF_KPROBE(do_mov_general_12)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x4a")
int BPF_KPROBE(do_mov_general_13)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x86")
int BPF_KPROBE(do_mov_general_14)
{
    u64 addr = ctx->r14 + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x96")
int BPF_KPROBE(do_mov_general_15)
{
    u64 addr = ctx->r14 + 0x1c;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xb5")
int BPF_KPROBE(do_mov_general_16)
{
    u64 addr = ctx->bx + 0x70;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xc3")
int BPF_KPROBE(do_mov_general_17)
{
    u64 addr = ctx->bx + 0xd0;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xf6")
int BPF_KPROBE(do_mov_general_18)
{
    u64 addr = ctx->r15 - 0x6;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0xfb")
int BPF_KPROBE(do_mov_general_19)
{
    u64 addr = ctx->r15 - 0x7;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_init+0x100")
int BPF_KPROBE(do_mov_general_20)
{
    u64 addr = ctx->r15 - 0x4;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_sk_dst_lookup_flow+0x3e")
int BPF_KPROBE(do_switch_38)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_sk_dst_lookup_flow+0x43")
int BPF_KPROBE(do_switch_39)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_sk_dst_lookup_flow+0xd3")
int BPF_KPROBE(do_switch_40)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_sk_dst_lookup_flow+0xd8")
int BPF_KPROBE(do_switch_41)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x118")
int BPF_KPROBE(do_switch_44)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x11d")
int BPF_KPROBE(do_switch_45)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x1be")
int BPF_KPROBE(do_mov_slab_21)
{
    u64 addr = ctx->dx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/ip6_xmit+0x1eb")
int BPF_KPROBE(do_mov_slab_22)
{
    u64 addr = ctx->dx + 0x20;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/ip6_xmit+0x43b")
int BPF_KPROBE(do_switch_51)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x440")
int BPF_KPROBE(do_switch_52)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x48b")
int BPF_KPROBE(do_switch_54)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x490")
int BPF_KPROBE(do_switch_55)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x4e2")
int BPF_KPROBE(do_switch_56)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x4e7")
int BPF_KPROBE(do_switch_57)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x536")
int BPF_KPROBE(do_switch_58)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x53b")
int BPF_KPROBE(do_switch_59)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x518")
int BPF_KPROBE(do_mov_general_23)
{
    u64 addr = ctx->r12 + 0x81;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_xmit+0x200")
int BPF_KPROBE(do_mov_slab_24)
{
    u64 addr = ctx->r12 + 0xb4;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == 0xffff8881001fa000) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/ip6_xmit+0x556")
int BPF_KPROBE(do_mov_general_25)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_xmit+0x589")
int BPF_KPROBE(do_switch_60)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_xmit+0x58e")
int BPF_KPROBE(do_switch_61)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x269")
int BPF_KPROBE(do_mov_slab_26)
{
    u64 addr = ctx->cx - 0x10;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x26d")
int BPF_KPROBE(do_mov_slab_27)
{
    u64 addr = ctx->cx - 0x8;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x2ac")
int BPF_KPROBE(do_switch_67)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x2b1")
int BPF_KPROBE(do_switch_68)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x2c3")
int BPF_KPROBE(do_switch_69)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x2c8")
int BPF_KPROBE(do_switch_70)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x38a")
int BPF_KPROBE(do_switch_72)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x38f")
int BPF_KPROBE(do_switch_73)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x3f4")
int BPF_KPROBE(do_switch_75)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x3f9")
int BPF_KPROBE(do_switch_76)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x42c")
int BPF_KPROBE(do_switch_77)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x431")
int BPF_KPROBE(do_switch_78)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x498")
int BPF_KPROBE(do_switch_80)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x49d")
int BPF_KPROBE(do_switch_81)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x4dd")
int BPF_KPROBE(do_switch_82)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output2+0x4e2")
int BPF_KPROBE(do_switch_83)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0xa9")
int BPF_KPROBE(do_switch_89)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0xa9")
int BPF_KPROBE(do_hotbpf_89)
{
    if (cache8k == 0) return 0;
	u64 alloc_addr = bpf_cache_alloc(cache8k, ctx->si);
	u64 nxt_ip = (u64)ctx->ip + 4;
    if (alloc_addr == 0 || nxt_ip == 0) return 0;
	struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15;
    x_regs.r14 = ctx->r14;
    x_regs.r13 = ctx->r13;
    x_regs.r12 = ctx->r12;
    x_regs.bp  = ctx->bp;
    x_regs.bx  = ctx->bx;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9;
    x_regs.r8  = ctx->r8;
    x_regs.ax  = alloc_addr;
    x_regs.cx  = ctx->cx;
    x_regs.dx  = ctx->dx;
    x_regs.si  = ctx->si;
    x_regs.di  = ctx->di;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = nxt_ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
	bpf_set_regs(ctx, &x_regs);

	return 0;
}


SEC("kprobe/ip6_setup_cork+0xae")
int BPF_KPROBE(do_switch_90)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0xb5")
int BPF_KPROBE(do_mov_general_28)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0xc1")
int BPF_KPROBE(do_mov_general_29)
{
    u64 addr = ctx->r10 + 0x4;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x14b")
int BPF_KPROBE(do_mov_general_30)
{
    u64 addr = ctx->r10 + 0x28;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x23f")
int BPF_KPROBE(do_mov_general_31)
{
    u64 addr = ctx->bx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x255")
int BPF_KPROBE(do_mov_general_32)
{
    u64 addr = ctx->bx + 0x30;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x35d")
int BPF_KPROBE(do_switch_97)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x362")
int BPF_KPROBE(do_switch_98)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x37b")
int BPF_KPROBE(do_mov_general_33)
{
    u64 addr = ctx->r10 + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_setup_cork+0x367")
int BPF_KPROBE(do_mov_general_34)
{
    u64 addr = ctx->r10 + 0x28;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x2a")
int BPF_KPROBE(do_mov_general_35)
{
    u64 addr = ctx->di + 0x80;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x43")
int BPF_KPROBE(do_mov_general_36)
{
    u64 addr = ctx->di + 0xb4;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x1ff")
int BPF_KPROBE(do_switch_99)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x204")
int BPF_KPROBE(do_switch_100)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x241")
int BPF_KPROBE(do_switch_105)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x246")
int BPF_KPROBE(do_switch_106)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0xaa")
int BPF_KPROBE(do_mov_general_37)
{
    u64 addr = ctx->bx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_copy_metadata+0x1ef")
int BPF_KPROBE(do_mov_general_38)
{
    u64 addr = ctx->bx + 0xe0;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0x46")
int BPF_KPROBE(do_mov_general_39)
{
    u64 addr = ctx->r12 + 0xb6;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0x59")
int BPF_KPROBE(do_mov_general_40)
{
    u64 addr = ctx->r12 + 0xd0;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0x9d")
int BPF_KPROBE(do_mov_general_41)
{
    u64 addr = ctx->r13 - 0x7;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xa2")
int BPF_KPROBE(do_mov_general_42)
{
    u64 addr = ctx->r13 - 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xae")
int BPF_KPROBE(do_mov_general_43)
{
    u64 addr = ctx->r13 - 0x6;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xbd")
int BPF_KPROBE(do_mov_general_44)
{
    u64 addr = ctx->r13 - 0x6;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare+0xcb")
int BPF_KPROBE(do_mov_general_45)
{
    u64 addr = ctx->r13 - 0x4;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x56")
int BPF_KPROBE(do_switch_111)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x5b")
int BPF_KPROBE(do_switch_112)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x91")
int BPF_KPROBE(do_switch_114)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x96")
int BPF_KPROBE(do_switch_115)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0xdf")
int BPF_KPROBE(do_switch_116)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0xe4")
int BPF_KPROBE(do_switch_117)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x14a")
int BPF_KPROBE(do_mov_general_46)
{
    u64 addr = ctx->r8;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x168")
int BPF_KPROBE(do_switch_119)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_frag_next+0x16d")
int BPF_KPROBE(do_switch_120)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x2b4")
int BPF_KPROBE(do_switch_121)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x2b9")
int BPF_KPROBE(do_switch_122)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x37d")
int BPF_KPROBE(do_switch_124)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x382")
int BPF_KPROBE(do_switch_125)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x248")
int BPF_KPROBE(do_mov_general_47)
{
    u64 addr = ctx->si + 0x14;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x3dd")
int BPF_KPROBE(do_mov_general_48)
{
    u64 addr = ctx->si + 0x3c;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x4f1")
int BPF_KPROBE(do_switch_127)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x4f6")
int BPF_KPROBE(do_switch_128)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x713")
int BPF_KPROBE(do_switch_131)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x718")
int BPF_KPROBE(do_switch_132)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xa3e")
int BPF_KPROBE(do_switch_135)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xa43")
int BPF_KPROBE(do_switch_136)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xb2a")
int BPF_KPROBE(do_switch_138)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xb2f")
int BPF_KPROBE(do_switch_139)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xb6e")
int BPF_KPROBE(do_switch_140)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xb73")
int BPF_KPROBE(do_switch_141)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xc17")
int BPF_KPROBE(do_switch_143)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xc1c")
int BPF_KPROBE(do_switch_144)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xcaf")
int BPF_KPROBE(do_switch_145)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xcb4")
int BPF_KPROBE(do_switch_146)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xc87")
int BPF_KPROBE(do_mov_general_49)
{
    u64 addr = ctx->r9 + 0x80;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xceb")
int BPF_KPROBE(do_mov_general_50)
{
    u64 addr = ctx->r9 + 0xb8;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xe63")
int BPF_KPROBE(do_mov_general_51)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xebd")
int BPF_KPROBE(do_switch_148)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xec2")
int BPF_KPROBE(do_switch_149)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xf5d")
int BPF_KPROBE(do_switch_150)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xf62")
int BPF_KPROBE(do_switch_151)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xf2c")
int BPF_KPROBE(do_mov_general_52)
{
    u64 addr = ctx->r12 + 0x70;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0xf31")
int BPF_KPROBE(do_mov_general_53)
{
    u64 addr = ctx->r12 + 0xbc;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x115a")
int BPF_KPROBE(do_switch_154)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0+0x115f")
int BPF_KPROBE(do_switch_155)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x54")
int BPF_KPROBE(do_switch_163)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x59")
int BPF_KPROBE(do_switch_164)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x144")
int BPF_KPROBE(do_switch_165)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x149")
int BPF_KPROBE(do_switch_166)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_append_data+0x120")
int BPF_KPROBE(do_mov_general_54)
{
    u64 addr = ctx->di + 0x378;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_append_data+0x199")
int BPF_KPROBE(do_mov_general_55)
{
    u64 addr = ctx->di + 0x3d0;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_forward+0x397")
int BPF_KPROBE(do_switch_176)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x39c")
int BPF_KPROBE(do_switch_177)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x3e3")
int BPF_KPROBE(do_switch_178)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x3e8")
int BPF_KPROBE(do_switch_179)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x76b")
int BPF_KPROBE(do_switch_187)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x770")
int BPF_KPROBE(do_switch_188)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x868")
int BPF_KPROBE(do_switch_191)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x86d")
int BPF_KPROBE(do_switch_192)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x8fd")
int BPF_KPROBE(do_switch_197)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x902")
int BPF_KPROBE(do_switch_198)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x999")
int BPF_KPROBE(do_switch_201)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_forward+0x99e")
int BPF_KPROBE(do_switch_202)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_fragment+0x540")
int BPF_KPROBE(do_switch_213)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_fragment+0x545")
int BPF_KPROBE(do_switch_214)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_fragment+0x5a2")
int BPF_KPROBE(do_switch_215)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_fragment+0x5a7")
int BPF_KPROBE(do_switch_216)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x217")
int BPF_KPROBE(do_switch_231)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x21c")
int BPF_KPROBE(do_switch_232)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x26d")
int BPF_KPROBE(do_switch_233)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x272")
int BPF_KPROBE(do_switch_234)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x28a")
int BPF_KPROBE(do_switch_235)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x28f")
int BPF_KPROBE(do_switch_236)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x2a6")
int BPF_KPROBE(do_switch_237)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_finish_output+0x2ab")
int BPF_KPROBE(do_switch_238)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_fragment+0x75f")
int BPF_KPROBE(do_mov_general_56)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_fragment+0x6b4")
int BPF_KPROBE(do_mov_general_57)
{
    u64 addr = ctx->r15 + 0x82;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x95")
int BPF_KPROBE(do_mov_general_58)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0xaa")
int BPF_KPROBE(do_mov_general_59)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x10f")
int BPF_KPROBE(do_mov_general_60)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x122")
int BPF_KPROBE(do_mov_general_61)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x151")
int BPF_KPROBE(do_mov_general_62)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x28a")
int BPF_KPROBE(do_switch_245)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x28f")
int BPF_KPROBE(do_switch_246)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x220")
int BPF_KPROBE(do_mov_general_63)
{
    u64 addr = ctx->r12 + 0x70;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x2a4")
int BPF_KPROBE(do_mov_general_64)
{
    u64 addr = ctx->r12 + 0xb8;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x30d")
int BPF_KPROBE(do_mov_general_65)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x342")
int BPF_KPROBE(do_mov_general_66)
{
    u64 addr = ctx->dx + 0x20;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x364")
int BPF_KPROBE(do_mov_general_67)
{
    u64 addr = ctx->r12 + 0x20;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x358")
int BPF_KPROBE(do_mov_general_68)
{
    u64 addr = ctx->r12 + 0xa8;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x569")
int BPF_KPROBE(do_switch_249)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x56e")
int BPF_KPROBE(do_switch_250)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x383")
int BPF_KPROBE(do_mov_general_69)
{
    u64 addr = ctx->r12 + 0x58;
    check(addr);
    return 0;
}


SEC("kprobe/__ip6_make_skb+0x41d")
int BPF_KPROBE(do_mov_general_70)
{
    u64 addr = ctx->r12 + 0xd0;
    check(addr);
    return 0;
}


SEC("kprobe/ip6_make_skb+0x186")
int BPF_KPROBE(do_switch_259)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}


SEC("kprobe/ip6_make_skb+0x18b")
int BPF_KPROBE(do_switch_260)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}
