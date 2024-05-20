
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
	bpf_printk("=============ML policy disabled=============\n");
	ML_enable = false;
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
	u64 k = 0xffff888100043500;
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
	
	if (stkid == 0xaaa || stkid == 0xe3df || stkid == 2 || stkid == 3) {
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


SEC("kprobe/route4_walk+0xa5")
int BPF_KPROBE(do_mov_general_1)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/route4_reset_fastmap+0x1d")
int BPF_KPROBE(do_mov_general_2)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/route4_dump+0xe0")
int BPF_KPROBE(do_mov_general_3)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/route4_delete_filter_work+0x59")
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


SEC("kprobe/route4_delete_filter_work+0x5e")
int BPF_KPROBE(do_switch_18)
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


SEC("kprobe/route4_init+0x1e")
int BPF_KPROBE(do_switch_20)
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


SEC("kprobe/route4_init+0x1e")
int BPF_KPROBE(do_hotbpf_20)
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


SEC("kprobe/route4_init+0x23")
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


SEC("kprobe/route4_destroy+0x191")
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


SEC("kprobe/route4_destroy+0x196")
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


SEC("kprobe/route4_delete+0x82")
int BPF_KPROBE(do_mov_general_4)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/route4_delete+0xaa")
int BPF_KPROBE(do_mov_general_5)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/route4_delete+0xe2")
int BPF_KPROBE(do_mov_general_6)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0xce")
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


SEC("kprobe/route4_change+0xce")
int BPF_KPROBE(do_hotbpf_40)
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


SEC("kprobe/route4_change+0xd3")
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


SEC("kprobe/route4_change+0x107")
int BPF_KPROBE(do_switch_42)
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


SEC("kprobe/route4_change+0x107")
int BPF_KPROBE(do_hotbpf_42)
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


SEC("kprobe/route4_change+0x10c")
int BPF_KPROBE(do_switch_43)
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


SEC("kprobe/route4_change+0x139")
int BPF_KPROBE(do_mov_general_7)
{
    u64 addr = ctx->bx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x15e")
int BPF_KPROBE(do_mov_general_8)
{
    u64 addr = ctx->bx + 0x50;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x358")
int BPF_KPROBE(do_switch_48)
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


SEC("kprobe/route4_change+0x358")
int BPF_KPROBE(do_hotbpf_48)
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


SEC("kprobe/route4_change+0x35d")
int BPF_KPROBE(do_switch_49)
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


SEC("kprobe/route4_change+0x4cf")
int BPF_KPROBE(do_mov_general_9)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x3b0")
int BPF_KPROBE(do_mov_general_10)
{
    u64 addr = ctx->bx + 0x50;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x566")
int BPF_KPROBE(do_mov_general_11)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x619")
int BPF_KPROBE(do_mov_general_12)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x641")
int BPF_KPROBE(do_mov_general_13)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/route4_change+0x6da")
int BPF_KPROBE(do_mov_general_14)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x114")
int BPF_KPROBE(do_mov_general_15)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x175")
int BPF_KPROBE(do_mov_general_16)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x1ea")
int BPF_KPROBE(do_mov_general_17)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x216")
int BPF_KPROBE(do_mov_general_18)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x298")
int BPF_KPROBE(do_mov_general_19)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x28f")
int BPF_KPROBE(do_mov_general_20)
{
    u64 addr = ctx->dx + 0xc;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x2ff")
int BPF_KPROBE(do_mov_general_21)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/route4_classify+0x2fb")
int BPF_KPROBE(do_mov_general_22)
{
    u64 addr = ctx->ax + 0xc;
    check(addr);
    return 0;
}
