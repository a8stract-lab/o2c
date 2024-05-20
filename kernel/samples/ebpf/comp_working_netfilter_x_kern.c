
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

SEC("kprobe/nft_reg_track_cancel+0x37")
int BPF_KPROBE(do_mov_general_1)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_reg_track_cancel+0x76")
int BPF_KPROBE(do_mov_general_2)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_reg_track_cancel+0x16")
int BPF_KPROBE(do_mov_general_3)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_unregister_expr+0x28")
int BPF_KPROBE(do_mov_general_4)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_unregister_obj+0x28")
int BPF_KPROBE(do_mov_general_5)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x1e")
int BPF_KPROBE(do_mov_general_6)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_register_flowtable_type+0x29")
int BPF_KPROBE(do_mov_general_7)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_unregister_flowtable_type+0x27")
int BPF_KPROBE(do_mov_general_8)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_obj_destroy+0x30")
int BPF_KPROBE(do_switch_27)
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


SEC("kprobe/nft_obj_destroy+0x35")
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


SEC("kprobe/nf_tables_flowtable_destroy+0x70")
int BPF_KPROBE(do_mov_general_9)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_destroy+0x9d")
int BPF_KPROBE(do_switch_36)
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


SEC("kprobe/nf_tables_flowtable_destroy+0xa2")
int BPF_KPROBE(do_switch_37)
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


SEC("kprobe/nft_chain_release_hook+0x41")
int BPF_KPROBE(do_mov_general_10)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x44")
int BPF_KPROBE(do_mov_general_11)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_chain_release_hook+0x63")
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


SEC("kprobe/nft_chain_release_hook+0x68")
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


SEC("kprobe/nft_set_ext_memcpy+0x40")
int BPF_KPROBE(do_mov_general_12)
{
    u64 addr = ctx->r10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x5b")
int BPF_KPROBE(do_mov_general_13)
{
    u64 addr = ctx->r10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x7d")
int BPF_KPROBE(do_mov_general_14)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_ext_memcpy+0x9b")
int BPF_KPROBE(do_mov_general_15)
{
    u64 addr = ctx->r10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_parse_u32_check+0x12")
int BPF_KPROBE(do_mov_stk_16)
{
    u64 addr = bpf_get_slab_start(ctx->dx);
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


SEC("kprobe/nf_tables_trans_destroy_flush_work+0x10")
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


SEC("kprobe/nf_tables_trans_destroy_flush_work+0x15")
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


SEC("kprobe/nft_netdev_unregister_hooks+0x51")
int BPF_KPROBE(do_mov_general_17)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_netdev_unregister_hooks+0x54")
int BPF_KPROBE(do_mov_general_18)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit_audit_log+0x5e")
int BPF_KPROBE(do_mov_stk_19)
{
    u64 addr = bpf_get_slab_start(ctx->ax);
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


SEC("kprobe/nf_tables_commit_audit_log+0xe7")
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


SEC("kprobe/nf_tables_commit_audit_log+0xec")
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


SEC("kprobe/nft_netdev_hook_alloc+0x39")
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


SEC("kprobe/nft_netdev_hook_alloc+0x39")
int BPF_KPROBE(do_hotbpf_72)
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


SEC("kprobe/nft_netdev_hook_alloc+0x3e")
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


SEC("kprobe/nft_netdev_hook_alloc+0x5e")
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


SEC("kprobe/nft_netdev_hook_alloc+0x63")
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


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa0")
int BPF_KPROBE(do_mov_general_20)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0xa7")
int BPF_KPROBE(do_mov_general_21)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x106")
int BPF_KPROBE(do_mov_general_22)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_parse_netdev_hooks+0x109")
int BPF_KPROBE(do_mov_general_23)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x36")
int BPF_KPROBE(do_mov_general_24)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nft_reg_track_update+0x72")
int BPF_KPROBE(do_mov_general_25)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_parse_register_load+0x30")
int BPF_KPROBE(do_mov_slab_26)
{
    u64 addr = ctx->si;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_register_flowtable_net_hooks+0x112")
int BPF_KPROBE(do_mov_general_27)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_catchall_gc+0x68")
int BPF_KPROBE(do_mov_general_28)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj_start+0x2f")
int BPF_KPROBE(do_switch_104)
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


SEC("kprobe/nf_tables_dump_obj_start+0x2f")
int BPF_KPROBE(do_hotbpf_104)
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


SEC("kprobe/nf_tables_dump_obj_start+0x34")
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


SEC("kprobe/nf_tables_dump_obj_start+0x52")
int BPF_KPROBE(do_mov_slab_29)
{
    u64 addr = ctx->r12;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_dump_rules_start+0x2f")
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


SEC("kprobe/nf_tables_dump_rules_start+0x2f")
int BPF_KPROBE(do_hotbpf_119)
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


SEC("kprobe/nf_tables_dump_rules_start+0x34")
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


SEC("kprobe/nf_tables_dump_rules_start+0x52")
int BPF_KPROBE(do_mov_general_30)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable_start+0x31")
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


SEC("kprobe/nf_tables_dump_flowtable_start+0x31")
int BPF_KPROBE(do_hotbpf_125)
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


SEC("kprobe/nf_tables_dump_flowtable_start+0x36")
int BPF_KPROBE(do_switch_126)
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


SEC("kprobe/nf_tables_dump_flowtable_start+0x4f")
int BPF_KPROBE(do_mov_general_31)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xb9")
int BPF_KPROBE(do_mov_general_32)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0x4b")
int BPF_KPROBE(do_mov_general_33)
{
    u64 addr = ctx->bx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xff")
int BPF_KPROBE(do_mov_general_34)
{
    u64 addr = ctx->ax + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_flowtable_parse_hook+0xf0")
int BPF_KPROBE(do_mov_general_35)
{
    u64 addr = ctx->ax + 0x30;
    check(addr);
    return 0;
}


SEC("kprobe/nft_stats_alloc+0x7b")
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


SEC("kprobe/nft_stats_alloc+0x80")
int BPF_KPROBE(do_switch_137)
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


SEC("kprobe/nf_tables_set_desc_parse+0x5f")
int BPF_KPROBE(do_mov_general_36)
{
    u64 addr = ctx->bx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x107")
int BPF_KPROBE(do_mov_general_37)
{
    u64 addr = ctx->bx + 0x1c;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_set_desc_parse+0x10a")
int BPF_KPROBE(do_mov_general_38)
{
    u64 addr = ctx->bx + ctx->dx * 0x1 + 0xc;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x3d")
int BPF_KPROBE(do_mov_general_39)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_rule_destroy+0x59")
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


SEC("kprobe/nf_tables_rule_destroy+0x5e")
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


SEC("kprobe/nf_tables_init_net+0x44")
int BPF_KPROBE(do_mov_general_40)
{
    u64 addr = ctx->bx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_init_net+0x76")
int BPF_KPROBE(do_mov_general_41)
{
    u64 addr = ctx->bx + 0x6c;
    check(addr);
    return 0;
}


SEC("kprobe/nft_data_init+0x12c")
int BPF_KPROBE(do_mov_slab_42)
{
    u64 addr = ctx->r12;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x76")
int BPF_KPROBE(do_mov_general_43)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_module_autoload_cleanup+0x79")
int BPF_KPROBE(do_mov_general_44)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_parse_register_store+0x48")
int BPF_KPROBE(do_mov_slab_45)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_parse_register_store+0x8f")
int BPF_KPROBE(do_mov_slab_46)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_setelem_remove+0x6e")
int BPF_KPROBE(do_mov_general_47)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_obj_del+0xa6")
int BPF_KPROBE(do_mov_general_48)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_event+0x108")
int BPF_KPROBE(do_mov_general_49)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_elem_expr_destroy+0x3d")
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


SEC("kprobe/nft_set_elem_expr_destroy+0x42")
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


SEC("kprobe/nft_set_elem_expr_destroy+0x7d")
int BPF_KPROBE(do_switch_204)
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


SEC("kprobe/nft_set_elem_expr_destroy+0x82")
int BPF_KPROBE(do_switch_205)
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


SEC("kprobe/nft_request_module+0xfe")
int BPF_KPROBE(do_switch_210)
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


SEC("kprobe/nft_request_module+0xfe")
int BPF_KPROBE(do_hotbpf_210)
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


SEC("kprobe/nft_request_module+0x103")
int BPF_KPROBE(do_switch_211)
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


SEC("kprobe/nft_request_module+0x14d")
int BPF_KPROBE(do_mov_general_50)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_request_module+0x154")
int BPF_KPROBE(do_mov_general_51)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_expr_parse+0xd9")
int BPF_KPROBE(do_switch_217)
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


SEC("kprobe/nf_tables_expr_parse+0xde")
int BPF_KPROBE(do_switch_218)
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


SEC("kprobe/nf_tables_expr_parse+0x175")
int BPF_KPROBE(do_mov_stk_52)
{
    u64 addr = bpf_get_slab_start(ctx->ax);
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


SEC("kprobe/nf_tables_expr_parse+0x233")
int BPF_KPROBE(do_switch_225)
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


SEC("kprobe/nf_tables_expr_parse+0x238")
int BPF_KPROBE(do_switch_226)
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


SEC("kprobe/nft_trans_alloc_gfp+0x1a")
int BPF_KPROBE(do_switch_228)
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


SEC("kprobe/nft_trans_alloc_gfp+0x1a")
int BPF_KPROBE(do_hotbpf_228)
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


SEC("kprobe/nft_trans_alloc_gfp+0x1f")
int BPF_KPROBE(do_switch_229)
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


SEC("kprobe/nft_trans_alloc_gfp+0x27")
int BPF_KPROBE(do_mov_slab_53)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x36")
int BPF_KPROBE(do_mov_slab_54)
{
    u64 addr = ctx->ax + 0x8;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_trans_alloc_gfp+0x5a")
int BPF_KPROBE(do_mov_slab_55)
{
    u64 addr = ctx->ax + 0x40;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x64")
int BPF_KPROBE(do_mov_slab_56)
{
    u64 addr = ctx->r12;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_trans_rule_add+0x6d")
int BPF_KPROBE(do_mov_slab_57)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_delset+0x68")
int BPF_KPROBE(do_mov_general_58)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delset+0x6f")
int BPF_KPROBE(do_mov_general_59)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delobj+0x64")
int BPF_KPROBE(do_mov_general_60)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delobj+0x6b")
int BPF_KPROBE(do_mov_general_61)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x150")
int BPF_KPROBE(do_mov_general_62)
{
    u64 addr = ctx->cx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delobj+0x154")
int BPF_KPROBE(do_mov_general_63)
{
    u64 addr = ctx->cx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delchain+0x5f")
int BPF_KPROBE(do_mov_slab_64)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_delchain+0x66")
int BPF_KPROBE(do_mov_slab_65)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_delflowtable+0x47")
int BPF_KPROBE(do_mov_general_66)
{
    u64 addr = ctx->bx + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x4b")
int BPF_KPROBE(do_mov_general_67)
{
    u64 addr = ctx->bx + 0x60;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x74")
int BPF_KPROBE(do_mov_general_68)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delflowtable+0x7b")
int BPF_KPROBE(do_mov_general_69)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xd8")
int BPF_KPROBE(do_mov_general_70)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_bind_set+0xe1")
int BPF_KPROBE(do_mov_general_71)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_chain_parse_hook+0x1c5")
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


SEC("kprobe/nft_chain_parse_hook+0x1ca")
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


SEC("kprobe/nft_chain_parse_hook+0x1de")
int BPF_KPROBE(do_mov_stk_72)
{
    u64 addr = bpf_get_slab_start(ctx->r13 + 0x8);
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


SEC("kprobe/nft_chain_parse_hook+0x1e6")
int BPF_KPROBE(do_mov_stk_73)
{
    u64 addr = bpf_get_slab_start(ctx->r13 + 0x18);
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


SEC("kprobe/nft_chain_parse_hook+0x240")
int BPF_KPROBE(do_switch_262)
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


SEC("kprobe/nft_chain_parse_hook+0x245")
int BPF_KPROBE(do_switch_263)
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


SEC("kprobe/nft_chain_parse_hook+0x27c")
int BPF_KPROBE(do_switch_265)
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


SEC("kprobe/nft_chain_parse_hook+0x281")
int BPF_KPROBE(do_switch_266)
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


SEC("kprobe/nft_obj_init+0x2a")
int BPF_KPROBE(do_switch_269)
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


SEC("kprobe/nft_obj_init+0x2a")
int BPF_KPROBE(do_hotbpf_269)
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


SEC("kprobe/nft_obj_init+0x2f")
int BPF_KPROBE(do_switch_270)
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


SEC("kprobe/nft_obj_init+0x9e")
int BPF_KPROBE(do_switch_273)
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


SEC("kprobe/nft_obj_init+0x9e")
int BPF_KPROBE(do_hotbpf_273)
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


SEC("kprobe/nft_obj_init+0xa3")
int BPF_KPROBE(do_switch_274)
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


SEC("kprobe/nft_expr_init+0x63")
int BPF_KPROBE(do_switch_282)
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


SEC("kprobe/nft_expr_init+0x68")
int BPF_KPROBE(do_switch_283)
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


SEC("kprobe/nft_expr_init+0x8f")
int BPF_KPROBE(do_switch_284)
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


SEC("kprobe/nft_expr_init+0x8f")
int BPF_KPROBE(do_hotbpf_284)
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


SEC("kprobe/nft_expr_init+0x94")
int BPF_KPROBE(do_switch_285)
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


SEC("kprobe/nft_expr_init+0xa3")
int BPF_KPROBE(do_mov_general_74)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nft_expr_init+0xc6")
int BPF_KPROBE(do_mov_general_75)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x223")
int BPF_KPROBE(do_mov_general_76)
{
    u64 addr = ctx->cx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delset+0x227")
int BPF_KPROBE(do_mov_general_77)
{
    u64 addr = ctx->cx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x305")
int BPF_KPROBE(do_mov_general_78)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x313")
int BPF_KPROBE(do_mov_general_79)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x316")
int BPF_KPROBE(do_mov_general_80)
{
    u64 addr = ctx->ax + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x34c")
int BPF_KPROBE(do_mov_general_81)
{
    u64 addr = ctx->ax + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x37f")
int BPF_KPROBE(do_mov_general_82)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3ae")
int BPF_KPROBE(do_mov_general_83)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3b1")
int BPF_KPROBE(do_mov_general_84)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3f4")
int BPF_KPROBE(do_mov_general_85)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x3fc")
int BPF_KPROBE(do_mov_general_86)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x430")
int BPF_KPROBE(do_mov_general_87)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x463")
int BPF_KPROBE(do_mov_general_88)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delflowtable+0x466")
int BPF_KPROBE(do_mov_general_89)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0x12e")
int BPF_KPROBE(do_switch_319)
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


SEC("kprobe/nf_tables_fill_gen_info+0x133")
int BPF_KPROBE(do_switch_320)
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


SEC("kprobe/nf_tables_getgen+0x29")
int BPF_KPROBE(do_switch_325)
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


SEC("kprobe/nf_tables_getgen+0x2e")
int BPF_KPROBE(do_switch_326)
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


SEC("kprobe/nf_tables_fill_gen_info+0x168")
int BPF_KPROBE(do_mov_slab_90)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_fill_gen_info+0xc3")
int BPF_KPROBE(do_mov_slab_91)
{
    u64 addr = ctx->bx + 0x12;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_delrule+0x67")
int BPF_KPROBE(do_mov_slab_92)
{
    u64 addr = ctx->r12;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_delrule+0x70")
int BPF_KPROBE(do_mov_slab_93)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_delrule+0x10a")
int BPF_KPROBE(do_mov_general_94)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delrule+0x117")
int BPF_KPROBE(do_mov_general_95)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delrule+0x14f")
int BPF_KPROBE(do_mov_general_96)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_delrule+0x15c")
int BPF_KPROBE(do_mov_general_97)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b0")
int BPF_KPROBE(do_mov_slab_98)
{
    u64 addr = ctx->r12;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_flush_table+0x2b9")
int BPF_KPROBE(do_mov_slab_99)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x1eb")
int BPF_KPROBE(do_mov_general_100)
{
    u64 addr = ctx->di + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_delrule+0x1e3")
int BPF_KPROBE(do_mov_general_101)
{
    u64 addr = ctx->di + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0x42")
int BPF_KPROBE(do_switch_383)
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


SEC("kprobe/nf_tables_table_notify+0x47")
int BPF_KPROBE(do_switch_384)
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


SEC("kprobe/nf_tables_fill_table_info+0x1c4")
int BPF_KPROBE(do_mov_stk_102)
{
    u64 addr = bpf_get_slab_start(ctx->bx);
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


SEC("kprobe/nf_tables_fill_table_info+0xc0")
int BPF_KPROBE(do_mov_stk_103)
{
    u64 addr = bpf_get_slab_start(ctx->bx + 0x12);
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


SEC("kprobe/nf_tables_table_notify+0xc3")
int BPF_KPROBE(do_mov_general_104)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_table_notify+0xcc")
int BPF_KPROBE(do_mov_general_105)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_gettable+0xa5")
int BPF_KPROBE(do_switch_396)
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


SEC("kprobe/nf_tables_gettable+0xaa")
int BPF_KPROBE(do_switch_397)
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


SEC("kprobe/nf_tables_dump_tables+0x169")
int BPF_KPROBE(do_mov_slab_106)
{
    u64 addr = ctx->r12 + 0x40;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_dump_tables+0xd7")
int BPF_KPROBE(do_mov_slab_107)
{
    u64 addr = ctx->r12 + 0x78;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_gettable+0x15e")
int BPF_KPROBE(do_switch_400)
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


SEC("kprobe/nf_tables_gettable+0x163")
int BPF_KPROBE(do_switch_401)
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


SEC("kprobe/nf_tables_gettable+0x187")
int BPF_KPROBE(do_switch_405)
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


SEC("kprobe/nf_tables_gettable+0x18c")
int BPF_KPROBE(do_switch_406)
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


SEC("kprobe/nf_tables_fill_obj_info+0xcd")
int BPF_KPROBE(do_mov_general_108)
{
    u64 addr = ctx->bx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0xc8")
int BPF_KPROBE(do_mov_general_109)
{
    u64 addr = ctx->bx + 0x12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_obj_info+0x247")
int BPF_KPROBE(do_mov_general_110)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_obj_notify+0xb3")
int BPF_KPROBE(do_switch_429)
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


SEC("kprobe/nft_obj_notify+0xb8")
int BPF_KPROBE(do_switch_430)
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


SEC("kprobe/nft_obj_notify+0x108")
int BPF_KPROBE(do_mov_general_111)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x10f")
int BPF_KPROBE(do_mov_general_112)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_obj_notify+0x164")
int BPF_KPROBE(do_switch_434)
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


SEC("kprobe/nft_obj_notify+0x169")
int BPF_KPROBE(do_switch_435)
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


SEC("kprobe/nf_tables_dump_obj+0x148")
int BPF_KPROBE(do_mov_general_113)
{
    u64 addr = ctx->r15 + 0x40;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x1a1")
int BPF_KPROBE(do_mov_general_114)
{
    u64 addr = ctx->r15 + 0x78;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_obj+0x278")
int BPF_KPROBE(do_switch_444)
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


SEC("kprobe/nf_tables_dump_obj+0x27d")
int BPF_KPROBE(do_switch_445)
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


SEC("kprobe/nf_tables_getobj+0xe2")
int BPF_KPROBE(do_switch_448)
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


SEC("kprobe/nf_tables_getobj+0xe7")
int BPF_KPROBE(do_switch_449)
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


SEC("kprobe/nf_tables_getobj+0x1c9")
int BPF_KPROBE(do_switch_452)
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


SEC("kprobe/nf_tables_getobj+0x1ce")
int BPF_KPROBE(do_switch_453)
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


SEC("kprobe/nf_tables_getobj+0x1f8")
int BPF_KPROBE(do_switch_457)
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


SEC("kprobe/nf_tables_getobj+0x1fd")
int BPF_KPROBE(do_switch_458)
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


SEC("kprobe/nf_tables_getobj+0x2ba")
int BPF_KPROBE(do_switch_464)
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


SEC("kprobe/nf_tables_getobj+0x2bf")
int BPF_KPROBE(do_switch_465)
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


SEC("kprobe/nf_tables_getobj+0x191")
int BPF_KPROBE(do_mov_general_115)
{
    u64 addr = ctx->di + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getobj+0x189")
int BPF_KPROBE(do_mov_general_116)
{
    u64 addr = ctx->di + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xcc")
int BPF_KPROBE(do_mov_general_117)
{
    u64 addr = ctx->r13 + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0xc7")
int BPF_KPROBE(do_mov_general_118)
{
    u64 addr = ctx->r13 + 0x12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x322")
int BPF_KPROBE(do_mov_general_119)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_flowtable_info+0x338")
int BPF_KPROBE(do_mov_general_120)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0x6e")
int BPF_KPROBE(do_switch_489)
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


SEC("kprobe/nf_tables_flowtable_notify+0x73")
int BPF_KPROBE(do_switch_490)
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


SEC("kprobe/nf_tables_flowtable_notify+0xd5")
int BPF_KPROBE(do_mov_general_121)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_flowtable_notify+0xdc")
int BPF_KPROBE(do_mov_general_122)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x1a1")
int BPF_KPROBE(do_mov_general_123)
{
    u64 addr = ctx->r14 + 0x40;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_flowtable+0x115")
int BPF_KPROBE(do_mov_general_124)
{
    u64 addr = ctx->r14 + 0x78;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getflowtable+0x120")
int BPF_KPROBE(do_switch_502)
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


SEC("kprobe/nf_tables_getflowtable+0x125")
int BPF_KPROBE(do_switch_503)
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


SEC("kprobe/nf_tables_getflowtable+0x1bb")
int BPF_KPROBE(do_switch_506)
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


SEC("kprobe/nf_tables_getflowtable+0x1c0")
int BPF_KPROBE(do_switch_507)
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


SEC("kprobe/nf_tables_getflowtable+0x1e6")
int BPF_KPROBE(do_switch_511)
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


SEC("kprobe/nf_tables_getflowtable+0x1eb")
int BPF_KPROBE(do_switch_512)
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


SEC("kprobe/nf_tables_newobj+0x1a0")
int BPF_KPROBE(do_switch_517)
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


SEC("kprobe/nf_tables_newobj+0x1a5")
int BPF_KPROBE(do_switch_518)
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


SEC("kprobe/nf_tables_newobj+0x1fb")
int BPF_KPROBE(do_mov_general_125)
{
    u64 addr = ctx->r12 + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x200")
int BPF_KPROBE(do_mov_general_126)
{
    u64 addr = ctx->r12 + 0x58;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x22a")
int BPF_KPROBE(do_mov_general_127)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x233")
int BPF_KPROBE(do_mov_general_128)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x297")
int BPF_KPROBE(do_switch_523)
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


SEC("kprobe/nf_tables_newobj+0x29c")
int BPF_KPROBE(do_switch_524)
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


SEC("kprobe/nf_tables_newobj+0x365")
int BPF_KPROBE(do_switch_526)
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


SEC("kprobe/nf_tables_newobj+0x36a")
int BPF_KPROBE(do_switch_527)
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


SEC("kprobe/nf_tables_newobj+0x3ff")
int BPF_KPROBE(do_mov_general_129)
{
    u64 addr = ctx->r12 + 0x20;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x43e")
int BPF_KPROBE(do_mov_general_130)
{
    u64 addr = ctx->r12 + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x4fc")
int BPF_KPROBE(do_mov_general_131)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x504")
int BPF_KPROBE(do_mov_general_132)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x58a")
int BPF_KPROBE(do_mov_general_133)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newobj+0x596")
int BPF_KPROBE(do_mov_general_134)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x1c4")
int BPF_KPROBE(do_mov_stk_135)
{
    u64 addr = bpf_get_slab_start(ctx->bx);
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


SEC("kprobe/nf_tables_fill_chain_info+0xc6")
int BPF_KPROBE(do_mov_stk_136)
{
    u64 addr = bpf_get_slab_start(ctx->bx + 0x12);
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


SEC("kprobe/nf_tables_fill_chain_info+0x407")
int BPF_KPROBE(do_mov_stk_137)
{
    u64 addr = bpf_get_slab_start(ctx->di);
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


SEC("kprobe/nf_tables_fill_chain_info+0x54f")
int BPF_KPROBE(do_mov_general_138)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_chain_info+0x57b")
int BPF_KPROBE(do_mov_general_139)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0x42")
int BPF_KPROBE(do_switch_571)
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


SEC("kprobe/nf_tables_chain_notify+0x47")
int BPF_KPROBE(do_switch_572)
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


SEC("kprobe/nf_tables_chain_notify+0xc8")
int BPF_KPROBE(do_mov_general_140)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_chain_notify+0xd1")
int BPF_KPROBE(do_mov_general_141)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getchain+0xe0")
int BPF_KPROBE(do_switch_585)
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


SEC("kprobe/nf_tables_getchain+0xe5")
int BPF_KPROBE(do_switch_586)
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


SEC("kprobe/nf_tables_dump_chains+0x195")
int BPF_KPROBE(do_mov_slab_142)
{
    u64 addr = ctx->r12 + 0x40;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_dump_chains+0xfa")
int BPF_KPROBE(do_mov_slab_143)
{
    u64 addr = ctx->r12 + 0x78;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_getchain+0x1c5")
int BPF_KPROBE(do_switch_589)
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


SEC("kprobe/nf_tables_getchain+0x1ca")
int BPF_KPROBE(do_switch_590)
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


SEC("kprobe/nf_tables_getchain+0x1ee")
int BPF_KPROBE(do_switch_594)
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


SEC("kprobe/nf_tables_getchain+0x1f3")
int BPF_KPROBE(do_switch_595)
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


SEC("kprobe/nf_tables_newtable+0x22a")
int BPF_KPROBE(do_mov_general_144)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x233")
int BPF_KPROBE(do_mov_general_145)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x2d7")
int BPF_KPROBE(do_switch_604)
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


SEC("kprobe/nf_tables_newtable+0x2d7")
int BPF_KPROBE(do_hotbpf_604)
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


SEC("kprobe/nf_tables_newtable+0x2dc")
int BPF_KPROBE(do_switch_605)
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


SEC("kprobe/nf_tables_newtable+0x391")
int BPF_KPROBE(do_mov_slab_146)
{
    u64 addr = ctx->r15 + 0x98;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x32f")
int BPF_KPROBE(do_mov_general_147)
{
    u64 addr = ctx->r15 + 0x108;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x4fc")
int BPF_KPROBE(do_mov_slab_148)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x503")
int BPF_KPROBE(do_mov_slab_149)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x50a")
int BPF_KPROBE(do_mov_slab_150)
{
    u64 addr = ctx->r15;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x511")
int BPF_KPROBE(do_mov_slab_151)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x687")
int BPF_KPROBE(do_mov_general_152)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newtable+0x694")
int BPF_KPROBE(do_mov_general_153)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x17c")
int BPF_KPROBE(do_switch_622)
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


SEC("kprobe/nf_tables_newflowtable+0x17c")
int BPF_KPROBE(do_hotbpf_622)
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


SEC("kprobe/nf_tables_newflowtable+0x181")
int BPF_KPROBE(do_switch_623)
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


SEC("kprobe/nf_tables_newflowtable+0x225")
int BPF_KPROBE(do_switch_625)
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


SEC("kprobe/nf_tables_newflowtable+0x22a")
int BPF_KPROBE(do_switch_626)
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


SEC("kprobe/nf_tables_newflowtable+0x1d3")
int BPF_KPROBE(do_mov_general_154)
{
    u64 addr = ctx->r15 + 0x18;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x1c6")
int BPF_KPROBE(do_mov_general_155)
{
    u64 addr = ctx->r15 + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x372")
int BPF_KPROBE(do_mov_general_156)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x37f")
int BPF_KPROBE(do_mov_general_157)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x420")
int BPF_KPROBE(do_mov_general_158)
{
    u64 addr = ctx->ax - 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x424")
int BPF_KPROBE(do_mov_general_159)
{
    u64 addr = ctx->ax - 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x44c")
int BPF_KPROBE(do_mov_general_160)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x47f")
int BPF_KPROBE(do_mov_general_161)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x488")
int BPF_KPROBE(do_mov_general_162)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x4b9")
int BPF_KPROBE(do_mov_general_163)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x54c")
int BPF_KPROBE(do_mov_general_164)
{
    u64 addr = ctx->cx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x544")
int BPF_KPROBE(do_mov_general_165)
{
    u64 addr = ctx->cx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5d7")
int BPF_KPROBE(do_mov_general_166)
{
    u64 addr = ctx->r15 + 0xf0;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x5e5")
int BPF_KPROBE(do_mov_general_167)
{
    u64 addr = ctx->r15 + 0x190;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x672")
int BPF_KPROBE(do_mov_general_168)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x69b")
int BPF_KPROBE(do_mov_general_169)
{
    u64 addr = ctx->r15 + 0x20;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x691")
int BPF_KPROBE(do_mov_general_170)
{
    u64 addr = ctx->r15 + 0xe8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x719")
int BPF_KPROBE(do_mov_general_171)
{
    u64 addr = ctx->r12 + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x71e")
int BPF_KPROBE(do_mov_general_172)
{
    u64 addr = ctx->r12 + 0x60;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x74b")
int BPF_KPROBE(do_mov_general_173)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x754")
int BPF_KPROBE(do_mov_general_174)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x75e")
int BPF_KPROBE(do_mov_general_175)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x768")
int BPF_KPROBE(do_mov_general_176)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x7a1")
int BPF_KPROBE(do_mov_general_177)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newflowtable+0x7eb")
int BPF_KPROBE(do_switch_646)
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


SEC("kprobe/nf_tables_newflowtable+0x7f0")
int BPF_KPROBE(do_switch_647)
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


SEC("kprobe/nf_tables_newflowtable+0x8a5")
int BPF_KPROBE(do_mov_general_178)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_chain_destroy+0x9d")
int BPF_KPROBE(do_mov_general_179)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_chain_destroy+0xca")
int BPF_KPROBE(do_switch_657)
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


SEC("kprobe/nf_tables_chain_destroy+0xcf")
int BPF_KPROBE(do_switch_658)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0xcd")
int BPF_KPROBE(do_switch_668)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0xcd")
int BPF_KPROBE(do_hotbpf_668)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0xd2")
int BPF_KPROBE(do_switch_669)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x14a")
int BPF_KPROBE(do_mov_slab_180)
{
    u64 addr = ctx->dx + 0x28;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x135")
int BPF_KPROBE(do_mov_general_181)
{
    u64 addr = ctx->dx + 0x48;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1a0")
int BPF_KPROBE(do_mov_general_182)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1f6")
int BPF_KPROBE(do_mov_general_183)
{
    u64 addr = ctx->ax + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x1e6")
int BPF_KPROBE(do_mov_general_184)
{
    u64 addr = ctx->ax + 0x30;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x209")
int BPF_KPROBE(do_mov_general_185)
{
    u64 addr = ctx->dx + 0x1c;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x24c")
int BPF_KPROBE(do_mov_slab_186)
{
    u64 addr = ctx->dx + 0xd0;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x2eb")
int BPF_KPROBE(do_switch_672)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x2eb")
int BPF_KPROBE(do_hotbpf_672)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x2f0")
int BPF_KPROBE(do_switch_673)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x317")
int BPF_KPROBE(do_mov_slab_187)
{
    u64 addr = ctx->r8 + 0x10;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x30f")
int BPF_KPROBE(do_mov_slab_188)
{
    u64 addr = ctx->r8 + 0x54;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x3cb")
int BPF_KPROBE(do_switch_676)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x3d0")
int BPF_KPROBE(do_switch_677)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x3e0")
int BPF_KPROBE(do_mov_slab_189)
{
    u64 addr = ctx->r8;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x399")
int BPF_KPROBE(do_mov_general_190)
{
    u64 addr = ctx->r8 + 0x68;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x48e")
int BPF_KPROBE(do_switch_681)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x493")
int BPF_KPROBE(do_switch_682)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x557")
int BPF_KPROBE(do_mov_slab_191)
{
    u64 addr = ctx->r14;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x55e")
int BPF_KPROBE(do_mov_slab_192)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x5ca")
int BPF_KPROBE(do_mov_slab_193)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x5ba")
int BPF_KPROBE(do_mov_slab_194)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x64b")
int BPF_KPROBE(do_mov_general_195)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x68f")
int BPF_KPROBE(do_mov_general_196)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x692")
int BPF_KPROBE(do_mov_general_197)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x6cd")
int BPF_KPROBE(do_switch_689)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x6d2")
int BPF_KPROBE(do_switch_690)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x75a")
int BPF_KPROBE(do_mov_general_198)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x75d")
int BPF_KPROBE(do_mov_general_199)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x798")
int BPF_KPROBE(do_switch_695)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x79d")
int BPF_KPROBE(do_switch_696)
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


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d6")
int BPF_KPROBE(do_mov_general_200)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_addchain.constprop.0+0x7d9")
int BPF_KPROBE(do_mov_general_201)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3e6")
int BPF_KPROBE(do_mov_general_202)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x3f3")
int BPF_KPROBE(do_mov_general_203)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x416")
int BPF_KPROBE(do_switch_709)
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


SEC("kprobe/nf_tables_newchain+0x41b")
int BPF_KPROBE(do_switch_710)
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


SEC("kprobe/nf_tables_newchain+0x624")
int BPF_KPROBE(do_mov_slab_204)
{
    u64 addr = ctx->r15;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x62b")
int BPF_KPROBE(do_mov_slab_205)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == 0xffff888100042c00) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x82c")
int BPF_KPROBE(do_mov_general_206)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x82f")
int BPF_KPROBE(do_mov_general_207)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x859")
int BPF_KPROBE(do_switch_725)
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


SEC("kprobe/nf_tables_newchain+0x85e")
int BPF_KPROBE(do_switch_726)
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


SEC("kprobe/nf_tables_newchain+0x8a3")
int BPF_KPROBE(do_mov_general_208)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newchain+0x8a6")
int BPF_KPROBE(do_mov_general_209)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_expr_dump+0x53")
int BPF_KPROBE(do_mov_stk_210)
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


SEC("kprobe/nf_tables_fill_rule_info+0xcf")
int BPF_KPROBE(do_mov_stk_211)
{
    u64 addr = bpf_get_slab_start(ctx->bx + 0x10);
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


SEC("kprobe/nf_tables_fill_rule_info+0xd6")
int BPF_KPROBE(do_mov_stk_212)
{
    u64 addr = bpf_get_slab_start(ctx->bx + 0x12);
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


SEC("kprobe/nf_tables_fill_rule_info+0x2c6")
int BPF_KPROBE(do_mov_stk_213)
{
    u64 addr = bpf_get_slab_start(ctx->bx);
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


SEC("kprobe/nf_tables_rule_notify+0x66")
int BPF_KPROBE(do_switch_749)
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


SEC("kprobe/nf_tables_rule_notify+0x6b")
int BPF_KPROBE(do_switch_750)
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


SEC("kprobe/nf_tables_rule_notify+0xf2")
int BPF_KPROBE(do_mov_general_214)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_rule_notify+0xfb")
int BPF_KPROBE(do_mov_general_215)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x147")
int BPF_KPROBE(do_switch_757)
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


SEC("kprobe/nf_tables_getrule+0x14c")
int BPF_KPROBE(do_switch_758)
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


SEC("kprobe/nf_tables_getrule+0x26d")
int BPF_KPROBE(do_switch_761)
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


SEC("kprobe/nf_tables_getrule+0x272")
int BPF_KPROBE(do_switch_762)
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


SEC("kprobe/nf_tables_getrule+0x298")
int BPF_KPROBE(do_switch_766)
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


SEC("kprobe/nf_tables_getrule+0x29d")
int BPF_KPROBE(do_switch_767)
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


SEC("kprobe/nf_tables_getrule+0x1f0")
int BPF_KPROBE(do_mov_general_216)
{
    u64 addr = ctx->bx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getrule+0x1e8")
int BPF_KPROBE(do_mov_general_217)
{
    u64 addr = ctx->bx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x105")
int BPF_KPROBE(do_mov_slab_218)
{
    u64 addr = ctx->r12 + 0x40;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x72")
int BPF_KPROBE(do_mov_slab_219)
{
    u64 addr = ctx->r12 + 0x78;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/__nf_tables_dump_rules+0x146")
int BPF_KPROBE(do_mov_stk_220)
{
    u64 addr = bpf_get_slab_start(ctx->r13);
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


SEC("kprobe/nf_tables_fill_set+0x29e")
int BPF_KPROBE(do_mov_general_221)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x2cf")
int BPF_KPROBE(do_mov_general_222)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x370")
int BPF_KPROBE(do_mov_general_223)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x4a5")
int BPF_KPROBE(do_mov_general_224)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_set+0x54e")
int BPF_KPROBE(do_switch_804)
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


SEC("kprobe/nf_tables_fill_set+0x553")
int BPF_KPROBE(do_switch_805)
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


SEC("kprobe/nf_tables_fill_set+0x61e")
int BPF_KPROBE(do_mov_general_225)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getset+0x181")
int BPF_KPROBE(do_switch_813)
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


SEC("kprobe/nf_tables_getset+0x186")
int BPF_KPROBE(do_switch_814)
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


SEC("kprobe/nf_tables_getset+0x253")
int BPF_KPROBE(do_switch_818)
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


SEC("kprobe/nf_tables_getset+0x258")
int BPF_KPROBE(do_switch_819)
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


SEC("kprobe/nf_tables_getset+0x281")
int BPF_KPROBE(do_switch_823)
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


SEC("kprobe/nf_tables_getset+0x286")
int BPF_KPROBE(do_switch_824)
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


SEC("kprobe/nf_tables_set_notify.constprop.0+0x6a")
int BPF_KPROBE(do_switch_835)
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


SEC("kprobe/nf_tables_set_notify.constprop.0+0x6f")
int BPF_KPROBE(do_switch_836)
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


SEC("kprobe/nf_tables_dump_sets+0x240")
int BPF_KPROBE(do_mov_general_226)
{
    u64 addr = ctx->r9 + 0x50;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_sets+0x244")
int BPF_KPROBE(do_mov_general_227)
{
    u64 addr = ctx->r9 + 0x60;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc0")
int BPF_KPROBE(do_mov_general_228)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_set_notify.constprop.0+0xc7")
int BPF_KPROBE(do_mov_general_229)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x1e")
int BPF_KPROBE(do_mov_general_230)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_deactivate_set+0x51")
int BPF_KPROBE(do_mov_general_231)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_expr_clone+0x17")
int BPF_KPROBE(do_mov_general_232)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_expr_clone+0x2c")
int BPF_KPROBE(do_switch_842)
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


SEC("kprobe/nft_expr_clone+0x31")
int BPF_KPROBE(do_switch_843)
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


SEC("kprobe/nft_expr_destroy+0x25")
int BPF_KPROBE(do_switch_846)
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


SEC("kprobe/nft_expr_destroy+0x2a")
int BPF_KPROBE(do_switch_847)
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


SEC("kprobe/nf_tables_rule_release+0x63")
int BPF_KPROBE(do_switch_851)
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


SEC("kprobe/nf_tables_rule_release+0x68")
int BPF_KPROBE(do_switch_852)
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


SEC("kprobe/nf_tables_newrule+0x228")
int BPF_KPROBE(do_switch_860)
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


SEC("kprobe/nf_tables_newrule+0x22d")
int BPF_KPROBE(do_switch_861)
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


SEC("kprobe/nf_tables_newrule+0x34b")
int BPF_KPROBE(do_switch_863)
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


SEC("kprobe/nf_tables_newrule+0x34b")
int BPF_KPROBE(do_hotbpf_863)
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


SEC("kprobe/nf_tables_newrule+0x350")
int BPF_KPROBE(do_switch_864)
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


SEC("kprobe/nf_tables_newrule+0x465")
int BPF_KPROBE(do_mov_stk_233)
{
    u64 addr = bpf_get_slab_start(ctx->r15);
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


SEC("kprobe/nf_tables_newrule+0x485")
int BPF_KPROBE(do_mov_slab_234)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x4b2")
int BPF_KPROBE(do_mov_general_235)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x502")
int BPF_KPROBE(do_switch_869)
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


SEC("kprobe/nf_tables_newrule+0x507")
int BPF_KPROBE(do_switch_870)
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


SEC("kprobe/nf_tables_newrule+0x6e9")
int BPF_KPROBE(do_mov_general_236)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x66b")
int BPF_KPROBE(do_mov_general_237)
{
    u64 addr = ctx->cx + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d6")
int BPF_KPROBE(do_mov_general_238)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x7d9")
int BPF_KPROBE(do_mov_general_239)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x838")
int BPF_KPROBE(do_mov_general_240)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x8a3")
int BPF_KPROBE(do_mov_general_241)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x862")
int BPF_KPROBE(do_mov_general_242)
{
    u64 addr = ctx->si + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x93f")
int BPF_KPROBE(do_mov_general_243)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x91f")
int BPF_KPROBE(do_mov_slab_244)
{
    u64 addr = ctx->cx + 0x18;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x972")
int BPF_KPROBE(do_mov_general_245)
{
    u64 addr = ctx->si + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newrule+0x96a")
int BPF_KPROBE(do_mov_general_246)
{
    u64 addr = ctx->si + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_msecs_to_jiffies64+0x4e")
int BPF_KPROBE(do_switch_885)
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


SEC("kprobe/nf_msecs_to_jiffies64+0x53")
int BPF_KPROBE(do_switch_886)
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


SEC("kprobe/nf_jiffies64_to_msecs+0x9")
int BPF_KPROBE(do_switch_888)
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


SEC("kprobe/nf_jiffies64_to_msecs+0xe")
int BPF_KPROBE(do_switch_889)
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


SEC("kprobe/nft_set_elem_expr_alloc+0x76")
int BPF_KPROBE(do_switch_893)
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


SEC("kprobe/nft_set_elem_expr_alloc+0x7b")
int BPF_KPROBE(do_switch_894)
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


SEC("kprobe/nf_tables_newset+0x207")
int BPF_KPROBE(do_switch_897)
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


SEC("kprobe/nf_tables_newset+0x20c")
int BPF_KPROBE(do_switch_898)
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


SEC("kprobe/nf_tables_newset+0x710")
int BPF_KPROBE(do_switch_906)
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


SEC("kprobe/nf_tables_newset+0x715")
int BPF_KPROBE(do_switch_907)
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


SEC("kprobe/nf_tables_newset+0x747")
int BPF_KPROBE(do_switch_909)
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


SEC("kprobe/nf_tables_newset+0x74c")
int BPF_KPROBE(do_switch_910)
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


SEC("kprobe/nf_tables_newset+0x768")
int BPF_KPROBE(do_switch_911)
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


SEC("kprobe/nf_tables_newset+0x76d")
int BPF_KPROBE(do_switch_912)
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


SEC("kprobe/nf_tables_newset+0x77b")
int BPF_KPROBE(do_switch_913)
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


SEC("kprobe/nf_tables_newset+0x780")
int BPF_KPROBE(do_switch_914)
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


SEC("kprobe/nf_tables_newset+0x91e")
int BPF_KPROBE(do_switch_917)
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


SEC("kprobe/nf_tables_newset+0x923")
int BPF_KPROBE(do_switch_918)
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


SEC("kprobe/nf_tables_newset+0xa05")
int BPF_KPROBE(do_mov_general_247)
{
    u64 addr = ctx->di + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xa1b")
int BPF_KPROBE(do_mov_general_248)
{
    u64 addr = ctx->di + 0xe8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc44")
int BPF_KPROBE(do_mov_general_249)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc4b")
int BPF_KPROBE(do_mov_general_250)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc55")
int BPF_KPROBE(do_mov_general_251)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xc5c")
int BPF_KPROBE(do_mov_general_252)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newset+0xd40")
int BPF_KPROBE(do_switch_929)
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


SEC("kprobe/nf_tables_newset+0xd45")
int BPF_KPROBE(do_switch_930)
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


SEC("kprobe/nf_tables_newset+0xdfc")
int BPF_KPROBE(do_mov_general_253)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x43")
int BPF_KPROBE(do_switch_941)
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


SEC("kprobe/nft_set_elem_init+0x43")
int BPF_KPROBE(do_hotbpf_941)
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


SEC("kprobe/nft_set_elem_init+0x48")
int BPF_KPROBE(do_switch_942)
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


SEC("kprobe/nft_set_elem_init+0x65")
int BPF_KPROBE(do_mov_general_254)
{
    u64 addr = ctx->bx + 0x1;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x6e")
int BPF_KPROBE(do_mov_general_255)
{
    u64 addr = ctx->bx + 0x9;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x108")
int BPF_KPROBE(do_mov_general_256)
{
    u64 addr = ctx->bx + ctx->ax * 0x1;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_elem_init+0x11e")
int BPF_KPROBE(do_mov_general_257)
{
    u64 addr = ctx->bx + ctx->ax * 0x1;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_elem_expr_clone+0x60")
int BPF_KPROBE(do_switch_947)
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


SEC("kprobe/nft_set_elem_expr_clone+0x60")
int BPF_KPROBE(do_hotbpf_947)
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


SEC("kprobe/nft_set_elem_expr_clone+0x65")
int BPF_KPROBE(do_switch_948)
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


SEC("kprobe/nft_set_elem_expr_clone+0xb0")
int BPF_KPROBE(do_switch_952)
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


SEC("kprobe/nft_set_elem_expr_clone+0xb5")
int BPF_KPROBE(do_switch_953)
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


SEC("kprobe/nft_set_gc_batch_alloc+0x41")
int BPF_KPROBE(do_switch_956)
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


SEC("kprobe/nft_set_gc_batch_alloc+0x41")
int BPF_KPROBE(do_hotbpf_956)
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


SEC("kprobe/nft_set_gc_batch_alloc+0x46")
int BPF_KPROBE(do_switch_957)
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


SEC("kprobe/nft_chain_del+0xa9")
int BPF_KPROBE(do_mov_slab_258)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x294")
int BPF_KPROBE(do_switch_966)
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


SEC("kprobe/nft_add_set_elem+0x299")
int BPF_KPROBE(do_switch_967)
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


SEC("kprobe/nft_add_set_elem+0x7d8")
int BPF_KPROBE(do_mov_general_259)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x8c1")
int BPF_KPROBE(do_switch_979)
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


SEC("kprobe/nft_add_set_elem+0x8c6")
int BPF_KPROBE(do_switch_980)
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


SEC("kprobe/nft_add_set_elem+0x8ce")
int BPF_KPROBE(do_mov_stk_1)
{
    u64 addr = ctx->bp + ctx->r12 * 0x8 - 0x180;
    if (addr >= ctx->sp && addr <= ctx->bp) {}
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x950")
int BPF_KPROBE(do_switch_984)
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


SEC("kprobe/nft_add_set_elem+0x955")
int BPF_KPROBE(do_switch_985)
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


SEC("kprobe/nft_add_set_elem+0x95d")
int BPF_KPROBE(do_mov_general_260)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xa84")
int BPF_KPROBE(do_switch_990)
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


SEC("kprobe/nft_add_set_elem+0xa89")
int BPF_KPROBE(do_switch_991)
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


SEC("kprobe/nft_add_set_elem+0xae4")
int BPF_KPROBE(do_switch_993)
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


SEC("kprobe/nft_add_set_elem+0xae9")
int BPF_KPROBE(do_switch_994)
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


SEC("kprobe/nft_add_set_elem+0xbb5")
int BPF_KPROBE(do_mov_stk_2)
{
    u64 addr = ctx->bp + ctx->r14 * 0x8 - 0x180;
    if (addr >= ctx->sp && addr <= ctx->bp) {}
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xdf8")
int BPF_KPROBE(do_mov_general_261)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf26")
int BPF_KPROBE(do_mov_general_262)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf5b")
int BPF_KPROBE(do_mov_general_263)
{
    u64 addr = ctx->r9;
    check(addr);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0xf62")
int BPF_KPROBE(do_mov_general_264)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_add_set_elem+0x1066")
int BPF_KPROBE(do_switch_1003)
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


SEC("kprobe/nft_add_set_elem+0x1066")
int BPF_KPROBE(do_hotbpf_1003)
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


SEC("kprobe/nft_add_set_elem+0x106b")
int BPF_KPROBE(do_switch_1004)
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


SEC("kprobe/nft_add_set_elem+0x107f")
int BPF_KPROBE(do_mov_general_265)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x1f3")
int BPF_KPROBE(do_mov_general_266)
{
    u64 addr = ctx->di + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_newsetelem+0x1eb")
int BPF_KPROBE(do_mov_general_267)
{
    u64 addr = ctx->di + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0x7f")
int BPF_KPROBE(do_mov_general_268)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xa6")
int BPF_KPROBE(do_mov_general_269)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nft_setelem_flush+0xaf")
int BPF_KPROBE(do_mov_general_270)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xda")
int BPF_KPROBE(do_mov_general_271)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_catchall_flush+0xe1")
int BPF_KPROBE(do_mov_general_272)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x49a")
int BPF_KPROBE(do_mov_general_273)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4c8")
int BPF_KPROBE(do_mov_general_274)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/nft_del_setelem+0x4cf")
int BPF_KPROBE(do_mov_general_275)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_set_destroy+0x57")
int BPF_KPROBE(do_switch_1055)
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


SEC("kprobe/nft_set_destroy+0x5c")
int BPF_KPROBE(do_switch_1056)
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


SEC("kprobe/nft_set_destroy+0xb6")
int BPF_KPROBE(do_mov_general_276)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x66")
int BPF_KPROBE(do_mov_slab_277)
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


SEC("kprobe/nf_tables_trans_destroy_work+0xcd")
int BPF_KPROBE(do_mov_general_278)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0xd5")
int BPF_KPROBE(do_mov_slab_279)
{
    u64 addr = ctx->r15;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x141")
int BPF_KPROBE(do_mov_general_280)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_trans_destroy_work+0x26d")
int BPF_KPROBE(do_switch_1079)
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


SEC("kprobe/nf_tables_trans_destroy_work+0x272")
int BPF_KPROBE(do_switch_1080)
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


SEC("kprobe/__nft_release_basechain+0x5d")
int BPF_KPROBE(do_mov_general_281)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0x6a")
int BPF_KPROBE(do_mov_general_282)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_basechain+0xc5")
int BPF_KPROBE(do_switch_1086)
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


SEC("kprobe/__nft_release_basechain+0xca")
int BPF_KPROBE(do_switch_1087)
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


SEC("kprobe/__nf_tables_abort+0xcb")
int BPF_KPROBE(do_mov_general_283)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0xd8")
int BPF_KPROBE(do_mov_general_284)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x12a")
int BPF_KPROBE(do_mov_general_285)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x197")
int BPF_KPROBE(do_mov_general_286)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x312")
int BPF_KPROBE(do_mov_general_287)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x40d")
int BPF_KPROBE(do_mov_general_288)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x5df")
int BPF_KPROBE(do_mov_general_289)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6d0")
int BPF_KPROBE(do_mov_general_290)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x6f6")
int BPF_KPROBE(do_mov_general_291)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x798")
int BPF_KPROBE(do_mov_general_292)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nf_tables_abort+0x7cf")
int BPF_KPROBE(do_switch_1121)
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


SEC("kprobe/__nf_tables_abort+0x7d4")
int BPF_KPROBE(do_switch_1122)
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


SEC("kprobe/__nf_tables_abort+0x810")
int BPF_KPROBE(do_mov_general_293)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_table+0xb5")
int BPF_KPROBE(do_mov_general_294)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_table+0xc2")
int BPF_KPROBE(do_mov_general_295)
{
    u64 addr = ctx->r15;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_table+0x11e")
int BPF_KPROBE(do_switch_1135)
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


SEC("kprobe/__nft_release_table+0x123")
int BPF_KPROBE(do_switch_1136)
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


SEC("kprobe/__nft_release_table+0x1a5")
int BPF_KPROBE(do_mov_general_296)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_table+0x1ac")
int BPF_KPROBE(do_mov_general_297)
{
    u64 addr = ctx->di;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_table+0x204")
int BPF_KPROBE(do_mov_general_298)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/__nft_release_table+0x20b")
int BPF_KPROBE(do_mov_general_299)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xbf")
int BPF_KPROBE(do_mov_general_300)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_exit_net+0xc2")
int BPF_KPROBE(do_mov_general_301)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nft_rcv_nl_event+0x95")
int BPF_KPROBE(do_switch_1157)
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


SEC("kprobe/nft_rcv_nl_event+0x9a")
int BPF_KPROBE(do_switch_1158)
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


SEC("kprobe/nft_rcv_nl_event+0xec")
int BPF_KPROBE(do_mov_general_302)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nft_rcv_nl_event+0x102")
int BPF_KPROBE(do_mov_stk_3)
{
    u64 addr = ctx->bp + ctx->r12 * 0x8 - 0x70;
    if (addr >= ctx->sp && addr <= ctx->bp) {}
    return 0;
}


SEC("kprobe/nft_verdict_dump+0x93")
int BPF_KPROBE(do_mov_stk_303)
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


SEC("kprobe/nft_data_dump+0x6c")
int BPF_KPROBE(do_mov_stk_304)
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


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x1a7")
int BPF_KPROBE(do_switch_1179)
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


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x1ac")
int BPF_KPROBE(do_switch_1180)
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


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x1fc")
int BPF_KPROBE(do_switch_1182)
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


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x201")
int BPF_KPROBE(do_switch_1183)
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


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x243")
int BPF_KPROBE(do_mov_general_305)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem.isra.0+0x351")
int BPF_KPROBE(do_mov_general_306)
{
    u64 addr = ctx->si;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x17f")
int BPF_KPROBE(do_mov_general_307)
{
    u64 addr = ctx->r13 + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x187")
int BPF_KPROBE(do_mov_general_308)
{
    u64 addr = ctx->r13 + 0x12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_dump_set+0x2a9")
int BPF_KPROBE(do_mov_general_309)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb0")
int BPF_KPROBE(do_mov_general_310)
{
    u64 addr = ctx->ax + 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0xb8")
int BPF_KPROBE(do_mov_general_311)
{
    u64 addr = ctx->ax + 0x12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_fill_setelem_info+0x188")
int BPF_KPROBE(do_mov_general_312)
{
    u64 addr = ctx->bx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0x56")
int BPF_KPROBE(do_switch_1221)
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


SEC("kprobe/nf_tables_setelem_notify+0x5b")
int BPF_KPROBE(do_switch_1222)
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


SEC("kprobe/nf_tables_setelem_notify+0xd2")
int BPF_KPROBE(do_mov_general_313)
{
    u64 addr = ctx->r12;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_setelem_notify+0xdb")
int BPF_KPROBE(do_mov_general_314)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10c")
int BPF_KPROBE(do_switch_1232)
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


SEC("kprobe/nf_tables_commit+0x10c")
int BPF_KPROBE(do_hotbpf_1232)
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


SEC("kprobe/nf_tables_commit+0x111")
int BPF_KPROBE(do_switch_1233)
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


SEC("kprobe/nf_tables_commit+0x122")
int BPF_KPROBE(do_mov_slab_315)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x1d7")
int BPF_KPROBE(do_switch_1234)
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


SEC("kprobe/nf_tables_commit+0x1dc")
int BPF_KPROBE(do_switch_1235)
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


SEC("kprobe/nf_tables_commit+0x1e5")
int BPF_KPROBE(do_mov_slab_316)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x131")
int BPF_KPROBE(do_mov_slab_317)
{
    u64 addr = ctx->ax + 0x18;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x2c5")
int BPF_KPROBE(do_mov_general_318)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x3dd")
int BPF_KPROBE(do_mov_general_319)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x493")
int BPF_KPROBE(do_mov_slab_320)
{
    u64 addr = ctx->r14;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5e2")
int BPF_KPROBE(do_mov_slab_321)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == 0xffff888100042c00) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x5ef")
int BPF_KPROBE(do_mov_slab_322)
{
    u64 addr = ctx->r14;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x613")
int BPF_KPROBE(do_mov_slab_323)
{
    u64 addr = ctx->r14;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6d1")
int BPF_KPROBE(do_mov_general_324)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x6de")
int BPF_KPROBE(do_mov_general_325)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x724")
int BPF_KPROBE(do_switch_1249)
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


SEC("kprobe/nf_tables_commit+0x729")
int BPF_KPROBE(do_switch_1250)
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


SEC("kprobe/nf_tables_commit+0x750")
int BPF_KPROBE(do_mov_general_326)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x75d")
int BPF_KPROBE(do_mov_general_327)
{
    u64 addr = ctx->r13;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x7fb")
int BPF_KPROBE(do_switch_1255)
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


SEC("kprobe/nf_tables_commit+0x800")
int BPF_KPROBE(do_switch_1256)
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


SEC("kprobe/nf_tables_commit+0x903")
int BPF_KPROBE(do_mov_slab_329)
{
    u64 addr = ctx->ax;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0x940")
int BPF_KPROBE(do_switch_1265)
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


SEC("kprobe/nf_tables_commit+0x945")
int BPF_KPROBE(do_switch_1266)
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


SEC("kprobe/nf_tables_commit+0x9e6")
int BPF_KPROBE(do_mov_general_330)
{
    u64 addr = ctx->cx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb2f")
int BPF_KPROBE(do_mov_general_331)
{
    u64 addr = ctx->r13 - 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xb96")
int BPF_KPROBE(do_mov_slab_332)
{
    u64 addr = ctx->dx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == 0xffff888100042c00) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0xc3e")
int BPF_KPROBE(do_mov_slab_333)
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


SEC("kprobe/nf_tables_commit+0xcf9")
int BPF_KPROBE(do_mov_general_334)
{
    u64 addr = ctx->dx;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xde4")
int BPF_KPROBE(do_mov_slab_335)
{
    u64 addr = ctx->bx;
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == cache8k) {}
    else if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }
    return 0;
}


SEC("kprobe/nf_tables_commit+0xe69")
int BPF_KPROBE(do_mov_general_336)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf44")
int BPF_KPROBE(do_mov_general_337)
{
    u64 addr = ctx->ax;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0xf51")
int BPF_KPROBE(do_mov_general_338)
{
    u64 addr = ctx->r14;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10c4")
int BPF_KPROBE(do_mov_general_339)
{
    u64 addr = ctx->ax - 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_commit+0x10e3")
int BPF_KPROBE(do_mov_general_340)
{
    u64 addr = ctx->ax - 0x10;
    check(addr);
    return 0;
}


SEC("kprobe/nft_get_set_elem+0x19d")
int BPF_KPROBE(do_switch_1316)
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


SEC("kprobe/nft_get_set_elem+0x1a2")
int BPF_KPROBE(do_switch_1317)
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


SEC("kprobe/nf_tables_getsetelem+0x2f1")
int BPF_KPROBE(do_switch_1326)
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


SEC("kprobe/nf_tables_getsetelem+0x2f6")
int BPF_KPROBE(do_switch_1327)
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


SEC("kprobe/nf_tables_getsetelem+0x329")
int BPF_KPROBE(do_switch_1331)
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


SEC("kprobe/nf_tables_getsetelem+0x32e")
int BPF_KPROBE(do_switch_1332)
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


SEC("kprobe/nf_tables_getsetelem+0x25c")
int BPF_KPROBE(do_mov_general_341)
{
    u64 addr = ctx->cx + 0x8;
    check(addr);
    return 0;
}


SEC("kprobe/nf_tables_getsetelem+0x254")
int BPF_KPROBE(do_mov_general_342)
{
    u64 addr = ctx->cx + 0x10;
    check(addr);
    return 0;
}
