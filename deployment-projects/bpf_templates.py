headers = '''
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // addr
	__type(value, u64); // value
	__uint(max_entries, 10000000);
} map SEC(".maps");


SEC("kprobe/__kmalloc")
int BPF_KPROBE(do___kmalloc) {
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&map, &cpu);
    if (pv) {
        bpf_printk("-\\n");
    }
    return 0;
}

SEC("kprobe/kmalloc_trace")
int BPF_KPROBE(do_kmalloc_trace) {
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&map, &cpu);
    if (pv) {
        bpf_printk("-\\n");
    }
    return 0;
}

bool check(u64 addr) {
	if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {
		struct page *page = bpf_virt_to_page(addr);
		u64 flags = BPF_CORE_READ(page, flags);
		if (flags & 0x200) {
			u64 slab_addr = page + 24;
			u64 *pv = bpf_map_lookup_elem(&map, &slab_addr);
			if (pv) return true;
		} else {
			u64 *pv = bpf_map_lookup_elem(&map, &addr);
			if (pv) return true;
		}
	} else if (addr >= 0xffffc90000000000 && addr <= 0xffffe8ffffffffff) {
		struct vm_struct *vms = bpf_get_vm_struct(addr);
		u64 caller = BPF_CORE_READ(vms, caller);
		u64 *pv = bpf_map_lookup_elem(&map, &caller);
		if (pv) return true;
	}
	return false;
}
'''


maps = '''
struct {{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // addr
	__type(value, u64); // value
	__uint(max_entries, 10000000);
}} {map_name} SEC(".maps");
'''



function_entry = '''
SEC("kprobe/{func}")
int BPF_KPROBE(do_entry_{prog}) 
{{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}}
'''

function_exit = '''
SEC("kretprobe/{func}")
int BPF_KRETPROBE(do_exit_{prog})
{{
    u64 saved_rbp = ctx->bp;
    u64 *psaved_ret = bpf_map_lookup_elem(&map, &saved_rbp);
    if (psaved_ret && *psaved_ret == ctx->ax)
    {{
        bpf_map_delete_elem(&map, &saved_rbp);
    }}
    return 0;
}}
'''


mov_write = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_{prog})
{{
    u64 addr = {target_addr};
    if (check(addr)) bpf_printk("-\\n");
    return 0;
}}
'''


sampling_mov_write = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_{prog})
{{
    u64 addr = {target_addr};
    sampling(addr, ctx->ip);
    return 0;
}}
'''

switch_gate = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_switch_{prog})
{{
    u32 pid = bpf_get_current_pid_tgid();
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&private_stk, &cpu);
    struct pt_regs x_regs = {{}};
    x_regs.r15 = ctx->r15 ;
    x_regs.r14 = ctx->r14 ;
    x_regs.r13 = ctx->r13 ;
    x_regs.r12 = ctx->r12 ;
    x_regs.bp  = ctx->bp  ;
    x_regs.bx  = ctx->bx  ;
    x_regs.r11 = ctx->r11;
    x_regs.r10 = ctx->r10;
    x_regs.r9  = ctx->r9 ;
    x_regs.r8  = ctx->r8 ;
    x_regs.ax  = ctx->ax ;
    x_regs.cx  = ctx->cx ;
    x_regs.dx  = ctx->dx ;
    x_regs.si  = ctx->si ;
    x_regs.di  = ctx->di ;
    x_regs.orig_ax = ctx->orig_ax;
    x_regs.ip = ctx->ip;
    x_regs.cs = ctx->cs;
    x_regs.flags = ctx->flags;
    x_regs.sp = ctx->sp;
    x_regs.ss = ctx->ss;
    bpf_set_regs(ctx, &x_regs);
    return 0;
}}
'''

mov_stk = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_stk_{prog})
{{
    u64 addr = {target_addr};
    if (addr >= ctx->sp && addr <= ctx->bp) {{}}
    return 0;
}}
'''


mov_slab = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_slab_{prog})
{{
    u64 addr = {target_addr};
    u64 cache = bpf_get_slab_cache(addr);
    if (cache == {target_cache}) {{}}
    else if (ML_enable) {{
        u64 start = bpf_get_slab_start(addr);
        u64 val = 1;
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    }}
    return 0;
}}
'''


mov_buddy = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_stk_{prog})
{{
    u64 addr = bpf_get_slab_start({target_addr});
    u64 *pv = bpf_map_lookup_elem(&buddy_objs, &addr);
    if (pv) {{}}
    else {{
        if (ML_enable) {{
            u64 val = 1;
            bpf_map_update_elem(&ml_record, &addr, &val, BPF_ANY);
        }} else {{ /* error happens */ }}
    }}
    return 0;
}}
'''

mov_vmalloc = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_vmalloc_{prog})
{{
    u64 addr = {target_addr};
    u64 vms = bpf_get_vm_struct(addr);
    u64 caller = BPF_CORE_READ(vms, caller);
    u64 *pv = bpf_map_lookup_elem(&vmalloc, &caller);
    if (pv) {{}}
    else {{ /* error happens */ }}
    return 0;
}}
'''

mov_page = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_page_{prog})
{{
    u64 addr = {target_addr};
    if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {{}}
    else {{ /* error happens */ }}
    return 0;
}}
'''

icall = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_icall_{prog})
{{
    u64 addr = {target_addr};
    u64 *pv = bpf_map_lookup_elem(&cfg, &addr);
    if (pv) {{}}
    else {{ /* error happens */ }}
    return 0;
}}
'''


# mov_general = '''
# SEC("kprobe/{func}+{offset}")
# int BPF_KPROBE(do_mov_general_{prog})
# {{
#     u64 addr = {target_addr};
#     u64 val = 1;
#     if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {{
#         struct kmem_cache *s = (struct kmem_cache *)bpf_get_slab_cache(addr);
#         if (s) {{
#             u64 *pv = bpf_map_lookup_elem(&slabcaches, &s);
#             if (pv) {{}}
#             else if (ML_enable) {{
#                 u64 start = bpf_get_slab_start(addr);
#                 bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
#             }} else {{ /* error happens */ }}
#         }} else {{
#             u64 k = bpf_get_slab_start(addr);
#             u64 *pv = bpf_map_lookup_elem(&buddy_objs, &k);
#             if (pv) {{}}
#             else if (ML_enable) {{
#                 bpf_map_update_elem(&ml_record, &k, &val, BPF_ANY);
#             }} else {{ /* error happens */ }}
#         }}
#     }} else if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {{
        
#     }} else if (addr >= 0xffffc90000000000 && addr <= 0xffffe8ffffffffff) {{
#         struct vm_struct *vms = (struct vm_struct *)bpf_get_vm_struct(addr);
#         u64 caller = BPF_CORE_READ(vms, caller);
#         u64 *pv = bpf_map_lookup_elem(&vmalloc_objs, &pv);
#         if (pv) {{}}
#         else {{ /* error happens */ }}
#     }} else {{ /* error happens */ }}
#     return 0;
# }}
# '''

mov_general = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_mov_general_{prog})
{{
    u64 addr = {target_addr};
    check(addr);
    return 0;
}}
'''


hotbpf = '''
SEC("kprobe/{func}+{offset}")
int BPF_KPROBE(do_hotbpf_{prog})
{{
    if (cache8k == 0) return 0;
	u64 alloc_addr = bpf_cache_alloc(cache8k, ctx->si);
	u64 nxt_ip = (u64)ctx->ip + 4;
    if (alloc_addr == 0 || nxt_ip == 0) return 0;
	struct pt_regs x_regs = {{}};
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
}}
'''