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
SEC("kprobe/{func} + {offset}")
int BPF_KPROBE(do_mov_{prog})
{{
    u64 addr = {target_addr};
    if (check(addr)) bpf_printk("-\\n");
    return 0;
}}
'''