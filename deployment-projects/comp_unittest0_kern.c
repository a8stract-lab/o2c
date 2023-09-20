
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
        bpf_printk("-\n");
    }
    return 0;
}

SEC("kprobe/kmalloc_trace")
int BPF_KPROBE(do_kmalloc_trace) {
    u64 cpu = bpf_get_smp_processor_id();
    u64 *pv = bpf_map_lookup_elem(&map, &cpu);
    if (pv) {
        bpf_printk("-\n");
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


SEC("kprobe/add_addr")
int BPF_KPROBE(do_entry_0) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_add_dev")
int BPF_KPROBE(do_entry_1) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_add_ifaddr")
int BPF_KPROBE(do_entry_2) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_add_linklocal")
int BPF_KPROBE(do_entry_3) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_add_mroute")
int BPF_KPROBE(do_entry_4) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_addr_gen")
int BPF_KPROBE(do_entry_5) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_cleanup")
int BPF_KPROBE(do_entry_6) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_completed")
int BPF_KPROBE(do_entry_7) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_failure")
int BPF_KPROBE(do_entry_8) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_kick")
int BPF_KPROBE(do_entry_9) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_run")
int BPF_KPROBE(do_entry_10) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_start")
int BPF_KPROBE(do_entry_11) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_stop")
int BPF_KPROBE(do_entry_12) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_dad_work")
int BPF_KPROBE(do_entry_13) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_del_dad_work")
int BPF_KPROBE(do_entry_14) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_del_ifaddr")
int BPF_KPROBE(do_entry_15) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_disable_policy_idev")
int BPF_KPROBE(do_entry_16) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_exit_net")
int BPF_KPROBE(do_entry_17) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_get_prefix_route")
int BPF_KPROBE(do_entry_18) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0")
int BPF_KPROBE(do_entry_19) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_init_net")
int BPF_KPROBE(do_entry_20) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_join_solict")
int BPF_KPROBE(do_entry_21) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_leave_anycast")
int BPF_KPROBE(do_entry_22) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_leave_solict")
int BPF_KPROBE(do_entry_23) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_mod_dad_work")
int BPF_KPROBE(do_entry_24) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_notify")
int BPF_KPROBE(do_entry_25) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv")
int BPF_KPROBE(do_entry_26) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr")
int BPF_KPROBE(do_entry_27) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_prefix_route")
int BPF_KPROBE(do_entry_28) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_rs_timer")
int BPF_KPROBE(do_entry_29) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_set_dstaddr")
int BPF_KPROBE(do_entry_30) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode")
int BPF_KPROBE(do_entry_31) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable")
int BPF_KPROBE(do_entry_32) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy")
int BPF_KPROBE(do_entry_33) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward")
int BPF_KPROBE(do_entry_34) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown")
int BPF_KPROBE(do_entry_35) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu")
int BPF_KPROBE(do_entry_36) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_proxy_ndp")
int BPF_KPROBE(do_entry_37) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register")
int BPF_KPROBE(do_entry_38) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_register")
int BPF_KPROBE(do_entry_39) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret")
int BPF_KPROBE(do_entry_40) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_sysctl_unregister")
int BPF_KPROBE(do_entry_41) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl")
int BPF_KPROBE(do_entry_42) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_verify_work")
int BPF_KPROBE(do_entry_43) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/add_v4_addrs")
int BPF_KPROBE(do_entry_44) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/check_cleanup_prefix_route")
int BPF_KPROBE(do_entry_45) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cleanup_prefix_route")
int BPF_KPROBE(do_entry_46) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dev_disable_change")
int BPF_KPROBE(do_entry_47) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dev_forward_change")
int BPF_KPROBE(do_entry_48) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_proc_exit")
int BPF_KPROBE(do_entry_49) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_proc_net_exit")
int BPF_KPROBE(do_entry_50) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_proc_net_init")
int BPF_KPROBE(do_entry_51) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_seq_next")
int BPF_KPROBE(do_entry_52) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_seq_show")
int BPF_KPROBE(do_entry_53) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_seq_start")
int BPF_KPROBE(do_entry_54) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/if6_seq_stop")
int BPF_KPROBE(do_entry_55) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/in6_dump_addrs")
int BPF_KPROBE(do_entry_56) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_addr_add")
int BPF_KPROBE(do_entry_57) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_addr_del")
int BPF_KPROBE(do_entry_58) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_dump_addr")
int BPF_KPROBE(do_entry_59) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_dump_ifacaddr")
int BPF_KPROBE(do_entry_60) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_dump_ifaddr")
int BPF_KPROBE(do_entry_61) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo")
int BPF_KPROBE(do_entry_62) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_dump_ifmcaddr")
int BPF_KPROBE(do_entry_63) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr")
int BPF_KPROBE(do_entry_64) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo")
int BPF_KPROBE(do_entry_65) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs")
int BPF_KPROBE(do_entry_66) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_fill_link_af")
int BPF_KPROBE(do_entry_67) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_get_link_af_size")
int BPF_KPROBE(do_entry_68) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_ifa_finish_destroy")
int BPF_KPROBE(do_entry_69) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_ifinfo_notify")
int BPF_KPROBE(do_entry_70) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf")
int BPF_KPROBE(do_entry_71) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf")
int BPF_KPROBE(do_entry_72) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf")
int BPF_KPROBE(do_entry_73) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_netconf_notify_devconf")
int BPF_KPROBE(do_entry_74) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rtm_deladdr")
int BPF_KPROBE(do_entry_75) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr")
int BPF_KPROBE(do_entry_76) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr")
int BPF_KPROBE(do_entry_77) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_set_link_af")
int BPF_KPROBE(do_entry_78) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_validate_link_af")
int BPF_KPROBE(do_entry_79) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_add_addr")
int BPF_KPROBE(do_entry_80) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_add_dev")
int BPF_KPROBE(do_entry_81) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_addr")
int BPF_KPROBE(do_entry_82) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_chk_addr_and_flags")
int BPF_KPROBE(do_entry_83) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_addr_and_flags")
int BPF_KPROBE(do_entry_84) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_custom_prefix")
int BPF_KPROBE(do_entry_85) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_home_addr")
int BPF_KPROBE(do_entry_86) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_prefix")
int BPF_KPROBE(do_entry_87) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_rpl_srh_loop")
int BPF_KPROBE(do_entry_88) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0")
int BPF_KPROBE(do_entry_89) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_del_addr")
int BPF_KPROBE(do_entry_90) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_dev_find")
int BPF_KPROBE(do_entry_91) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr")
int BPF_KPROBE(do_entry_92) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr")
int BPF_KPROBE(do_entry_93) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_find_idev")
int BPF_KPROBE(do_entry_94) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_generate_eui64")
int BPF_KPROBE(do_entry_95) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address")
int BPF_KPROBE(do_entry_96) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_get_ifaddr")
int BPF_KPROBE(do_entry_97) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_get_lladdr")
int BPF_KPROBE(do_entry_98) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_get_saddr_eval")
int BPF_KPROBE(do_entry_99) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify")
int BPF_KPROBE(do_entry_100) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid")
int BPF_KPROBE(do_entry_101) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_config")
int BPF_KPROBE(do_entry_102) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/manage_tempaddrs")
int BPF_KPROBE(do_entry_103) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/modify_prefix_route")
int BPF_KPROBE(do_entry_104) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_misc_proc_exit")
int BPF_KPROBE(do_entry_105) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_proc_exit_net")
int BPF_KPROBE(do_entry_106) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_proc_init_net")
int BPF_KPROBE(do_entry_107) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_dev_seq_show")
int BPF_KPROBE(do_entry_108) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_register_dev")
int BPF_KPROBE(do_entry_109) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_seq_show")
int BPF_KPROBE(do_entry_110) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_seq_show_icmpv6msg")
int BPF_KPROBE(do_entry_111) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_seq_show_item")
int BPF_KPROBE(do_entry_112) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_seq_show_item64.constprop.0")
int BPF_KPROBE(do_entry_113) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/snmp6_unregister_dev")
int BPF_KPROBE(do_entry_114) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/sockstat6_seq_show")
int BPF_KPROBE(do_entry_115) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0")
int BPF_KPROBE(do_entry_116) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_proc_exit")
int BPF_KPROBE(do_entry_117) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_proc_init")
int BPF_KPROBE(do_entry_118) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_seq_next")
int BPF_KPROBE(do_entry_119) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_seq_show")
int BPF_KPROBE(do_entry_120) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_seq_start")
int BPF_KPROBE(do_entry_121) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ac6_seq_stop")
int BPF_KPROBE(do_entry_122) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/aca_free_rcu")
int BPF_KPROBE(do_entry_123) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/aca_put")
int BPF_KPROBE(do_entry_124) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_ac_destroy_dev")
int BPF_KPROBE(do_entry_125) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_anycast_cleanup")
int BPF_KPROBE(do_entry_126) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_acast_addr")
int BPF_KPROBE(do_entry_127) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_acast_addr_src")
int BPF_KPROBE(do_entry_128) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec")
int BPF_KPROBE(do_entry_129) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc")
int BPF_KPROBE(do_entry_130) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_sock_ac_close")
int BPF_KPROBE(do_entry_131) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_ac_close")
int BPF_KPROBE(do_entry_132) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_ac_drop")
int BPF_KPROBE(do_entry_133) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join")
int BPF_KPROBE(do_entry_134) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_dst_destroy")
int BPF_KPROBE(do_entry_135) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_dst_ifdown")
int BPF_KPROBE(do_entry_136) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_dst_lookup")
int BPF_KPROBE(do_entry_137) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_fill_dst")
int BPF_KPROBE(do_entry_138) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_fini")
int BPF_KPROBE(do_entry_139) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_get_saddr")
int BPF_KPROBE(do_entry_140) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_net_exit")
int BPF_KPROBE(do_entry_141) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_net_init")
int BPF_KPROBE(do_entry_142) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_redirect")
int BPF_KPROBE(do_entry_143) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_update_pmtu")
int BPF_KPROBE(do_entry_144) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__inet6_bind")
int BPF_KPROBE(do_entry_145) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_bind")
int BPF_KPROBE(do_entry_146) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_cleanup_sock")
int BPF_KPROBE(do_entry_147) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_compat_ioctl")
int BPF_KPROBE(do_entry_148) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_create")
int BPF_KPROBE(do_entry_149) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_getname")
int BPF_KPROBE(do_entry_150) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_ioctl")
int BPF_KPROBE(do_entry_151) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_net_exit")
int BPF_KPROBE(do_entry_152) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_net_init")
int BPF_KPROBE(do_entry_153) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_recvmsg")
int BPF_KPROBE(do_entry_154) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_register_protosw")
int BPF_KPROBE(do_entry_155) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_release")
int BPF_KPROBE(do_entry_156) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_sendmsg")
int BPF_KPROBE(do_entry_157) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header")
int BPF_KPROBE(do_entry_158) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_sock_destruct")
int BPF_KPROBE(do_entry_159) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_unregister_protosw")
int BPF_KPROBE(do_entry_160) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mod_enabled")
int BPF_KPROBE(do_entry_161) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_opt_accepted")
int BPF_KPROBE(do_entry_162) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_input")
int BPF_KPROBE(do_entry_163) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_hoplimit")
int BPF_KPROBE(do_entry_164) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_find_1stfragopt")
int BPF_KPROBE(do_entry_165) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_local_out")
int BPF_KPROBE(do_entry_166) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_local_out")
int BPF_KPROBE(do_entry_167) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_proxy_select_ident")
int BPF_KPROBE(do_entry_168) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_select_ident")
int BPF_KPROBE(do_entry_169) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__inet6_check_established")
int BPF_KPROBE(do_entry_170) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_ehashfn")
int BPF_KPROBE(do_entry_171) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_hash")
int BPF_KPROBE(do_entry_172) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_hash_connect")
int BPF_KPROBE(do_entry_173) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_lhash2_lookup")
int BPF_KPROBE(do_entry_174) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_lookup")
int BPF_KPROBE(do_entry_175) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__inet6_lookup_established")
int BPF_KPROBE(do_entry_176) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_lookup_listener")
int BPF_KPROBE(do_entry_177) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_frag_expire")
int BPF_KPROBE(do_entry_178) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_frag_exit")
int BPF_KPROBE(do_entry_179) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_frag_rcv")
int BPF_KPROBE(do_entry_180) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_frags_exit_net")
int BPF_KPROBE(do_entry_181) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_frags_init_net")
int BPF_KPROBE(do_entry_182) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_frags_pre_exit_net")
int BPF_KPROBE(do_entry_183) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter")
int BPF_KPROBE(do_entry_184) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/compat_ipv6_mcast_join_leave")
int BPF_KPROBE(do_entry_185) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter")
int BPF_KPROBE(do_entry_186) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr")
int BPF_KPROBE(do_entry_187) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt")
int BPF_KPROBE(do_entry_188) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/do_ipv6_mcast_group_source")
int BPF_KPROBE(do_entry_189) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt")
int BPF_KPROBE(do_entry_190) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_ra_control")
int BPF_KPROBE(do_entry_191) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_get_msfilter")
int BPF_KPROBE(do_entry_192) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_getsockopt")
int BPF_KPROBE(do_entry_193) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mcast_join_leave")
int BPF_KPROBE(do_entry_194) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_setsockopt")
int BPF_KPROBE(do_entry_195) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_update_options")
int BPF_KPROBE(do_entry_196) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp6_gro_complete")
int BPF_KPROBE(do_entry_197) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp6_gro_receive")
int BPF_KPROBE(do_entry_198) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp6_gso_segment")
int BPF_KPROBE(do_entry_199) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc")
int BPF_KPROBE(do_entry_200) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_backtrack")
int BPF_KPROBE(do_entry_201) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_clean_tohost")
int BPF_KPROBE(do_entry_202) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_ifdown")
int BPF_KPROBE(do_entry_203) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_ifup")
int BPF_KPROBE(do_entry_204) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_info_hw_flags_set")
int BPF_KPROBE(do_entry_205) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_info_nh_uses_dev")
int BPF_KPROBE(do_entry_206) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_del_cached_rt")
int BPF_KPROBE(do_entry_207) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_find_match")
int BPF_KPROBE(do_entry_208) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_flush_exceptions")
int BPF_KPROBE(do_entry_209) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_init")
int BPF_KPROBE(do_entry_210) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_mtu_change")
int BPF_KPROBE(do_entry_211) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_redirect_match")
int BPF_KPROBE(do_entry_212) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_release")
int BPF_KPROBE(do_entry_213) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_release_dsts")
int BPF_KPROBE(do_entry_214) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_remove_exception")
int BPF_KPROBE(do_entry_215) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_remove_prefsrc")
int BPF_KPROBE(do_entry_216) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rt_update")
int BPF_KPROBE(do_entry_217) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_select_path")
int BPF_KPROBE(do_entry_218) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_table_lookup")
int BPF_KPROBE(do_entry_219) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__find_rr_leaf")
int BPF_KPROBE(do_entry_220) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmp6_dst_alloc")
int BPF_KPROBE(do_entry_221) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rtm_delroute")
int BPF_KPROBE(do_entry_222) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rtm_getroute")
int BPF_KPROBE(do_entry_223) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rtm_newroute")
int BPF_KPROBE(do_entry_224) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_rt_notify")
int BPF_KPROBE(do_entry_225) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_blackhole_route")
int BPF_KPROBE(do_entry_226) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_confirm_neigh")
int BPF_KPROBE(do_entry_227) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_create_rt_rcu")
int BPF_KPROBE(do_entry_228) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_default_advmss")
int BPF_KPROBE(do_entry_229) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_del_rt")
int BPF_KPROBE(do_entry_230) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_alloc")
int BPF_KPROBE(do_entry_231) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_check")
int BPF_KPROBE(do_entry_232) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_destroy")
int BPF_KPROBE(do_entry_233) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_gc")
int BPF_KPROBE(do_entry_234) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_ifdown")
int BPF_KPROBE(do_entry_235) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_neigh_lookup")
int BPF_KPROBE(do_entry_236) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_hold_safe")
int BPF_KPROBE(do_entry_237) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_ins_rt")
int BPF_KPROBE(do_entry_238) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_link_failure")
int BPF_KPROBE(do_entry_239) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mtu")
int BPF_KPROBE(do_entry_240) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mtu_from_fib6")
int BPF_KPROBE(do_entry_241) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0")
int BPF_KPROBE(do_entry_242) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_negative_advice")
int BPF_KPROBE(do_entry_243) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_neigh_lookup")
int BPF_KPROBE(do_entry_244) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0")
int BPF_KPROBE(do_entry_245) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pkt_discard")
int BPF_KPROBE(do_entry_246) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pkt_discard_out")
int BPF_KPROBE(do_entry_247) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pkt_drop")
int BPF_KPROBE(do_entry_248) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pkt_prohibit")
int BPF_KPROBE(do_entry_249) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pkt_prohibit_out")
int BPF_KPROBE(do_entry_250) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pol_route")
int BPF_KPROBE(do_entry_251) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pol_route_input")
int BPF_KPROBE(do_entry_252) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup")
int BPF_KPROBE(do_entry_253) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_pol_route_output")
int BPF_KPROBE(do_entry_254) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_redirect")
int BPF_KPROBE(do_entry_255) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_redirect_nh_match")
int BPF_KPROBE(do_entry_256) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_redirect_no_header")
int BPF_KPROBE(do_entry_257) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_add")
int BPF_KPROBE(do_entry_258) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_check_nh")
int BPF_KPROBE(do_entry_259) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_cleanup")
int BPF_KPROBE(do_entry_260) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_del")
int BPF_KPROBE(do_entry_261) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_dev_notify")
int BPF_KPROBE(do_entry_262) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_info_create")
int BPF_KPROBE(do_entry_263) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_input")
int BPF_KPROBE(do_entry_264) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_input_lookup")
int BPF_KPROBE(do_entry_265) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_lookup")
int BPF_KPROBE(do_entry_266) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_multipath_add")
int BPF_KPROBE(do_entry_267) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_multipath_del")
int BPF_KPROBE(do_entry_268) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_net_exit")
int BPF_KPROBE(do_entry_269) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_net_exit_late")
int BPF_KPROBE(do_entry_270) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_net_init")
int BPF_KPROBE(do_entry_271) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_net_init_late")
int BPF_KPROBE(do_entry_272) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_output_flags")
int BPF_KPROBE(do_entry_273) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_output_flags_noref")
int BPF_KPROBE(do_entry_274) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_route_redirect")
int BPF_KPROBE(do_entry_275) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0")
int BPF_KPROBE(do_entry_276) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc")
int BPF_KPROBE(do_entry_277) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rt_copy_init")
int BPF_KPROBE(do_entry_278) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rt_get_dev_rcu")
int BPF_KPROBE(do_entry_279) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu")
int BPF_KPROBE(do_entry_280) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rt_update_pmtu")
int BPF_KPROBE(do_entry_281) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow")
int BPF_KPROBE(do_entry_282) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_sk_redirect")
int BPF_KPROBE(do_entry_283) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_sk_update_pmtu")
int BPF_KPROBE(do_entry_284) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_update_pmtu")
int BPF_KPROBE(do_entry_285) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_inetpeer_exit")
int BPF_KPROBE(do_entry_286) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_inetpeer_init")
int BPF_KPROBE(do_entry_287) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_ioctl")
int BPF_KPROBE(do_entry_288) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init")
int BPF_KPROBE(do_entry_289) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sysctl_rtcache_flush")
int BPF_KPROBE(do_entry_290) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_add_dflt_router")
int BPF_KPROBE(do_entry_291) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_add_route_info")
int BPF_KPROBE(do_entry_292) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_age_exceptions")
int BPF_KPROBE(do_entry_293) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_check_expired")
int BPF_KPROBE(do_entry_294) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_clean_tohost")
int BPF_KPROBE(do_entry_295) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_disable_ip")
int BPF_KPROBE(do_entry_296) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_do_redirect")
int BPF_KPROBE(do_entry_297) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu")
int BPF_KPROBE(do_entry_298) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_dump_route")
int BPF_KPROBE(do_entry_299) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0")
int BPF_KPROBE(do_entry_300) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_fill_node")
int BPF_KPROBE(do_entry_301) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_find_cached_rt")
int BPF_KPROBE(do_entry_302) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__rt6_find_exception_rcu")
int BPF_KPROBE(do_entry_303) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__rt6_find_exception_spinlock")
int BPF_KPROBE(do_entry_304) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_flush_exceptions")
int BPF_KPROBE(do_entry_305) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_get_dflt_router")
int BPF_KPROBE(do_entry_306) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_get_route_info")
int BPF_KPROBE(do_entry_307) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_info_init")
int BPF_KPROBE(do_entry_308) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_insert_exception")
int BPF_KPROBE(do_entry_309) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_lookup")
int BPF_KPROBE(do_entry_310) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_mtu_change")
int BPF_KPROBE(do_entry_311) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_mtu_change_route")
int BPF_KPROBE(do_entry_312) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_multipath_hash")
int BPF_KPROBE(do_entry_313) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_multipath_rebalance")
int BPF_KPROBE(do_entry_314) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nh_age_exceptions")
int BPF_KPROBE(do_entry_315) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__rt6_nh_dev_match")
int BPF_KPROBE(do_entry_316) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nh_dump_exceptions")
int BPF_KPROBE(do_entry_317) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nh_find_match")
int BPF_KPROBE(do_entry_318) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nh_flush_exceptions")
int BPF_KPROBE(do_entry_319) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nh_nlmsg_size")
int BPF_KPROBE(do_entry_320) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nh_remove_exception_rt")
int BPF_KPROBE(do_entry_321) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_nlmsg_size")
int BPF_KPROBE(do_entry_322) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_probe")
int BPF_KPROBE(do_entry_323) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_probe_deferred")
int BPF_KPROBE(do_entry_324) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_purge_dflt_routers")
int BPF_KPROBE(do_entry_325) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_remove_exception_rt")
int BPF_KPROBE(do_entry_326) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_remove_prefsrc")
int BPF_KPROBE(do_entry_327) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_route_rcv")
int BPF_KPROBE(do_entry_328) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_score_route")
int BPF_KPROBE(do_entry_329) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_stats_seq_show")
int BPF_KPROBE(do_entry_330) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_sync_down_dev")
int BPF_KPROBE(do_entry_331) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_sync_up")
int BPF_KPROBE(do_entry_332) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_uncached_list_add")
int BPF_KPROBE(do_entry_333) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rt6_uncached_list_del")
int BPF_KPROBE(do_entry_334) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rtm_to_fib6_config")
int BPF_KPROBE(do_entry_335) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__traceiter_fib6_table_lookup")
int BPF_KPROBE(do_entry_336) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl6_update_dst")
int BPF_KPROBE(do_entry_337) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_parse_tlv")
int BPF_KPROBE(do_entry_338) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_tlvopt_unknown")
int BPF_KPROBE(do_entry_339) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_destopt_rcv")
int BPF_KPROBE(do_entry_340) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_dup_options")
int BPF_KPROBE(do_entry_341) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_exthdrs_exit")
int BPF_KPROBE(do_entry_342) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_fixup_options")
int BPF_KPROBE(do_entry_343) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_parse_hopopts")
int BPF_KPROBE(do_entry_344) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_push_exthdr")
int BPF_KPROBE(do_entry_345) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_push_frag_opts")
int BPF_KPROBE(do_entry_346) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_push_nfrag_opts")
int BPF_KPROBE(do_entry_347) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_renew_option")
int BPF_KPROBE(do_entry_348) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_renew_options")
int BPF_KPROBE(do_entry_349) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rthdr_rcv")
int BPF_KPROBE(do_entry_350) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_local_error")
int BPF_KPROBE(do_entry_351) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_local_rxpmtu")
int BPF_KPROBE(do_entry_352) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__xfrm6_output")
int BPF_KPROBE(do_entry_353) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_output")
int BPF_KPROBE(do_entry_354) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__xfrm6_output_finish")
int BPF_KPROBE(do_entry_355) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_input_addr")
int BPF_KPROBE(do_entry_356) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_rcv")
int BPF_KPROBE(do_entry_357) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_rcv_spi")
int BPF_KPROBE(do_entry_358) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_rcv_tnl")
int BPF_KPROBE(do_entry_359) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_transport_finish")
int BPF_KPROBE(do_entry_360) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_transport_finish2")
int BPF_KPROBE(do_entry_361) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_udp_encap_rcv")
int BPF_KPROBE(do_entry_362) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_csk_addr2sockaddr")
int BPF_KPROBE(do_entry_363) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_csk_route_req")
int BPF_KPROBE(do_entry_364) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_csk_route_socket")
int BPF_KPROBE(do_entry_365) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_csk_update_pmtu")
int BPF_KPROBE(do_entry_366) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_csk_xmit")
int BPF_KPROBE(do_entry_367) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_free_hi")
int BPF_KPROBE(do_entry_368) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_cmpfn")
int BPF_KPROBE(do_entry_369) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_compute")
int BPF_KPROBE(do_entry_370) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_exit")
int BPF_KPROBE(do_entry_371) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_info_add")
int BPF_KPROBE(do_entry_372) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_info_del")
int BPF_KPROBE(do_entry_373) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_info_lookup")
int BPF_KPROBE(do_entry_374) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_net_exit")
int BPF_KPROBE(do_entry_375) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_net_init")
int BPF_KPROBE(do_entry_376) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_hmac_validate_skb")
int BPF_KPROBE(do_entry_377) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_push_hmac")
int BPF_KPROBE(do_entry_378) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_bpf")
int BPF_KPROBE(do_entry_379) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_counters")
int BPF_KPROBE(do_entry_380) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_flavors")
int BPF_KPROBE(do_entry_381) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_iif")
int BPF_KPROBE(do_entry_382) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_nh4")
int BPF_KPROBE(do_entry_383) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_nh6")
int BPF_KPROBE(do_entry_384) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_oif")
int BPF_KPROBE(do_entry_385) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_srh")
int BPF_KPROBE(do_entry_386) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_table")
int BPF_KPROBE(do_entry_387) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cmp_nla_vrftable")
int BPF_KPROBE(do_entry_388) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/decap_and_validate")
int BPF_KPROBE(do_entry_389) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/destroy_attr_bpf")
int BPF_KPROBE(do_entry_390) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/destroy_attr_counters")
int BPF_KPROBE(do_entry_391) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/destroy_attr_srh")
int BPF_KPROBE(do_entry_392) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/end_dt_vrf_core")
int BPF_KPROBE(do_entry_393) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end")
int BPF_KPROBE(do_entry_394) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_b6")
int BPF_KPROBE(do_entry_395) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_b6_encap")
int BPF_KPROBE(do_entry_396) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_bpf")
int BPF_KPROBE(do_entry_397) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_core.constprop.0")
int BPF_KPROBE(do_entry_398) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dt4")
int BPF_KPROBE(do_entry_399) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dt46")
int BPF_KPROBE(do_entry_400) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dt6")
int BPF_KPROBE(do_entry_401) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dx2")
int BPF_KPROBE(do_entry_402) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dx4")
int BPF_KPROBE(do_entry_403) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dx4_finish")
int BPF_KPROBE(do_entry_404) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dx6")
int BPF_KPROBE(do_entry_405) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_dx6_finish")
int BPF_KPROBE(do_entry_406) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_t")
int BPF_KPROBE(do_entry_407) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/input_action_end_x")
int BPF_KPROBE(do_entry_408) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_bpf")
int BPF_KPROBE(do_entry_409) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_counters")
int BPF_KPROBE(do_entry_410) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_flavors")
int BPF_KPROBE(do_entry_411) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_iif")
int BPF_KPROBE(do_entry_412) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_nh4")
int BPF_KPROBE(do_entry_413) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_nh6")
int BPF_KPROBE(do_entry_414) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_oif")
int BPF_KPROBE(do_entry_415) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_srh")
int BPF_KPROBE(do_entry_416) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_table")
int BPF_KPROBE(do_entry_417) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/parse_nla_vrftable")
int BPF_KPROBE(do_entry_418) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_bpf")
int BPF_KPROBE(do_entry_419) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_counters")
int BPF_KPROBE(do_entry_420) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_flavors")
int BPF_KPROBE(do_entry_421) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_iif")
int BPF_KPROBE(do_entry_422) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_nh4")
int BPF_KPROBE(do_entry_423) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_nh6")
int BPF_KPROBE(do_entry_424) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_oif")
int BPF_KPROBE(do_entry_425) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_srh")
int BPF_KPROBE(do_entry_426) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_table")
int BPF_KPROBE(do_entry_427) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/put_nla_vrftable")
int BPF_KPROBE(do_entry_428) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_bpf_has_valid_srh")
int BPF_KPROBE(do_entry_429) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_end_dt46_build")
int BPF_KPROBE(do_entry_430) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_end_dt4_build")
int BPF_KPROBE(do_entry_431) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_end_dt6_build")
int BPF_KPROBE(do_entry_432) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__seg6_end_dt_vrf_build")
int BPF_KPROBE(do_entry_433) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_build_state")
int BPF_KPROBE(do_entry_434) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_cmp_encap")
int BPF_KPROBE(do_entry_435) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_destroy_state")
int BPF_KPROBE(do_entry_436) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_exit")
int BPF_KPROBE(do_entry_437) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_fill_encap")
int BPF_KPROBE(do_entry_438) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_get_encap_size")
int BPF_KPROBE(do_entry_439) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_input")
int BPF_KPROBE(do_entry_440) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_local_input_core")
int BPF_KPROBE(do_entry_441) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_lookup_any_nexthop")
int BPF_KPROBE(do_entry_442) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_lookup_nexthop")
int BPF_KPROBE(do_entry_443) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_check_mld")
int BPF_KPROBE(do_entry_444) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_build_state")
int BPF_KPROBE(do_entry_445) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_destroy_state")
int BPF_KPROBE(do_entry_446) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_do_srh")
int BPF_KPROBE(do_entry_447) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap")
int BPF_KPROBE(do_entry_448) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_do_srh_encap_red")
int BPF_KPROBE(do_entry_449) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_do_srh_inline")
int BPF_KPROBE(do_entry_450) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_encap_cmp")
int BPF_KPROBE(do_entry_451) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_encap_nlsize")
int BPF_KPROBE(do_entry_452) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_fill_encap_info")
int BPF_KPROBE(do_entry_453) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_input")
int BPF_KPROBE(do_entry_454) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_input_core")
int BPF_KPROBE(do_entry_455) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_input_finish")
int BPF_KPROBE(do_entry_456) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_iptunnel_exit")
int BPF_KPROBE(do_entry_457) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_output")
int BPF_KPROBE(do_entry_458) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_output_core")
int BPF_KPROBE(do_entry_459) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/set_tun_src")
int BPF_KPROBE(do_entry_460) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6addrlbl_add")
int BPF_KPROBE(do_entry_461) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc")
int BPF_KPROBE(do_entry_462) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_dump")
int BPF_KPROBE(do_entry_463) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0")
int BPF_KPROBE(do_entry_464) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_get")
int BPF_KPROBE(do_entry_465) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_net_exit")
int BPF_KPROBE(do_entry_466) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init")
int BPF_KPROBE(do_entry_467) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel")
int BPF_KPROBE(do_entry_468) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_addr_label")
int BPF_KPROBE(do_entry_469) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_addr_label")
int BPF_KPROBE(do_entry_470) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_addr_label_cleanup")
int BPF_KPROBE(do_entry_471) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_csum_init")
int BPF_KPROBE(do_entry_472) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_set_csum")
int BPF_KPROBE(do_entry_473) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_ext_hdr")
int BPF_KPROBE(do_entry_474) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_find_hdr")
int BPF_KPROBE(do_entry_475) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_find_tlv")
int BPF_KPROBE(do_entry_476) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_skip_exthdr")
int BPF_KPROBE(do_entry_477) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_alloc_skb")
int BPF_KPROBE(do_entry_478) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_allow_add")
int BPF_KPROBE(do_entry_479) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_cleanup")
int BPF_KPROBE(do_entry_480) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_constructor")
int BPF_KPROBE(do_entry_481) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_error_report")
int BPF_KPROBE(do_entry_482) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ndisc_fill_addr_option")
int BPF_KPROBE(do_entry_483) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_hash")
int BPF_KPROBE(do_entry_484) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_ifinfo_sysctl_change")
int BPF_KPROBE(do_entry_485) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_is_multicast")
int BPF_KPROBE(do_entry_486) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_key_eq")
int BPF_KPROBE(do_entry_487) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_late_cleanup")
int BPF_KPROBE(do_entry_488) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_mc_map")
int BPF_KPROBE(do_entry_489) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_netdev_event")
int BPF_KPROBE(do_entry_490) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_net_exit")
int BPF_KPROBE(do_entry_491) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_net_init")
int BPF_KPROBE(do_entry_492) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_next_option")
int BPF_KPROBE(do_entry_493) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_ns_create")
int BPF_KPROBE(do_entry_494) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_parse_options")
int BPF_KPROBE(do_entry_495) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_rcv")
int BPF_KPROBE(do_entry_496) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_recv_na")
int BPF_KPROBE(do_entry_497) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_recv_ns")
int BPF_KPROBE(do_entry_498) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_recv_rs")
int BPF_KPROBE(do_entry_499) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_redirect_rcv")
int BPF_KPROBE(do_entry_500) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_router_discovery")
int BPF_KPROBE(do_entry_501) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_send_na")
int BPF_KPROBE(do_entry_502) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_send_ns")
int BPF_KPROBE(do_entry_503) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_send_redirect")
int BPF_KPROBE(do_entry_504) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_send_rs")
int BPF_KPROBE(do_entry_505) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_send_skb")
int BPF_KPROBE(do_entry_506) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_send_unsol_na")
int BPF_KPROBE(do_entry_507) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_solicit")
int BPF_KPROBE(do_entry_508) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ndisc_update")
int BPF_KPROBE(do_entry_509) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/pndisc_constructor")
int BPF_KPROBE(do_entry_510) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/pndisc_destructor")
int BPF_KPROBE(do_entry_511) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/pndisc_redo")
int BPF_KPROBE(do_entry_512) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_lookup")
int BPF_KPROBE(do_entry_513) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_action")
int BPF_KPROBE(do_entry_514) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_compare")
int BPF_KPROBE(do_entry_515) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_configure")
int BPF_KPROBE(do_entry_516) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_default")
int BPF_KPROBE(do_entry_517) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_delete")
int BPF_KPROBE(do_entry_518) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_fill")
int BPF_KPROBE(do_entry_519) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_lookup")
int BPF_KPROBE(do_entry_520) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_match")
int BPF_KPROBE(do_entry_521) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_nlmsg_payload")
int BPF_KPROBE(do_entry_522) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rules_cleanup")
int BPF_KPROBE(do_entry_523) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rules_dump")
int BPF_KPROBE(do_entry_524) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rules_net_exit_batch")
int BPF_KPROBE(do_entry_525) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rules_net_init")
int BPF_KPROBE(do_entry_526) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rules_seq_read")
int BPF_KPROBE(do_entry_527) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_rule_suppress")
int BPF_KPROBE(do_entry_528) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/br_ip6_fragment")
int BPF_KPROBE(do_entry_529) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_route_me_harder")
int BPF_KPROBE(do_entry_530) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_netfilter_fini")
int BPF_KPROBE(do_entry_531) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/nf_ip6_reroute")
int BPF_KPROBE(do_entry_532) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__nf_ip6_route")
int BPF_KPROBE(do_entry_533) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_ndo_send")
int BPF_KPROBE(do_entry_534) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_add_offload")
int BPF_KPROBE(do_entry_535) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_add_protocol")
int BPF_KPROBE(do_entry_536) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_del_offload")
int BPF_KPROBE(do_entry_537) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_del_protocol")
int BPF_KPROBE(do_entry_538) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_exit")
int BPF_KPROBE(do_entry_539) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_fill_trace_data")
int BPF_KPROBE(do_entry_540) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_free_ns")
int BPF_KPROBE(do_entry_541) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_free_sc")
int BPF_KPROBE(do_entry_542) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_addns")
int BPF_KPROBE(do_entry_543) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_addsc")
int BPF_KPROBE(do_entry_544) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_delns")
int BPF_KPROBE(do_entry_545) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_delsc")
int BPF_KPROBE(do_entry_546) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpns")
int BPF_KPROBE(do_entry_547) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpns_done")
int BPF_KPROBE(do_entry_548) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpns_start")
int BPF_KPROBE(do_entry_549) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpsc")
int BPF_KPROBE(do_entry_550) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpsc_done")
int BPF_KPROBE(do_entry_551) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_dumpsc_start")
int BPF_KPROBE(do_entry_552) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_genl_ns_set_schema")
int BPF_KPROBE(do_entry_553) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_namespace")
int BPF_KPROBE(do_entry_554) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_net_exit")
int BPF_KPROBE(do_entry_555) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_net_init")
int BPF_KPROBE(do_entry_556) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_ns_cmpfn")
int BPF_KPROBE(do_entry_557) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_sc_cmpfn")
int BPF_KPROBE(do_entry_558) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_ehashfn")
int BPF_KPROBE(do_entry_559) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__udp6_lib_err")
int BPF_KPROBE(do_entry_560) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__udp6_lib_lookup")
int BPF_KPROBE(do_entry_561) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_lib_lookup")
int BPF_KPROBE(do_entry_562) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_lib_lookup2")
int BPF_KPROBE(do_entry_563) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_lib_lookup_skb")
int BPF_KPROBE(do_entry_564) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__udp6_lib_rcv")
int BPF_KPROBE(do_entry_565) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_proc_exit")
int BPF_KPROBE(do_entry_566) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_proc_init")
int BPF_KPROBE(do_entry_567) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_seq_show")
int BPF_KPROBE(do_entry_568) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_unicast_rcv_skb")
int BPF_KPROBE(do_entry_569) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_destroy_sock")
int BPF_KPROBE(do_entry_570) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_destruct_sock")
int BPF_KPROBE(do_entry_571) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp_v6_early_demux")
int BPF_KPROBE(do_entry_572) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_encap_enable")
int BPF_KPROBE(do_entry_573) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_exit")
int BPF_KPROBE(do_entry_574) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp_v6_get_port")
int BPF_KPROBE(do_entry_575) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_getsockopt")
int BPF_KPROBE(do_entry_576) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_init_sock")
int BPF_KPROBE(do_entry_577) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_pre_connect")
int BPF_KPROBE(do_entry_578) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp_v6_push_pending_frames")
int BPF_KPROBE(do_entry_579) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb")
int BPF_KPROBE(do_entry_580) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb")
int BPF_KPROBE(do_entry_581) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_rcv")
int BPF_KPROBE(do_entry_582) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(do_entry_583) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp_v6_rehash")
int BPF_KPROBE(do_entry_584) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(do_entry_585) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp_v6_send_skb")
int BPF_KPROBE(do_entry_586) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_setsockopt")
int BPF_KPROBE(do_entry_587) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_cache_find_any")
int BPF_KPROBE(do_entry_588) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_cache_find_parent.isra.0")
int BPF_KPROBE(do_entry_589) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_cache_report")
int BPF_KPROBE(do_entry_590) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_cache_unresolved")
int BPF_KPROBE(do_entry_591) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mr_cleanup")
int BPF_KPROBE(do_entry_592) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_compat_ioctl")
int BPF_KPROBE(do_entry_593) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_destroy_unres")
int BPF_KPROBE(do_entry_594) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_device_event")
int BPF_KPROBE(do_entry_595) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_dump")
int BPF_KPROBE(do_entry_596) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_fib_lookup")
int BPF_KPROBE(do_entry_597) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/_ip6mr_fill_mroute")
int BPF_KPROBE(do_entry_598) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_fill_mroute")
int BPF_KPROBE(do_entry_599) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mr_forward")
int BPF_KPROBE(do_entry_600) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_forward2.isra.0")
int BPF_KPROBE(do_entry_601) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_get_route")
int BPF_KPROBE(do_entry_602) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_hash_cmp")
int BPF_KPROBE(do_entry_603) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mr_input")
int BPF_KPROBE(do_entry_604) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_ioctl")
int BPF_KPROBE(do_entry_605) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_mfc_add")
int BPF_KPROBE(do_entry_606) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_mfc_delete")
int BPF_KPROBE(do_entry_607) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_mr_table_iter")
int BPF_KPROBE(do_entry_608) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_net_exit")
int BPF_KPROBE(do_entry_609) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_net_exit_batch")
int BPF_KPROBE(do_entry_610) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_net_init")
int BPF_KPROBE(do_entry_611) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_new_table_set")
int BPF_KPROBE(do_entry_612) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mroute_getsockopt")
int BPF_KPROBE(do_entry_613) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mroute_setsockopt")
int BPF_KPROBE(do_entry_614) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rtm_dumproute")
int BPF_KPROBE(do_entry_615) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rtm_getroute")
int BPF_KPROBE(do_entry_616) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rule_action")
int BPF_KPROBE(do_entry_617) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rule_compare")
int BPF_KPROBE(do_entry_618) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rule_configure")
int BPF_KPROBE(do_entry_619) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rule_default")
int BPF_KPROBE(do_entry_620) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rule_fill")
int BPF_KPROBE(do_entry_621) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rule_match")
int BPF_KPROBE(do_entry_622) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rules_dump")
int BPF_KPROBE(do_entry_623) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_rules_exit")
int BPF_KPROBE(do_entry_624) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_seq_read")
int BPF_KPROBE(do_entry_625) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_sk_done")
int BPF_KPROBE(do_entry_626) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_update_thresholds")
int BPF_KPROBE(do_entry_627) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_vif_seq_show")
int BPF_KPROBE(do_entry_628) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_vif_seq_start")
int BPF_KPROBE(do_entry_629) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6mr_vif_seq_stop")
int BPF_KPROBE(do_entry_630) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipmr_do_expire_process")
int BPF_KPROBE(do_entry_631) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipmr_expire_process")
int BPF_KPROBE(do_entry_632) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_show")
int BPF_KPROBE(do_entry_633) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start")
int BPF_KPROBE(do_entry_634) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mif6_delete")
int BPF_KPROBE(do_entry_635) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mr6_netlink_event")
int BPF_KPROBE(do_entry_636) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mroute6_is_socket")
int BPF_KPROBE(do_entry_637) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mroute_clean_tables")
int BPF_KPROBE(do_entry_638) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/pim6_rcv")
int BPF_KPROBE(do_entry_639) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/reg_vif_get_iflink")
int BPF_KPROBE(do_entry_640) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/reg_vif_setup")
int BPF_KPROBE(do_entry_641) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/reg_vif_xmit")
int BPF_KPROBE(do_entry_642) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_fib6_get_table")
int BPF_KPROBE(do_entry_643) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_fib6_lookup")
int BPF_KPROBE(do_entry_644) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_fib6_nh_init")
int BPF_KPROBE(do_entry_645) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_fib6_select_path")
int BPF_KPROBE(do_entry_646) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_fib6_table_lookup")
int BPF_KPROBE(do_entry_647) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_ip6_del_rt")
int BPF_KPROBE(do_entry_648) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_ip6_mtu_from_fib6")
int BPF_KPROBE(do_entry_649) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_ipv6_dev_find")
int BPF_KPROBE(do_entry_650) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_ipv6_dst_lookup_flow")
int BPF_KPROBE(do_entry_651) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_ipv6_fragment")
int BPF_KPROBE(do_entry_652) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/eafnosupport_ipv6_route_input")
int BPF_KPROBE(do_entry_653) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/in6_dev_finish_destroy")
int BPF_KPROBE(do_entry_654) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/in6_dev_finish_destroy_rcu")
int BPF_KPROBE(do_entry_655) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6addr_notifier_call_chain")
int BPF_KPROBE(do_entry_656) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6addr_validator_notifier_call_chain")
int BPF_KPROBE(do_entry_657) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_addr_type")
int BPF_KPROBE(do_entry_658) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/register_inet6addr_notifier")
int BPF_KPROBE(do_entry_659) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/register_inet6addr_validator_notifier")
int BPF_KPROBE(do_entry_660) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/unregister_inet6addr_notifier")
int BPF_KPROBE(do_entry_661) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/unregister_inet6addr_validator_notifier")
int BPF_KPROBE(do_entry_662) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_state_fini")
int BPF_KPROBE(do_entry_663) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_ah_err")
int BPF_KPROBE(do_entry_664) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_ah_rcv")
int BPF_KPROBE(do_entry_665) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_esp_err")
int BPF_KPROBE(do_entry_666) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_esp_rcv")
int BPF_KPROBE(do_entry_667) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_ipcomp_err")
int BPF_KPROBE(do_entry_668) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_ipcomp_rcv")
int BPF_KPROBE(do_entry_669) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_protocol_deregister")
int BPF_KPROBE(do_entry_670) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_protocol_fini")
int BPF_KPROBE(do_entry_671) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_protocol_register")
int BPF_KPROBE(do_entry_672) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_rcv_cb")
int BPF_KPROBE(do_entry_673) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/xfrm6_rcv_encap")
int BPF_KPROBE(do_entry_674) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmp6_send")
int BPF_KPROBE(do_entry_675) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_cleanup")
int BPF_KPROBE(do_entry_676) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_echo_reply")
int BPF_KPROBE(do_entry_677) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_err")
int BPF_KPROBE(do_entry_678) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_err_convert")
int BPF_KPROBE(do_entry_679) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_flow_init")
int BPF_KPROBE(do_entry_680) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_getfrag")
int BPF_KPROBE(do_entry_681) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_notify")
int BPF_KPROBE(do_entry_682) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_param_prob_reason")
int BPF_KPROBE(do_entry_683) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames")
int BPF_KPROBE(do_entry_684) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_rcv")
int BPF_KPROBE(do_entry_685) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_route_lookup")
int BPF_KPROBE(do_entry_686) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/icmpv6_xrlim_allow")
int BPF_KPROBE(do_entry_687) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach")
int BPF_KPROBE(do_entry_688) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init")
int BPF_KPROBE(do_entry_689) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_sk_rx_dst_set")
int BPF_KPROBE(do_entry_690) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp6_proc_exit")
int BPF_KPROBE(do_entry_691) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp6_proc_init")
int BPF_KPROBE(do_entry_692) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp6_seq_show")
int BPF_KPROBE(do_entry_693) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(do_entry_694) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_conn_request")
int BPF_KPROBE(do_entry_695) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_do_rcv")
int BPF_KPROBE(do_entry_696) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_early_demux")
int BPF_KPROBE(do_entry_697) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_err")
int BPF_KPROBE(do_entry_698) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcpv6_exit")
int BPF_KPROBE(do_entry_699) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_fill_cb")
int BPF_KPROBE(do_entry_700) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_get_syncookie")
int BPF_KPROBE(do_entry_701) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_init_seq")
int BPF_KPROBE(do_entry_702) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_init_sock")
int BPF_KPROBE(do_entry_703) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_init_ts_off")
int BPF_KPROBE(do_entry_704) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_headers.isra.0")
int BPF_KPROBE(do_entry_705) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_md5_hash_skb")
int BPF_KPROBE(do_entry_706) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_md5_lookup")
int BPF_KPROBE(do_entry_707) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_mtu_reduced")
int BPF_KPROBE(do_entry_708) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcpv6_net_exit")
int BPF_KPROBE(do_entry_709) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcpv6_net_exit_batch")
int BPF_KPROBE(do_entry_710) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcpv6_net_init")
int BPF_KPROBE(do_entry_711) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_parse_md5_keys")
int BPF_KPROBE(do_entry_712) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_pre_connect")
int BPF_KPROBE(do_entry_713) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_rcv")
int BPF_KPROBE(do_entry_714) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_reqsk_destructor")
int BPF_KPROBE(do_entry_715) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_reqsk_send_ack")
int BPF_KPROBE(do_entry_716) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_restore_cb")
int BPF_KPROBE(do_entry_717) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_route_req")
int BPF_KPROBE(do_entry_718) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_send_check")
int BPF_KPROBE(do_entry_719) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_send_reset")
int BPF_KPROBE(do_entry_720) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_send_response")
int BPF_KPROBE(do_entry_721) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_send_synack")
int BPF_KPROBE(do_entry_722) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/tcp_v6_syn_recv_sock")
int BPF_KPROBE(do_entry_723) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/add_grec")
int BPF_KPROBE(do_entry_724) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/add_grhead")
int BPF_KPROBE(do_entry_725) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_cleanup")
int BPF_KPROBE(do_entry_726) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_event_query")
int BPF_KPROBE(do_entry_727) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_event_report")
int BPF_KPROBE(do_entry_728) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_group_added")
int BPF_KPROBE(do_entry_729) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_group_dropped")
int BPF_KPROBE(do_entry_730) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_group_queried")
int BPF_KPROBE(do_entry_731) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_late_cleanup")
int BPF_KPROBE(do_entry_732) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0")
int BPF_KPROBE(do_entry_733) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next")
int BPF_KPROBE(do_entry_734) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_show")
int BPF_KPROBE(do_entry_735) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start")
int BPF_KPROBE(do_entry_736) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_stop")
int BPF_KPROBE(do_entry_737) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next")
int BPF_KPROBE(do_entry_738) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_show")
int BPF_KPROBE(do_entry_739) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start")
int BPF_KPROBE(do_entry_740) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_mc_seq_stop")
int BPF_KPROBE(do_entry_741) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_net_exit")
int BPF_KPROBE(do_entry_742) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_net_init")
int BPF_KPROBE(do_entry_743) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/igmp6_send")
int BPF_KPROBE(do_entry_744) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_mc_check")
int BPF_KPROBE(do_entry_745) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_add_src")
int BPF_KPROBE(do_entry_746) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_del1_src")
int BPF_KPROBE(do_entry_747) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0")
int BPF_KPROBE(do_entry_748) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_find_dev_rtnl")
int BPF_KPROBE(do_entry_749) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0")
int BPF_KPROBE(do_entry_750) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_leave_src.isra.0")
int BPF_KPROBE(do_entry_751) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_msfget")
int BPF_KPROBE(do_entry_752) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_msfilter")
int BPF_KPROBE(do_entry_753) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_source")
int BPF_KPROBE(do_entry_754) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_chk_mcast_addr")
int BPF_KPROBE(do_entry_755) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_dec")
int BPF_KPROBE(do_entry_756) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_dev_mc_dec")
int BPF_KPROBE(do_entry_757) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc")
int BPF_KPROBE(do_entry_758) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_dev_mc_inc")
int BPF_KPROBE(do_entry_759) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_dad_complete")
int BPF_KPROBE(do_entry_760) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_destroy_dev")
int BPF_KPROBE(do_entry_761) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_down")
int BPF_KPROBE(do_entry_762) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_init_dev")
int BPF_KPROBE(do_entry_763) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_netdev_event")
int BPF_KPROBE(do_entry_764) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_remap")
int BPF_KPROBE(do_entry_765) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_unmap")
int BPF_KPROBE(do_entry_766) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_mc_up")
int BPF_KPROBE(do_entry_767) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_close")
int BPF_KPROBE(do_entry_768) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_mc_close")
int BPF_KPROBE(do_entry_769) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_mc_drop")
int BPF_KPROBE(do_entry_770) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join")
int BPF_KPROBE(do_entry_771) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_mc_join")
int BPF_KPROBE(do_entry_772) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sock_mc_join_ssm")
int BPF_KPROBE(do_entry_773) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/is_in")
int BPF_KPROBE(do_entry_774) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ma_put")
int BPF_KPROBE(do_entry_775) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_clear_delrec")
int BPF_KPROBE(do_entry_776) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_dad_work")
int BPF_KPROBE(do_entry_777) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_del_delrec")
int BPF_KPROBE(do_entry_778) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_gq_work")
int BPF_KPROBE(do_entry_779) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_ifc_event")
int BPF_KPROBE(do_entry_780) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_ifc_work")
int BPF_KPROBE(do_entry_781) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_mca_work")
int BPF_KPROBE(do_entry_782) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_newpack.isra.0")
int BPF_KPROBE(do_entry_783) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_query_work")
int BPF_KPROBE(do_entry_784) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_report_work")
int BPF_KPROBE(do_entry_785) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_sendpack")
int BPF_KPROBE(do_entry_786) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/mld_send_report")
int BPF_KPROBE(do_entry_787) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/sf_markstate")
int BPF_KPROBE(do_entry_788) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/sf_setstate")
int BPF_KPROBE(do_entry_789) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cookie_hash.isra.0")
int BPF_KPROBE(do_entry_790) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__cookie_v6_check")
int BPF_KPROBE(do_entry_791) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cookie_v6_check")
int BPF_KPROBE(do_entry_792) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__cookie_v6_init_sequence")
int BPF_KPROBE(do_entry_793) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/cookie_v6_init_sequence")
int BPF_KPROBE(do_entry_794) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl6_free_socklist")
int BPF_KPROBE(do_entry_795) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl6_merge_options")
int BPF_KPROBE(do_entry_796) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl6_renew")
int BPF_KPROBE(do_entry_797) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__fl6_sock_lookup")
int BPF_KPROBE(do_entry_798) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl_create")
int BPF_KPROBE(do_entry_799) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl_free_rcu")
int BPF_KPROBE(do_entry_800) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl_lookup")
int BPF_KPROBE(do_entry_801) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fl_release")
int BPF_KPROBE(do_entry_802) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_fl_gc")
int BPF_KPROBE(do_entry_803) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6fl_get_next.isra.0")
int BPF_KPROBE(do_entry_804) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_flowlabel_cleanup")
int BPF_KPROBE(do_entry_805) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_flowlabel_init")
int BPF_KPROBE(do_entry_806) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_flowlabel_net_exit")
int BPF_KPROBE(do_entry_807) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_flowlabel_proc_init")
int BPF_KPROBE(do_entry_808) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6fl_seq_next")
int BPF_KPROBE(do_entry_809) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6fl_seq_show")
int BPF_KPROBE(do_entry_810) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6fl_seq_start")
int BPF_KPROBE(do_entry_811) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6fl_seq_stop")
int BPF_KPROBE(do_entry_812) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt")
int BPF_KPROBE(do_entry_813) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_flowlabel_opt_get")
int BPF_KPROBE(do_entry_814) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_input")
int BPF_KPROBE(do_entry_815) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_input_finish")
int BPF_KPROBE(do_entry_816) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_mc_input")
int BPF_KPROBE(do_entry_817) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu")
int BPF_KPROBE(do_entry_818) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rcv_core")
int BPF_KPROBE(do_entry_819) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rcv_finish")
int BPF_KPROBE(do_entry_820) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_rcv_finish_core.constprop.0")
int BPF_KPROBE(do_entry_821) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv")
int BPF_KPROBE(do_entry_822) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_sublist_rcv_finish")
int BPF_KPROBE(do_entry_823) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_list_rcv")
int BPF_KPROBE(do_entry_824) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rcv")
int BPF_KPROBE(do_entry_825) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_cache_add")
int BPF_KPROBE(do_entry_826) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_cache_entry_free")
int BPF_KPROBE(do_entry_827) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_cache_invalidate")
int BPF_KPROBE(do_entry_828) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_add")
int BPF_KPROBE(do_entry_829) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_free")
int BPF_KPROBE(do_entry_830) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_free_rcu")
int BPF_KPROBE(do_entry_831) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_getdef")
int BPF_KPROBE(do_entry_832) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_putdef")
int BPF_KPROBE(do_entry_833) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_remove")
int BPF_KPROBE(do_entry_834) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_doi_walk")
int BPF_KPROBE(do_entry_835) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_exit")
int BPF_KPROBE(do_entry_836) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_genopt")
int BPF_KPROBE(do_entry_837) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_opt_del")
int BPF_KPROBE(do_entry_838) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_opt_find")
int BPF_KPROBE(do_entry_839) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_opt_getattr")
int BPF_KPROBE(do_entry_840) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_opt_insert")
int BPF_KPROBE(do_entry_841) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_opt_update")
int BPF_KPROBE(do_entry_842) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_pad_write.isra.0")
int BPF_KPROBE(do_entry_843) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_req_delattr")
int BPF_KPROBE(do_entry_844) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_req_setattr")
int BPF_KPROBE(do_entry_845) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_skbuff_delattr")
int BPF_KPROBE(do_entry_846) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_skbuff_optptr")
int BPF_KPROBE(do_entry_847) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_skbuff_setattr")
int BPF_KPROBE(do_entry_848) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_sock_delattr")
int BPF_KPROBE(do_entry_849) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_sock_getattr")
int BPF_KPROBE(do_entry_850) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_sock_setattr")
int BPF_KPROBE(do_entry_851) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_tlv_len")
int BPF_KPROBE(do_entry_852) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/calipso_validate")
int BPF_KPROBE(do_entry_853) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers")
int BPF_KPROBE(do_entry_854) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace")
int BPF_KPROBE(do_entry_855) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers")
int BPF_KPROBE(do_entry_856) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_add")
int BPF_KPROBE(do_entry_857) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0")
int BPF_KPROBE(do_entry_858) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_age")
int BPF_KPROBE(do_entry_859) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__fib6_clean_all")
int BPF_KPROBE(do_entry_860) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_clean_all")
int BPF_KPROBE(do_entry_861) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_clean_all_skip_notify")
int BPF_KPROBE(do_entry_862) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_clean_node")
int BPF_KPROBE(do_entry_863) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_clean_tree")
int BPF_KPROBE(do_entry_864) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_del")
int BPF_KPROBE(do_entry_865) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_dump_done")
int BPF_KPROBE(do_entry_866) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_dump_node")
int BPF_KPROBE(do_entry_867) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0")
int BPF_KPROBE(do_entry_868) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_flush_trees")
int BPF_KPROBE(do_entry_869) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_force_start_gc")
int BPF_KPROBE(do_entry_870) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_gc_cleanup")
int BPF_KPROBE(do_entry_871) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_gc_timer_cb")
int BPF_KPROBE(do_entry_872) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_get_table")
int BPF_KPROBE(do_entry_873) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_info_alloc")
int BPF_KPROBE(do_entry_874) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_info_destroy_rcu")
int BPF_KPROBE(do_entry_875) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_locate")
int BPF_KPROBE(do_entry_876) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_locate_1")
int BPF_KPROBE(do_entry_877) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_metric_set")
int BPF_KPROBE(do_entry_878) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_net_exit")
int BPF_KPROBE(do_entry_879) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_net_init")
int BPF_KPROBE(do_entry_880) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_new_table")
int BPF_KPROBE(do_entry_881) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_nh_drop_pcpu_from")
int BPF_KPROBE(do_entry_882) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_node_dump")
int BPF_KPROBE(do_entry_883) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_node_lookup")
int BPF_KPROBE(do_entry_884) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_node_lookup_1")
int BPF_KPROBE(do_entry_885) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_purge_rt")
int BPF_KPROBE(do_entry_886) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_run_gc")
int BPF_KPROBE(do_entry_887) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_tables_dump")
int BPF_KPROBE(do_entry_888) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_tables_seq_read")
int BPF_KPROBE(do_entry_889) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_update_sernum")
int BPF_KPROBE(do_entry_890) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_update_sernum_stub")
int BPF_KPROBE(do_entry_891) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_update_sernum_upto_root")
int BPF_KPROBE(do_entry_892) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_walk_continue")
int BPF_KPROBE(do_entry_893) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/inet6_dump_fib")
int BPF_KPROBE(do_entry_894) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_seq_next")
int BPF_KPROBE(do_entry_895) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk")
int BPF_KPROBE(do_entry_896) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_seq_show")
int BPF_KPROBE(do_entry_897) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_seq_start")
int BPF_KPROBE(do_entry_898) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop")
int BPF_KPROBE(do_entry_899) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_route_yield")
int BPF_KPROBE(do_entry_900) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/node_free_rcu")
int BPF_KPROBE(do_entry_901) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplite6_proc_exit")
int BPF_KPROBE(do_entry_902) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplite6_proc_exit_net")
int BPF_KPROBE(do_entry_903) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplite6_proc_init_net")
int BPF_KPROBE(do_entry_904) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplitev6_err")
int BPF_KPROBE(do_entry_905) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplitev6_exit")
int BPF_KPROBE(do_entry_906) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplitev6_rcv")
int BPF_KPROBE(do_entry_907) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udplitev6_sk_init")
int BPF_KPROBE(do_entry_908) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_gro_complete")
int BPF_KPROBE(do_entry_909) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_gro_receive")
int BPF_KPROBE(do_entry_910) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udp6_ufo_fragment")
int BPF_KPROBE(do_entry_911) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_offload_exit")
int BPF_KPROBE(do_entry_912) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/udpv6_offload_init")
int BPF_KPROBE(do_entry_913) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_exit")
int BPF_KPROBE(do_entry_914) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_genl_dumphmac")
int BPF_KPROBE(do_entry_915) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_genl_dumphmac_done")
int BPF_KPROBE(do_entry_916) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_genl_dumphmac_start")
int BPF_KPROBE(do_entry_917) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_genl_get_tunsrc")
int BPF_KPROBE(do_entry_918) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_genl_sethmac")
int BPF_KPROBE(do_entry_919) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_genl_set_tunsrc")
int BPF_KPROBE(do_entry_920) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_get_srh")
int BPF_KPROBE(do_entry_921) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_icmp_srh")
int BPF_KPROBE(do_entry_922) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_net_exit")
int BPF_KPROBE(do_entry_923) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_net_init")
int BPF_KPROBE(do_entry_924) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/seg6_validate_srh")
int BPF_KPROBE(do_entry_925) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip4ip6_gro_complete")
int BPF_KPROBE(do_entry_926) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip4ip6_gro_receive")
int BPF_KPROBE(do_entry_927) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip4ip6_gso_segment")
int BPF_KPROBE(do_entry_928) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6ip6_gro_complete")
int BPF_KPROBE(do_entry_929) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6ip6_gso_segment")
int BPF_KPROBE(do_entry_930) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_gro_complete")
int BPF_KPROBE(do_entry_931) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_gro_receive")
int BPF_KPROBE(do_entry_932) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_gso_pull_exthdrs")
int BPF_KPROBE(do_entry_933) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_gso_segment")
int BPF_KPROBE(do_entry_934) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/sit_gro_complete")
int BPF_KPROBE(do_entry_935) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/sit_gso_segment")
int BPF_KPROBE(do_entry_936) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/sit_ip6ip6_gro_receive")
int BPF_KPROBE(do_entry_937) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sysctl_net_exit")
int BPF_KPROBE(do_entry_938) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sysctl_net_init")
int BPF_KPROBE(do_entry_939) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sysctl_register")
int BPF_KPROBE(do_entry_940) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_sysctl_unregister")
int BPF_KPROBE(do_entry_941) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/proc_rt6_multipath_hash_fields")
int BPF_KPROBE(do_entry_942) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/proc_rt6_multipath_hash_policy")
int BPF_KPROBE(do_entry_943) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_datagram_connect")
int BPF_KPROBE(do_entry_944) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_connect")
int BPF_KPROBE(do_entry_945) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_connect_v6_only")
int BPF_KPROBE(do_entry_946) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_dst_update")
int BPF_KPROBE(do_entry_947) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_recv_common_ctl")
int BPF_KPROBE(do_entry_948) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_recv_ctl")
int BPF_KPROBE(do_entry_949) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_recv_specific_ctl")
int BPF_KPROBE(do_entry_950) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_release_cb")
int BPF_KPROBE(do_entry_951) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_datagram_send_ctl")
int BPF_KPROBE(do_entry_952) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_dgram_sock_seq_show")
int BPF_KPROBE(do_entry_953) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_icmp_error")
int BPF_KPROBE(do_entry_954) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_local_error")
int BPF_KPROBE(do_entry_955) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_local_rxpmtu")
int BPF_KPROBE(do_entry_956) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_recv_error")
int BPF_KPROBE(do_entry_957) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_recv_rxpmtu")
int BPF_KPROBE(do_entry_958) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_build_state")
int BPF_KPROBE(do_entry_959) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_destroy_state")
int BPF_KPROBE(do_entry_960) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_encap_cmp")
int BPF_KPROBE(do_entry_961) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_encap_nlsize")
int BPF_KPROBE(do_entry_962) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_fill_encap_info")
int BPF_KPROBE(do_entry_963) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_iptunnel_exit")
int BPF_KPROBE(do_entry_964) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ioam6_output")
int BPF_KPROBE(do_entry_965) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_append_data")
int BPF_KPROBE(do_entry_966) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0")
int BPF_KPROBE(do_entry_967) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_autoflowlabel")
int BPF_KPROBE(do_entry_968) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_copy_metadata")
int BPF_KPROBE(do_entry_969) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_cork_release")
int BPF_KPROBE(do_entry_970) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_lookup")
int BPF_KPROBE(do_entry_971) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_flow")
int BPF_KPROBE(do_entry_972) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0")
int BPF_KPROBE(do_entry_973) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel")
int BPF_KPROBE(do_entry_974) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_finish_output")
int BPF_KPROBE(do_entry_975) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_finish_output2")
int BPF_KPROBE(do_entry_976) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames")
int BPF_KPROBE(do_entry_977) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_flush_pending_frames")
int BPF_KPROBE(do_entry_978) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_forward")
int BPF_KPROBE(do_entry_979) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_frag_init")
int BPF_KPROBE(do_entry_980) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_fraglist_init")
int BPF_KPROBE(do_entry_981) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare")
int BPF_KPROBE(do_entry_982) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_fragment")
int BPF_KPROBE(do_entry_983) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_frag_next")
int BPF_KPROBE(do_entry_984) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/__ip6_make_skb")
int BPF_KPROBE(do_entry_985) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_make_skb")
int BPF_KPROBE(do_entry_986) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_output")
int BPF_KPROBE(do_entry_987) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_push_pending_frames")
int BPF_KPROBE(do_entry_988) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_send_skb")
int BPF_KPROBE(do_entry_989) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_setup_cork")
int BPF_KPROBE(do_entry_990) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_sk_dst_lookup_flow")
int BPF_KPROBE(do_entry_991) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ip6_xmit")
int BPF_KPROBE(do_entry_992) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dummy_icmpv6_err_convert")
int BPF_KPROBE(do_entry_993) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dummy_ip6_datagram_recv_ctl")
int BPF_KPROBE(do_entry_994) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dummy_ipv6_chk_addr")
int BPF_KPROBE(do_entry_995) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dummy_ipv6_icmp_error")
int BPF_KPROBE(do_entry_996) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/dummy_ipv6_recv_error")
int BPF_KPROBE(do_entry_997) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/pingv6_exit")
int BPF_KPROBE(do_entry_998) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ping_v6_pre_connect")
int BPF_KPROBE(do_entry_999) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ping_v6_proc_exit_net")
int BPF_KPROBE(do_entry_1000) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ping_v6_proc_init_net")
int BPF_KPROBE(do_entry_1001) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ping_v6_sendmsg")
int BPF_KPROBE(do_entry_1002) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ping_v6_seq_show")
int BPF_KPROBE(do_entry_1003) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ping_v6_seq_start")
int BPF_KPROBE(do_entry_1004) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/call_fib6_notifier")
int BPF_KPROBE(do_entry_1005) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/call_fib6_notifiers")
int BPF_KPROBE(do_entry_1006) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_dump")
int BPF_KPROBE(do_entry_1007) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_notifier_exit")
int BPF_KPROBE(do_entry_1008) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_notifier_init")
int BPF_KPROBE(do_entry_1009) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/fib6_seq_read")
int BPF_KPROBE(do_entry_1010) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/compat_rawv6_ioctl")
int BPF_KPROBE(do_entry_1011) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_destroy")
int BPF_KPROBE(do_entry_1012) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_exit_net")
int BPF_KPROBE(do_entry_1013) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_getfrag")
int BPF_KPROBE(do_entry_1014) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_icmp_error")
int BPF_KPROBE(do_entry_1015) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_init_net")
int BPF_KPROBE(do_entry_1016) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_local_deliver")
int BPF_KPROBE(do_entry_1017) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_proc_exit")
int BPF_KPROBE(do_entry_1018) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw6_seq_show")
int BPF_KPROBE(do_entry_1019) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_bind")
int BPF_KPROBE(do_entry_1020) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_close")
int BPF_KPROBE(do_entry_1021) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_exit")
int BPF_KPROBE(do_entry_1022) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_getsockopt")
int BPF_KPROBE(do_entry_1023) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_init_sk")
int BPF_KPROBE(do_entry_1024) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_ioctl")
int BPF_KPROBE(do_entry_1025) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/raw_v6_match")
int BPF_KPROBE(do_entry_1026) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_mh_filter_register")
int BPF_KPROBE(do_entry_1027) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_mh_filter_unregister")
int BPF_KPROBE(do_entry_1028) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_rcv")
int BPF_KPROBE(do_entry_1029) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_recvmsg")
int BPF_KPROBE(do_entry_1030) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_sendmsg")
int BPF_KPROBE(do_entry_1031) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/rawv6_setsockopt")
int BPF_KPROBE(do_entry_1032) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_compress")
int BPF_KPROBE(do_entry_1033) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rpl_addr_decompress")
int BPF_KPROBE(do_entry_1034) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_compress")
int BPF_KPROBE(do_entry_1035) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_decompress")
int BPF_KPROBE(do_entry_1036) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/ipv6_rpl_srh_size")
int BPF_KPROBE(do_entry_1037) 
{
    u64 saved_rbp = ctx->bp;
    u64 saved_ret = bpf_core_read(&saved_ret, 8, ctx->bp);
    bpf_map_update_elem(&map, &saved_rbp, &saved_ret, 0);
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1e")
int BPF_KPROBE(do_mov_1038)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x80")
int BPF_KPROBE(do_mov_1039)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x9d")
int BPF_KPROBE(do_mov_1040)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xb5")
int BPF_KPROBE(do_mov_1041)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xbd")
int BPF_KPROBE(do_mov_1042)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xc4")
int BPF_KPROBE(do_mov_1043)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xcd")
int BPF_KPROBE(do_mov_1044)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xd7")
int BPF_KPROBE(do_mov_1045)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xe1")
int BPF_KPROBE(do_mov_1046)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xeb")
int BPF_KPROBE(do_mov_1047)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xf5")
int BPF_KPROBE(do_mov_1048)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xff")
int BPF_KPROBE(do_mov_1049)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x109")
int BPF_KPROBE(do_mov_1050)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x113")
int BPF_KPROBE(do_mov_1051)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x11d")
int BPF_KPROBE(do_mov_1052)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x127")
int BPF_KPROBE(do_mov_1053)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x131")
int BPF_KPROBE(do_mov_1054)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x13b")
int BPF_KPROBE(do_mov_1055)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x145")
int BPF_KPROBE(do_mov_1056)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x14f")
int BPF_KPROBE(do_mov_1057)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x159")
int BPF_KPROBE(do_mov_1058)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x166")
int BPF_KPROBE(do_mov_1059)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x176")
int BPF_KPROBE(do_mov_1060)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x186")
int BPF_KPROBE(do_mov_1061)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x196")
int BPF_KPROBE(do_mov_1062)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1a6")
int BPF_KPROBE(do_mov_1063)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1b6")
int BPF_KPROBE(do_mov_1064)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1c6")
int BPF_KPROBE(do_mov_1065)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1d6")
int BPF_KPROBE(do_mov_1066)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1e6")
int BPF_KPROBE(do_mov_1067)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1f6")
int BPF_KPROBE(do_mov_1068)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x206")
int BPF_KPROBE(do_mov_1069)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x216")
int BPF_KPROBE(do_mov_1070)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x226")
int BPF_KPROBE(do_mov_1071)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x236")
int BPF_KPROBE(do_mov_1072)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x246")
int BPF_KPROBE(do_mov_1073)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x256")
int BPF_KPROBE(do_mov_1074)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x266")
int BPF_KPROBE(do_mov_1075)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_markstate + 0x2b")
int BPF_KPROBE(do_mov_1076)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_markstate + 0x47")
int BPF_KPROBE(do_mov_1077)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x95")
int BPF_KPROBE(do_mov_1078)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x9d")
int BPF_KPROBE(do_mov_1079)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0xbb")
int BPF_KPROBE(do_mov_1080)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0xdb")
int BPF_KPROBE(do_mov_1081)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x11e")
int BPF_KPROBE(do_mov_1082)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x125")
int BPF_KPROBE(do_mov_1083)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x12d")
int BPF_KPROBE(do_mov_1084)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x135")
int BPF_KPROBE(do_mov_1085)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x13e")
int BPF_KPROBE(do_mov_1086)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x143")
int BPF_KPROBE(do_mov_1087)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x146")
int BPF_KPROBE(do_mov_1088)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x14f")
int BPF_KPROBE(do_mov_1089)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x36")
int BPF_KPROBE(do_mov_1090)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x39")
int BPF_KPROBE(do_mov_1091)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x3d")
int BPF_KPROBE(do_mov_1092)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x45")
int BPF_KPROBE(do_mov_1093)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x65")
int BPF_KPROBE(do_mov_1094)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x69")
int BPF_KPROBE(do_mov_1095)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1c")
int BPF_KPROBE(do_mov_1096)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1f")
int BPF_KPROBE(do_mov_1097)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x2c")
int BPF_KPROBE(do_mov_1098)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x36")
int BPF_KPROBE(do_mov_1099)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3e")
int BPF_KPROBE(do_mov_1100)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x74")
int BPF_KPROBE(do_mov_1101)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x88")
int BPF_KPROBE(do_mov_1102)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0xa4")
int BPF_KPROBE(do_mov_1103)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x11c")
int BPF_KPROBE(do_mov_1104)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x126")
int BPF_KPROBE(do_mov_1105)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x182")
int BPF_KPROBE(do_mov_1106)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x189")
int BPF_KPROBE(do_mov_1107)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x190")
int BPF_KPROBE(do_mov_1108)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x197")
int BPF_KPROBE(do_mov_1109)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x19f")
int BPF_KPROBE(do_mov_1110)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1c2")
int BPF_KPROBE(do_mov_1111)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x22e")
int BPF_KPROBE(do_mov_1112)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x23d")
int BPF_KPROBE(do_mov_1113)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x241")
int BPF_KPROBE(do_mov_1114)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x2a4")
int BPF_KPROBE(do_mov_1115)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x2b0")
int BPF_KPROBE(do_mov_1116)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x2d5")
int BPF_KPROBE(do_mov_1117)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x326")
int BPF_KPROBE(do_mov_1118)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x343")
int BPF_KPROBE(do_mov_1119)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x384")
int BPF_KPROBE(do_mov_1120)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x38b")
int BPF_KPROBE(do_mov_1121)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3b1")
int BPF_KPROBE(do_mov_1122)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3da")
int BPF_KPROBE(do_mov_1123)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3e8")
int BPF_KPROBE(do_mov_1124)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3f3")
int BPF_KPROBE(do_mov_1125)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x4af")
int BPF_KPROBE(do_mov_1126)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_setup + 0x16")
int BPF_KPROBE(do_mov_1127)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_setup + 0x20")
int BPF_KPROBE(do_mov_1128)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_setup + 0x2b")
int BPF_KPROBE(do_mov_1129)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_setup + 0x35")
int BPF_KPROBE(do_mov_1130)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_setup + 0x40")
int BPF_KPROBE(do_mov_1131)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start + 0x37")
int BPF_KPROBE(do_mov_1132)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start + 0x40")
int BPF_KPROBE(do_mov_1133)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_mfc_seq_start + 0x48")
int BPF_KPROBE(do_mov_1134)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_xmit + 0x34")
int BPF_KPROBE(do_mov_1135)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_xmit + 0x4a")
int BPF_KPROBE(do_mov_1136)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_xmit + 0x5e")
int BPF_KPROBE(do_mov_1137)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_xmit + 0x69")
int BPF_KPROBE(do_mov_1138)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/reg_vif_xmit + 0xdc")
int BPF_KPROBE(do_mov_1139)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_expire_process + 0x78")
int BPF_KPROBE(do_mov_1140)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_expire_process + 0x7c")
int BPF_KPROBE(do_mov_1141)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_expire_process + 0x80")
int BPF_KPROBE(do_mov_1142)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_expire_process + 0x92")
int BPF_KPROBE(do_mov_1143)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_expire_process + 0x9b")
int BPF_KPROBE(do_mov_1144)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipmr_expire_process + 0xa0")
int BPF_KPROBE(do_mov_1145)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x28")
int BPF_KPROBE(do_mov_1146)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x34")
int BPF_KPROBE(do_mov_1147)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x3c")
int BPF_KPROBE(do_mov_1148)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x47")
int BPF_KPROBE(do_mov_1149)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x4b")
int BPF_KPROBE(do_mov_1150)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x87")
int BPF_KPROBE(do_mov_1151)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xad")
int BPF_KPROBE(do_mov_1152)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xe1")
int BPF_KPROBE(do_mov_1153)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xe8")
int BPF_KPROBE(do_mov_1154)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xee")
int BPF_KPROBE(do_mov_1155)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xf2")
int BPF_KPROBE(do_mov_1156)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xf6")
int BPF_KPROBE(do_mov_1157)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0xfe")
int BPF_KPROBE(do_mov_1158)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x106")
int BPF_KPROBE(do_mov_1159)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x15d")
int BPF_KPROBE(do_mov_1160)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x161")
int BPF_KPROBE(do_mov_1161)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x16e")
int BPF_KPROBE(do_mov_1162)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x177")
int BPF_KPROBE(do_mov_1163)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x17f")
int BPF_KPROBE(do_mov_1164)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x187")
int BPF_KPROBE(do_mov_1165)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x18f")
int BPF_KPROBE(do_mov_1166)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x196")
int BPF_KPROBE(do_mov_1167)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x19a")
int BPF_KPROBE(do_mov_1168)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x2e5")
int BPF_KPROBE(do_mov_1169)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x322")
int BPF_KPROBE(do_mov_1170)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x340")
int BPF_KPROBE(do_mov_1171)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x344")
int BPF_KPROBE(do_mov_1172)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x34c")
int BPF_KPROBE(do_mov_1173)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mroute_clean_tables + 0x350")
int BPF_KPROBE(do_mov_1174)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x3e")
int BPF_KPROBE(do_mov_1175)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x4a")
int BPF_KPROBE(do_mov_1176)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x4d")
int BPF_KPROBE(do_mov_1177)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x8b")
int BPF_KPROBE(do_mov_1178)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x99")
int BPF_KPROBE(do_mov_1179)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x9d")
int BPF_KPROBE(do_mov_1180)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0xac")
int BPF_KPROBE(do_mov_1181)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0xc6")
int BPF_KPROBE(do_mov_1182)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x11c")
int BPF_KPROBE(do_mov_1183)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x120")
int BPF_KPROBE(do_mov_1184)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x12d")
int BPF_KPROBE(do_mov_1185)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x159")
int BPF_KPROBE(do_mov_1186)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_getname + 0x15d")
int BPF_KPROBE(do_mov_1187)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_recvmsg + 0x20")
int BPF_KPROBE(do_mov_1188)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_recvmsg + 0x26")
int BPF_KPROBE(do_mov_1189)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_recvmsg + 0x49")
int BPF_KPROBE(do_mov_1190)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0x23")
int BPF_KPROBE(do_mov_1191)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0x60")
int BPF_KPROBE(do_mov_1192)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0x75")
int BPF_KPROBE(do_mov_1193)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0x8b")
int BPF_KPROBE(do_mov_1194)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0x9d")
int BPF_KPROBE(do_mov_1195)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0xb0")
int BPF_KPROBE(do_mov_1196)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0xc2")
int BPF_KPROBE(do_mov_1197)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_compat_ioctl + 0xd3")
int BPF_KPROBE(do_mov_1198)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_ioctl + 0x28")
int BPF_KPROBE(do_mov_1199)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_register_protosw + 0x6a")
int BPF_KPROBE(do_mov_1200)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_register_protosw + 0x6e")
int BPF_KPROBE(do_mov_1201)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_register_protosw + 0x71")
int BPF_KPROBE(do_mov_1202)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_register_protosw + 0x77")
int BPF_KPROBE(do_mov_1203)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x16")
int BPF_KPROBE(do_mov_1204)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x9c")
int BPF_KPROBE(do_mov_1205)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0xaa")
int BPF_KPROBE(do_mov_1206)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0xea")
int BPF_KPROBE(do_mov_1207)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x108")
int BPF_KPROBE(do_mov_1208)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x124")
int BPF_KPROBE(do_mov_1209)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x13d")
int BPF_KPROBE(do_mov_1210)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x14a")
int BPF_KPROBE(do_mov_1211)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x155")
int BPF_KPROBE(do_mov_1212)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x165")
int BPF_KPROBE(do_mov_1213)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x180")
int BPF_KPROBE(do_mov_1214)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x196")
int BPF_KPROBE(do_mov_1215)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x1a7")
int BPF_KPROBE(do_mov_1216)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x1c2")
int BPF_KPROBE(do_mov_1217)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x1dd")
int BPF_KPROBE(do_mov_1218)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x1eb")
int BPF_KPROBE(do_mov_1219)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x1f5")
int BPF_KPROBE(do_mov_1220)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x1fd")
int BPF_KPROBE(do_mov_1221)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x201")
int BPF_KPROBE(do_mov_1222)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x20c")
int BPF_KPROBE(do_mov_1223)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x237")
int BPF_KPROBE(do_mov_1224)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x23e")
int BPF_KPROBE(do_mov_1225)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x26c")
int BPF_KPROBE(do_mov_1226)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x3bb")
int BPF_KPROBE(do_mov_1227)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_create + 0x3d0")
int BPF_KPROBE(do_mov_1228)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x27")
int BPF_KPROBE(do_mov_1229)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x99")
int BPF_KPROBE(do_mov_1230)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xaa")
int BPF_KPROBE(do_mov_1231)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xb3")
int BPF_KPROBE(do_mov_1232)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xc0")
int BPF_KPROBE(do_mov_1233)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xc5")
int BPF_KPROBE(do_mov_1234)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xce")
int BPF_KPROBE(do_mov_1235)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xd7")
int BPF_KPROBE(do_mov_1236)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xe3")
int BPF_KPROBE(do_mov_1237)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xed")
int BPF_KPROBE(do_mov_1238)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0xfb")
int BPF_KPROBE(do_mov_1239)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x108")
int BPF_KPROBE(do_mov_1240)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x195")
int BPF_KPROBE(do_mov_1241)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x1a4")
int BPF_KPROBE(do_mov_1242)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x1ae")
int BPF_KPROBE(do_mov_1243)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x1bb")
int BPF_KPROBE(do_mov_1244)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_sk_rebuild_header + 0x1c9")
int BPF_KPROBE(do_mov_1245)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x11")
int BPF_KPROBE(do_mov_1246)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x1f")
int BPF_KPROBE(do_mov_1247)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x26")
int BPF_KPROBE(do_mov_1248)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x30")
int BPF_KPROBE(do_mov_1249)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x37")
int BPF_KPROBE(do_mov_1250)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x42")
int BPF_KPROBE(do_mov_1251)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x4f")
int BPF_KPROBE(do_mov_1252)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x6a")
int BPF_KPROBE(do_mov_1253)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x7b")
int BPF_KPROBE(do_mov_1254)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x8c")
int BPF_KPROBE(do_mov_1255)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x9d")
int BPF_KPROBE(do_mov_1256)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xa4")
int BPF_KPROBE(do_mov_1257)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xab")
int BPF_KPROBE(do_mov_1258)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xb2")
int BPF_KPROBE(do_mov_1259)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xbc")
int BPF_KPROBE(do_mov_1260)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xc6")
int BPF_KPROBE(do_mov_1261)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xd7")
int BPF_KPROBE(do_mov_1262)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0xf6")
int BPF_KPROBE(do_mov_1263)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x115")
int BPF_KPROBE(do_mov_1264)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x125")
int BPF_KPROBE(do_mov_1265)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x15a")
int BPF_KPROBE(do_mov_1266)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_net_init + 0x180")
int BPF_KPROBE(do_mov_1267)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_unregister_protosw + 0x31")
int BPF_KPROBE(do_mov_1268)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_unregister_protosw + 0x35")
int BPF_KPROBE(do_mov_1269)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_unregister_protosw + 0x42")
int BPF_KPROBE(do_mov_1270)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x2a")
int BPF_KPROBE(do_mov_1271)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x48")
int BPF_KPROBE(do_mov_1272)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x69")
int BPF_KPROBE(do_mov_1273)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x91")
int BPF_KPROBE(do_mov_1274)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0xce")
int BPF_KPROBE(do_mov_1275)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0xd3")
int BPF_KPROBE(do_mov_1276)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0xe3")
int BPF_KPROBE(do_mov_1277)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0xec")
int BPF_KPROBE(do_mov_1278)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x130")
int BPF_KPROBE(do_mov_1279)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x17e")
int BPF_KPROBE(do_mov_1280)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x189")
int BPF_KPROBE(do_mov_1281)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x193")
int BPF_KPROBE(do_mov_1282)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x1f2")
int BPF_KPROBE(do_mov_1283)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x1f7")
int BPF_KPROBE(do_mov_1284)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x200")
int BPF_KPROBE(do_mov_1285)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x22e")
int BPF_KPROBE(do_mov_1286)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x232")
int BPF_KPROBE(do_mov_1287)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x237")
int BPF_KPROBE(do_mov_1288)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x282")
int BPF_KPROBE(do_mov_1289)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x28d")
int BPF_KPROBE(do_mov_1290)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x292")
int BPF_KPROBE(do_mov_1291)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x2cf")
int BPF_KPROBE(do_mov_1292)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x2d3")
int BPF_KPROBE(do_mov_1293)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x2d8")
int BPF_KPROBE(do_mov_1294)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x2dd")
int BPF_KPROBE(do_mov_1295)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x34d")
int BPF_KPROBE(do_mov_1296)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x351")
int BPF_KPROBE(do_mov_1297)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x356")
int BPF_KPROBE(do_mov_1298)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x38f")
int BPF_KPROBE(do_mov_1299)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x399")
int BPF_KPROBE(do_mov_1300)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x39e")
int BPF_KPROBE(do_mov_1301)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x3a3")
int BPF_KPROBE(do_mov_1302)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x3f7")
int BPF_KPROBE(do_mov_1303)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x3fc")
int BPF_KPROBE(do_mov_1304)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x401")
int BPF_KPROBE(do_mov_1305)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x422")
int BPF_KPROBE(do_mov_1306)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x427")
int BPF_KPROBE(do_mov_1307)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x42c")
int BPF_KPROBE(do_mov_1308)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x440")
int BPF_KPROBE(do_mov_1309)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x449")
int BPF_KPROBE(do_mov_1310)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x462")
int BPF_KPROBE(do_mov_1311)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x467")
int BPF_KPROBE(do_mov_1312)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x474")
int BPF_KPROBE(do_mov_1313)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x477")
int BPF_KPROBE(do_mov_1314)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x4d9")
int BPF_KPROBE(do_mov_1315)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x4ee")
int BPF_KPROBE(do_mov_1316)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x4f7")
int BPF_KPROBE(do_mov_1317)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x515")
int BPF_KPROBE(do_mov_1318)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x51e")
int BPF_KPROBE(do_mov_1319)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x5ee")
int BPF_KPROBE(do_mov_1320)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x5fa")
int BPF_KPROBE(do_mov_1321)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x61d")
int BPF_KPROBE(do_mov_1322)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x646")
int BPF_KPROBE(do_mov_1323)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x653")
int BPF_KPROBE(do_mov_1324)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x65b")
int BPF_KPROBE(do_mov_1325)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x664")
int BPF_KPROBE(do_mov_1326)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x6ea")
int BPF_KPROBE(do_mov_1327)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x70c")
int BPF_KPROBE(do_mov_1328)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x711")
int BPF_KPROBE(do_mov_1329)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__inet6_bind + 0x716")
int BPF_KPROBE(do_mov_1330)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_bind + 0x26")
int BPF_KPROBE(do_mov_1331)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_bind + 0x65")
int BPF_KPROBE(do_mov_1332)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_seq_stop + 0x23")
int BPF_KPROBE(do_mov_1333)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0 + 0x20")
int BPF_KPROBE(do_mov_1334)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0 + 0x30")
int BPF_KPROBE(do_mov_1335)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0 + 0x80")
int BPF_KPROBE(do_mov_1336)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_get_next.isra.0 + 0x88")
int BPF_KPROBE(do_mov_1337)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_seq_start + 0x2b")
int BPF_KPROBE(do_mov_1338)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_seq_start + 0x41")
int BPF_KPROBE(do_mov_1339)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_seq_start + 0x49")
int BPF_KPROBE(do_mov_1340)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_seq_start + 0x8d")
int BPF_KPROBE(do_mov_1341)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ac6_seq_start + 0xa8")
int BPF_KPROBE(do_mov_1342)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0xba")
int BPF_KPROBE(do_mov_1343)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x102")
int BPF_KPROBE(do_mov_1344)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x10a")
int BPF_KPROBE(do_mov_1345)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x12e")
int BPF_KPROBE(do_mov_1346)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x136")
int BPF_KPROBE(do_mov_1347)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x13e")
int BPF_KPROBE(do_mov_1348)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x142")
int BPF_KPROBE(do_mov_1349)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x14d")
int BPF_KPROBE(do_mov_1350)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x155")
int BPF_KPROBE(do_mov_1351)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x15e")
int BPF_KPROBE(do_mov_1352)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x166")
int BPF_KPROBE(do_mov_1353)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x16e")
int BPF_KPROBE(do_mov_1354)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x191")
int BPF_KPROBE(do_mov_1355)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x1ea")
int BPF_KPROBE(do_mov_1356)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x1ee")
int BPF_KPROBE(do_mov_1357)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x1f2")
int BPF_KPROBE(do_mov_1358)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x1ff")
int BPF_KPROBE(do_mov_1359)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x20a")
int BPF_KPROBE(do_mov_1360)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x22a")
int BPF_KPROBE(do_mov_1361)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x263")
int BPF_KPROBE(do_mov_1362)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x2cb")
int BPF_KPROBE(do_mov_1363)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x2e2")
int BPF_KPROBE(do_mov_1364)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x2f9")
int BPF_KPROBE(do_mov_1365)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_inc + 0x318")
int BPF_KPROBE(do_mov_1366)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x27")
int BPF_KPROBE(do_mov_1367)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x40")
int BPF_KPROBE(do_mov_1368)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x53")
int BPF_KPROBE(do_mov_1369)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0xac")
int BPF_KPROBE(do_mov_1370)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0xdc")
int BPF_KPROBE(do_mov_1371)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0xf3")
int BPF_KPROBE(do_mov_1372)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0xf6")
int BPF_KPROBE(do_mov_1373)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x129")
int BPF_KPROBE(do_mov_1374)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x1b2")
int BPF_KPROBE(do_mov_1375)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x1de")
int BPF_KPROBE(do_mov_1376)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x1e2")
int BPF_KPROBE(do_mov_1377)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_join + 0x22d")
int BPF_KPROBE(do_mov_1378)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0x7e")
int BPF_KPROBE(do_mov_1379)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0x99")
int BPF_KPROBE(do_mov_1380)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0xc0")
int BPF_KPROBE(do_mov_1381)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0xc8")
int BPF_KPROBE(do_mov_1382)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0xcc")
int BPF_KPROBE(do_mov_1383)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0x128")
int BPF_KPROBE(do_mov_1384)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_ac_dec + 0x154")
int BPF_KPROBE(do_mov_1385)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_drop + 0x3e")
int BPF_KPROBE(do_mov_1386)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_drop + 0x9f")
int BPF_KPROBE(do_mov_1387)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_drop + 0xfe")
int BPF_KPROBE(do_mov_1388)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_sock_ac_drop + 0x124")
int BPF_KPROBE(do_mov_1389)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_ac_close + 0x39")
int BPF_KPROBE(do_mov_1390)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_ac_close + 0x4b")
int BPF_KPROBE(do_mov_1391)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_ac_close + 0xd9")
int BPF_KPROBE(do_mov_1392)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_ac_destroy_dev + 0x22")
int BPF_KPROBE(do_mov_1393)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_ac_destroy_dev + 0x49")
int BPF_KPROBE(do_mov_1394)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_ac_destroy_dev + 0x51")
int BPF_KPROBE(do_mov_1395)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_ac_destroy_dev + 0x55")
int BPF_KPROBE(do_mov_1396)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x10")
int BPF_KPROBE(do_mov_1397)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x17")
int BPF_KPROBE(do_mov_1398)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x1a")
int BPF_KPROBE(do_mov_1399)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x22")
int BPF_KPROBE(do_mov_1400)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x25")
int BPF_KPROBE(do_mov_1401)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x2c")
int BPF_KPROBE(do_mov_1402)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x31")
int BPF_KPROBE(do_mov_1403)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x35")
int BPF_KPROBE(do_mov_1404)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x38")
int BPF_KPROBE(do_mov_1405)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_init + 0x3b")
int BPF_KPROBE(do_mov_1406)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_cork_release + 0x4c")
int BPF_KPROBE(do_mov_1407)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_cork_release + 0x65")
int BPF_KPROBE(do_mov_1408)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames + 0x30")
int BPF_KPROBE(do_mov_1409)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames + 0x3a")
int BPF_KPROBE(do_mov_1410)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames + 0x42")
int BPF_KPROBE(do_mov_1411)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames + 0x49")
int BPF_KPROBE(do_mov_1412)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_flush_pending_frames + 0x4d")
int BPF_KPROBE(do_mov_1413)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x33")
int BPF_KPROBE(do_mov_1414)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x41")
int BPF_KPROBE(do_mov_1415)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x56")
int BPF_KPROBE(do_mov_1416)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x5a")
int BPF_KPROBE(do_mov_1417)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x5f")
int BPF_KPROBE(do_mov_1418)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0xc2")
int BPF_KPROBE(do_mov_1419)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0xcd")
int BPF_KPROBE(do_mov_1420)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0xd5")
int BPF_KPROBE(do_mov_1421)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0xde")
int BPF_KPROBE(do_mov_1422)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0xe7")
int BPF_KPROBE(do_mov_1423)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0xef")
int BPF_KPROBE(do_mov_1424)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x100")
int BPF_KPROBE(do_mov_1425)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x12f")
int BPF_KPROBE(do_mov_1426)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x133")
int BPF_KPROBE(do_mov_1427)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tunnel + 0x148")
int BPF_KPROBE(do_mov_1428)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0xac")
int BPF_KPROBE(do_mov_1429)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0xde")
int BPF_KPROBE(do_mov_1430)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0x145")
int BPF_KPROBE(do_mov_1431)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0x149")
int BPF_KPROBE(do_mov_1432)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0x181")
int BPF_KPROBE(do_mov_1433)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0x201")
int BPF_KPROBE(do_mov_1434)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_tail.constprop.0 + 0x229")
int BPF_KPROBE(do_mov_1435)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_flow + 0x2c")
int BPF_KPROBE(do_mov_1436)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_flow + 0x36")
int BPF_KPROBE(do_mov_1437)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_flow + 0x53")
int BPF_KPROBE(do_mov_1438)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup_flow + 0x58")
int BPF_KPROBE(do_mov_1439)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_lookup + 0x6")
int BPF_KPROBE(do_mov_1440)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x2b")
int BPF_KPROBE(do_mov_1441)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x41")
int BPF_KPROBE(do_mov_1442)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x4a")
int BPF_KPROBE(do_mov_1443)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x6c")
int BPF_KPROBE(do_mov_1444)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x7d")
int BPF_KPROBE(do_mov_1445)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x86")
int BPF_KPROBE(do_mov_1446)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x8e")
int BPF_KPROBE(do_mov_1447)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x92")
int BPF_KPROBE(do_mov_1448)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x96")
int BPF_KPROBE(do_mov_1449)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0xb5")
int BPF_KPROBE(do_mov_1450)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0xc3")
int BPF_KPROBE(do_mov_1451)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0xd1")
int BPF_KPROBE(do_mov_1452)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0xf2")
int BPF_KPROBE(do_mov_1453)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0xf6")
int BPF_KPROBE(do_mov_1454)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0xfb")
int BPF_KPROBE(do_mov_1455)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x100")
int BPF_KPROBE(do_mov_1456)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x146")
int BPF_KPROBE(do_mov_1457)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x157")
int BPF_KPROBE(do_mov_1458)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_init + 0x15b")
int BPF_KPROBE(do_mov_1459)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x26")
int BPF_KPROBE(do_mov_1460)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x2a")
int BPF_KPROBE(do_mov_1461)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x32")
int BPF_KPROBE(do_mov_1462)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x40")
int BPF_KPROBE(do_mov_1463)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x71")
int BPF_KPROBE(do_mov_1464)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x85")
int BPF_KPROBE(do_mov_1465)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x96")
int BPF_KPROBE(do_mov_1466)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x9b")
int BPF_KPROBE(do_mov_1467)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x113")
int BPF_KPROBE(do_mov_1468)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x132")
int BPF_KPROBE(do_mov_1469)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1a8")
int BPF_KPROBE(do_mov_1470)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1af")
int BPF_KPROBE(do_mov_1471)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1be")
int BPF_KPROBE(do_mov_1472)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1c5")
int BPF_KPROBE(do_mov_1473)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1d5")
int BPF_KPROBE(do_mov_1474)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1d9")
int BPF_KPROBE(do_mov_1475)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1e7")
int BPF_KPROBE(do_mov_1476)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1eb")
int BPF_KPROBE(do_mov_1477)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x1f4")
int BPF_KPROBE(do_mov_1478)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x200")
int BPF_KPROBE(do_mov_1479)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x209")
int BPF_KPROBE(do_mov_1480)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x2c5")
int BPF_KPROBE(do_mov_1481)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x2c9")
int BPF_KPROBE(do_mov_1482)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x314")
int BPF_KPROBE(do_mov_1483)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x318")
int BPF_KPROBE(do_mov_1484)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x33b")
int BPF_KPROBE(do_mov_1485)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x33f")
int BPF_KPROBE(do_mov_1486)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x482")
int BPF_KPROBE(do_mov_1487)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x486")
int BPF_KPROBE(do_mov_1488)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x4da")
int BPF_KPROBE(do_mov_1489)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x4de")
int BPF_KPROBE(do_mov_1490)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x505")
int BPF_KPROBE(do_mov_1491)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x518")
int BPF_KPROBE(do_mov_1492)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x52d")
int BPF_KPROBE(do_mov_1493)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x531")
int BPF_KPROBE(do_mov_1494)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x549")
int BPF_KPROBE(do_mov_1495)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x556")
int BPF_KPROBE(do_mov_1496)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x55a")
int BPF_KPROBE(do_mov_1497)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x55e")
int BPF_KPROBE(do_mov_1498)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x56b")
int BPF_KPROBE(do_mov_1499)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x580")
int BPF_KPROBE(do_mov_1500)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x584")
int BPF_KPROBE(do_mov_1501)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_xmit + 0x5ca")
int BPF_KPROBE(do_mov_1502)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x37")
int BPF_KPROBE(do_mov_1503)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x1b1")
int BPF_KPROBE(do_mov_1504)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x1d8")
int BPF_KPROBE(do_mov_1505)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x269")
int BPF_KPROBE(do_mov_1506)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x26d")
int BPF_KPROBE(do_mov_1507)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x2a5")
int BPF_KPROBE(do_mov_1508)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x2b9")
int BPF_KPROBE(do_mov_1509)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x2be")
int BPF_KPROBE(do_mov_1510)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x369")
int BPF_KPROBE(do_mov_1511)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x37b")
int BPF_KPROBE(do_mov_1512)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x380")
int BPF_KPROBE(do_mov_1513)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x385")
int BPF_KPROBE(do_mov_1514)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x3ac")
int BPF_KPROBE(do_mov_1515)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x3b1")
int BPF_KPROBE(do_mov_1516)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x3e5")
int BPF_KPROBE(do_mov_1517)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x3ea")
int BPF_KPROBE(do_mov_1518)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x3ef")
int BPF_KPROBE(do_mov_1519)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x422")
int BPF_KPROBE(do_mov_1520)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x427")
int BPF_KPROBE(do_mov_1521)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x486")
int BPF_KPROBE(do_mov_1522)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x48e")
int BPF_KPROBE(do_mov_1523)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x493")
int BPF_KPROBE(do_mov_1524)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x4d3")
int BPF_KPROBE(do_mov_1525)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x4d8")
int BPF_KPROBE(do_mov_1526)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x507")
int BPF_KPROBE(do_mov_1527)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x50c")
int BPF_KPROBE(do_mov_1528)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x56a")
int BPF_KPROBE(do_mov_1529)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x56f")
int BPF_KPROBE(do_mov_1530)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x574")
int BPF_KPROBE(do_mov_1531)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output2 + 0x67d")
int BPF_KPROBE(do_mov_1532)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x2b")
int BPF_KPROBE(do_mov_1533)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x2f")
int BPF_KPROBE(do_mov_1534)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x47")
int BPF_KPROBE(do_mov_1535)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x50")
int BPF_KPROBE(do_mov_1536)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x54")
int BPF_KPROBE(do_mov_1537)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0xb5")
int BPF_KPROBE(do_mov_1538)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0xc1")
int BPF_KPROBE(do_mov_1539)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0xd5")
int BPF_KPROBE(do_mov_1540)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0xdf")
int BPF_KPROBE(do_mov_1541)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0xf5")
int BPF_KPROBE(do_mov_1542)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x10a")
int BPF_KPROBE(do_mov_1543)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x136")
int BPF_KPROBE(do_mov_1544)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x14b")
int BPF_KPROBE(do_mov_1545)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x177")
int BPF_KPROBE(do_mov_1546)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x18c")
int BPF_KPROBE(do_mov_1547)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x1b8")
int BPF_KPROBE(do_mov_1548)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x1cd")
int BPF_KPROBE(do_mov_1549)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x1eb")
int BPF_KPROBE(do_mov_1550)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x1f4")
int BPF_KPROBE(do_mov_1551)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x20d")
int BPF_KPROBE(do_mov_1552)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x23f")
int BPF_KPROBE(do_mov_1553)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x248")
int BPF_KPROBE(do_mov_1554)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x24c")
int BPF_KPROBE(do_mov_1555)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x255")
int BPF_KPROBE(do_mov_1556)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x288")
int BPF_KPROBE(do_mov_1557)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x2a1")
int BPF_KPROBE(do_mov_1558)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x2ac")
int BPF_KPROBE(do_mov_1559)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x2c9")
int BPF_KPROBE(do_mov_1560)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x301")
int BPF_KPROBE(do_mov_1561)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x367")
int BPF_KPROBE(do_mov_1562)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x37b")
int BPF_KPROBE(do_mov_1563)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_setup_cork + 0x38f")
int BPF_KPROBE(do_mov_1564)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x2a")
int BPF_KPROBE(do_mov_1565)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x36")
int BPF_KPROBE(do_mov_1566)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x43")
int BPF_KPROBE(do_mov_1567)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x82")
int BPF_KPROBE(do_mov_1568)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x9f")
int BPF_KPROBE(do_mov_1569)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0xaa")
int BPF_KPROBE(do_mov_1570)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0xb6")
int BPF_KPROBE(do_mov_1571)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0xc4")
int BPF_KPROBE(do_mov_1572)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0xe2")
int BPF_KPROBE(do_mov_1573)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0xf9")
int BPF_KPROBE(do_mov_1574)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x108")
int BPF_KPROBE(do_mov_1575)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x147")
int BPF_KPROBE(do_mov_1576)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x152")
int BPF_KPROBE(do_mov_1577)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x194")
int BPF_KPROBE(do_mov_1578)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x1a2")
int BPF_KPROBE(do_mov_1579)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x1b1")
int BPF_KPROBE(do_mov_1580)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x1c4")
int BPF_KPROBE(do_mov_1581)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_copy_metadata + 0x1ef")
int BPF_KPROBE(do_mov_1582)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0x46")
int BPF_KPROBE(do_mov_1583)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0x59")
int BPF_KPROBE(do_mov_1584)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0x69")
int BPF_KPROBE(do_mov_1585)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0x96")
int BPF_KPROBE(do_mov_1586)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0x9d")
int BPF_KPROBE(do_mov_1587)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0xa2")
int BPF_KPROBE(do_mov_1588)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0xae")
int BPF_KPROBE(do_mov_1589)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0xbd")
int BPF_KPROBE(do_mov_1590)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0xcb")
int BPF_KPROBE(do_mov_1591)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fraglist_prepare + 0xed")
int BPF_KPROBE(do_mov_1592)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0xa9")
int BPF_KPROBE(do_mov_1593)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0xc6")
int BPF_KPROBE(do_mov_1594)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0xdb")
int BPF_KPROBE(do_mov_1595)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x106")
int BPF_KPROBE(do_mov_1596)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x13c")
int BPF_KPROBE(do_mov_1597)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x145")
int BPF_KPROBE(do_mov_1598)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x14a")
int BPF_KPROBE(do_mov_1599)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x150")
int BPF_KPROBE(do_mov_1600)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x181")
int BPF_KPROBE(do_mov_1601)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x1ab")
int BPF_KPROBE(do_mov_1602)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x1bc")
int BPF_KPROBE(do_mov_1603)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_frag_next + 0x1cd")
int BPF_KPROBE(do_mov_1604)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x22")
int BPF_KPROBE(do_mov_1605)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x2d")
int BPF_KPROBE(do_mov_1606)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x3c")
int BPF_KPROBE(do_mov_1607)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x40")
int BPF_KPROBE(do_mov_1608)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x48")
int BPF_KPROBE(do_mov_1609)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x55")
int BPF_KPROBE(do_mov_1610)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x63")
int BPF_KPROBE(do_mov_1611)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x70")
int BPF_KPROBE(do_mov_1612)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x7a")
int BPF_KPROBE(do_mov_1613)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x91")
int BPF_KPROBE(do_mov_1614)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa6")
int BPF_KPROBE(do_mov_1615)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa9")
int BPF_KPROBE(do_mov_1616)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xec")
int BPF_KPROBE(do_mov_1617)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xf3")
int BPF_KPROBE(do_mov_1618)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x113")
int BPF_KPROBE(do_mov_1619)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x127")
int BPF_KPROBE(do_mov_1620)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x14b")
int BPF_KPROBE(do_mov_1621)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x15f")
int BPF_KPROBE(do_mov_1622)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x200")
int BPF_KPROBE(do_mov_1623)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x21a")
int BPF_KPROBE(do_mov_1624)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x21e")
int BPF_KPROBE(do_mov_1625)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x234")
int BPF_KPROBE(do_mov_1626)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x248")
int BPF_KPROBE(do_mov_1627)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x257")
int BPF_KPROBE(do_mov_1628)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x261")
int BPF_KPROBE(do_mov_1629)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x26c")
int BPF_KPROBE(do_mov_1630)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x32e")
int BPF_KPROBE(do_mov_1631)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x373")
int BPF_KPROBE(do_mov_1632)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x37a")
int BPF_KPROBE(do_mov_1633)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x3c8")
int BPF_KPROBE(do_mov_1634)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x3d9")
int BPF_KPROBE(do_mov_1635)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x3dd")
int BPF_KPROBE(do_mov_1636)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x3e0")
int BPF_KPROBE(do_mov_1637)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x41c")
int BPF_KPROBE(do_mov_1638)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x449")
int BPF_KPROBE(do_mov_1639)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x4e9")
int BPF_KPROBE(do_mov_1640)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x4fc")
int BPF_KPROBE(do_mov_1641)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x5bf")
int BPF_KPROBE(do_mov_1642)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x681")
int BPF_KPROBE(do_mov_1643)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x702")
int BPF_KPROBE(do_mov_1644)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x710")
int BPF_KPROBE(do_mov_1645)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x734")
int BPF_KPROBE(do_mov_1646)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x747")
int BPF_KPROBE(do_mov_1647)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x761")
int BPF_KPROBE(do_mov_1648)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x76f")
int BPF_KPROBE(do_mov_1649)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x7aa")
int BPF_KPROBE(do_mov_1650)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x7b3")
int BPF_KPROBE(do_mov_1651)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x7b7")
int BPF_KPROBE(do_mov_1652)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x7e1")
int BPF_KPROBE(do_mov_1653)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x827")
int BPF_KPROBE(do_mov_1654)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x887")
int BPF_KPROBE(do_mov_1655)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x897")
int BPF_KPROBE(do_mov_1656)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x8a7")
int BPF_KPROBE(do_mov_1657)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x8b5")
int BPF_KPROBE(do_mov_1658)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x8da")
int BPF_KPROBE(do_mov_1659)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x8e2")
int BPF_KPROBE(do_mov_1660)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x8ea")
int BPF_KPROBE(do_mov_1661)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x91a")
int BPF_KPROBE(do_mov_1662)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x98c")
int BPF_KPROBE(do_mov_1663)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x9b9")
int BPF_KPROBE(do_mov_1664)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x9e7")
int BPF_KPROBE(do_mov_1665)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa10")
int BPF_KPROBE(do_mov_1666)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa20")
int BPF_KPROBE(do_mov_1667)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa43")
int BPF_KPROBE(do_mov_1668)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa6d")
int BPF_KPROBE(do_mov_1669)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa85")
int BPF_KPROBE(do_mov_1670)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa90")
int BPF_KPROBE(do_mov_1671)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xa96")
int BPF_KPROBE(do_mov_1672)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xaaa")
int BPF_KPROBE(do_mov_1673)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xac3")
int BPF_KPROBE(do_mov_1674)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xac6")
int BPF_KPROBE(do_mov_1675)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xafd")
int BPF_KPROBE(do_mov_1676)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xb26")
int BPF_KPROBE(do_mov_1677)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xb38")
int BPF_KPROBE(do_mov_1678)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xb73")
int BPF_KPROBE(do_mov_1679)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xba2")
int BPF_KPROBE(do_mov_1680)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xbd1")
int BPF_KPROBE(do_mov_1681)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xbe8")
int BPF_KPROBE(do_mov_1682)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc06")
int BPF_KPROBE(do_mov_1683)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc10")
int BPF_KPROBE(do_mov_1684)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc4a")
int BPF_KPROBE(do_mov_1685)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc55")
int BPF_KPROBE(do_mov_1686)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc72")
int BPF_KPROBE(do_mov_1687)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc7e")
int BPF_KPROBE(do_mov_1688)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc87")
int BPF_KPROBE(do_mov_1689)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xc94")
int BPF_KPROBE(do_mov_1690)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xceb")
int BPF_KPROBE(do_mov_1691)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xcf8")
int BPF_KPROBE(do_mov_1692)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xd09")
int BPF_KPROBE(do_mov_1693)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xd22")
int BPF_KPROBE(do_mov_1694)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xd75")
int BPF_KPROBE(do_mov_1695)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xd79")
int BPF_KPROBE(do_mov_1696)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xd91")
int BPF_KPROBE(do_mov_1697)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xdf5")
int BPF_KPROBE(do_mov_1698)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xdf9")
int BPF_KPROBE(do_mov_1699)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe36")
int BPF_KPROBE(do_mov_1700)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe40")
int BPF_KPROBE(do_mov_1701)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe4e")
int BPF_KPROBE(do_mov_1702)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe51")
int BPF_KPROBE(do_mov_1703)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe5b")
int BPF_KPROBE(do_mov_1704)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe5f")
int BPF_KPROBE(do_mov_1705)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe63")
int BPF_KPROBE(do_mov_1706)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe69")
int BPF_KPROBE(do_mov_1707)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe73")
int BPF_KPROBE(do_mov_1708)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe79")
int BPF_KPROBE(do_mov_1709)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xe7c")
int BPF_KPROBE(do_mov_1710)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xea5")
int BPF_KPROBE(do_mov_1711)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xeaf")
int BPF_KPROBE(do_mov_1712)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xeb6")
int BPF_KPROBE(do_mov_1713)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xede")
int BPF_KPROBE(do_mov_1714)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xefc")
int BPF_KPROBE(do_mov_1715)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xf2c")
int BPF_KPROBE(do_mov_1716)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xf31")
int BPF_KPROBE(do_mov_1717)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xf49")
int BPF_KPROBE(do_mov_1718)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xf50")
int BPF_KPROBE(do_mov_1719)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xfab")
int BPF_KPROBE(do_mov_1720)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xfd1")
int BPF_KPROBE(do_mov_1721)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xfdc")
int BPF_KPROBE(do_mov_1722)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xfed")
int BPF_KPROBE(do_mov_1723)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0xff1")
int BPF_KPROBE(do_mov_1724)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1072")
int BPF_KPROBE(do_mov_1725)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1076")
int BPF_KPROBE(do_mov_1726)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1098")
int BPF_KPROBE(do_mov_1727)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x109c")
int BPF_KPROBE(do_mov_1728)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x10aa")
int BPF_KPROBE(do_mov_1729)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x10b3")
int BPF_KPROBE(do_mov_1730)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x10b9")
int BPF_KPROBE(do_mov_1731)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x10e3")
int BPF_KPROBE(do_mov_1732)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x10f0")
int BPF_KPROBE(do_mov_1733)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1107")
int BPF_KPROBE(do_mov_1734)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x111d")
int BPF_KPROBE(do_mov_1735)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1137")
int BPF_KPROBE(do_mov_1736)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x114c")
int BPF_KPROBE(do_mov_1737)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1153")
int BPF_KPROBE(do_mov_1738)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x118a")
int BPF_KPROBE(do_mov_1739)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x11a1")
int BPF_KPROBE(do_mov_1740)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_append_data.isra.0 + 0x1218")
int BPF_KPROBE(do_mov_1741)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x32")
int BPF_KPROBE(do_mov_1742)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0xed")
int BPF_KPROBE(do_mov_1743)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0xf8")
int BPF_KPROBE(do_mov_1744)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0xfc")
int BPF_KPROBE(do_mov_1745)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x100")
int BPF_KPROBE(do_mov_1746)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x120")
int BPF_KPROBE(do_mov_1747)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x12b")
int BPF_KPROBE(do_mov_1748)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x136")
int BPF_KPROBE(do_mov_1749)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x141")
int BPF_KPROBE(do_mov_1750)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x14c")
int BPF_KPROBE(do_mov_1751)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x157")
int BPF_KPROBE(do_mov_1752)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x162")
int BPF_KPROBE(do_mov_1753)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x16d")
int BPF_KPROBE(do_mov_1754)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x178")
int BPF_KPROBE(do_mov_1755)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x183")
int BPF_KPROBE(do_mov_1756)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x18e")
int BPF_KPROBE(do_mov_1757)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_append_data + 0x199")
int BPF_KPROBE(do_mov_1758)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x31")
int BPF_KPROBE(do_mov_1759)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x168")
int BPF_KPROBE(do_mov_1760)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x328")
int BPF_KPROBE(do_mov_1761)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x47b")
int BPF_KPROBE(do_mov_1762)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x543")
int BPF_KPROBE(do_mov_1763)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x653")
int BPF_KPROBE(do_mov_1764)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x65d")
int BPF_KPROBE(do_mov_1765)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x666")
int BPF_KPROBE(do_mov_1766)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x670")
int BPF_KPROBE(do_mov_1767)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x7be")
int BPF_KPROBE(do_mov_1768)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x7cc")
int BPF_KPROBE(do_mov_1769)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x850")
int BPF_KPROBE(do_mov_1770)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x85f")
int BPF_KPROBE(do_mov_1771)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x863")
int BPF_KPROBE(do_mov_1772)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_forward + 0x98e")
int BPF_KPROBE(do_mov_1773)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x1f")
int BPF_KPROBE(do_mov_1774)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x27")
int BPF_KPROBE(do_mov_1775)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x37")
int BPF_KPROBE(do_mov_1776)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3f")
int BPF_KPROBE(do_mov_1777)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x8a")
int BPF_KPROBE(do_mov_1778)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0xb6")
int BPF_KPROBE(do_mov_1779)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0xc3")
int BPF_KPROBE(do_mov_1780)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0xd2")
int BPF_KPROBE(do_mov_1781)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x147")
int BPF_KPROBE(do_mov_1782)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x269")
int BPF_KPROBE(do_mov_1783)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x298")
int BPF_KPROBE(do_mov_1784)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x2a3")
int BPF_KPROBE(do_mov_1785)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x2b1")
int BPF_KPROBE(do_mov_1786)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x307")
int BPF_KPROBE(do_mov_1787)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x30e")
int BPF_KPROBE(do_mov_1788)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x32e")
int BPF_KPROBE(do_mov_1789)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x337")
int BPF_KPROBE(do_mov_1790)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x38d")
int BPF_KPROBE(do_mov_1791)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x39a")
int BPF_KPROBE(do_mov_1792)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x39e")
int BPF_KPROBE(do_mov_1793)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3a8")
int BPF_KPROBE(do_mov_1794)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3ab")
int BPF_KPROBE(do_mov_1795)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3b1")
int BPF_KPROBE(do_mov_1796)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3b4")
int BPF_KPROBE(do_mov_1797)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3b8")
int BPF_KPROBE(do_mov_1798)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3bb")
int BPF_KPROBE(do_mov_1799)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3be")
int BPF_KPROBE(do_mov_1800)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3cb")
int BPF_KPROBE(do_mov_1801)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x3e3")
int BPF_KPROBE(do_mov_1802)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x402")
int BPF_KPROBE(do_mov_1803)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x4d1")
int BPF_KPROBE(do_mov_1804)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x4d5")
int BPF_KPROBE(do_mov_1805)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x54e")
int BPF_KPROBE(do_mov_1806)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x5d3")
int BPF_KPROBE(do_mov_1807)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x5e1")
int BPF_KPROBE(do_mov_1808)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x623")
int BPF_KPROBE(do_mov_1809)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x6a3")
int BPF_KPROBE(do_mov_1810)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x6b4")
int BPF_KPROBE(do_mov_1811)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x75b")
int BPF_KPROBE(do_mov_1812)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_fragment + 0x75f")
int BPF_KPROBE(do_mov_1813)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output + 0x29f")
int BPF_KPROBE(do_mov_1814)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_finish_output + 0x2b2")
int BPF_KPROBE(do_mov_1815)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_output + 0x2e")
int BPF_KPROBE(do_mov_1816)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_output + 0x44")
int BPF_KPROBE(do_mov_1817)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_output + 0x4b")
int BPF_KPROBE(do_mov_1818)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x2b")
int BPF_KPROBE(do_mov_1819)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x63")
int BPF_KPROBE(do_mov_1820)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x70")
int BPF_KPROBE(do_mov_1821)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x89")
int BPF_KPROBE(do_mov_1822)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x95")
int BPF_KPROBE(do_mov_1823)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x9d")
int BPF_KPROBE(do_mov_1824)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0xa6")
int BPF_KPROBE(do_mov_1825)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0xaa")
int BPF_KPROBE(do_mov_1826)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0xce")
int BPF_KPROBE(do_mov_1827)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x105")
int BPF_KPROBE(do_mov_1828)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x10f")
int BPF_KPROBE(do_mov_1829)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x116")
int BPF_KPROBE(do_mov_1830)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x11e")
int BPF_KPROBE(do_mov_1831)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x122")
int BPF_KPROBE(do_mov_1832)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x13e")
int BPF_KPROBE(do_mov_1833)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x151")
int BPF_KPROBE(do_mov_1834)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x175")
int BPF_KPROBE(do_mov_1835)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x17d")
int BPF_KPROBE(do_mov_1836)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x20b")
int BPF_KPROBE(do_mov_1837)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x220")
int BPF_KPROBE(do_mov_1838)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x23c")
int BPF_KPROBE(do_mov_1839)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x26e")
int BPF_KPROBE(do_mov_1840)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x285")
int BPF_KPROBE(do_mov_1841)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x2a4")
int BPF_KPROBE(do_mov_1842)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x30d")
int BPF_KPROBE(do_mov_1843)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x314")
int BPF_KPROBE(do_mov_1844)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x31c")
int BPF_KPROBE(do_mov_1845)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x32f")
int BPF_KPROBE(do_mov_1846)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x333")
int BPF_KPROBE(do_mov_1847)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x33e")
int BPF_KPROBE(do_mov_1848)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x342")
int BPF_KPROBE(do_mov_1849)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x34c")
int BPF_KPROBE(do_mov_1850)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x358")
int BPF_KPROBE(do_mov_1851)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x364")
int BPF_KPROBE(do_mov_1852)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x372")
int BPF_KPROBE(do_mov_1853)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x383")
int BPF_KPROBE(do_mov_1854)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x3a1")
int BPF_KPROBE(do_mov_1855)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x408")
int BPF_KPROBE(do_mov_1856)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x41d")
int BPF_KPROBE(do_mov_1857)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x537")
int BPF_KPROBE(do_mov_1858)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x53b")
int BPF_KPROBE(do_mov_1859)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x560")
int BPF_KPROBE(do_mov_1860)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x564")
int BPF_KPROBE(do_mov_1861)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x58a")
int BPF_KPROBE(do_mov_1862)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_make_skb + 0x59d")
int BPF_KPROBE(do_mov_1863)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x3c")
int BPF_KPROBE(do_mov_1864)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x40")
int BPF_KPROBE(do_mov_1865)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x50")
int BPF_KPROBE(do_mov_1866)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x7a")
int BPF_KPROBE(do_mov_1867)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x81")
int BPF_KPROBE(do_mov_1868)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x89")
int BPF_KPROBE(do_mov_1869)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x90")
int BPF_KPROBE(do_mov_1870)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x94")
int BPF_KPROBE(do_mov_1871)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x98")
int BPF_KPROBE(do_mov_1872)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x9c")
int BPF_KPROBE(do_mov_1873)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0xa0")
int BPF_KPROBE(do_mov_1874)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0xa7")
int BPF_KPROBE(do_mov_1875)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0xfc")
int BPF_KPROBE(do_mov_1876)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x171")
int BPF_KPROBE(do_mov_1877)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_make_skb + 0x196")
int BPF_KPROBE(do_mov_1878)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv_finish + 0x1e")
int BPF_KPROBE(do_mov_1879)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv_finish + 0x22")
int BPF_KPROBE(do_mov_1880)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv_finish + 0x29")
int BPF_KPROBE(do_mov_1881)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_finish_core.constprop.0 + 0x5f")
int BPF_KPROBE(do_mov_1882)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_finish_core.constprop.0 + 0x8c")
int BPF_KPROBE(do_mov_1883)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x19")
int BPF_KPROBE(do_mov_1884)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x26")
int BPF_KPROBE(do_mov_1885)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x39")
int BPF_KPROBE(do_mov_1886)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x3f")
int BPF_KPROBE(do_mov_1887)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x46")
int BPF_KPROBE(do_mov_1888)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0xec")
int BPF_KPROBE(do_mov_1889)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x108")
int BPF_KPROBE(do_mov_1890)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x171")
int BPF_KPROBE(do_mov_1891)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x17e")
int BPF_KPROBE(do_mov_1892)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x182")
int BPF_KPROBE(do_mov_1893)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x18a")
int BPF_KPROBE(do_mov_1894)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x18e")
int BPF_KPROBE(do_mov_1895)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x192")
int BPF_KPROBE(do_mov_1896)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x195")
int BPF_KPROBE(do_mov_1897)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x199")
int BPF_KPROBE(do_mov_1898)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x1b0")
int BPF_KPROBE(do_mov_1899)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x1b4")
int BPF_KPROBE(do_mov_1900)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sublist_rcv + 0x1bb")
int BPF_KPROBE(do_mov_1901)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0xa0")
int BPF_KPROBE(do_mov_1902)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0xae")
int BPF_KPROBE(do_mov_1903)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0xb7")
int BPF_KPROBE(do_mov_1904)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0xe9")
int BPF_KPROBE(do_mov_1905)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0x271")
int BPF_KPROBE(do_mov_1906)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0x27f")
int BPF_KPROBE(do_mov_1907)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0x2d9")
int BPF_KPROBE(do_mov_1908)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rcv_core + 0x2e2")
int BPF_KPROBE(do_mov_1909)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_rcv + 0x26")
int BPF_KPROBE(do_mov_1910)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x1a")
int BPF_KPROBE(do_mov_1911)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x27")
int BPF_KPROBE(do_mov_1912)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x33")
int BPF_KPROBE(do_mov_1913)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x37")
int BPF_KPROBE(do_mov_1914)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x3f")
int BPF_KPROBE(do_mov_1915)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x46")
int BPF_KPROBE(do_mov_1916)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x5c")
int BPF_KPROBE(do_mov_1917)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x60")
int BPF_KPROBE(do_mov_1918)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x63")
int BPF_KPROBE(do_mov_1919)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x67")
int BPF_KPROBE(do_mov_1920)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x88")
int BPF_KPROBE(do_mov_1921)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x8f")
int BPF_KPROBE(do_mov_1922)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0x92")
int BPF_KPROBE(do_mov_1923)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0xce")
int BPF_KPROBE(do_mov_1924)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0xd2")
int BPF_KPROBE(do_mov_1925)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0xd6")
int BPF_KPROBE(do_mov_1926)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_list_rcv + 0xda")
int BPF_KPROBE(do_mov_1927)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x30")
int BPF_KPROBE(do_mov_1928)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x39")
int BPF_KPROBE(do_mov_1929)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0xe5")
int BPF_KPROBE(do_mov_1930)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x209")
int BPF_KPROBE(do_mov_1931)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x270")
int BPF_KPROBE(do_mov_1932)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x296")
int BPF_KPROBE(do_mov_1933)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x2c5")
int BPF_KPROBE(do_mov_1934)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x30b")
int BPF_KPROBE(do_mov_1935)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x30f")
int BPF_KPROBE(do_mov_1936)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_protocol_deliver_rcu + 0x37d")
int BPF_KPROBE(do_mov_1937)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_input_finish + 0x21")
int BPF_KPROBE(do_mov_1938)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_input_finish + 0x29")
int BPF_KPROBE(do_mov_1939)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_input + 0x23")
int BPF_KPROBE(do_mov_1940)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_input + 0x23")
int BPF_KPROBE(do_mov_1941)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_input + 0x1c6")
int BPF_KPROBE(do_mov_1942)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid + 0x9d")
int BPF_KPROBE(do_mov_1943)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid + 0xa4")
int BPF_KPROBE(do_mov_1944)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid + 0xa9")
int BPF_KPROBE(do_mov_1945)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_isatap_ifid + 0xad")
int BPF_KPROBE(do_mov_1946)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x52")
int BPF_KPROBE(do_mov_1947)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x58")
int BPF_KPROBE(do_mov_1948)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x8f")
int BPF_KPROBE(do_mov_1949)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x95")
int BPF_KPROBE(do_mov_1950)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xab")
int BPF_KPROBE(do_mov_1951)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xb5")
int BPF_KPROBE(do_mov_1952)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xbf")
int BPF_KPROBE(do_mov_1953)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xca")
int BPF_KPROBE(do_mov_1954)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xd2")
int BPF_KPROBE(do_mov_1955)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xf4")
int BPF_KPROBE(do_mov_1956)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xfb")
int BPF_KPROBE(do_mov_1957)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0xff")
int BPF_KPROBE(do_mov_1958)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x10d")
int BPF_KPROBE(do_mov_1959)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x160")
int BPF_KPROBE(do_mov_1960)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x167")
int BPF_KPROBE(do_mov_1961)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x16c")
int BPF_KPROBE(do_mov_1962)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x173")
int BPF_KPROBE(do_mov_1963)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x17b")
int BPF_KPROBE(do_mov_1964)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x18e")
int BPF_KPROBE(do_mov_1965)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x199")
int BPF_KPROBE(do_mov_1966)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x1b9")
int BPF_KPROBE(do_mov_1967)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x1c5")
int BPF_KPROBE(do_mov_1968)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x1c9")
int BPF_KPROBE(do_mov_1969)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x1d7")
int BPF_KPROBE(do_mov_1970)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_eui64 + 0x1df")
int BPF_KPROBE(do_mov_1971)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0x1d")
int BPF_KPROBE(do_mov_1972)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0x46")
int BPF_KPROBE(do_mov_1973)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0x5a")
int BPF_KPROBE(do_mov_1974)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0x72")
int BPF_KPROBE(do_mov_1975)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0x85")
int BPF_KPROBE(do_mov_1976)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0x98")
int BPF_KPROBE(do_mov_1977)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0xad")
int BPF_KPROBE(do_mov_1978)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_anycast + 0xe5")
int BPF_KPROBE(do_mov_1979)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x1c")
int BPF_KPROBE(do_mov_1980)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x27")
int BPF_KPROBE(do_mov_1981)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x2e")
int BPF_KPROBE(do_mov_1982)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x36")
int BPF_KPROBE(do_mov_1983)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x3e")
int BPF_KPROBE(do_mov_1984)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x46")
int BPF_KPROBE(do_mov_1985)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x4e")
int BPF_KPROBE(do_mov_1986)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x5a")
int BPF_KPROBE(do_mov_1987)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x5e")
int BPF_KPROBE(do_mov_1988)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x66")
int BPF_KPROBE(do_mov_1989)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_mtu + 0x79")
int BPF_KPROBE(do_mov_1990)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_mc_config + 0x7d")
int BPF_KPROBE(do_mov_1991)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_saddr_eval + 0x8c")
int BPF_KPROBE(do_mov_1992)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_saddr_eval + 0x104")
int BPF_KPROBE(do_mov_1993)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_saddr_eval + 0x1e9")
int BPF_KPROBE(do_mov_1994)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x2c")
int BPF_KPROBE(do_mov_1995)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x3d")
int BPF_KPROBE(do_mov_1996)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x41")
int BPF_KPROBE(do_mov_1997)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x49")
int BPF_KPROBE(do_mov_1998)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x54")
int BPF_KPROBE(do_mov_1999)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x75")
int BPF_KPROBE(do_mov_2000)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x86")
int BPF_KPROBE(do_mov_2001)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x91")
int BPF_KPROBE(do_mov_2002)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0xe2")
int BPF_KPROBE(do_mov_2003)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x151")
int BPF_KPROBE(do_mov_2004)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x159")
int BPF_KPROBE(do_mov_2005)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_get_saddr + 0x160")
int BPF_KPROBE(do_mov_2006)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x2e")
int BPF_KPROBE(do_mov_2007)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x35")
int BPF_KPROBE(do_mov_2008)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x45")
int BPF_KPROBE(do_mov_2009)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x5a")
int BPF_KPROBE(do_mov_2010)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x6f")
int BPF_KPROBE(do_mov_2011)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x78")
int BPF_KPROBE(do_mov_2012)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x7c")
int BPF_KPROBE(do_mov_2013)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x81")
int BPF_KPROBE(do_mov_2014)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x89")
int BPF_KPROBE(do_mov_2015)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0xc9")
int BPF_KPROBE(do_mov_2016)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0xcc")
int BPF_KPROBE(do_mov_2017)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x100")
int BPF_KPROBE(do_mov_2018)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x10d")
int BPF_KPROBE(do_mov_2019)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x111")
int BPF_KPROBE(do_mov_2020)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x116")
int BPF_KPROBE(do_mov_2021)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x11e")
int BPF_KPROBE(do_mov_2022)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x1ad")
int BPF_KPROBE(do_mov_2023)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x1f8")
int BPF_KPROBE(do_mov_2024)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x213")
int BPF_KPROBE(do_mov_2025)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x21f")
int BPF_KPROBE(do_mov_2026)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x223")
int BPF_KPROBE(do_mov_2027)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x228")
int BPF_KPROBE(do_mov_2028)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x230")
int BPF_KPROBE(do_mov_2029)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x252")
int BPF_KPROBE(do_mov_2030)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_dev_get_saddr + 0x2cc")
int BPF_KPROBE(do_mov_2031)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_get_prefix_route + 0x21")
int BPF_KPROBE(do_mov_2032)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_get_prefix_route + 0x25")
int BPF_KPROBE(do_mov_2033)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x31")
int BPF_KPROBE(do_mov_2034)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x40")
int BPF_KPROBE(do_mov_2035)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x57")
int BPF_KPROBE(do_mov_2036)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x92")
int BPF_KPROBE(do_mov_2037)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x9e")
int BPF_KPROBE(do_mov_2038)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0xc2")
int BPF_KPROBE(do_mov_2039)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x119")
int BPF_KPROBE(do_mov_2040)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x124")
int BPF_KPROBE(do_mov_2041)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x12f")
int BPF_KPROBE(do_mov_2042)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x13a")
int BPF_KPROBE(do_mov_2043)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x145")
int BPF_KPROBE(do_mov_2044)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x150")
int BPF_KPROBE(do_mov_2045)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x15b")
int BPF_KPROBE(do_mov_2046)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x166")
int BPF_KPROBE(do_mov_2047)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x177")
int BPF_KPROBE(do_mov_2048)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x188")
int BPF_KPROBE(do_mov_2049)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x19c")
int BPF_KPROBE(do_mov_2050)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1a7")
int BPF_KPROBE(do_mov_2051)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1b8")
int BPF_KPROBE(do_mov_2052)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1c9")
int BPF_KPROBE(do_mov_2053)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1d7")
int BPF_KPROBE(do_mov_2054)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1e2")
int BPF_KPROBE(do_mov_2055)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1ed")
int BPF_KPROBE(do_mov_2056)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x1f8")
int BPF_KPROBE(do_mov_2057)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x203")
int BPF_KPROBE(do_mov_2058)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x20e")
int BPF_KPROBE(do_mov_2059)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x219")
int BPF_KPROBE(do_mov_2060)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x224")
int BPF_KPROBE(do_mov_2061)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x232")
int BPF_KPROBE(do_mov_2062)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x240")
int BPF_KPROBE(do_mov_2063)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x24b")
int BPF_KPROBE(do_mov_2064)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x260")
int BPF_KPROBE(do_mov_2065)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x26b")
int BPF_KPROBE(do_mov_2066)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x279")
int BPF_KPROBE(do_mov_2067)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x284")
int BPF_KPROBE(do_mov_2068)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x28f")
int BPF_KPROBE(do_mov_2069)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x29a")
int BPF_KPROBE(do_mov_2070)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2a5")
int BPF_KPROBE(do_mov_2071)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2b0")
int BPF_KPROBE(do_mov_2072)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2bb")
int BPF_KPROBE(do_mov_2073)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2c6")
int BPF_KPROBE(do_mov_2074)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2d1")
int BPF_KPROBE(do_mov_2075)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2df")
int BPF_KPROBE(do_mov_2076)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2ed")
int BPF_KPROBE(do_mov_2077)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x2fb")
int BPF_KPROBE(do_mov_2078)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x309")
int BPF_KPROBE(do_mov_2079)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x317")
int BPF_KPROBE(do_mov_2080)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x325")
int BPF_KPROBE(do_mov_2081)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x333")
int BPF_KPROBE(do_mov_2082)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x341")
int BPF_KPROBE(do_mov_2083)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x34f")
int BPF_KPROBE(do_mov_2084)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x35d")
int BPF_KPROBE(do_mov_2085)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x36b")
int BPF_KPROBE(do_mov_2086)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x379")
int BPF_KPROBE(do_mov_2087)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x387")
int BPF_KPROBE(do_mov_2088)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x395")
int BPF_KPROBE(do_mov_2089)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x3a4")
int BPF_KPROBE(do_mov_2090)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x3b2")
int BPF_KPROBE(do_mov_2091)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x3c0")
int BPF_KPROBE(do_mov_2092)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x3cf")
int BPF_KPROBE(do_mov_2093)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x3dd")
int BPF_KPROBE(do_mov_2094)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x46b")
int BPF_KPROBE(do_mov_2095)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x480")
int BPF_KPROBE(do_mov_2096)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x505")
int BPF_KPROBE(do_mov_2097)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifla6_attrs + 0x52b")
int BPF_KPROBE(do_mov_2098)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/if6_seq_next + 0x2e")
int BPF_KPROBE(do_mov_2099)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/if6_seq_next + 0x3b")
int BPF_KPROBE(do_mov_2100)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/if6_seq_next + 0x68")
int BPF_KPROBE(do_mov_2101)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/if6_seq_start + 0x25")
int BPF_KPROBE(do_mov_2102)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/if6_seq_start + 0x84")
int BPF_KPROBE(do_mov_2103)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/if6_seq_start + 0x8b")
int BPF_KPROBE(do_mov_2104)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0xc3")
int BPF_KPROBE(do_mov_2105)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0xe9")
int BPF_KPROBE(do_mov_2106)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0xf3")
int BPF_KPROBE(do_mov_2107)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0xfa")
int BPF_KPROBE(do_mov_2108)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x100")
int BPF_KPROBE(do_mov_2109)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x107")
int BPF_KPROBE(do_mov_2110)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x122")
int BPF_KPROBE(do_mov_2111)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x12d")
int BPF_KPROBE(do_mov_2112)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x131")
int BPF_KPROBE(do_mov_2113)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x164")
int BPF_KPROBE(do_mov_2114)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x167")
int BPF_KPROBE(do_mov_2115)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x1c4")
int BPF_KPROBE(do_mov_2116)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x1d5")
int BPF_KPROBE(do_mov_2117)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x200")
int BPF_KPROBE(do_mov_2118)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x205")
int BPF_KPROBE(do_mov_2119)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x262")
int BPF_KPROBE(do_mov_2120)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x26c")
int BPF_KPROBE(do_mov_2121)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_generate_stable_address + 0x27c")
int BPF_KPROBE(do_mov_2122)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0x30")
int BPF_KPROBE(do_mov_2123)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0x6b")
int BPF_KPROBE(do_mov_2124)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0x7a")
int BPF_KPROBE(do_mov_2125)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0x80")
int BPF_KPROBE(do_mov_2126)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0x90")
int BPF_KPROBE(do_mov_2127)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0x9c")
int BPF_KPROBE(do_mov_2128)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0xab")
int BPF_KPROBE(do_mov_2129)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0xb6")
int BPF_KPROBE(do_mov_2130)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_mroute + 0xba")
int BPF_KPROBE(do_mov_2131)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/check_cleanup_prefix_route + 0x20")
int BPF_KPROBE(do_mov_2132)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/check_cleanup_prefix_route + 0xcd")
int BPF_KPROBE(do_mov_2133)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x27")
int BPF_KPROBE(do_mov_2134)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x30")
int BPF_KPROBE(do_mov_2135)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x35")
int BPF_KPROBE(do_mov_2136)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x45")
int BPF_KPROBE(do_mov_2137)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x7c")
int BPF_KPROBE(do_mov_2138)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x9e")
int BPF_KPROBE(do_mov_2139)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xa2")
int BPF_KPROBE(do_mov_2140)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xa7")
int BPF_KPROBE(do_mov_2141)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xb1")
int BPF_KPROBE(do_mov_2142)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xbf")
int BPF_KPROBE(do_mov_2143)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xc8")
int BPF_KPROBE(do_mov_2144)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xd4")
int BPF_KPROBE(do_mov_2145)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xdc")
int BPF_KPROBE(do_mov_2146)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xe7")
int BPF_KPROBE(do_mov_2147)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0xec")
int BPF_KPROBE(do_mov_2148)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_route + 0x135")
int BPF_KPROBE(do_mov_2149)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_validate_link_af + 0x1f")
int BPF_KPROBE(do_mov_2150)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_disable_policy_idev + 0x2a")
int BPF_KPROBE(do_mov_2151)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_disable_policy_idev + 0xa4")
int BPF_KPROBE(do_mov_2152)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_disable_policy_idev + 0xb4")
int BPF_KPROBE(do_mov_2153)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_disable_policy_idev + 0xee")
int BPF_KPROBE(do_mov_2154)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_chk_addr_and_flags + 0x29")
int BPF_KPROBE(do_mov_2155)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_chk_addr_and_flags + 0x2f")
int BPF_KPROBE(do_mov_2156)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_chk_addr_and_flags + 0x39")
int BPF_KPROBE(do_mov_2157)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/cleanup_prefix_route + 0x63")
int BPF_KPROBE(do_mov_2158)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/cleanup_prefix_route + 0x67")
int BPF_KPROBE(do_mov_2159)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/modify_prefix_route + 0x77")
int BPF_KPROBE(do_mov_2160)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/modify_prefix_route + 0x7b")
int BPF_KPROBE(do_mov_2161)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/modify_prefix_route + 0xb1")
int BPF_KPROBE(do_mov_2162)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/modify_prefix_route + 0xb9")
int BPF_KPROBE(do_mov_2163)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x28")
int BPF_KPROBE(do_mov_2164)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x74")
int BPF_KPROBE(do_mov_2165)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x80")
int BPF_KPROBE(do_mov_2166)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x8b")
int BPF_KPROBE(do_mov_2167)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x94")
int BPF_KPROBE(do_mov_2168)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0xa4")
int BPF_KPROBE(do_mov_2169)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0xfe")
int BPF_KPROBE(do_mov_2170)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x143")
int BPF_KPROBE(do_mov_2171)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x1a9")
int BPF_KPROBE(do_mov_2172)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x1bf")
int BPF_KPROBE(do_mov_2173)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifinfo + 0x247")
int BPF_KPROBE(do_mov_2174)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x28")
int BPF_KPROBE(do_mov_2175)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x80")
int BPF_KPROBE(do_mov_2176)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0xa1")
int BPF_KPROBE(do_mov_2177)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x130")
int BPF_KPROBE(do_mov_2178)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x134")
int BPF_KPROBE(do_mov_2179)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x15c")
int BPF_KPROBE(do_mov_2180)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x17b")
int BPF_KPROBE(do_mov_2181)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_ifinfo + 0x19e")
int BPF_KPROBE(do_mov_2182)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x2c")
int BPF_KPROBE(do_mov_2183)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xa9")
int BPF_KPROBE(do_mov_2184)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xae")
int BPF_KPROBE(do_mov_2185)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xb2")
int BPF_KPROBE(do_mov_2186)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xb6")
int BPF_KPROBE(do_mov_2187)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xba")
int BPF_KPROBE(do_mov_2188)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xd2")
int BPF_KPROBE(do_mov_2189)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0xee")
int BPF_KPROBE(do_mov_2190)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x116")
int BPF_KPROBE(do_mov_2191)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x15c")
int BPF_KPROBE(do_mov_2192)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x1cc")
int BPF_KPROBE(do_mov_2193)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x205")
int BPF_KPROBE(do_mov_2194)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x220")
int BPF_KPROBE(do_mov_2195)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x227")
int BPF_KPROBE(do_mov_2196)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x24b")
int BPF_KPROBE(do_mov_2197)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x279")
int BPF_KPROBE(do_mov_2198)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x28d")
int BPF_KPROBE(do_mov_2199)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x2e9")
int BPF_KPROBE(do_mov_2200)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x30b")
int BPF_KPROBE(do_mov_2201)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_fill_ifaddr + 0x31d")
int BPF_KPROBE(do_mov_2202)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x34")
int BPF_KPROBE(do_mov_2203)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x6a")
int BPF_KPROBE(do_mov_2204)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x72")
int BPF_KPROBE(do_mov_2205)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x7a")
int BPF_KPROBE(do_mov_2206)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x82")
int BPF_KPROBE(do_mov_2207)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x89")
int BPF_KPROBE(do_mov_2208)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x8c")
int BPF_KPROBE(do_mov_2209)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x114")
int BPF_KPROBE(do_mov_2210)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x11c")
int BPF_KPROBE(do_mov_2211)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x125")
int BPF_KPROBE(do_mov_2212)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x157")
int BPF_KPROBE(do_mov_2213)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x1b4")
int BPF_KPROBE(do_mov_2214)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x2dd")
int BPF_KPROBE(do_mov_2215)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x2e9")
int BPF_KPROBE(do_mov_2216)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x30d")
int BPF_KPROBE(do_mov_2217)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x320")
int BPF_KPROBE(do_mov_2218)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x333")
int BPF_KPROBE(do_mov_2219)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x348")
int BPF_KPROBE(do_mov_2220)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x3aa")
int BPF_KPROBE(do_mov_2221)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_ifa_notify + 0x3e4")
int BPF_KPROBE(do_mov_2222)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x25")
int BPF_KPROBE(do_mov_2223)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x2a")
int BPF_KPROBE(do_mov_2224)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x2f")
int BPF_KPROBE(do_mov_2225)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x3d")
int BPF_KPROBE(do_mov_2226)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x48")
int BPF_KPROBE(do_mov_2227)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x4d")
int BPF_KPROBE(do_mov_2228)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x52")
int BPF_KPROBE(do_mov_2229)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x5b")
int BPF_KPROBE(do_mov_2230)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x64")
int BPF_KPROBE(do_mov_2231)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x6d")
int BPF_KPROBE(do_mov_2232)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x76")
int BPF_KPROBE(do_mov_2233)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x7f")
int BPF_KPROBE(do_mov_2234)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x9f")
int BPF_KPROBE(do_mov_2235)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0xad")
int BPF_KPROBE(do_mov_2236)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x182")
int BPF_KPROBE(do_mov_2237)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x190")
int BPF_KPROBE(do_mov_2238)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x194")
int BPF_KPROBE(do_mov_2239)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x1af")
int BPF_KPROBE(do_mov_2240)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_stable_secret + 0x208")
int BPF_KPROBE(do_mov_2241)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x23")
int BPF_KPROBE(do_mov_2242)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x40")
int BPF_KPROBE(do_mov_2243)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x75")
int BPF_KPROBE(do_mov_2244)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x96")
int BPF_KPROBE(do_mov_2245)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x103")
int BPF_KPROBE(do_mov_2246)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x13d")
int BPF_KPROBE(do_mov_2247)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x189")
int BPF_KPROBE(do_mov_2248)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x1b4")
int BPF_KPROBE(do_mov_2249)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_fill_devconf + 0x1df")
int BPF_KPROBE(do_mov_2250)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x2c")
int BPF_KPROBE(do_mov_2251)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x30")
int BPF_KPROBE(do_mov_2252)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x56")
int BPF_KPROBE(do_mov_2253)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x6d")
int BPF_KPROBE(do_mov_2254)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x93")
int BPF_KPROBE(do_mov_2255)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x11a")
int BPF_KPROBE(do_mov_2256)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x1df")
int BPF_KPROBE(do_mov_2257)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x1e3")
int BPF_KPROBE(do_mov_2258)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x228")
int BPF_KPROBE(do_mov_2259)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_dump_devconf + 0x247")
int BPF_KPROBE(do_mov_2260)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x2f")
int BPF_KPROBE(do_mov_2261)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x38")
int BPF_KPROBE(do_mov_2262)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x3e")
int BPF_KPROBE(do_mov_2263)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x46")
int BPF_KPROBE(do_mov_2264)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x4e")
int BPF_KPROBE(do_mov_2265)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x56")
int BPF_KPROBE(do_mov_2266)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x5e")
int BPF_KPROBE(do_mov_2267)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x66")
int BPF_KPROBE(do_mov_2268)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x72")
int BPF_KPROBE(do_mov_2269)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x7a")
int BPF_KPROBE(do_mov_2270)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0x95")
int BPF_KPROBE(do_mov_2271)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable_policy + 0xc4")
int BPF_KPROBE(do_mov_2272)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x22")
int BPF_KPROBE(do_mov_2273)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x2f")
int BPF_KPROBE(do_mov_2274)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x3f")
int BPF_KPROBE(do_mov_2275)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x6d")
int BPF_KPROBE(do_mov_2276)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x79")
int BPF_KPROBE(do_mov_2277)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0xab")
int BPF_KPROBE(do_mov_2278)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0xc0")
int BPF_KPROBE(do_mov_2279)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0xf4")
int BPF_KPROBE(do_mov_2280)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x122")
int BPF_KPROBE(do_mov_2281)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x12b")
int BPF_KPROBE(do_mov_2282)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x14f")
int BPF_KPROBE(do_mov_2283)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x15f")
int BPF_KPROBE(do_mov_2284)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x165")
int BPF_KPROBE(do_mov_2285)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x16a")
int BPF_KPROBE(do_mov_2286)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x199")
int BPF_KPROBE(do_mov_2287)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x1cd")
int BPF_KPROBE(do_mov_2288)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x1eb")
int BPF_KPROBE(do_mov_2289)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x211")
int BPF_KPROBE(do_mov_2290)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x23e")
int BPF_KPROBE(do_mov_2291)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x27b")
int BPF_KPROBE(do_mov_2292)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x28b")
int BPF_KPROBE(do_mov_2293)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x2ab")
int BPF_KPROBE(do_mov_2294)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x2b3")
int BPF_KPROBE(do_mov_2295)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x2f5")
int BPF_KPROBE(do_mov_2296)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x319")
int BPF_KPROBE(do_mov_2297)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x331")
int BPF_KPROBE(do_mov_2298)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x364")
int BPF_KPROBE(do_mov_2299)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x392")
int BPF_KPROBE(do_mov_2300)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x39b")
int BPF_KPROBE(do_mov_2301)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x3b5")
int BPF_KPROBE(do_mov_2302)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x3c0")
int BPF_KPROBE(do_mov_2303)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x3d2")
int BPF_KPROBE(do_mov_2304)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x3d6")
int BPF_KPROBE(do_mov_2305)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x3fc")
int BPF_KPROBE(do_mov_2306)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x430")
int BPF_KPROBE(do_mov_2307)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x450")
int BPF_KPROBE(do_mov_2308)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x478")
int BPF_KPROBE(do_mov_2309)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x4df")
int BPF_KPROBE(do_mov_2310)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/in6_dump_addrs + 0x4f1")
int BPF_KPROBE(do_mov_2311)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x24")
int BPF_KPROBE(do_mov_2312)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x3d")
int BPF_KPROBE(do_mov_2313)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x4a")
int BPF_KPROBE(do_mov_2314)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x52")
int BPF_KPROBE(do_mov_2315)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x5c")
int BPF_KPROBE(do_mov_2316)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x64")
int BPF_KPROBE(do_mov_2317)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x6c")
int BPF_KPROBE(do_mov_2318)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x72")
int BPF_KPROBE(do_mov_2319)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x75")
int BPF_KPROBE(do_mov_2320)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x82")
int BPF_KPROBE(do_mov_2321)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x8a")
int BPF_KPROBE(do_mov_2322)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x8e")
int BPF_KPROBE(do_mov_2323)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0xb3")
int BPF_KPROBE(do_mov_2324)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0xbf")
int BPF_KPROBE(do_mov_2325)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0xd5")
int BPF_KPROBE(do_mov_2326)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0xf0")
int BPF_KPROBE(do_mov_2327)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0xfb")
int BPF_KPROBE(do_mov_2328)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x161")
int BPF_KPROBE(do_mov_2329)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x1c8")
int BPF_KPROBE(do_mov_2330)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x1cc")
int BPF_KPROBE(do_mov_2331)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x238")
int BPF_KPROBE(do_mov_2332)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x28f")
int BPF_KPROBE(do_mov_2333)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_addr + 0x29f")
int BPF_KPROBE(do_mov_2334)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x22")
int BPF_KPROBE(do_mov_2335)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0xc7")
int BPF_KPROBE(do_mov_2336)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0xe4")
int BPF_KPROBE(do_mov_2337)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x10f")
int BPF_KPROBE(do_mov_2338)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x1a2")
int BPF_KPROBE(do_mov_2339)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x1ef")
int BPF_KPROBE(do_mov_2340)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x26d")
int BPF_KPROBE(do_mov_2341)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x2bd")
int BPF_KPROBE(do_mov_2342)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x2d3")
int BPF_KPROBE(do_mov_2343)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x2fd")
int BPF_KPROBE(do_mov_2344)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x317")
int BPF_KPROBE(do_mov_2345)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x357")
int BPF_KPROBE(do_mov_2346)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x37e")
int BPF_KPROBE(do_mov_2347)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_get_devconf + 0x3ab")
int BPF_KPROBE(do_mov_2348)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x2d")
int BPF_KPROBE(do_mov_2349)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x3b")
int BPF_KPROBE(do_mov_2350)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0xdb")
int BPF_KPROBE(do_mov_2351)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x122")
int BPF_KPROBE(do_mov_2352)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x137")
int BPF_KPROBE(do_mov_2353)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x13f")
int BPF_KPROBE(do_mov_2354)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x150")
int BPF_KPROBE(do_mov_2355)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x158")
int BPF_KPROBE(do_mov_2356)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x16f")
int BPF_KPROBE(do_mov_2357)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x189")
int BPF_KPROBE(do_mov_2358)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x193")
int BPF_KPROBE(do_mov_2359)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x198")
int BPF_KPROBE(do_mov_2360)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1a1")
int BPF_KPROBE(do_mov_2361)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1b4")
int BPF_KPROBE(do_mov_2362)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1c0")
int BPF_KPROBE(do_mov_2363)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1d0")
int BPF_KPROBE(do_mov_2364)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1da")
int BPF_KPROBE(do_mov_2365)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1e6")
int BPF_KPROBE(do_mov_2366)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1ef")
int BPF_KPROBE(do_mov_2367)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x1f7")
int BPF_KPROBE(do_mov_2368)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x201")
int BPF_KPROBE(do_mov_2369)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x209")
int BPF_KPROBE(do_mov_2370)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x21c")
int BPF_KPROBE(do_mov_2371)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x225")
int BPF_KPROBE(do_mov_2372)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x22e")
int BPF_KPROBE(do_mov_2373)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x23a")
int BPF_KPROBE(do_mov_2374)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x23f")
int BPF_KPROBE(do_mov_2375)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x264")
int BPF_KPROBE(do_mov_2376)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x299")
int BPF_KPROBE(do_mov_2377)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x2a0")
int BPF_KPROBE(do_mov_2378)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x330")
int BPF_KPROBE(do_mov_2379)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x340")
int BPF_KPROBE(do_mov_2380)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x348")
int BPF_KPROBE(do_mov_2381)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x354")
int BPF_KPROBE(do_mov_2382)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x36a")
int BPF_KPROBE(do_mov_2383)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x3cd")
int BPF_KPROBE(do_mov_2384)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x3d5")
int BPF_KPROBE(do_mov_2385)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x3dd")
int BPF_KPROBE(do_mov_2386)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x3e5")
int BPF_KPROBE(do_mov_2387)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x46e")
int BPF_KPROBE(do_mov_2388)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x479")
int BPF_KPROBE(do_mov_2389)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x47e")
int BPF_KPROBE(do_mov_2390)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x488")
int BPF_KPROBE(do_mov_2391)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x48d")
int BPF_KPROBE(do_mov_2392)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x5a6")
int BPF_KPROBE(do_mov_2393)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x5aa")
int BPF_KPROBE(do_mov_2394)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x5b9")
int BPF_KPROBE(do_mov_2395)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_addr + 0x5c5")
int BPF_KPROBE(do_mov_2396)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_netconf_notify_devconf + 0x83")
int BPF_KPROBE(do_mov_2397)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register + 0x3c")
int BPF_KPROBE(do_mov_2398)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register + 0x88")
int BPF_KPROBE(do_mov_2399)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register + 0x95")
int BPF_KPROBE(do_mov_2400)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register + 0x99")
int BPF_KPROBE(do_mov_2401)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__addrconf_sysctl_register + 0xc6")
int BPF_KPROBE(do_mov_2402)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x66")
int BPF_KPROBE(do_mov_2403)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x71")
int BPF_KPROBE(do_mov_2404)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x8e")
int BPF_KPROBE(do_mov_2405)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x93")
int BPF_KPROBE(do_mov_2406)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0xbb")
int BPF_KPROBE(do_mov_2407)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0xdd")
int BPF_KPROBE(do_mov_2408)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0xe9")
int BPF_KPROBE(do_mov_2409)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0xf6")
int BPF_KPROBE(do_mov_2410)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x13a")
int BPF_KPROBE(do_mov_2411)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x14b")
int BPF_KPROBE(do_mov_2412)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x187")
int BPF_KPROBE(do_mov_2413)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x1ae")
int BPF_KPROBE(do_mov_2414)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x1de")
int BPF_KPROBE(do_mov_2415)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x1ee")
int BPF_KPROBE(do_mov_2416)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x211")
int BPF_KPROBE(do_mov_2417)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x21d")
int BPF_KPROBE(do_mov_2418)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x225")
int BPF_KPROBE(do_mov_2419)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x235")
int BPF_KPROBE(do_mov_2420)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x24f")
int BPF_KPROBE(do_mov_2421)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x25b")
int BPF_KPROBE(do_mov_2422)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x281")
int BPF_KPROBE(do_mov_2423)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x2a6")
int BPF_KPROBE(do_mov_2424)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x302")
int BPF_KPROBE(do_mov_2425)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x461")
int BPF_KPROBE(do_mov_2426)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_add_dev + 0x4bd")
int BPF_KPROBE(do_mov_2427)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_find_idev + 0x76")
int BPF_KPROBE(do_mov_2428)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_dev + 0x61")
int BPF_KPROBE(do_mov_2429)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_dev + 0x8c")
int BPF_KPROBE(do_mov_2430)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x30")
int BPF_KPROBE(do_mov_2431)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x45")
int BPF_KPROBE(do_mov_2432)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x49")
int BPF_KPROBE(do_mov_2433)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x50")
int BPF_KPROBE(do_mov_2434)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x54")
int BPF_KPROBE(do_mov_2435)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x77")
int BPF_KPROBE(do_mov_2436)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x11d")
int BPF_KPROBE(do_mov_2437)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x134")
int BPF_KPROBE(do_mov_2438)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x13c")
int BPF_KPROBE(do_mov_2439)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x162")
int BPF_KPROBE(do_mov_2440)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x175")
int BPF_KPROBE(do_mov_2441)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x17f")
int BPF_KPROBE(do_mov_2442)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x190")
int BPF_KPROBE(do_mov_2443)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x19f")
int BPF_KPROBE(do_mov_2444)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x1a9")
int BPF_KPROBE(do_mov_2445)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x1b0")
int BPF_KPROBE(do_mov_2446)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x1b9")
int BPF_KPROBE(do_mov_2447)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x1c0")
int BPF_KPROBE(do_mov_2448)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x215")
int BPF_KPROBE(do_mov_2449)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x248")
int BPF_KPROBE(do_mov_2450)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x25b")
int BPF_KPROBE(do_mov_2451)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x2a1")
int BPF_KPROBE(do_mov_2452)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x2b8")
int BPF_KPROBE(do_mov_2453)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_init_net + 0x2c0")
int BPF_KPROBE(do_mov_2454)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x2f")
int BPF_KPROBE(do_mov_2455)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x38")
int BPF_KPROBE(do_mov_2456)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x3e")
int BPF_KPROBE(do_mov_2457)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x46")
int BPF_KPROBE(do_mov_2458)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x4e")
int BPF_KPROBE(do_mov_2459)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x56")
int BPF_KPROBE(do_mov_2460)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x5e")
int BPF_KPROBE(do_mov_2461)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x66")
int BPF_KPROBE(do_mov_2462)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x72")
int BPF_KPROBE(do_mov_2463)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x7a")
int BPF_KPROBE(do_mov_2464)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0xb2")
int BPF_KPROBE(do_mov_2465)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0xce")
int BPF_KPROBE(do_mov_2466)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0xfb")
int BPF_KPROBE(do_mov_2467)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x136")
int BPF_KPROBE(do_mov_2468)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x16a")
int BPF_KPROBE(do_mov_2469)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x199")
int BPF_KPROBE(do_mov_2470)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x1a0")
int BPF_KPROBE(do_mov_2471)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_ignore_routes_with_linkdown + 0x1a4")
int BPF_KPROBE(do_mov_2472)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x23")
int BPF_KPROBE(do_mov_2473)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x2d")
int BPF_KPROBE(do_mov_2474)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x31")
int BPF_KPROBE(do_mov_2475)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x97")
int BPF_KPROBE(do_mov_2476)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x9e")
int BPF_KPROBE(do_mov_2477)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0xa3")
int BPF_KPROBE(do_mov_2478)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0xaa")
int BPF_KPROBE(do_mov_2479)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x10d")
int BPF_KPROBE(do_mov_2480)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x11f")
int BPF_KPROBE(do_mov_2481)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x13b")
int BPF_KPROBE(do_mov_2482)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x14e")
int BPF_KPROBE(do_mov_2483)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x161")
int BPF_KPROBE(do_mov_2484)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x17a")
int BPF_KPROBE(do_mov_2485)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x1ac")
int BPF_KPROBE(do_mov_2486)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x1b0")
int BPF_KPROBE(do_mov_2487)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x1b3")
int BPF_KPROBE(do_mov_2488)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x1b6")
int BPF_KPROBE(do_mov_2489)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_forward_change + 0x239")
int BPF_KPROBE(do_mov_2490)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x2f")
int BPF_KPROBE(do_mov_2491)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x38")
int BPF_KPROBE(do_mov_2492)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x3e")
int BPF_KPROBE(do_mov_2493)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x46")
int BPF_KPROBE(do_mov_2494)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x4e")
int BPF_KPROBE(do_mov_2495)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x56")
int BPF_KPROBE(do_mov_2496)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x5e")
int BPF_KPROBE(do_mov_2497)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x66")
int BPF_KPROBE(do_mov_2498)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x72")
int BPF_KPROBE(do_mov_2499)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x7a")
int BPF_KPROBE(do_mov_2500)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0xcd")
int BPF_KPROBE(do_mov_2501)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0xfb")
int BPF_KPROBE(do_mov_2502)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x108")
int BPF_KPROBE(do_mov_2503)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x122")
int BPF_KPROBE(do_mov_2504)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x12d")
int BPF_KPROBE(do_mov_2505)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x138")
int BPF_KPROBE(do_mov_2506)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x171")
int BPF_KPROBE(do_mov_2507)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x181")
int BPF_KPROBE(do_mov_2508)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x187")
int BPF_KPROBE(do_mov_2509)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x18e")
int BPF_KPROBE(do_mov_2510)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x1d9")
int BPF_KPROBE(do_mov_2511)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x215")
int BPF_KPROBE(do_mov_2512)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x21b")
int BPF_KPROBE(do_mov_2513)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_forward + 0x222")
int BPF_KPROBE(do_mov_2514)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_unregister + 0x3c")
int BPF_KPROBE(do_mov_2515)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_exit_net + 0x2e")
int BPF_KPROBE(do_mov_2516)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_exit_net + 0x76")
int BPF_KPROBE(do_mov_2517)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_exit_net + 0xb4")
int BPF_KPROBE(do_mov_2518)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_exit_net + 0xcb")
int BPF_KPROBE(do_mov_2519)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_exit_net + 0x10f")
int BPF_KPROBE(do_mov_2520)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x1e")
int BPF_KPROBE(do_mov_2521)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x24")
int BPF_KPROBE(do_mov_2522)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x2c")
int BPF_KPROBE(do_mov_2523)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x34")
int BPF_KPROBE(do_mov_2524)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x3c")
int BPF_KPROBE(do_mov_2525)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x44")
int BPF_KPROBE(do_mov_2526)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x4a")
int BPF_KPROBE(do_mov_2527)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x52")
int BPF_KPROBE(do_mov_2528)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x5a")
int BPF_KPROBE(do_mov_2529)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x5e")
int BPF_KPROBE(do_mov_2530)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_addr + 0x65")
int BPF_KPROBE(do_mov_2531)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x31")
int BPF_KPROBE(do_mov_2532)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x57")
int BPF_KPROBE(do_mov_2533)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x5f")
int BPF_KPROBE(do_mov_2534)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x7c")
int BPF_KPROBE(do_mov_2535)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x96")
int BPF_KPROBE(do_mov_2536)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0xa3")
int BPF_KPROBE(do_mov_2537)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0xaa")
int BPF_KPROBE(do_mov_2538)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x111")
int BPF_KPROBE(do_mov_2539)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x11e")
int BPF_KPROBE(do_mov_2540)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x137")
int BPF_KPROBE(do_mov_2541)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x181")
int BPF_KPROBE(do_mov_2542)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_v4_addrs + 0x1fb")
int BPF_KPROBE(do_mov_2543)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_kick + 0x2a")
int BPF_KPROBE(do_mov_2544)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_kick + 0x5f")
int BPF_KPROBE(do_mov_2545)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_kick + 0x8c")
int BPF_KPROBE(do_mov_2546)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_kick + 0xa1")
int BPF_KPROBE(do_mov_2547)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_run + 0x2a")
int BPF_KPROBE(do_mov_2548)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_run + 0x53")
int BPF_KPROBE(do_mov_2549)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x1a")
int BPF_KPROBE(do_mov_2550)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x1f")
int BPF_KPROBE(do_mov_2551)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x2c")
int BPF_KPROBE(do_mov_2552)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x45")
int BPF_KPROBE(do_mov_2553)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x53")
int BPF_KPROBE(do_mov_2554)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x58")
int BPF_KPROBE(do_mov_2555)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0xe5")
int BPF_KPROBE(do_mov_2556)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x159")
int BPF_KPROBE(do_mov_2557)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x161")
int BPF_KPROBE(do_mov_2558)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x165")
int BPF_KPROBE(do_mov_2559)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x1a0")
int BPF_KPROBE(do_mov_2560)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x1ca")
int BPF_KPROBE(do_mov_2561)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x1e5")
int BPF_KPROBE(do_mov_2562)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x1fd")
int BPF_KPROBE(do_mov_2563)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x23e")
int BPF_KPROBE(do_mov_2564)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x242")
int BPF_KPROBE(do_mov_2565)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x24d")
int BPF_KPROBE(do_mov_2566)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x251")
int BPF_KPROBE(do_mov_2567)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x254")
int BPF_KPROBE(do_mov_2568)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x258")
int BPF_KPROBE(do_mov_2569)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x28d")
int BPF_KPROBE(do_mov_2570)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x336")
int BPF_KPROBE(do_mov_2571)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x33d")
int BPF_KPROBE(do_mov_2572)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x344")
int BPF_KPROBE(do_mov_2573)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x349")
int BPF_KPROBE(do_mov_2574)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x369")
int BPF_KPROBE(do_mov_2575)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x39c")
int BPF_KPROBE(do_mov_2576)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x3a0")
int BPF_KPROBE(do_mov_2577)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x3ad")
int BPF_KPROBE(do_mov_2578)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x3b5")
int BPF_KPROBE(do_mov_2579)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x3f1")
int BPF_KPROBE(do_mov_2580)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x43d")
int BPF_KPROBE(do_mov_2581)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x441")
int BPF_KPROBE(do_mov_2582)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x44e")
int BPF_KPROBE(do_mov_2583)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x4bd")
int BPF_KPROBE(do_mov_2584)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x4c8")
int BPF_KPROBE(do_mov_2585)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x53e")
int BPF_KPROBE(do_mov_2586)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x550")
int BPF_KPROBE(do_mov_2587)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x55b")
int BPF_KPROBE(do_mov_2588)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x5b0")
int BPF_KPROBE(do_mov_2589)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x5b9")
int BPF_KPROBE(do_mov_2590)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x5c3")
int BPF_KPROBE(do_mov_2591)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x603")
int BPF_KPROBE(do_mov_2592)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x646")
int BPF_KPROBE(do_mov_2593)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x651")
int BPF_KPROBE(do_mov_2594)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x680")
int BPF_KPROBE(do_mov_2595)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x68b")
int BPF_KPROBE(do_mov_2596)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_ifdown.isra.0 + 0x726")
int BPF_KPROBE(do_mov_2597)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_start + 0x24")
int BPF_KPROBE(do_mov_2598)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x20")
int BPF_KPROBE(do_mov_2599)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x57")
int BPF_KPROBE(do_mov_2600)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x97")
int BPF_KPROBE(do_mov_2601)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x9f")
int BPF_KPROBE(do_mov_2602)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0xa3")
int BPF_KPROBE(do_mov_2603)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0xfb")
int BPF_KPROBE(do_mov_2604)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0xff")
int BPF_KPROBE(do_mov_2605)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x10c")
int BPF_KPROBE(do_mov_2606)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x1cf")
int BPF_KPROBE(do_mov_2607)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x1d3")
int BPF_KPROBE(do_mov_2608)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x1e8")
int BPF_KPROBE(do_mov_2609)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x1f4")
int BPF_KPROBE(do_mov_2610)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x220")
int BPF_KPROBE(do_mov_2611)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_del_addr + 0x2c8")
int BPF_KPROBE(do_mov_2612)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x25")
int BPF_KPROBE(do_mov_2613)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x2b")
int BPF_KPROBE(do_mov_2614)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x3d")
int BPF_KPROBE(do_mov_2615)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x45")
int BPF_KPROBE(do_mov_2616)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x4d")
int BPF_KPROBE(do_mov_2617)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x55")
int BPF_KPROBE(do_mov_2618)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x5e")
int BPF_KPROBE(do_mov_2619)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x66")
int BPF_KPROBE(do_mov_2620)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0x6a")
int BPF_KPROBE(do_mov_2621)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_linklocal + 0xc0")
int BPF_KPROBE(do_mov_2622)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_addr_gen + 0x2d")
int BPF_KPROBE(do_mov_2623)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_addr_gen + 0x4d")
int BPF_KPROBE(do_mov_2624)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_addr_gen + 0x5a")
int BPF_KPROBE(do_mov_2625)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_addr_gen + 0xae")
int BPF_KPROBE(do_mov_2626)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x28")
int BPF_KPROBE(do_mov_2627)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x33")
int BPF_KPROBE(do_mov_2628)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x40")
int BPF_KPROBE(do_mov_2629)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x4d")
int BPF_KPROBE(do_mov_2630)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x5d")
int BPF_KPROBE(do_mov_2631)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x64")
int BPF_KPROBE(do_mov_2632)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x6c")
int BPF_KPROBE(do_mov_2633)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x97")
int BPF_KPROBE(do_mov_2634)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0xd2")
int BPF_KPROBE(do_mov_2635)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0xfe")
int BPF_KPROBE(do_mov_2636)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x114")
int BPF_KPROBE(do_mov_2637)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x15a")
int BPF_KPROBE(do_mov_2638)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x17c")
int BPF_KPROBE(do_mov_2639)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_addr_gen_mode + 0x1aa")
int BPF_KPROBE(do_mov_2640)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x27")
int BPF_KPROBE(do_mov_2641)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x3c")
int BPF_KPROBE(do_mov_2642)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x4d")
int BPF_KPROBE(do_mov_2643)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x5c")
int BPF_KPROBE(do_mov_2644)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0xaa")
int BPF_KPROBE(do_mov_2645)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0xc4")
int BPF_KPROBE(do_mov_2646)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0xec")
int BPF_KPROBE(do_mov_2647)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x19e")
int BPF_KPROBE(do_mov_2648)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x1eb")
int BPF_KPROBE(do_mov_2649)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x1fe")
int BPF_KPROBE(do_mov_2650)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x202")
int BPF_KPROBE(do_mov_2651)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x251")
int BPF_KPROBE(do_mov_2652)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x264")
int BPF_KPROBE(do_mov_2653)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x281")
int BPF_KPROBE(do_mov_2654)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x29e")
int BPF_KPROBE(do_mov_2655)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x2ad")
int BPF_KPROBE(do_mov_2656)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x2b1")
int BPF_KPROBE(do_mov_2657)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x2bd")
int BPF_KPROBE(do_mov_2658)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x393")
int BPF_KPROBE(do_mov_2659)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x435")
int BPF_KPROBE(do_mov_2660)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x43a")
int BPF_KPROBE(do_mov_2661)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x45a")
int BPF_KPROBE(do_mov_2662)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_create_tempaddr.isra.0 + 0x4da")
int BPF_KPROBE(do_mov_2663)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x2b")
int BPF_KPROBE(do_mov_2664)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x2f")
int BPF_KPROBE(do_mov_2665)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x33")
int BPF_KPROBE(do_mov_2666)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x4a")
int BPF_KPROBE(do_mov_2667)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x95")
int BPF_KPROBE(do_mov_2668)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0xe3")
int BPF_KPROBE(do_mov_2669)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0xf1")
int BPF_KPROBE(do_mov_2670)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0xf5")
int BPF_KPROBE(do_mov_2671)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x100")
int BPF_KPROBE(do_mov_2672)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/manage_tempaddrs + 0x104")
int BPF_KPROBE(do_mov_2673)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x16")
int BPF_KPROBE(do_mov_2674)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x55")
int BPF_KPROBE(do_mov_2675)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x5e")
int BPF_KPROBE(do_mov_2676)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x1b9")
int BPF_KPROBE(do_mov_2677)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x213")
int BPF_KPROBE(do_mov_2678)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x3ea")
int BPF_KPROBE(do_mov_2679)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x415")
int BPF_KPROBE(do_mov_2680)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x421")
int BPF_KPROBE(do_mov_2681)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x46b")
int BPF_KPROBE(do_mov_2682)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x47f")
int BPF_KPROBE(do_mov_2683)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x554")
int BPF_KPROBE(do_mov_2684)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x594")
int BPF_KPROBE(do_mov_2685)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_verify_rtnl + 0x5e7")
int BPF_KPROBE(do_mov_2686)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_del + 0x16")
int BPF_KPROBE(do_mov_2687)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_del + 0x34")
int BPF_KPROBE(do_mov_2688)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_del + 0x58")
int BPF_KPROBE(do_mov_2689)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_del + 0xdc")
int BPF_KPROBE(do_mov_2690)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_del + 0x173")
int BPF_KPROBE(do_mov_2691)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_del + 0x18a")
int BPF_KPROBE(do_mov_2692)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_deladdr + 0x1d")
int BPF_KPROBE(do_mov_2693)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_deladdr + 0xe6")
int BPF_KPROBE(do_mov_2694)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_deladdr + 0xfe")
int BPF_KPROBE(do_mov_2695)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0x1f")
int BPF_KPROBE(do_mov_2696)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0xb2")
int BPF_KPROBE(do_mov_2697)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0xc2")
int BPF_KPROBE(do_mov_2698)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0xdd")
int BPF_KPROBE(do_mov_2699)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0xf3")
int BPF_KPROBE(do_mov_2700)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0x105")
int BPF_KPROBE(do_mov_2701)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0x109")
int BPF_KPROBE(do_mov_2702)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_addr_add + 0x290")
int BPF_KPROBE(do_mov_2703)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_stop + 0x21")
int BPF_KPROBE(do_mov_2704)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_stop + 0xb3")
int BPF_KPROBE(do_mov_2705)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_stop + 0x1bb")
int BPF_KPROBE(do_mov_2706)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_lladdr + 0x7a")
int BPF_KPROBE(do_mov_2707)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_lladdr + 0x7f")
int BPF_KPROBE(do_mov_2708)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_rs_timer + 0x3e")
int BPF_KPROBE(do_mov_2709)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_rs_timer + 0x91")
int BPF_KPROBE(do_mov_2710)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_rs_timer + 0x121")
int BPF_KPROBE(do_mov_2711)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_completed + 0x37")
int BPF_KPROBE(do_mov_2712)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_completed + 0x13e")
int BPF_KPROBE(do_mov_2713)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_completed + 0x177")
int BPF_KPROBE(do_mov_2714)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_completed + 0x184")
int BPF_KPROBE(do_mov_2715)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_completed + 0x3a0")
int BPF_KPROBE(do_mov_2716)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_completed + 0x3b7")
int BPF_KPROBE(do_mov_2717)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x32")
int BPF_KPROBE(do_mov_2718)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x4e")
int BPF_KPROBE(do_mov_2719)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x5b")
int BPF_KPROBE(do_mov_2720)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x86")
int BPF_KPROBE(do_mov_2721)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x140")
int BPF_KPROBE(do_mov_2722)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x1f1")
int BPF_KPROBE(do_mov_2723)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x230")
int BPF_KPROBE(do_mov_2724)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x234")
int BPF_KPROBE(do_mov_2725)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x23f")
int BPF_KPROBE(do_mov_2726)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x247")
int BPF_KPROBE(do_mov_2727)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x26e")
int BPF_KPROBE(do_mov_2728)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x274")
int BPF_KPROBE(do_mov_2729)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x2a8")
int BPF_KPROBE(do_mov_2730)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x34b")
int BPF_KPROBE(do_mov_2731)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x389")
int BPF_KPROBE(do_mov_2732)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x3a0")
int BPF_KPROBE(do_mov_2733)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x3a8")
int BPF_KPROBE(do_mov_2734)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_work + 0x3e4")
int BPF_KPROBE(do_mov_2735)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x25")
int BPF_KPROBE(do_mov_2736)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x30")
int BPF_KPROBE(do_mov_2737)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x3b")
int BPF_KPROBE(do_mov_2738)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x46")
int BPF_KPROBE(do_mov_2739)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x50")
int BPF_KPROBE(do_mov_2740)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x5a")
int BPF_KPROBE(do_mov_2741)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x6b")
int BPF_KPROBE(do_mov_2742)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x74")
int BPF_KPROBE(do_mov_2743)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x117")
int BPF_KPROBE(do_mov_2744)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x169")
int BPF_KPROBE(do_mov_2745)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x1f1")
int BPF_KPROBE(do_mov_2746)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x33b")
int BPF_KPROBE(do_mov_2747)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x3b1")
int BPF_KPROBE(do_mov_2748)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x3d9")
int BPF_KPROBE(do_mov_2749)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getaddr + 0x408")
int BPF_KPROBE(do_mov_2750)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x30")
int BPF_KPROBE(do_mov_2751)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x34")
int BPF_KPROBE(do_mov_2752)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x40")
int BPF_KPROBE(do_mov_2753)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x67")
int BPF_KPROBE(do_mov_2754)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x6f")
int BPF_KPROBE(do_mov_2755)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x7f")
int BPF_KPROBE(do_mov_2756)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x85")
int BPF_KPROBE(do_mov_2757)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x8d")
int BPF_KPROBE(do_mov_2758)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x93")
int BPF_KPROBE(do_mov_2759)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x9b")
int BPF_KPROBE(do_mov_2760)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0xa1")
int BPF_KPROBE(do_mov_2761)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0xa5")
int BPF_KPROBE(do_mov_2762)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0xac")
int BPF_KPROBE(do_mov_2763)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0xb4")
int BPF_KPROBE(do_mov_2764)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x107")
int BPF_KPROBE(do_mov_2765)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x10f")
int BPF_KPROBE(do_mov_2766)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x13b")
int BPF_KPROBE(do_mov_2767)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x210")
int BPF_KPROBE(do_mov_2768)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x223")
int BPF_KPROBE(do_mov_2769)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x226")
int BPF_KPROBE(do_mov_2770)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x22d")
int BPF_KPROBE(do_mov_2771)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x237")
int BPF_KPROBE(do_mov_2772)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x23d")
int BPF_KPROBE(do_mov_2773)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv_add_addr + 0x265")
int BPF_KPROBE(do_mov_2774)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x29")
int BPF_KPROBE(do_mov_2775)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0xb9")
int BPF_KPROBE(do_mov_2776)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0xdf")
int BPF_KPROBE(do_mov_2777)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0xef")
int BPF_KPROBE(do_mov_2778)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0xfa")
int BPF_KPROBE(do_mov_2779)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x10c")
int BPF_KPROBE(do_mov_2780)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x11f")
int BPF_KPROBE(do_mov_2781)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x125")
int BPF_KPROBE(do_mov_2782)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x13c")
int BPF_KPROBE(do_mov_2783)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x145")
int BPF_KPROBE(do_mov_2784)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x17a")
int BPF_KPROBE(do_mov_2785)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x224")
int BPF_KPROBE(do_mov_2786)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x240")
int BPF_KPROBE(do_mov_2787)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x2a0")
int BPF_KPROBE(do_mov_2788)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x2c5")
int BPF_KPROBE(do_mov_2789)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x2e5")
int BPF_KPROBE(do_mov_2790)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x319")
int BPF_KPROBE(do_mov_2791)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x32a")
int BPF_KPROBE(do_mov_2792)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x351")
int BPF_KPROBE(do_mov_2793)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x369")
int BPF_KPROBE(do_mov_2794)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x36f")
int BPF_KPROBE(do_mov_2795)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x379")
int BPF_KPROBE(do_mov_2796)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x383")
int BPF_KPROBE(do_mov_2797)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x38e")
int BPF_KPROBE(do_mov_2798)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x3a5")
int BPF_KPROBE(do_mov_2799)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x3fe")
int BPF_KPROBE(do_mov_2800)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x4f2")
int BPF_KPROBE(do_mov_2801)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x4f9")
int BPF_KPROBE(do_mov_2802)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x516")
int BPF_KPROBE(do_mov_2803)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x627")
int BPF_KPROBE(do_mov_2804)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x654")
int BPF_KPROBE(do_mov_2805)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newaddr + 0x6a8")
int BPF_KPROBE(do_mov_2806)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_failure + 0x37")
int BPF_KPROBE(do_mov_2807)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_failure + 0x59")
int BPF_KPROBE(do_mov_2808)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_dad_failure + 0x64")
int BPF_KPROBE(do_mov_2809)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_join_solict + 0x1a")
int BPF_KPROBE(do_mov_2810)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_join_solict + 0x30")
int BPF_KPROBE(do_mov_2811)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_join_solict + 0x38")
int BPF_KPROBE(do_mov_2812)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_join_solict + 0x42")
int BPF_KPROBE(do_mov_2813)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_solict + 0x1a")
int BPF_KPROBE(do_mov_2814)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_solict + 0x31")
int BPF_KPROBE(do_mov_2815)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_solict + 0x39")
int BPF_KPROBE(do_mov_2816)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_leave_solict + 0x43")
int BPF_KPROBE(do_mov_2817)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x28")
int BPF_KPROBE(do_mov_2818)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x3b")
int BPF_KPROBE(do_mov_2819)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x9d")
int BPF_KPROBE(do_mov_2820)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0xa0")
int BPF_KPROBE(do_mov_2821)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0xaa")
int BPF_KPROBE(do_mov_2822)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0xb4")
int BPF_KPROBE(do_mov_2823)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0xdc")
int BPF_KPROBE(do_mov_2824)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x139")
int BPF_KPROBE(do_mov_2825)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x182")
int BPF_KPROBE(do_mov_2826)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x1da")
int BPF_KPROBE(do_mov_2827)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x1dd")
int BPF_KPROBE(do_mov_2828)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x1e9")
int BPF_KPROBE(do_mov_2829)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x208")
int BPF_KPROBE(do_mov_2830)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x210")
int BPF_KPROBE(do_mov_2831)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x224")
int BPF_KPROBE(do_mov_2832)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x2a7")
int BPF_KPROBE(do_mov_2833)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x303")
int BPF_KPROBE(do_mov_2834)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x314")
int BPF_KPROBE(do_mov_2835)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x31c")
int BPF_KPROBE(do_mov_2836)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x323")
int BPF_KPROBE(do_mov_2837)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x329")
int BPF_KPROBE(do_mov_2838)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x335")
int BPF_KPROBE(do_mov_2839)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x342")
int BPF_KPROBE(do_mov_2840)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x379")
int BPF_KPROBE(do_mov_2841)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x381")
int BPF_KPROBE(do_mov_2842)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x3b9")
int BPF_KPROBE(do_mov_2843)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x431")
int BPF_KPROBE(do_mov_2844)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x47a")
int BPF_KPROBE(do_mov_2845)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x5ee")
int BPF_KPROBE(do_mov_2846)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x623")
int BPF_KPROBE(do_mov_2847)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x641")
int BPF_KPROBE(do_mov_2848)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x648")
int BPF_KPROBE(do_mov_2849)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x692")
int BPF_KPROBE(do_mov_2850)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x6ad")
int BPF_KPROBE(do_mov_2851)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_prefix_rcv + 0x6b6")
int BPF_KPROBE(do_mov_2852)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_set_dstaddr + 0x2b")
int BPF_KPROBE(do_mov_2853)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_set_dstaddr + 0xae")
int BPF_KPROBE(do_mov_2854)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_set_dstaddr + 0xc4")
int BPF_KPROBE(do_mov_2855)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_set_dstaddr + 0xc9")
int BPF_KPROBE(do_mov_2856)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_set_dstaddr + 0xd2")
int BPF_KPROBE(do_mov_2857)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_ifaddr + 0x30")
int BPF_KPROBE(do_mov_2858)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_ifaddr + 0x45")
int BPF_KPROBE(do_mov_2859)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_ifaddr + 0x4d")
int BPF_KPROBE(do_mov_2860)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_ifaddr + 0x7b")
int BPF_KPROBE(do_mov_2861)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_add_ifaddr + 0x83")
int BPF_KPROBE(do_mov_2862)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_del_ifaddr + 0x2d")
int BPF_KPROBE(do_mov_2863)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x134")
int BPF_KPROBE(do_mov_2864)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x391")
int BPF_KPROBE(do_mov_2865)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x3dd")
int BPF_KPROBE(do_mov_2866)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x3f4")
int BPF_KPROBE(do_mov_2867)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x422")
int BPF_KPROBE(do_mov_2868)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x42c")
int BPF_KPROBE(do_mov_2869)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x433")
int BPF_KPROBE(do_mov_2870)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x606")
int BPF_KPROBE(do_mov_2871)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_notify + 0x738")
int BPF_KPROBE(do_mov_2872)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_disable_change + 0x16")
int BPF_KPROBE(do_mov_2873)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_disable_change + 0x2f")
int BPF_KPROBE(do_mov_2874)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/dev_disable_change + 0x33")
int BPF_KPROBE(do_mov_2875)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x2f")
int BPF_KPROBE(do_mov_2876)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x38")
int BPF_KPROBE(do_mov_2877)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x3e")
int BPF_KPROBE(do_mov_2878)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x46")
int BPF_KPROBE(do_mov_2879)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x4e")
int BPF_KPROBE(do_mov_2880)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x56")
int BPF_KPROBE(do_mov_2881)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x5e")
int BPF_KPROBE(do_mov_2882)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x66")
int BPF_KPROBE(do_mov_2883)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x72")
int BPF_KPROBE(do_mov_2884)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x7a")
int BPF_KPROBE(do_mov_2885)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x8c")
int BPF_KPROBE(do_mov_2886)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0xca")
int BPF_KPROBE(do_mov_2887)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x120")
int BPF_KPROBE(do_mov_2888)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_sysctl_disable + 0x151")
int BPF_KPROBE(do_mov_2889)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x2e")
int BPF_KPROBE(do_mov_2890)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x88")
int BPF_KPROBE(do_mov_2891)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x109")
int BPF_KPROBE(do_mov_2892)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x163")
int BPF_KPROBE(do_mov_2893)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x1be")
int BPF_KPROBE(do_mov_2894)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x20f")
int BPF_KPROBE(do_mov_2895)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x290")
int BPF_KPROBE(do_mov_2896)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x2c3")
int BPF_KPROBE(do_mov_2897)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x310")
int BPF_KPROBE(do_mov_2898)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x37f")
int BPF_KPROBE(do_mov_2899)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x3a2")
int BPF_KPROBE(do_mov_2900)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_set_link_af + 0x3c5")
int BPF_KPROBE(do_mov_2901)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_exit + 0x3e")
int BPF_KPROBE(do_mov_2902)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_exit + 0x47")
int BPF_KPROBE(do_mov_2903)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_exit + 0x65")
int BPF_KPROBE(do_mov_2904)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_exit + 0x7c")
int BPF_KPROBE(do_mov_2905)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x88")
int BPF_KPROBE(do_mov_2906)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x94")
int BPF_KPROBE(do_mov_2907)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x9c")
int BPF_KPROBE(do_mov_2908)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0xa8")
int BPF_KPROBE(do_mov_2909)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0xbf")
int BPF_KPROBE(do_mov_2910)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0xdd")
int BPF_KPROBE(do_mov_2911)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0xe5")
int BPF_KPROBE(do_mov_2912)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0xed")
int BPF_KPROBE(do_mov_2913)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0xf0")
int BPF_KPROBE(do_mov_2914)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x103")
int BPF_KPROBE(do_mov_2915)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x10f")
int BPF_KPROBE(do_mov_2916)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x113")
int BPF_KPROBE(do_mov_2917)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x120")
int BPF_KPROBE(do_mov_2918)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x12d")
int BPF_KPROBE(do_mov_2919)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x135")
int BPF_KPROBE(do_mov_2920)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x139")
int BPF_KPROBE(do_mov_2921)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6addrlbl_add + 0x145")
int BPF_KPROBE(do_mov_2922)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0x21")
int BPF_KPROBE(do_mov_2923)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0x7f")
int BPF_KPROBE(do_mov_2924)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0x8b")
int BPF_KPROBE(do_mov_2925)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0x93")
int BPF_KPROBE(do_mov_2926)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0x97")
int BPF_KPROBE(do_mov_2927)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0x9a")
int BPF_KPROBE(do_mov_2928)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0xbc")
int BPF_KPROBE(do_mov_2929)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_fill.constprop.0 + 0xdb")
int BPF_KPROBE(do_mov_2930)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0x2d")
int BPF_KPROBE(do_mov_2931)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0x80")
int BPF_KPROBE(do_mov_2932)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0xc2")
int BPF_KPROBE(do_mov_2933)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0xef")
int BPF_KPROBE(do_mov_2934)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0x11e")
int BPF_KPROBE(do_mov_2935)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0x13d")
int BPF_KPROBE(do_mov_2936)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_dump + 0x15f")
int BPF_KPROBE(do_mov_2937)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_get + 0x22")
int BPF_KPROBE(do_mov_2938)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_get + 0x105")
int BPF_KPROBE(do_mov_2939)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_get + 0x1d9")
int BPF_KPROBE(do_mov_2940)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_get + 0x251")
int BPF_KPROBE(do_mov_2941)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_get + 0x278")
int BPF_KPROBE(do_mov_2942)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_get + 0x29f")
int BPF_KPROBE(do_mov_2943)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0x78")
int BPF_KPROBE(do_mov_2944)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0x82")
int BPF_KPROBE(do_mov_2945)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xa0")
int BPF_KPROBE(do_mov_2946)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xa3")
int BPF_KPROBE(do_mov_2947)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xb6")
int BPF_KPROBE(do_mov_2948)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xba")
int BPF_KPROBE(do_mov_2949)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xbe")
int BPF_KPROBE(do_mov_2950)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xc2")
int BPF_KPROBE(do_mov_2951)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xc6")
int BPF_KPROBE(do_mov_2952)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xce")
int BPF_KPROBE(do_mov_2953)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xda")
int BPF_KPROBE(do_mov_2954)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_alloc + 0xf7")
int BPF_KPROBE(do_mov_2955)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x30")
int BPF_KPROBE(do_mov_2956)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x10c")
int BPF_KPROBE(do_mov_2957)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x117")
int BPF_KPROBE(do_mov_2958)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x135")
int BPF_KPROBE(do_mov_2959)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x148")
int BPF_KPROBE(do_mov_2960)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x15b")
int BPF_KPROBE(do_mov_2961)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x171")
int BPF_KPROBE(do_mov_2962)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x19c")
int BPF_KPROBE(do_mov_2963)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x1e1")
int BPF_KPROBE(do_mov_2964)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x1e9")
int BPF_KPROBE(do_mov_2965)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x203")
int BPF_KPROBE(do_mov_2966)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x220")
int BPF_KPROBE(do_mov_2967)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x2c7")
int BPF_KPROBE(do_mov_2968)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x2fb")
int BPF_KPROBE(do_mov_2969)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_newdel + 0x30d")
int BPF_KPROBE(do_mov_2970)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0x2a")
int BPF_KPROBE(do_mov_2971)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0x34")
int BPF_KPROBE(do_mov_2972)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0x64")
int BPF_KPROBE(do_mov_2973)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0xc9")
int BPF_KPROBE(do_mov_2974)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0xd2")
int BPF_KPROBE(do_mov_2975)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0xf0")
int BPF_KPROBE(do_mov_2976)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6addrlbl_net_init + 0x107")
int BPF_KPROBE(do_mov_2977)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_find_match + 0x3f")
int BPF_KPROBE(do_mov_2978)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_remove_prefsrc + 0x64")
int BPF_KPROBE(do_mov_2979)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_info_init + 0xd")
int BPF_KPROBE(do_mov_2980)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_info_init + 0x17")
int BPF_KPROBE(do_mov_2981)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_info_init + 0x3d")
int BPF_KPROBE(do_mov_2982)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_info_init + 0x45")
int BPF_KPROBE(do_mov_2983)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_lookup + 0x31")
int BPF_KPROBE(do_mov_2984)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_lookup + 0x45")
int BPF_KPROBE(do_mov_2985)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_lookup + 0x49")
int BPF_KPROBE(do_mov_2986)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_lookup + 0x4e")
int BPF_KPROBE(do_mov_2987)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_lookup + 0x6a")
int BPF_KPROBE(do_mov_2988)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_lookup + 0x6f")
int BPF_KPROBE(do_mov_2989)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pkt_drop + 0x115")
int BPF_KPROBE(do_mov_2990)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pkt_drop + 0x18a")
int BPF_KPROBE(do_mov_2991)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pkt_discard_out + 0x19")
int BPF_KPROBE(do_mov_2992)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pkt_prohibit_out + 0x1c")
int BPF_KPROBE(do_mov_2993)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe_deferred + 0x28")
int BPF_KPROBE(do_mov_2994)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe_deferred + 0x37")
int BPF_KPROBE(do_mov_2995)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe_deferred + 0x3f")
int BPF_KPROBE(do_mov_2996)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe_deferred + 0x49")
int BPF_KPROBE(do_mov_2997)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_output_flags_noref + 0x26")
int BPF_KPROBE(do_mov_2998)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_output_flags_noref + 0x36")
int BPF_KPROBE(do_mov_2999)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nlmsg_size + 0x21")
int BPF_KPROBE(do_mov_3000)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nlmsg_size + 0x37")
int BPF_KPROBE(do_mov_3001)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nlmsg_size + 0x66")
int BPF_KPROBE(do_mov_3002)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nlmsg_size + 0x95")
int BPF_KPROBE(do_mov_3003)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_nlmsg_size + 0x24")
int BPF_KPROBE(do_mov_3004)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_gc + 0x3d")
int BPF_KPROBE(do_mov_3005)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_gc + 0xb5")
int BPF_KPROBE(do_mov_3006)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_gc + 0xcb")
int BPF_KPROBE(do_mov_3007)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_gc + 0xef")
int BPF_KPROBE(do_mov_3008)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_gc + 0xf6")
int BPF_KPROBE(do_mov_3009)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_inetpeer_exit + 0x12")
int BPF_KPROBE(do_mov_3010)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_inetpeer_init + 0x35")
int BPF_KPROBE(do_mov_3011)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x37")
int BPF_KPROBE(do_mov_3012)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x49")
int BPF_KPROBE(do_mov_3013)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x63")
int BPF_KPROBE(do_mov_3014)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x8e")
int BPF_KPROBE(do_mov_3015)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0xb4")
int BPF_KPROBE(do_mov_3016)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0xbe")
int BPF_KPROBE(do_mov_3017)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0xda")
int BPF_KPROBE(do_mov_3018)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0xee")
int BPF_KPROBE(do_mov_3019)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0xfe")
int BPF_KPROBE(do_mov_3020)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x120")
int BPF_KPROBE(do_mov_3021)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x132")
int BPF_KPROBE(do_mov_3022)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x139")
int BPF_KPROBE(do_mov_3023)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x145")
int BPF_KPROBE(do_mov_3024)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x151")
int BPF_KPROBE(do_mov_3025)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x161")
int BPF_KPROBE(do_mov_3026)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x178")
int BPF_KPROBE(do_mov_3027)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x18a")
int BPF_KPROBE(do_mov_3028)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x191")
int BPF_KPROBE(do_mov_3029)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1a2")
int BPF_KPROBE(do_mov_3030)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1b2")
int BPF_KPROBE(do_mov_3031)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1bd")
int BPF_KPROBE(do_mov_3032)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1cf")
int BPF_KPROBE(do_mov_3033)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1d6")
int BPF_KPROBE(do_mov_3034)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1e7")
int BPF_KPROBE(do_mov_3035)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x1f8")
int BPF_KPROBE(do_mov_3036)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x209")
int BPF_KPROBE(do_mov_3037)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x213")
int BPF_KPROBE(do_mov_3038)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x21a")
int BPF_KPROBE(do_mov_3039)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x224")
int BPF_KPROBE(do_mov_3040)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_net_init + 0x235")
int BPF_KPROBE(do_mov_3041)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__rt6_nh_dev_match + 0x5")
int BPF_KPROBE(do_mov_3042)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x19")
int BPF_KPROBE(do_mov_3043)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x21")
int BPF_KPROBE(do_mov_3044)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x2b")
int BPF_KPROBE(do_mov_3045)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x37")
int BPF_KPROBE(do_mov_3046)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x3f")
int BPF_KPROBE(do_mov_3047)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x48")
int BPF_KPROBE(do_mov_3048)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x51")
int BPF_KPROBE(do_mov_3049)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x5a")
int BPF_KPROBE(do_mov_3050)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x63")
int BPF_KPROBE(do_mov_3051)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x6c")
int BPF_KPROBE(do_mov_3052)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x75")
int BPF_KPROBE(do_mov_3053)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x7e")
int BPF_KPROBE(do_mov_3054)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x87")
int BPF_KPROBE(do_mov_3055)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x94")
int BPF_KPROBE(do_mov_3056)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_redirect.isra.0 + 0x9c")
int BPF_KPROBE(do_mov_3057)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x1e")
int BPF_KPROBE(do_mov_3058)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x25")
int BPF_KPROBE(do_mov_3059)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x2a")
int BPF_KPROBE(do_mov_3060)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x33")
int BPF_KPROBE(do_mov_3061)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x3c")
int BPF_KPROBE(do_mov_3062)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x4f")
int BPF_KPROBE(do_mov_3063)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_exception_hash.isra.0 + 0x54")
int BPF_KPROBE(do_mov_3064)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__rt6_find_exception_spinlock + 0x40")
int BPF_KPROBE(do_mov_3065)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__rt6_find_exception_rcu + 0x40")
int BPF_KPROBE(do_mov_3066)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x29")
int BPF_KPROBE(do_mov_3067)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x52")
int BPF_KPROBE(do_mov_3068)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x56")
int BPF_KPROBE(do_mov_3069)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x64")
int BPF_KPROBE(do_mov_3070)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x68")
int BPF_KPROBE(do_mov_3071)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x71")
int BPF_KPROBE(do_mov_3072)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x7a")
int BPF_KPROBE(do_mov_3073)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x11c")
int BPF_KPROBE(do_mov_3074)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x120")
int BPF_KPROBE(do_mov_3075)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x12c")
int BPF_KPROBE(do_mov_3076)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x130")
int BPF_KPROBE(do_mov_3077)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x13d")
int BPF_KPROBE(do_mov_3078)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_multipath_l3_keys.constprop.0 + 0x15d")
int BPF_KPROBE(do_mov_3079)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_mtu_change + 0x90")
int BPF_KPROBE(do_mov_3080)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_mtu_change + 0x101")
int BPF_KPROBE(do_mov_3081)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_mtu_change_route + 0x20")
int BPF_KPROBE(do_mov_3082)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_score_route + 0x104")
int BPF_KPROBE(do_mov_3083)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_score_route + 0x156")
int BPF_KPROBE(do_mov_3084)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_score_route + 0x166")
int BPF_KPROBE(do_mov_3085)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_find_cached_rt + 0x26")
int BPF_KPROBE(do_mov_3086)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_find_cached_rt + 0x8d")
int BPF_KPROBE(do_mov_3087)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_nh_match + 0x51")
int BPF_KPROBE(do_mov_3088)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_nh_match + 0x8c")
int BPF_KPROBE(do_mov_3089)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_redirect_match + 0xc")
int BPF_KPROBE(do_mov_3090)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu + 0x44")
int BPF_KPROBE(do_mov_3091)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu + 0x53")
int BPF_KPROBE(do_mov_3092)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu + 0x86")
int BPF_KPROBE(do_mov_3093)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu + 0x90")
int BPF_KPROBE(do_mov_3094)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_update_pmtu + 0xb6")
int BPF_KPROBE(do_mov_3095)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x34")
int BPF_KPROBE(do_mov_3096)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xbc")
int BPF_KPROBE(do_mov_3097)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xc3")
int BPF_KPROBE(do_mov_3098)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xc6")
int BPF_KPROBE(do_mov_3099)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xca")
int BPF_KPROBE(do_mov_3100)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xce")
int BPF_KPROBE(do_mov_3101)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xd2")
int BPF_KPROBE(do_mov_3102)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xd6")
int BPF_KPROBE(do_mov_3103)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xdd")
int BPF_KPROBE(do_mov_3104)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0xe4")
int BPF_KPROBE(do_mov_3105)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x100")
int BPF_KPROBE(do_mov_3106)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x12d")
int BPF_KPROBE(do_mov_3107)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x16c")
int BPF_KPROBE(do_mov_3108)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x206")
int BPF_KPROBE(do_mov_3109)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x20a")
int BPF_KPROBE(do_mov_3110)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x21d")
int BPF_KPROBE(do_mov_3111)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x22f")
int BPF_KPROBE(do_mov_3112)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x242")
int BPF_KPROBE(do_mov_3113)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x24c")
int BPF_KPROBE(do_mov_3114)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x25e")
int BPF_KPROBE(do_mov_3115)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x273")
int BPF_KPROBE(do_mov_3116)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x280")
int BPF_KPROBE(do_mov_3117)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x2bf")
int BPF_KPROBE(do_mov_3118)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x2d9")
int BPF_KPROBE(do_mov_3119)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x311")
int BPF_KPROBE(do_mov_3120)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x342")
int BPF_KPROBE(do_mov_3121)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x354")
int BPF_KPROBE(do_mov_3122)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x393")
int BPF_KPROBE(do_mov_3123)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x397")
int BPF_KPROBE(do_mov_3124)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x3b1")
int BPF_KPROBE(do_mov_3125)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x3d4")
int BPF_KPROBE(do_mov_3126)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x3fe")
int BPF_KPROBE(do_mov_3127)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rtm_to_fib6_config + 0x421")
int BPF_KPROBE(do_mov_3128)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_hold_safe + 0x49")
int BPF_KPROBE(do_mov_3129)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_ifdown + 0x60")
int BPF_KPROBE(do_mov_3130)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0xfc")
int BPF_KPROBE(do_mov_3131)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x171")
int BPF_KPROBE(do_mov_3132)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x18d")
int BPF_KPROBE(do_mov_3133)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1c6")
int BPF_KPROBE(do_mov_3134)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1ce")
int BPF_KPROBE(do_mov_3135)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1d5")
int BPF_KPROBE(do_mov_3136)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1d9")
int BPF_KPROBE(do_mov_3137)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1e1")
int BPF_KPROBE(do_mov_3138)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1e5")
int BPF_KPROBE(do_mov_3139)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_probe + 0x1f8")
int BPF_KPROBE(do_mov_3140)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_find_match + 0x1e")
int BPF_KPROBE(do_mov_3141)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_find_match + 0x81")
int BPF_KPROBE(do_mov_3142)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_find_match + 0x8a")
int BPF_KPROBE(do_mov_3143)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_find_match + 0xbd")
int BPF_KPROBE(do_mov_3144)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_confirm_neigh + 0x10d")
int BPF_KPROBE(do_mov_3145)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_flush_exceptions + 0xaf")
int BPF_KPROBE(do_mov_3146)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x2c")
int BPF_KPROBE(do_mov_3147)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x4a")
int BPF_KPROBE(do_mov_3148)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0xca")
int BPF_KPROBE(do_mov_3149)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x101")
int BPF_KPROBE(do_mov_3150)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x105")
int BPF_KPROBE(do_mov_3151)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x110")
int BPF_KPROBE(do_mov_3152)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x114")
int BPF_KPROBE(do_mov_3153)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x117")
int BPF_KPROBE(do_mov_3154)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x11f")
int BPF_KPROBE(do_mov_3155)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x204")
int BPF_KPROBE(do_mov_3156)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x207")
int BPF_KPROBE(do_mov_3157)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x23d")
int BPF_KPROBE(do_mov_3158)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_insert_exception + 0x246")
int BPF_KPROBE(do_mov_3159)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_remove_exception + 0x1b")
int BPF_KPROBE(do_mov_3160)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_remove_exception + 0x69")
int BPF_KPROBE(do_mov_3161)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_remove_exception + 0x80")
int BPF_KPROBE(do_mov_3162)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_exception_rt + 0x19")
int BPF_KPROBE(do_mov_3163)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_exception_rt + 0x40")
int BPF_KPROBE(do_mov_3164)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_exception_rt + 0x4b")
int BPF_KPROBE(do_mov_3165)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_link_failure + 0x67")
int BPF_KPROBE(do_mov_3166)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_del_cached_rt + 0x1a")
int BPF_KPROBE(do_mov_3167)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_del_cached_rt + 0x22")
int BPF_KPROBE(do_mov_3168)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_del_cached_rt + 0x32")
int BPF_KPROBE(do_mov_3169)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_del_cached_rt + 0x3a")
int BPF_KPROBE(do_mov_3170)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_del_cached_rt + 0x42")
int BPF_KPROBE(do_mov_3171)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x2e")
int BPF_KPROBE(do_mov_3172)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x3d")
int BPF_KPROBE(do_mov_3173)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x50")
int BPF_KPROBE(do_mov_3174)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x65")
int BPF_KPROBE(do_mov_3175)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x86")
int BPF_KPROBE(do_mov_3176)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x8f")
int BPF_KPROBE(do_mov_3177)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x98")
int BPF_KPROBE(do_mov_3178)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0xa4")
int BPF_KPROBE(do_mov_3179)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0xed")
int BPF_KPROBE(do_mov_3180)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0xf8")
int BPF_KPROBE(do_mov_3181)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x110")
int BPF_KPROBE(do_mov_3182)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x117")
int BPF_KPROBE(do_mov_3183)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x124")
int BPF_KPROBE(do_mov_3184)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x12a")
int BPF_KPROBE(do_mov_3185)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x146")
int BPF_KPROBE(do_mov_3186)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x16c")
int BPF_KPROBE(do_mov_3187)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x178")
int BPF_KPROBE(do_mov_3188)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x184")
int BPF_KPROBE(do_mov_3189)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x199")
int BPF_KPROBE(do_mov_3190)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x1d0")
int BPF_KPROBE(do_mov_3191)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x1dc")
int BPF_KPROBE(do_mov_3192)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x1e4")
int BPF_KPROBE(do_mov_3193)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x1f5")
int BPF_KPROBE(do_mov_3194)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x1f9")
int BPF_KPROBE(do_mov_3195)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x206")
int BPF_KPROBE(do_mov_3196)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x20e")
int BPF_KPROBE(do_mov_3197)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x21b")
int BPF_KPROBE(do_mov_3198)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x223")
int BPF_KPROBE(do_mov_3199)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x243")
int BPF_KPROBE(do_mov_3200)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_copy_init + 0x24b")
int BPF_KPROBE(do_mov_3201)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_destroy + 0x74")
int BPF_KPROBE(do_mov_3202)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_destroy + 0x78")
int BPF_KPROBE(do_mov_3203)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_destroy + 0x7b")
int BPF_KPROBE(do_mov_3204)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_destroy + 0x82")
int BPF_KPROBE(do_mov_3205)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_dst_destroy + 0x9a")
int BPF_KPROBE(do_mov_3206)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x1a")
int BPF_KPROBE(do_mov_3207)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x1d")
int BPF_KPROBE(do_mov_3208)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x21")
int BPF_KPROBE(do_mov_3209)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x29")
int BPF_KPROBE(do_mov_3210)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x36")
int BPF_KPROBE(do_mov_3211)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x4a")
int BPF_KPROBE(do_mov_3212)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x65")
int BPF_KPROBE(do_mov_3213)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0xf0")
int BPF_KPROBE(do_mov_3214)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0xf2")
int BPF_KPROBE(do_mov_3215)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0xf4")
int BPF_KPROBE(do_mov_3216)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0xf8")
int BPF_KPROBE(do_mov_3217)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0xff")
int BPF_KPROBE(do_mov_3218)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x10b")
int BPF_KPROBE(do_mov_3219)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x16e")
int BPF_KPROBE(do_mov_3220)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x171")
int BPF_KPROBE(do_mov_3221)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x179")
int BPF_KPROBE(do_mov_3222)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x17f")
int BPF_KPROBE(do_mov_3223)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x187")
int BPF_KPROBE(do_mov_3224)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x18e")
int BPF_KPROBE(do_mov_3225)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x196")
int BPF_KPROBE(do_mov_3226)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x1e9")
int BPF_KPROBE(do_mov_3227)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x1ec")
int BPF_KPROBE(do_mov_3228)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x200")
int BPF_KPROBE(do_mov_3229)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x238")
int BPF_KPROBE(do_mov_3230)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x243")
int BPF_KPROBE(do_mov_3231)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x248")
int BPF_KPROBE(do_mov_3232)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__find_rr_leaf + 0x283")
int BPF_KPROBE(do_mov_3233)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_get_route_info + 0x22")
int BPF_KPROBE(do_mov_3234)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x83")
int BPF_KPROBE(do_mov_3235)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0xc7")
int BPF_KPROBE(do_mov_3236)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x10f")
int BPF_KPROBE(do_mov_3237)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x127")
int BPF_KPROBE(do_mov_3238)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x136")
int BPF_KPROBE(do_mov_3239)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x17f")
int BPF_KPROBE(do_mov_3240)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x18e")
int BPF_KPROBE(do_mov_3241)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x1d7")
int BPF_KPROBE(do_mov_3242)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x1e6")
int BPF_KPROBE(do_mov_3243)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_dev_notify + 0x22a")
int BPF_KPROBE(do_mov_3244)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x28")
int BPF_KPROBE(do_mov_3245)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x2f")
int BPF_KPROBE(do_mov_3246)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x3f")
int BPF_KPROBE(do_mov_3247)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x45")
int BPF_KPROBE(do_mov_3248)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x49")
int BPF_KPROBE(do_mov_3249)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x51")
int BPF_KPROBE(do_mov_3250)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x59")
int BPF_KPROBE(do_mov_3251)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x61")
int BPF_KPROBE(do_mov_3252)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x69")
int BPF_KPROBE(do_mov_3253)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x71")
int BPF_KPROBE(do_mov_3254)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x75")
int BPF_KPROBE(do_mov_3255)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x79")
int BPF_KPROBE(do_mov_3256)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x8e")
int BPF_KPROBE(do_mov_3257)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x9a")
int BPF_KPROBE(do_mov_3258)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0xd8")
int BPF_KPROBE(do_mov_3259)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0xfa")
int BPF_KPROBE(do_mov_3260)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x125")
int BPF_KPROBE(do_mov_3261)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x13f")
int BPF_KPROBE(do_mov_3262)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x142")
int BPF_KPROBE(do_mov_3263)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x14a")
int BPF_KPROBE(do_mov_3264)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x1f8")
int BPF_KPROBE(do_mov_3265)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x208")
int BPF_KPROBE(do_mov_3266)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_route_redirect + 0x212")
int BPF_KPROBE(do_mov_3267)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x1a")
int BPF_KPROBE(do_mov_3268)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x1e")
int BPF_KPROBE(do_mov_3269)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x23")
int BPF_KPROBE(do_mov_3270)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x31")
int BPF_KPROBE(do_mov_3271)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x3b")
int BPF_KPROBE(do_mov_3272)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x40")
int BPF_KPROBE(do_mov_3273)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xa5")
int BPF_KPROBE(do_mov_3274)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xb1")
int BPF_KPROBE(do_mov_3275)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xb5")
int BPF_KPROBE(do_mov_3276)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xbd")
int BPF_KPROBE(do_mov_3277)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xc8")
int BPF_KPROBE(do_mov_3278)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xcc")
int BPF_KPROBE(do_mov_3279)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0xec")
int BPF_KPROBE(do_mov_3280)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x101")
int BPF_KPROBE(do_mov_3281)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x11b")
int BPF_KPROBE(do_mov_3282)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x122")
int BPF_KPROBE(do_mov_3283)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x12b")
int BPF_KPROBE(do_mov_3284)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x137")
int BPF_KPROBE(do_mov_3285)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x146")
int BPF_KPROBE(do_mov_3286)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x16c")
int BPF_KPROBE(do_mov_3287)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x198")
int BPF_KPROBE(do_mov_3288)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x1cb")
int BPF_KPROBE(do_mov_3289)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x224")
int BPF_KPROBE(do_mov_3290)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x26a")
int BPF_KPROBE(do_mov_3291)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x2bd")
int BPF_KPROBE(do_mov_3292)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x2f7")
int BPF_KPROBE(do_mov_3293)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x319")
int BPF_KPROBE(do_mov_3294)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x347")
int BPF_KPROBE(do_mov_3295)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x448")
int BPF_KPROBE(do_mov_3296)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x44d")
int BPF_KPROBE(do_mov_3297)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x4ee")
int BPF_KPROBE(do_mov_3298)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x4f8")
int BPF_KPROBE(do_mov_3299)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x530")
int BPF_KPROBE(do_mov_3300)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x53a")
int BPF_KPROBE(do_mov_3301)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x58f")
int BPF_KPROBE(do_mov_3302)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x714")
int BPF_KPROBE(do_mov_3303)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x78c")
int BPF_KPROBE(do_mov_3304)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x7c6")
int BPF_KPROBE(do_mov_3305)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x7cb")
int BPF_KPROBE(do_mov_3306)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x7fd")
int BPF_KPROBE(do_mov_3307)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_fill_node + 0x867")
int BPF_KPROBE(do_mov_3308)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_dump_exceptions + 0x3a")
int BPF_KPROBE(do_mov_3309)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_nh_dump_exceptions + 0x4c")
int BPF_KPROBE(do_mov_3310)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_info_hw_flags_set + 0x24")
int BPF_KPROBE(do_mov_3311)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_info_hw_flags_set + 0x2c")
int BPF_KPROBE(do_mov_3312)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_info_hw_flags_set + 0x42")
int BPF_KPROBE(do_mov_3313)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x36")
int BPF_KPROBE(do_mov_3314)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x12b")
int BPF_KPROBE(do_mov_3315)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x170")
int BPF_KPROBE(do_mov_3316)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x17a")
int BPF_KPROBE(do_mov_3317)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x19c")
int BPF_KPROBE(do_mov_3318)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x1a3")
int BPF_KPROBE(do_mov_3319)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x1cd")
int BPF_KPROBE(do_mov_3320)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x1d4")
int BPF_KPROBE(do_mov_3321)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x1e2")
int BPF_KPROBE(do_mov_3322)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x1f4")
int BPF_KPROBE(do_mov_3323)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x201")
int BPF_KPROBE(do_mov_3324)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x213")
int BPF_KPROBE(do_mov_3325)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x228")
int BPF_KPROBE(do_mov_3326)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x25a")
int BPF_KPROBE(do_mov_3327)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x26d")
int BPF_KPROBE(do_mov_3328)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x281")
int BPF_KPROBE(do_mov_3329)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x2d7")
int BPF_KPROBE(do_mov_3330)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x2ee")
int BPF_KPROBE(do_mov_3331)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x37b")
int BPF_KPROBE(do_mov_3332)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x397")
int BPF_KPROBE(do_mov_3333)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x3f5")
int BPF_KPROBE(do_mov_3334)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x470")
int BPF_KPROBE(do_mov_3335)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x48f")
int BPF_KPROBE(do_mov_3336)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x4af")
int BPF_KPROBE(do_mov_3337)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x501")
int BPF_KPROBE(do_mov_3338)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x53d")
int BPF_KPROBE(do_mov_3339)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x564")
int BPF_KPROBE(do_mov_3340)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x596")
int BPF_KPROBE(do_mov_3341)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x5b9")
int BPF_KPROBE(do_mov_3342)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x5dc")
int BPF_KPROBE(do_mov_3343)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_getroute + 0x603")
int BPF_KPROBE(do_mov_3344)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x20")
int BPF_KPROBE(do_mov_3345)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x50")
int BPF_KPROBE(do_mov_3346)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0xb1")
int BPF_KPROBE(do_mov_3347)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0xc1")
int BPF_KPROBE(do_mov_3348)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0xcd")
int BPF_KPROBE(do_mov_3349)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0xd2")
int BPF_KPROBE(do_mov_3350)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x15c")
int BPF_KPROBE(do_mov_3351)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x189")
int BPF_KPROBE(do_mov_3352)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x195")
int BPF_KPROBE(do_mov_3353)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x19d")
int BPF_KPROBE(do_mov_3354)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_rt_cache_alloc + 0x1b7")
int BPF_KPROBE(do_mov_3355)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x23")
int BPF_KPROBE(do_mov_3356)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0xf1")
int BPF_KPROBE(do_mov_3357)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0xf9")
int BPF_KPROBE(do_mov_3358)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x101")
int BPF_KPROBE(do_mov_3359)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x109")
int BPF_KPROBE(do_mov_3360)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x11a")
int BPF_KPROBE(do_mov_3361)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x12a")
int BPF_KPROBE(do_mov_3362)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x134")
int BPF_KPROBE(do_mov_3363)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x15c")
int BPF_KPROBE(do_mov_3364)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x164")
int BPF_KPROBE(do_mov_3365)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x168")
int BPF_KPROBE(do_mov_3366)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x184")
int BPF_KPROBE(do_mov_3367)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x20e")
int BPF_KPROBE(do_mov_3368)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x219")
int BPF_KPROBE(do_mov_3369)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x224")
int BPF_KPROBE(do_mov_3370)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x25f")
int BPF_KPROBE(do_mov_3371)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ip6_rt_update_pmtu + 0x280")
int BPF_KPROBE(do_mov_3372)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x32")
int BPF_KPROBE(do_mov_3373)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x42")
int BPF_KPROBE(do_mov_3374)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x58")
int BPF_KPROBE(do_mov_3375)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x63")
int BPF_KPROBE(do_mov_3376)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x68")
int BPF_KPROBE(do_mov_3377)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x6d")
int BPF_KPROBE(do_mov_3378)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x7a")
int BPF_KPROBE(do_mov_3379)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x81")
int BPF_KPROBE(do_mov_3380)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_update_pmtu + 0x8f")
int BPF_KPROBE(do_mov_3381)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sk_update_pmtu + 0x2d")
int BPF_KPROBE(do_mov_3382)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x2e")
int BPF_KPROBE(do_mov_3383)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x41")
int BPF_KPROBE(do_mov_3384)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x4c")
int BPF_KPROBE(do_mov_3385)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x57")
int BPF_KPROBE(do_mov_3386)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x65")
int BPF_KPROBE(do_mov_3387)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x1be")
int BPF_KPROBE(do_mov_3388)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x1e4")
int BPF_KPROBE(do_mov_3389)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x1eb")
int BPF_KPROBE(do_mov_3390)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x1f2")
int BPF_KPROBE(do_mov_3391)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x24a")
int BPF_KPROBE(do_mov_3392)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x27b")
int BPF_KPROBE(do_mov_3393)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x286")
int BPF_KPROBE(do_mov_3394)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x294")
int BPF_KPROBE(do_mov_3395)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x2b0")
int BPF_KPROBE(do_mov_3396)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x2d6")
int BPF_KPROBE(do_mov_3397)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x2de")
int BPF_KPROBE(do_mov_3398)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x309")
int BPF_KPROBE(do_mov_3399)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x320")
int BPF_KPROBE(do_mov_3400)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x327")
int BPF_KPROBE(do_mov_3401)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x347")
int BPF_KPROBE(do_mov_3402)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x34e")
int BPF_KPROBE(do_mov_3403)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x355")
int BPF_KPROBE(do_mov_3404)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x35c")
int BPF_KPROBE(do_mov_3405)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_do_redirect + 0x4c5")
int BPF_KPROBE(do_mov_3406)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x32")
int BPF_KPROBE(do_mov_3407)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x3e")
int BPF_KPROBE(do_mov_3408)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x42")
int BPF_KPROBE(do_mov_3409)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x4d")
int BPF_KPROBE(do_mov_3410)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x52")
int BPF_KPROBE(do_mov_3411)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x5f")
int BPF_KPROBE(do_mov_3412)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x64")
int BPF_KPROBE(do_mov_3413)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x71")
int BPF_KPROBE(do_mov_3414)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x79")
int BPF_KPROBE(do_mov_3415)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect + 0x8d")
int BPF_KPROBE(do_mov_3416)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x2e")
int BPF_KPROBE(do_mov_3417)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x15a")
int BPF_KPROBE(do_mov_3418)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x188")
int BPF_KPROBE(do_mov_3419)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x1a6")
int BPF_KPROBE(do_mov_3420)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x1aa")
int BPF_KPROBE(do_mov_3421)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x1f1")
int BPF_KPROBE(do_mov_3422)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x1fd")
int BPF_KPROBE(do_mov_3423)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x205")
int BPF_KPROBE(do_mov_3424)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x20d")
int BPF_KPROBE(do_mov_3425)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x224")
int BPF_KPROBE(do_mov_3426)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x2cf")
int BPF_KPROBE(do_mov_3427)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x2e5")
int BPF_KPROBE(do_mov_3428)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x2f9")
int BPF_KPROBE(do_mov_3429)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x30e")
int BPF_KPROBE(do_mov_3430)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x319")
int BPF_KPROBE(do_mov_3431)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x37a")
int BPF_KPROBE(do_mov_3432)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x392")
int BPF_KPROBE(do_mov_3433)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x42f")
int BPF_KPROBE(do_mov_3434)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x432")
int BPF_KPROBE(do_mov_3435)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x47a")
int BPF_KPROBE(do_mov_3436)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x53b")
int BPF_KPROBE(do_mov_3437)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x555")
int BPF_KPROBE(do_mov_3438)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x57e")
int BPF_KPROBE(do_mov_3439)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x595")
int BPF_KPROBE(do_mov_3440)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x5ae")
int BPF_KPROBE(do_mov_3441)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x5b1")
int BPF_KPROBE(do_mov_3442)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x5ef")
int BPF_KPROBE(do_mov_3443)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x620")
int BPF_KPROBE(do_mov_3444)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x623")
int BPF_KPROBE(do_mov_3445)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_del + 0x646")
int BPF_KPROBE(do_mov_3446)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_del + 0x2d")
int BPF_KPROBE(do_mov_3447)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_del + 0x92")
int BPF_KPROBE(do_mov_3448)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_del + 0x9d")
int BPF_KPROBE(do_mov_3449)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_del + 0xf2")
int BPF_KPROBE(do_mov_3450)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_del + 0xf7")
int BPF_KPROBE(do_mov_3451)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_del + 0x149")
int BPF_KPROBE(do_mov_3452)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_delroute + 0x2c")
int BPF_KPROBE(do_mov_3453)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_delroute + 0x99")
int BPF_KPROBE(do_mov_3454)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_add + 0x1e")
int BPF_KPROBE(do_mov_3455)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_add + 0x41")
int BPF_KPROBE(do_mov_3456)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_add + 0x46")
int BPF_KPROBE(do_mov_3457)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_add + 0x4d")
int BPF_KPROBE(do_mov_3458)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_add + 0x54")
int BPF_KPROBE(do_mov_3459)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_del + 0x44")
int BPF_KPROBE(do_mov_3460)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_del + 0x48")
int BPF_KPROBE(do_mov_3461)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_del + 0x4b")
int BPF_KPROBE(do_mov_3462)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_uncached_list_del + 0x52")
int BPF_KPROBE(do_mov_3463)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ins_rt + 0x21")
int BPF_KPROBE(do_mov_3464)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ins_rt + 0x27")
int BPF_KPROBE(do_mov_3465)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ins_rt + 0x2f")
int BPF_KPROBE(do_mov_3466)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ins_rt + 0x3a")
int BPF_KPROBE(do_mov_3467)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_age_exceptions + 0x1d")
int BPF_KPROBE(do_mov_3468)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_age_exceptions + 0x28")
int BPF_KPROBE(do_mov_3469)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_age_exceptions + 0x36")
int BPF_KPROBE(do_mov_3470)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x2a")
int BPF_KPROBE(do_mov_3471)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x32")
int BPF_KPROBE(do_mov_3472)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x38")
int BPF_KPROBE(do_mov_3473)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x45")
int BPF_KPROBE(do_mov_3474)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x50")
int BPF_KPROBE(do_mov_3475)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x65")
int BPF_KPROBE(do_mov_3476)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x69")
int BPF_KPROBE(do_mov_3477)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0xa8")
int BPF_KPROBE(do_mov_3478)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0xac")
int BPF_KPROBE(do_mov_3479)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0xb3")
int BPF_KPROBE(do_mov_3480)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0xbe")
int BPF_KPROBE(do_mov_3481)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x107")
int BPF_KPROBE(do_mov_3482)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x10d")
int BPF_KPROBE(do_mov_3483)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x11c")
int BPF_KPROBE(do_mov_3484)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x132")
int BPF_KPROBE(do_mov_3485)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x135")
int BPF_KPROBE(do_mov_3486)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x163")
int BPF_KPROBE(do_mov_3487)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x16a")
int BPF_KPROBE(do_mov_3488)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x16e")
int BPF_KPROBE(do_mov_3489)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x1af")
int BPF_KPROBE(do_mov_3490)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x1b8")
int BPF_KPROBE(do_mov_3491)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_table_lookup + 0x1d4")
int BPF_KPROBE(do_mov_3492)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x28")
int BPF_KPROBE(do_mov_3493)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x121")
int BPF_KPROBE(do_mov_3494)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x162")
int BPF_KPROBE(do_mov_3495)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x18b")
int BPF_KPROBE(do_mov_3496)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1a3")
int BPF_KPROBE(do_mov_3497)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1ae")
int BPF_KPROBE(do_mov_3498)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1b9")
int BPF_KPROBE(do_mov_3499)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1c0")
int BPF_KPROBE(do_mov_3500)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1c7")
int BPF_KPROBE(do_mov_3501)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1d1")
int BPF_KPROBE(do_mov_3502)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1e4")
int BPF_KPROBE(do_mov_3503)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1ef")
int BPF_KPROBE(do_mov_3504)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x1fa")
int BPF_KPROBE(do_mov_3505)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x204")
int BPF_KPROBE(do_mov_3506)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x210")
int BPF_KPROBE(do_mov_3507)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x21a")
int BPF_KPROBE(do_mov_3508)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x244")
int BPF_KPROBE(do_mov_3509)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x256")
int BPF_KPROBE(do_mov_3510)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x25a")
int BPF_KPROBE(do_mov_3511)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x26c")
int BPF_KPROBE(do_mov_3512)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x270")
int BPF_KPROBE(do_mov_3513)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x27e")
int BPF_KPROBE(do_mov_3514)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x28f")
int BPF_KPROBE(do_mov_3515)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x29c")
int BPF_KPROBE(do_mov_3516)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x2aa")
int BPF_KPROBE(do_mov_3517)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x2eb")
int BPF_KPROBE(do_mov_3518)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x2f3")
int BPF_KPROBE(do_mov_3519)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x2fe")
int BPF_KPROBE(do_mov_3520)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x309")
int BPF_KPROBE(do_mov_3521)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x310")
int BPF_KPROBE(do_mov_3522)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x317")
int BPF_KPROBE(do_mov_3523)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x321")
int BPF_KPROBE(do_mov_3524)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x374")
int BPF_KPROBE(do_mov_3525)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x390")
int BPF_KPROBE(do_mov_3526)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x394")
int BPF_KPROBE(do_mov_3527)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x3ac")
int BPF_KPROBE(do_mov_3528)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x3b0")
int BPF_KPROBE(do_mov_3529)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x3c1")
int BPF_KPROBE(do_mov_3530)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x3d0")
int BPF_KPROBE(do_mov_3531)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x3e0")
int BPF_KPROBE(do_mov_3532)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x3f1")
int BPF_KPROBE(do_mov_3533)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x4aa")
int BPF_KPROBE(do_mov_3534)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x4bd")
int BPF_KPROBE(do_mov_3535)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x4d1")
int BPF_KPROBE(do_mov_3536)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x51e")
int BPF_KPROBE(do_mov_3537)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x529")
int BPF_KPROBE(do_mov_3538)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x531")
int BPF_KPROBE(do_mov_3539)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x53c")
int BPF_KPROBE(do_mov_3540)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x543")
int BPF_KPROBE(do_mov_3541)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x54e")
int BPF_KPROBE(do_mov_3542)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x559")
int BPF_KPROBE(do_mov_3543)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x564")
int BPF_KPROBE(do_mov_3544)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x58b")
int BPF_KPROBE(do_mov_3545)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x593")
int BPF_KPROBE(do_mov_3546)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x620")
int BPF_KPROBE(do_mov_3547)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x630")
int BPF_KPROBE(do_mov_3548)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x643")
int BPF_KPROBE(do_mov_3549)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x650")
int BPF_KPROBE(do_mov_3550)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x668")
int BPF_KPROBE(do_mov_3551)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x66c")
int BPF_KPROBE(do_mov_3552)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x684")
int BPF_KPROBE(do_mov_3553)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x688")
int BPF_KPROBE(do_mov_3554)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_multipath_hash + 0x69f")
int BPF_KPROBE(do_mov_3555)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_select_path + 0x60")
int BPF_KPROBE(do_mov_3556)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_select_path + 0x10e")
int BPF_KPROBE(do_mov_3557)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_select_path + 0x114")
int BPF_KPROBE(do_mov_3558)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_select_path + 0x149")
int BPF_KPROBE(do_mov_3559)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_select_path + 0x177")
int BPF_KPROBE(do_mov_3560)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_select_path + 0x1ad")
int BPF_KPROBE(do_mov_3561)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x2a")
int BPF_KPROBE(do_mov_3562)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x31")
int BPF_KPROBE(do_mov_3563)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x38")
int BPF_KPROBE(do_mov_3564)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x3f")
int BPF_KPROBE(do_mov_3565)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x4c")
int BPF_KPROBE(do_mov_3566)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x52")
int BPF_KPROBE(do_mov_3567)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x5a")
int BPF_KPROBE(do_mov_3568)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x62")
int BPF_KPROBE(do_mov_3569)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x6a")
int BPF_KPROBE(do_mov_3570)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x85")
int BPF_KPROBE(do_mov_3571)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x91")
int BPF_KPROBE(do_mov_3572)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x9c")
int BPF_KPROBE(do_mov_3573)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0xee")
int BPF_KPROBE(do_mov_3574)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0xf5")
int BPF_KPROBE(do_mov_3575)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x152")
int BPF_KPROBE(do_mov_3576)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x16f")
int BPF_KPROBE(do_mov_3577)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x173")
int BPF_KPROBE(do_mov_3578)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x179")
int BPF_KPROBE(do_mov_3579)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x1a4")
int BPF_KPROBE(do_mov_3580)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x1f0")
int BPF_KPROBE(do_mov_3581)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x1f8")
int BPF_KPROBE(do_mov_3582)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x1fc")
int BPF_KPROBE(do_mov_3583)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x200")
int BPF_KPROBE(do_mov_3584)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x204")
int BPF_KPROBE(do_mov_3585)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x2c1")
int BPF_KPROBE(do_mov_3586)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x2cd")
int BPF_KPROBE(do_mov_3587)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x2d7")
int BPF_KPROBE(do_mov_3588)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x2eb")
int BPF_KPROBE(do_mov_3589)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x30d")
int BPF_KPROBE(do_mov_3590)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x353")
int BPF_KPROBE(do_mov_3591)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x38a")
int BPF_KPROBE(do_mov_3592)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x3f2")
int BPF_KPROBE(do_mov_3593)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x473")
int BPF_KPROBE(do_mov_3594)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route_lookup + 0x477")
int BPF_KPROBE(do_mov_3595)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x28")
int BPF_KPROBE(do_mov_3596)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x3c")
int BPF_KPROBE(do_mov_3597)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x45")
int BPF_KPROBE(do_mov_3598)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x52")
int BPF_KPROBE(do_mov_3599)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x5a")
int BPF_KPROBE(do_mov_3600)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x62")
int BPF_KPROBE(do_mov_3601)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x6a")
int BPF_KPROBE(do_mov_3602)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x74")
int BPF_KPROBE(do_mov_3603)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0xe0")
int BPF_KPROBE(do_mov_3604)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x129")
int BPF_KPROBE(do_mov_3605)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x140")
int BPF_KPROBE(do_mov_3606)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x189")
int BPF_KPROBE(do_mov_3607)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x1f4")
int BPF_KPROBE(do_mov_3608)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x219")
int BPF_KPROBE(do_mov_3609)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x247")
int BPF_KPROBE(do_mov_3610)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x333")
int BPF_KPROBE(do_mov_3611)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x347")
int BPF_KPROBE(do_mov_3612)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x353")
int BPF_KPROBE(do_mov_3613)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x37a")
int BPF_KPROBE(do_mov_3614)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x37f")
int BPF_KPROBE(do_mov_3615)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x386")
int BPF_KPROBE(do_mov_3616)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_pol_route + 0x38d")
int BPF_KPROBE(do_mov_3617)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x3a")
int BPF_KPROBE(do_mov_3618)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x4a")
int BPF_KPROBE(do_mov_3619)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x58")
int BPF_KPROBE(do_mov_3620)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x64")
int BPF_KPROBE(do_mov_3621)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x68")
int BPF_KPROBE(do_mov_3622)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x73")
int BPF_KPROBE(do_mov_3623)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0x77")
int BPF_KPROBE(do_mov_3624)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_nh_lookup_table.isra.0 + 0xec")
int BPF_KPROBE(do_mov_3625)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x31")
int BPF_KPROBE(do_mov_3626)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x41")
int BPF_KPROBE(do_mov_3627)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x47")
int BPF_KPROBE(do_mov_3628)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x52")
int BPF_KPROBE(do_mov_3629)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x5d")
int BPF_KPROBE(do_mov_3630)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x68")
int BPF_KPROBE(do_mov_3631)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0xc7")
int BPF_KPROBE(do_mov_3632)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0xd8")
int BPF_KPROBE(do_mov_3633)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0xde")
int BPF_KPROBE(do_mov_3634)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x18e")
int BPF_KPROBE(do_mov_3635)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_check_nh + 0x1dd")
int BPF_KPROBE(do_mov_3636)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x3c")
int BPF_KPROBE(do_mov_3637)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x64")
int BPF_KPROBE(do_mov_3638)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x70")
int BPF_KPROBE(do_mov_3639)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x7a")
int BPF_KPROBE(do_mov_3640)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x7e")
int BPF_KPROBE(do_mov_3641)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x81")
int BPF_KPROBE(do_mov_3642)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x8d")
int BPF_KPROBE(do_mov_3643)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x91")
int BPF_KPROBE(do_mov_3644)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x99")
int BPF_KPROBE(do_mov_3645)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0xdf")
int BPF_KPROBE(do_mov_3646)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x134")
int BPF_KPROBE(do_mov_3647)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x13f")
int BPF_KPROBE(do_mov_3648)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x142")
int BPF_KPROBE(do_mov_3649)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x1be")
int BPF_KPROBE(do_mov_3650)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x1c7")
int BPF_KPROBE(do_mov_3651)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x1f1")
int BPF_KPROBE(do_mov_3652)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_input + 0x223")
int BPF_KPROBE(do_mov_3653)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x5c")
int BPF_KPROBE(do_mov_3654)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x66")
int BPF_KPROBE(do_mov_3655)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x6e")
int BPF_KPROBE(do_mov_3656)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xa1")
int BPF_KPROBE(do_mov_3657)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xa8")
int BPF_KPROBE(do_mov_3658)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xb0")
int BPF_KPROBE(do_mov_3659)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xb8")
int BPF_KPROBE(do_mov_3660)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xc0")
int BPF_KPROBE(do_mov_3661)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xc8")
int BPF_KPROBE(do_mov_3662)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xd0")
int BPF_KPROBE(do_mov_3663)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xd8")
int BPF_KPROBE(do_mov_3664)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0xdf")
int BPF_KPROBE(do_mov_3665)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x120")
int BPF_KPROBE(do_mov_3666)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x13a")
int BPF_KPROBE(do_mov_3667)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x141")
int BPF_KPROBE(do_mov_3668)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x155")
int BPF_KPROBE(do_mov_3669)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x160")
int BPF_KPROBE(do_mov_3670)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x16c")
int BPF_KPROBE(do_mov_3671)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x17b")
int BPF_KPROBE(do_mov_3672)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x189")
int BPF_KPROBE(do_mov_3673)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x198")
int BPF_KPROBE(do_mov_3674)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x1a7")
int BPF_KPROBE(do_mov_3675)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_blackhole_route + 0x1e5")
int BPF_KPROBE(do_mov_3676)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow + 0x7a")
int BPF_KPROBE(do_mov_3677)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow + 0xa0")
int BPF_KPROBE(do_mov_3678)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow + 0xb3")
int BPF_KPROBE(do_mov_3679)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_sk_dst_store_flow + 0xb7")
int BPF_KPROBE(do_mov_3680)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x36")
int BPF_KPROBE(do_mov_3681)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x44")
int BPF_KPROBE(do_mov_3682)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x53")
int BPF_KPROBE(do_mov_3683)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x75")
int BPF_KPROBE(do_mov_3684)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x80")
int BPF_KPROBE(do_mov_3685)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x85")
int BPF_KPROBE(do_mov_3686)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x92")
int BPF_KPROBE(do_mov_3687)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_redirect_no_header + 0x9a")
int BPF_KPROBE(do_mov_3688)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xa1")
int BPF_KPROBE(do_mov_3689)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xaf")
int BPF_KPROBE(do_mov_3690)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xc0")
int BPF_KPROBE(do_mov_3691)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xc8")
int BPF_KPROBE(do_mov_3692)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xd8")
int BPF_KPROBE(do_mov_3693)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xe0")
int BPF_KPROBE(do_mov_3694)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xe5")
int BPF_KPROBE(do_mov_3695)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0xed")
int BPF_KPROBE(do_mov_3696)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x11f")
int BPF_KPROBE(do_mov_3697)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x135")
int BPF_KPROBE(do_mov_3698)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x158")
int BPF_KPROBE(do_mov_3699)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x15c")
int BPF_KPROBE(do_mov_3700)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x164")
int BPF_KPROBE(do_mov_3701)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x16c")
int BPF_KPROBE(do_mov_3702)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_dst_alloc + 0x1fa")
int BPF_KPROBE(do_mov_3703)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x2b")
int BPF_KPROBE(do_mov_3704)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x38")
int BPF_KPROBE(do_mov_3705)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x3e")
int BPF_KPROBE(do_mov_3706)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x42")
int BPF_KPROBE(do_mov_3707)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x51")
int BPF_KPROBE(do_mov_3708)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x59")
int BPF_KPROBE(do_mov_3709)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x85")
int BPF_KPROBE(do_mov_3710)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0xb3")
int BPF_KPROBE(do_mov_3711)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0xe3")
int BPF_KPROBE(do_mov_3712)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x11a")
int BPF_KPROBE(do_mov_3713)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x123")
int BPF_KPROBE(do_mov_3714)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x134")
int BPF_KPROBE(do_mov_3715)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x13d")
int BPF_KPROBE(do_mov_3716)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x175")
int BPF_KPROBE(do_mov_3717)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x1a1")
int BPF_KPROBE(do_mov_3718)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x1cb")
int BPF_KPROBE(do_mov_3719)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x1ff")
int BPF_KPROBE(do_mov_3720)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x206")
int BPF_KPROBE(do_mov_3721)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x2c7")
int BPF_KPROBE(do_mov_3722)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x2d8")
int BPF_KPROBE(do_mov_3723)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x2e1")
int BPF_KPROBE(do_mov_3724)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x2f4")
int BPF_KPROBE(do_mov_3725)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x305")
int BPF_KPROBE(do_mov_3726)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x309")
int BPF_KPROBE(do_mov_3727)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x30d")
int BPF_KPROBE(do_mov_3728)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x33b")
int BPF_KPROBE(do_mov_3729)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x347")
int BPF_KPROBE(do_mov_3730)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x384")
int BPF_KPROBE(do_mov_3731)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x398")
int BPF_KPROBE(do_mov_3732)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x3bc")
int BPF_KPROBE(do_mov_3733)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x3dc")
int BPF_KPROBE(do_mov_3734)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x436")
int BPF_KPROBE(do_mov_3735)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x45d")
int BPF_KPROBE(do_mov_3736)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x46e")
int BPF_KPROBE(do_mov_3737)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x487")
int BPF_KPROBE(do_mov_3738)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x4a5")
int BPF_KPROBE(do_mov_3739)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x4af")
int BPF_KPROBE(do_mov_3740)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x4d3")
int BPF_KPROBE(do_mov_3741)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x4eb")
int BPF_KPROBE(do_mov_3742)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x531")
int BPF_KPROBE(do_mov_3743)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x535")
int BPF_KPROBE(do_mov_3744)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x539")
int BPF_KPROBE(do_mov_3745)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x54a")
int BPF_KPROBE(do_mov_3746)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x563")
int BPF_KPROBE(do_mov_3747)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x580")
int BPF_KPROBE(do_mov_3748)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5a2")
int BPF_KPROBE(do_mov_3749)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5b4")
int BPF_KPROBE(do_mov_3750)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5c6")
int BPF_KPROBE(do_mov_3751)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5d9")
int BPF_KPROBE(do_mov_3752)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5e1")
int BPF_KPROBE(do_mov_3753)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5f0")
int BPF_KPROBE(do_mov_3754)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x5fc")
int BPF_KPROBE(do_mov_3755)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x66e")
int BPF_KPROBE(do_mov_3756)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x6a1")
int BPF_KPROBE(do_mov_3757)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x6d4")
int BPF_KPROBE(do_mov_3758)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x71e")
int BPF_KPROBE(do_mov_3759)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x72a")
int BPF_KPROBE(do_mov_3760)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x7f5")
int BPF_KPROBE(do_mov_3761)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x801")
int BPF_KPROBE(do_mov_3762)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x828")
int BPF_KPROBE(do_mov_3763)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x87f")
int BPF_KPROBE(do_mov_3764)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x8b4")
int BPF_KPROBE(do_mov_3765)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x8de")
int BPF_KPROBE(do_mov_3766)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x90d")
int BPF_KPROBE(do_mov_3767)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_init + 0x945")
int BPF_KPROBE(do_mov_3768)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x23")
int BPF_KPROBE(do_mov_3769)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x96")
int BPF_KPROBE(do_mov_3770)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x2e5")
int BPF_KPROBE(do_mov_3771)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x313")
int BPF_KPROBE(do_mov_3772)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x328")
int BPF_KPROBE(do_mov_3773)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x34c")
int BPF_KPROBE(do_mov_3774)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x37e")
int BPF_KPROBE(do_mov_3775)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x3d7")
int BPF_KPROBE(do_mov_3776)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_info_create + 0x576")
int BPF_KPROBE(do_mov_3777)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_nh_release + 0x2d")
int BPF_KPROBE(do_mov_3778)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x38")
int BPF_KPROBE(do_mov_3779)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x4d")
int BPF_KPROBE(do_mov_3780)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x61")
int BPF_KPROBE(do_mov_3781)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x65")
int BPF_KPROBE(do_mov_3782)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x6a")
int BPF_KPROBE(do_mov_3783)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x73")
int BPF_KPROBE(do_mov_3784)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x78")
int BPF_KPROBE(do_mov_3785)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x80")
int BPF_KPROBE(do_mov_3786)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0x88")
int BPF_KPROBE(do_mov_3787)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0xbd")
int BPF_KPROBE(do_mov_3788)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0xc6")
int BPF_KPROBE(do_mov_3789)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0xce")
int BPF_KPROBE(do_mov_3790)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0xd2")
int BPF_KPROBE(do_mov_3791)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_route_info + 0xd7")
int BPF_KPROBE(do_mov_3792)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_del_rt + 0x21")
int BPF_KPROBE(do_mov_3793)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_del_rt + 0x27")
int BPF_KPROBE(do_mov_3794)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_del_rt + 0x2f")
int BPF_KPROBE(do_mov_3795)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_del_rt + 0x37")
int BPF_KPROBE(do_mov_3796)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_del_rt + 0x3b")
int BPF_KPROBE(do_mov_3797)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x2a")
int BPF_KPROBE(do_mov_3798)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0xbb")
int BPF_KPROBE(do_mov_3799)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0xca")
int BPF_KPROBE(do_mov_3800)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x11f")
int BPF_KPROBE(do_mov_3801)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x124")
int BPF_KPROBE(do_mov_3802)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x1a1")
int BPF_KPROBE(do_mov_3803)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x1b4")
int BPF_KPROBE(do_mov_3804)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x1b9")
int BPF_KPROBE(do_mov_3805)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x1f9")
int BPF_KPROBE(do_mov_3806)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x218")
int BPF_KPROBE(do_mov_3807)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x21f")
int BPF_KPROBE(do_mov_3808)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x280")
int BPF_KPROBE(do_mov_3809)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x288")
int BPF_KPROBE(do_mov_3810)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x2b6")
int BPF_KPROBE(do_mov_3811)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x2cc")
int BPF_KPROBE(do_mov_3812)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x2e4")
int BPF_KPROBE(do_mov_3813)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x30a")
int BPF_KPROBE(do_mov_3814)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x31f")
int BPF_KPROBE(do_mov_3815)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_route_rcv + 0x33d")
int BPF_KPROBE(do_mov_3816)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0x29")
int BPF_KPROBE(do_mov_3817)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0x3f")
int BPF_KPROBE(do_mov_3818)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0x8b")
int BPF_KPROBE(do_mov_3819)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0x92")
int BPF_KPROBE(do_mov_3820)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xa3")
int BPF_KPROBE(do_mov_3821)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xab")
int BPF_KPROBE(do_mov_3822)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xb0")
int BPF_KPROBE(do_mov_3823)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xb5")
int BPF_KPROBE(do_mov_3824)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xb9")
int BPF_KPROBE(do_mov_3825)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xc1")
int BPF_KPROBE(do_mov_3826)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_add_dflt_router + 0xc9")
int BPF_KPROBE(do_mov_3827)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_purge_dflt_routers + 0x25")
int BPF_KPROBE(do_mov_3828)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_purge_dflt_routers + 0x111")
int BPF_KPROBE(do_mov_3829)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_purge_dflt_routers + 0x119")
int BPF_KPROBE(do_mov_3830)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_purge_dflt_routers + 0x121")
int BPF_KPROBE(do_mov_3831)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_purge_dflt_routers + 0x138")
int BPF_KPROBE(do_mov_3832)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x26")
int BPF_KPROBE(do_mov_3833)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x8d")
int BPF_KPROBE(do_mov_3834)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xac")
int BPF_KPROBE(do_mov_3835)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xb9")
int BPF_KPROBE(do_mov_3836)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xca")
int BPF_KPROBE(do_mov_3837)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xce")
int BPF_KPROBE(do_mov_3838)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xdc")
int BPF_KPROBE(do_mov_3839)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xe1")
int BPF_KPROBE(do_mov_3840)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xee")
int BPF_KPROBE(do_mov_3841)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xf2")
int BPF_KPROBE(do_mov_3842)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0xfb")
int BPF_KPROBE(do_mov_3843)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x100")
int BPF_KPROBE(do_mov_3844)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x104")
int BPF_KPROBE(do_mov_3845)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x109")
int BPF_KPROBE(do_mov_3846)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x10e")
int BPF_KPROBE(do_mov_3847)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x113")
int BPF_KPROBE(do_mov_3848)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x119")
int BPF_KPROBE(do_mov_3849)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x128")
int BPF_KPROBE(do_mov_3850)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x130")
int BPF_KPROBE(do_mov_3851)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x139")
int BPF_KPROBE(do_mov_3852)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x143")
int BPF_KPROBE(do_mov_3853)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x14b")
int BPF_KPROBE(do_mov_3854)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_ioctl + 0x153")
int BPF_KPROBE(do_mov_3855)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x25")
int BPF_KPROBE(do_mov_3856)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x2e")
int BPF_KPROBE(do_mov_3857)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x43")
int BPF_KPROBE(do_mov_3858)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x7a")
int BPF_KPROBE(do_mov_3859)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x8d")
int BPF_KPROBE(do_mov_3860)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x91")
int BPF_KPROBE(do_mov_3861)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x99")
int BPF_KPROBE(do_mov_3862)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0xa7")
int BPF_KPROBE(do_mov_3863)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0xb3")
int BPF_KPROBE(do_mov_3864)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0xb8")
int BPF_KPROBE(do_mov_3865)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0xcc")
int BPF_KPROBE(do_mov_3866)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0xd4")
int BPF_KPROBE(do_mov_3867)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x11f")
int BPF_KPROBE(do_mov_3868)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/addrconf_f6i_alloc + 0x127")
int BPF_KPROBE(do_mov_3869)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_prefsrc + 0x1d")
int BPF_KPROBE(do_mov_3870)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_prefsrc + 0x2f")
int BPF_KPROBE(do_mov_3871)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_prefsrc + 0x3a")
int BPF_KPROBE(do_mov_3872)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_remove_prefsrc + 0x41")
int BPF_KPROBE(do_mov_3873)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x16")
int BPF_KPROBE(do_mov_3874)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x1e")
int BPF_KPROBE(do_mov_3875)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x25")
int BPF_KPROBE(do_mov_3876)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x29")
int BPF_KPROBE(do_mov_3877)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x2d")
int BPF_KPROBE(do_mov_3878)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x31")
int BPF_KPROBE(do_mov_3879)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_up + 0x6e")
int BPF_KPROBE(do_mov_3880)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_down_dev + 0x16")
int BPF_KPROBE(do_mov_3881)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_down_dev + 0x1c")
int BPF_KPROBE(do_mov_3882)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_sync_down_dev + 0x2b")
int BPF_KPROBE(do_mov_3883)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x26")
int BPF_KPROBE(do_mov_3884)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2c")
int BPF_KPROBE(do_mov_3885)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x37")
int BPF_KPROBE(do_mov_3886)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x5e")
int BPF_KPROBE(do_mov_3887)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x6c")
int BPF_KPROBE(do_mov_3888)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x87")
int BPF_KPROBE(do_mov_3889)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0xd8")
int BPF_KPROBE(do_mov_3890)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0xe2")
int BPF_KPROBE(do_mov_3891)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x12d")
int BPF_KPROBE(do_mov_3892)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x15c")
int BPF_KPROBE(do_mov_3893)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x160")
int BPF_KPROBE(do_mov_3894)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x167")
int BPF_KPROBE(do_mov_3895)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x16b")
int BPF_KPROBE(do_mov_3896)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x176")
int BPF_KPROBE(do_mov_3897)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x17d")
int BPF_KPROBE(do_mov_3898)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x18d")
int BPF_KPROBE(do_mov_3899)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x191")
int BPF_KPROBE(do_mov_3900)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x195")
int BPF_KPROBE(do_mov_3901)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x1dd")
int BPF_KPROBE(do_mov_3902)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x1e1")
int BPF_KPROBE(do_mov_3903)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x1e5")
int BPF_KPROBE(do_mov_3904)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x1f9")
int BPF_KPROBE(do_mov_3905)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x240")
int BPF_KPROBE(do_mov_3906)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x28c")
int BPF_KPROBE(do_mov_3907)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x290")
int BPF_KPROBE(do_mov_3908)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2b8")
int BPF_KPROBE(do_mov_3909)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2bc")
int BPF_KPROBE(do_mov_3910)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2c0")
int BPF_KPROBE(do_mov_3911)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2e2")
int BPF_KPROBE(do_mov_3912)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2e6")
int BPF_KPROBE(do_mov_3913)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_disable_ip + 0x2ea")
int BPF_KPROBE(do_mov_3914)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_mtu_change + 0x16")
int BPF_KPROBE(do_mov_3915)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_mtu_change + 0x1c")
int BPF_KPROBE(do_mov_3916)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_mtu_change + 0x2b")
int BPF_KPROBE(do_mov_3917)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_mtu_change + 0x33")
int BPF_KPROBE(do_mov_3918)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_mtu_change + 0x3d")
int BPF_KPROBE(do_mov_3919)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_dump_route + 0x23")
int BPF_KPROBE(do_mov_3920)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_dump_route + 0x76")
int BPF_KPROBE(do_mov_3921)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_dump_route + 0x7a")
int BPF_KPROBE(do_mov_3922)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_dump_route + 0x7e")
int BPF_KPROBE(do_mov_3923)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_dump_route + 0x82")
int BPF_KPROBE(do_mov_3924)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rt6_dump_route + 0x86")
int BPF_KPROBE(do_mov_3925)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rt_notify + 0x29")
int BPF_KPROBE(do_mov_3926)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rt_notify + 0x55")
int BPF_KPROBE(do_mov_3927)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rt_notify + 0x96")
int BPF_KPROBE(do_mov_3928)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x37")
int BPF_KPROBE(do_mov_3929)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x4f")
int BPF_KPROBE(do_mov_3930)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x66")
int BPF_KPROBE(do_mov_3931)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x6f")
int BPF_KPROBE(do_mov_3932)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8d")
int BPF_KPROBE(do_mov_3933)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x9d")
int BPF_KPROBE(do_mov_3934)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0xc4")
int BPF_KPROBE(do_mov_3935)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0xf9")
int BPF_KPROBE(do_mov_3936)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0xfe")
int BPF_KPROBE(do_mov_3937)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x10e")
int BPF_KPROBE(do_mov_3938)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x116")
int BPF_KPROBE(do_mov_3939)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x157")
int BPF_KPROBE(do_mov_3940)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x164")
int BPF_KPROBE(do_mov_3941)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x16c")
int BPF_KPROBE(do_mov_3942)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x17c")
int BPF_KPROBE(do_mov_3943)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x18e")
int BPF_KPROBE(do_mov_3944)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x193")
int BPF_KPROBE(do_mov_3945)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x203")
int BPF_KPROBE(do_mov_3946)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x258")
int BPF_KPROBE(do_mov_3947)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x29f")
int BPF_KPROBE(do_mov_3948)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x2e2")
int BPF_KPROBE(do_mov_3949)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x2e6")
int BPF_KPROBE(do_mov_3950)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x2f3")
int BPF_KPROBE(do_mov_3951)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x2fa")
int BPF_KPROBE(do_mov_3952)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x329")
int BPF_KPROBE(do_mov_3953)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x371")
int BPF_KPROBE(do_mov_3954)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x37c")
int BPF_KPROBE(do_mov_3955)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x39d")
int BPF_KPROBE(do_mov_3956)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x3a5")
int BPF_KPROBE(do_mov_3957)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x3da")
int BPF_KPROBE(do_mov_3958)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x3df")
int BPF_KPROBE(do_mov_3959)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x3fd")
int BPF_KPROBE(do_mov_3960)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x40a")
int BPF_KPROBE(do_mov_3961)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x41d")
int BPF_KPROBE(do_mov_3962)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x422")
int BPF_KPROBE(do_mov_3963)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x439")
int BPF_KPROBE(do_mov_3964)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x459")
int BPF_KPROBE(do_mov_3965)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x471")
int BPF_KPROBE(do_mov_3966)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x4c3")
int BPF_KPROBE(do_mov_3967)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x50f")
int BPF_KPROBE(do_mov_3968)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x51a")
int BPF_KPROBE(do_mov_3969)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x523")
int BPF_KPROBE(do_mov_3970)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x5ea")
int BPF_KPROBE(do_mov_3971)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x676")
int BPF_KPROBE(do_mov_3972)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x775")
int BPF_KPROBE(do_mov_3973)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x80d")
int BPF_KPROBE(do_mov_3974)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x812")
int BPF_KPROBE(do_mov_3975)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x885")
int BPF_KPROBE(do_mov_3976)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x891")
int BPF_KPROBE(do_mov_3977)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8ae")
int BPF_KPROBE(do_mov_3978)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8ca")
int BPF_KPROBE(do_mov_3979)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8d4")
int BPF_KPROBE(do_mov_3980)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8db")
int BPF_KPROBE(do_mov_3981)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8e0")
int BPF_KPROBE(do_mov_3982)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x8e7")
int BPF_KPROBE(do_mov_3983)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_route_multipath_add + 0x93c")
int BPF_KPROBE(do_mov_3984)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newroute + 0x28")
int BPF_KPROBE(do_mov_3985)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_rtm_newroute + 0x6c")
int BPF_KPROBE(do_mov_3986)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x3a")
int BPF_KPROBE(do_mov_3987)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x41")
int BPF_KPROBE(do_mov_3988)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x4c")
int BPF_KPROBE(do_mov_3989)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x5a")
int BPF_KPROBE(do_mov_3990)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x65")
int BPF_KPROBE(do_mov_3991)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x73")
int BPF_KPROBE(do_mov_3992)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x81")
int BPF_KPROBE(do_mov_3993)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x8f")
int BPF_KPROBE(do_mov_3994)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0x96")
int BPF_KPROBE(do_mov_3995)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0xa4")
int BPF_KPROBE(do_mov_3996)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0xb2")
int BPF_KPROBE(do_mov_3997)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0xb9")
int BPF_KPROBE(do_mov_3998)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_sysctl_init + 0xca")
int BPF_KPROBE(do_mov_3999)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_yield + 0x27")
int BPF_KPROBE(do_mov_4000)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_yield + 0x2b")
int BPF_KPROBE(do_mov_4001)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x3b")
int BPF_KPROBE(do_mov_4002)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x3e")
int BPF_KPROBE(do_mov_4003)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x5a")
int BPF_KPROBE(do_mov_4004)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x7e")
int BPF_KPROBE(do_mov_4005)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x8e")
int BPF_KPROBE(do_mov_4006)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x9e")
int BPF_KPROBE(do_mov_4007)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0xa2")
int BPF_KPROBE(do_mov_4008)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0xb7")
int BPF_KPROBE(do_mov_4009)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0xf2")
int BPF_KPROBE(do_mov_4010)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0xfd")
int BPF_KPROBE(do_mov_4011)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x109")
int BPF_KPROBE(do_mov_4012)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x115")
int BPF_KPROBE(do_mov_4013)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x121")
int BPF_KPROBE(do_mov_4014)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_walk_continue + 0x12c")
int BPF_KPROBE(do_mov_4015)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_node + 0x1d")
int BPF_KPROBE(do_mov_4016)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_node + 0x5b")
int BPF_KPROBE(do_mov_4017)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_node + 0x65")
int BPF_KPROBE(do_mov_4018)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x26")
int BPF_KPROBE(do_mov_4019)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x52")
int BPF_KPROBE(do_mov_4020)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x56")
int BPF_KPROBE(do_mov_4021)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x5a")
int BPF_KPROBE(do_mov_4022)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x7d")
int BPF_KPROBE(do_mov_4023)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x85")
int BPF_KPROBE(do_mov_4024)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_exit + 0x89")
int BPF_KPROBE(do_mov_4025)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_show + 0x2b")
int BPF_KPROBE(do_mov_4026)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_show + 0x31")
int BPF_KPROBE(do_mov_4027)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_show + 0x51")
int BPF_KPROBE(do_mov_4028)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_show + 0x55")
int BPF_KPROBE(do_mov_4029)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_show + 0x5e")
int BPF_KPROBE(do_mov_4030)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_show + 0x14e")
int BPF_KPROBE(do_mov_4031)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x2a")
int BPF_KPROBE(do_mov_4032)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x32")
int BPF_KPROBE(do_mov_4033)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x4a")
int BPF_KPROBE(do_mov_4034)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x55")
int BPF_KPROBE(do_mov_4035)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x61")
int BPF_KPROBE(do_mov_4036)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x65")
int BPF_KPROBE(do_mov_4037)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x6c")
int BPF_KPROBE(do_mov_4038)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x70")
int BPF_KPROBE(do_mov_4039)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x73")
int BPF_KPROBE(do_mov_4040)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x87")
int BPF_KPROBE(do_mov_4041)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x8b")
int BPF_KPROBE(do_mov_4042)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x97")
int BPF_KPROBE(do_mov_4043)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_setup_walk + 0x9b")
int BPF_KPROBE(do_mov_4044)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x1e")
int BPF_KPROBE(do_mov_4045)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x47")
int BPF_KPROBE(do_mov_4046)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x4f")
int BPF_KPROBE(do_mov_4047)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x58")
int BPF_KPROBE(do_mov_4048)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x5d")
int BPF_KPROBE(do_mov_4049)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x70")
int BPF_KPROBE(do_mov_4050)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_dump + 0x93")
int BPF_KPROBE(do_mov_4051)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x4f")
int BPF_KPROBE(do_mov_4052)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x5a")
int BPF_KPROBE(do_mov_4053)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x67")
int BPF_KPROBE(do_mov_4054)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x6b")
int BPF_KPROBE(do_mov_4055)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x84")
int BPF_KPROBE(do_mov_4056)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x92")
int BPF_KPROBE(do_mov_4057)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x96")
int BPF_KPROBE(do_mov_4058)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0x99")
int BPF_KPROBE(do_mov_4059)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_new_table + 0xa1")
int BPF_KPROBE(do_mov_4060)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0x1c")
int BPF_KPROBE(do_mov_4061)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0x5b")
int BPF_KPROBE(do_mov_4062)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0x5f")
int BPF_KPROBE(do_mov_4063)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0x6c")
int BPF_KPROBE(do_mov_4064)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0x74")
int BPF_KPROBE(do_mov_4065)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0xae")
int BPF_KPROBE(do_mov_4066)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0xd4")
int BPF_KPROBE(do_mov_4067)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_stop + 0xdc")
int BPF_KPROBE(do_mov_4068)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x2c")
int BPF_KPROBE(do_mov_4069)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x32")
int BPF_KPROBE(do_mov_4070)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x39")
int BPF_KPROBE(do_mov_4071)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x3d")
int BPF_KPROBE(do_mov_4072)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x41")
int BPF_KPROBE(do_mov_4073)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x44")
int BPF_KPROBE(do_mov_4074)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x48")
int BPF_KPROBE(do_mov_4075)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x4c")
int BPF_KPROBE(do_mov_4076)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x50")
int BPF_KPROBE(do_mov_4077)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x58")
int BPF_KPROBE(do_mov_4078)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x60")
int BPF_KPROBE(do_mov_4079)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x77")
int BPF_KPROBE(do_mov_4080)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x7b")
int BPF_KPROBE(do_mov_4081)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x82")
int BPF_KPROBE(do_mov_4082)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0x90")
int BPF_KPROBE(do_mov_4083)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0xdb")
int BPF_KPROBE(do_mov_4084)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0xdf")
int BPF_KPROBE(do_mov_4085)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0xec")
int BPF_KPROBE(do_mov_4086)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_tree + 0xf7")
int BPF_KPROBE(do_mov_4087)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__fib6_clean_all + 0x20")
int BPF_KPROBE(do_mov_4088)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__fib6_clean_all + 0x23")
int BPF_KPROBE(do_mov_4089)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__fib6_clean_all + 0x2c")
int BPF_KPROBE(do_mov_4090)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x34")
int BPF_KPROBE(do_mov_4091)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x4b")
int BPF_KPROBE(do_mov_4092)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x53")
int BPF_KPROBE(do_mov_4093)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x5f")
int BPF_KPROBE(do_mov_4094)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x6b")
int BPF_KPROBE(do_mov_4095)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x92")
int BPF_KPROBE(do_mov_4096)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0xb9")
int BPF_KPROBE(do_mov_4097)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0xe0")
int BPF_KPROBE(do_mov_4098)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0xf1")
int BPF_KPROBE(do_mov_4099)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x10d")
int BPF_KPROBE(do_mov_4100)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x119")
int BPF_KPROBE(do_mov_4101)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x144")
int BPF_KPROBE(do_mov_4102)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x155")
int BPF_KPROBE(do_mov_4103)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x16c")
int BPF_KPROBE(do_mov_4104)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x17d")
int BPF_KPROBE(do_mov_4105)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x19a")
int BPF_KPROBE(do_mov_4106)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1b4")
int BPF_KPROBE(do_mov_4107)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1b8")
int BPF_KPROBE(do_mov_4108)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1bb")
int BPF_KPROBE(do_mov_4109)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1c3")
int BPF_KPROBE(do_mov_4110)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1cf")
int BPF_KPROBE(do_mov_4111)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1e9")
int BPF_KPROBE(do_mov_4112)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1ed")
int BPF_KPROBE(do_mov_4113)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1f0")
int BPF_KPROBE(do_mov_4114)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_net_init + 0x1fc")
int BPF_KPROBE(do_mov_4115)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x22")
int BPF_KPROBE(do_mov_4116)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x33")
int BPF_KPROBE(do_mov_4117)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x43")
int BPF_KPROBE(do_mov_4118)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x65")
int BPF_KPROBE(do_mov_4119)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x87")
int BPF_KPROBE(do_mov_4120)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x8b")
int BPF_KPROBE(do_mov_4121)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0x98")
int BPF_KPROBE(do_mov_4122)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_done + 0xa0")
int BPF_KPROBE(do_mov_4123)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x51")
int BPF_KPROBE(do_mov_4124)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x59")
int BPF_KPROBE(do_mov_4125)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x5d")
int BPF_KPROBE(do_mov_4126)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x71")
int BPF_KPROBE(do_mov_4127)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0xbc")
int BPF_KPROBE(do_mov_4128)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0xc0")
int BPF_KPROBE(do_mov_4129)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0xcd")
int BPF_KPROBE(do_mov_4130)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0xd5")
int BPF_KPROBE(do_mov_4131)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x125")
int BPF_KPROBE(do_mov_4132)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x13d")
int BPF_KPROBE(do_mov_4133)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x17c")
int BPF_KPROBE(do_mov_4134)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x180")
int BPF_KPROBE(do_mov_4135)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x18d")
int BPF_KPROBE(do_mov_4136)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_next + 0x195")
int BPF_KPROBE(do_mov_4137)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_start + 0x1f")
int BPF_KPROBE(do_mov_4138)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_start + 0x58")
int BPF_KPROBE(do_mov_4139)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_start + 0x63")
int BPF_KPROBE(do_mov_4140)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_start + 0x69")
int BPF_KPROBE(do_mov_4141)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_start + 0x73")
int BPF_KPROBE(do_mov_4142)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_route_seq_start + 0x7b")
int BPF_KPROBE(do_mov_4143)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x29")
int BPF_KPROBE(do_mov_4144)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x3e")
int BPF_KPROBE(do_mov_4145)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x46")
int BPF_KPROBE(do_mov_4146)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x4d")
int BPF_KPROBE(do_mov_4147)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x54")
int BPF_KPROBE(do_mov_4148)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x5b")
int BPF_KPROBE(do_mov_4149)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x94")
int BPF_KPROBE(do_mov_4150)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x9d")
int BPF_KPROBE(do_mov_4151)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xa7")
int BPF_KPROBE(do_mov_4152)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xb8")
int BPF_KPROBE(do_mov_4153)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xc9")
int BPF_KPROBE(do_mov_4154)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xcd")
int BPF_KPROBE(do_mov_4155)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xe1")
int BPF_KPROBE(do_mov_4156)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xe5")
int BPF_KPROBE(do_mov_4157)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xef")
int BPF_KPROBE(do_mov_4158)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0xf3")
int BPF_KPROBE(do_mov_4159)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x11a")
int BPF_KPROBE(do_mov_4160)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x12b")
int BPF_KPROBE(do_mov_4161)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x14e")
int BPF_KPROBE(do_mov_4162)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x152")
int BPF_KPROBE(do_mov_4163)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x15f")
int BPF_KPROBE(do_mov_4164)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x166")
int BPF_KPROBE(do_mov_4165)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x16f")
int BPF_KPROBE(do_mov_4166)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x190")
int BPF_KPROBE(do_mov_4167)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x194")
int BPF_KPROBE(do_mov_4168)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x1a1")
int BPF_KPROBE(do_mov_4169)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_dump_table.isra.0 + 0x1a8")
int BPF_KPROBE(do_mov_4170)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x35")
int BPF_KPROBE(do_mov_4171)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x47")
int BPF_KPROBE(do_mov_4172)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x52")
int BPF_KPROBE(do_mov_4173)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x7e")
int BPF_KPROBE(do_mov_4174)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x82")
int BPF_KPROBE(do_mov_4175)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x86")
int BPF_KPROBE(do_mov_4176)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x8a")
int BPF_KPROBE(do_mov_4177)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x9e")
int BPF_KPROBE(do_mov_4178)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0xbf")
int BPF_KPROBE(do_mov_4179)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x176")
int BPF_KPROBE(do_mov_4180)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x194")
int BPF_KPROBE(do_mov_4181)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1a3")
int BPF_KPROBE(do_mov_4182)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1b5")
int BPF_KPROBE(do_mov_4183)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1bd")
int BPF_KPROBE(do_mov_4184)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1c8")
int BPF_KPROBE(do_mov_4185)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1d3")
int BPF_KPROBE(do_mov_4186)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1da")
int BPF_KPROBE(do_mov_4187)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x1fd")
int BPF_KPROBE(do_mov_4188)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x208")
int BPF_KPROBE(do_mov_4189)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x217")
int BPF_KPROBE(do_mov_4190)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x21f")
int BPF_KPROBE(do_mov_4191)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x274")
int BPF_KPROBE(do_mov_4192)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x29c")
int BPF_KPROBE(do_mov_4193)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x2ac")
int BPF_KPROBE(do_mov_4194)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x2b7")
int BPF_KPROBE(do_mov_4195)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x2e4")
int BPF_KPROBE(do_mov_4196)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x2e8")
int BPF_KPROBE(do_mov_4197)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x2eb")
int BPF_KPROBE(do_mov_4198)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x2f3")
int BPF_KPROBE(do_mov_4199)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x30e")
int BPF_KPROBE(do_mov_4200)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/inet6_dump_fib + 0x316")
int BPF_KPROBE(do_mov_4201)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x2b")
int BPF_KPROBE(do_mov_4202)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x5c")
int BPF_KPROBE(do_mov_4203)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x60")
int BPF_KPROBE(do_mov_4204)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x88")
int BPF_KPROBE(do_mov_4205)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x8c")
int BPF_KPROBE(do_mov_4206)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x8f")
int BPF_KPROBE(do_mov_4207)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x93")
int BPF_KPROBE(do_mov_4208)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_purge_rt + 0x122")
int BPF_KPROBE(do_mov_4209)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x33")
int BPF_KPROBE(do_mov_4210)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x113")
int BPF_KPROBE(do_mov_4211)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x157")
int BPF_KPROBE(do_mov_4212)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x162")
int BPF_KPROBE(do_mov_4213)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x1d7")
int BPF_KPROBE(do_mov_4214)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x20b")
int BPF_KPROBE(do_mov_4215)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x212")
int BPF_KPROBE(do_mov_4216)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x21f")
int BPF_KPROBE(do_mov_4217)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x223")
int BPF_KPROBE(do_mov_4218)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x22f")
int BPF_KPROBE(do_mov_4219)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x24f")
int BPF_KPROBE(do_mov_4220)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x287")
int BPF_KPROBE(do_mov_4221)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x2ca")
int BPF_KPROBE(do_mov_4222)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x2cf")
int BPF_KPROBE(do_mov_4223)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x2db")
int BPF_KPROBE(do_mov_4224)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x2e4")
int BPF_KPROBE(do_mov_4225)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x2e8")
int BPF_KPROBE(do_mov_4226)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x2f4")
int BPF_KPROBE(do_mov_4227)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x31d")
int BPF_KPROBE(do_mov_4228)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x322")
int BPF_KPROBE(do_mov_4229)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x329")
int BPF_KPROBE(do_mov_4230)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x34e")
int BPF_KPROBE(do_mov_4231)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x352")
int BPF_KPROBE(do_mov_4232)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x357")
int BPF_KPROBE(do_mov_4233)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x364")
int BPF_KPROBE(do_mov_4234)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x376")
int BPF_KPROBE(do_mov_4235)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x37a")
int BPF_KPROBE(do_mov_4236)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3a4")
int BPF_KPROBE(do_mov_4237)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3b1")
int BPF_KPROBE(do_mov_4238)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3ba")
int BPF_KPROBE(do_mov_4239)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3be")
int BPF_KPROBE(do_mov_4240)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3c7")
int BPF_KPROBE(do_mov_4241)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3f9")
int BPF_KPROBE(do_mov_4242)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x3fd")
int BPF_KPROBE(do_mov_4243)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x401")
int BPF_KPROBE(do_mov_4244)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x419")
int BPF_KPROBE(do_mov_4245)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x43e")
int BPF_KPROBE(do_mov_4246)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x442")
int BPF_KPROBE(do_mov_4247)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x446")
int BPF_KPROBE(do_mov_4248)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add_1.constprop.0 + 0x11c9c8")
int BPF_KPROBE(do_mov_4249)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_update_sernum + 0x3c")
int BPF_KPROBE(do_mov_4250)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_info_alloc + 0x35")
int BPF_KPROBE(do_mov_4251)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_info_alloc + 0x39")
int BPF_KPROBE(do_mov_4252)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_info_alloc + 0x3d")
int BPF_KPROBE(do_mov_4253)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers + 0x1a")
int BPF_KPROBE(do_mov_4254)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers + 0x24")
int BPF_KPROBE(do_mov_4255)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers + 0x2c")
int BPF_KPROBE(do_mov_4256)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers + 0x38")
int BPF_KPROBE(do_mov_4257)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers + 0x41")
int BPF_KPROBE(do_mov_4258)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers + 0x1a")
int BPF_KPROBE(do_mov_4259)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers + 0x24")
int BPF_KPROBE(do_mov_4260)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers + 0x2c")
int BPF_KPROBE(do_mov_4261)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers + 0x39")
int BPF_KPROBE(do_mov_4262)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers + 0x41")
int BPF_KPROBE(do_mov_4263)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_multipath_entry_notifiers + 0x46")
int BPF_KPROBE(do_mov_4264)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace + 0x1a")
int BPF_KPROBE(do_mov_4265)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace + 0x24")
int BPF_KPROBE(do_mov_4266)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace + 0x2c")
int BPF_KPROBE(do_mov_4267)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace + 0x35")
int BPF_KPROBE(do_mov_4268)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace + 0x3e")
int BPF_KPROBE(do_mov_4269)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/call_fib6_entry_notifiers_replace + 0x4a")
int BPF_KPROBE(do_mov_4270)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x29")
int BPF_KPROBE(do_mov_4271)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x3d")
int BPF_KPROBE(do_mov_4272)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x51")
int BPF_KPROBE(do_mov_4273)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x60")
int BPF_KPROBE(do_mov_4274)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x64")
int BPF_KPROBE(do_mov_4275)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x68")
int BPF_KPROBE(do_mov_4276)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x6c")
int BPF_KPROBE(do_mov_4277)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x74")
int BPF_KPROBE(do_mov_4278)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x98")
int BPF_KPROBE(do_mov_4279)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xaf")
int BPF_KPROBE(do_mov_4280)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xbf")
int BPF_KPROBE(do_mov_4281)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xca")
int BPF_KPROBE(do_mov_4282)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xe1")
int BPF_KPROBE(do_mov_4283)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xe5")
int BPF_KPROBE(do_mov_4284)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xec")
int BPF_KPROBE(do_mov_4285)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0xf3")
int BPF_KPROBE(do_mov_4286)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x162")
int BPF_KPROBE(do_mov_4287)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x166")
int BPF_KPROBE(do_mov_4288)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x169")
int BPF_KPROBE(do_mov_4289)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_tables_dump + 0x170")
int BPF_KPROBE(do_mov_4290)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_metric_set + 0x2d")
int BPF_KPROBE(do_mov_4291)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_metric_set + 0x54")
int BPF_KPROBE(do_mov_4292)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_metric_set + 0x5b")
int BPF_KPROBE(do_mov_4293)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_update_sernum_upto_root + 0x3d")
int BPF_KPROBE(do_mov_4294)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_update_sernum_stub + 0x52")
int BPF_KPROBE(do_mov_4295)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x2e")
int BPF_KPROBE(do_mov_4296)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x3b")
int BPF_KPROBE(do_mov_4297)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x97")
int BPF_KPROBE(do_mov_4298)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x144")
int BPF_KPROBE(do_mov_4299)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x17b")
int BPF_KPROBE(do_mov_4300)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x203")
int BPF_KPROBE(do_mov_4301)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x20f")
int BPF_KPROBE(do_mov_4302)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x276")
int BPF_KPROBE(do_mov_4303)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x27a")
int BPF_KPROBE(do_mov_4304)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x27f")
int BPF_KPROBE(do_mov_4305)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x284")
int BPF_KPROBE(do_mov_4306)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x2c6")
int BPF_KPROBE(do_mov_4307)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x35f")
int BPF_KPROBE(do_mov_4308)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x36c")
int BPF_KPROBE(do_mov_4309)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x4a8")
int BPF_KPROBE(do_mov_4310)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x631")
int BPF_KPROBE(do_mov_4311)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x63a")
int BPF_KPROBE(do_mov_4312)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x63f")
int BPF_KPROBE(do_mov_4313)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x66f")
int BPF_KPROBE(do_mov_4314)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x677")
int BPF_KPROBE(do_mov_4315)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x6d9")
int BPF_KPROBE(do_mov_4316)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x72f")
int BPF_KPROBE(do_mov_4317)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x732")
int BPF_KPROBE(do_mov_4318)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x833")
int BPF_KPROBE(do_mov_4319)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x896")
int BPF_KPROBE(do_mov_4320)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x89d")
int BPF_KPROBE(do_mov_4321)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x8d3")
int BPF_KPROBE(do_mov_4322)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x8d7")
int BPF_KPROBE(do_mov_4323)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x905")
int BPF_KPROBE(do_mov_4324)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x924")
int BPF_KPROBE(do_mov_4325)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x92b")
int BPF_KPROBE(do_mov_4326)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x932")
int BPF_KPROBE(do_mov_4327)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x938")
int BPF_KPROBE(do_mov_4328)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x9b8")
int BPF_KPROBE(do_mov_4329)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x9bc")
int BPF_KPROBE(do_mov_4330)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x9c3")
int BPF_KPROBE(do_mov_4331)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x9ca")
int BPF_KPROBE(do_mov_4332)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x9d1")
int BPF_KPROBE(do_mov_4333)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0x9d7")
int BPF_KPROBE(do_mov_4334)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xaf7")
int BPF_KPROBE(do_mov_4335)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xb2f")
int BPF_KPROBE(do_mov_4336)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xb4d")
int BPF_KPROBE(do_mov_4337)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xbf9")
int BPF_KPROBE(do_mov_4338)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xc81")
int BPF_KPROBE(do_mov_4339)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xc9a")
int BPF_KPROBE(do_mov_4340)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xcac")
int BPF_KPROBE(do_mov_4341)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xcce")
int BPF_KPROBE(do_mov_4342)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xcf6")
int BPF_KPROBE(do_mov_4343)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xcfe")
int BPF_KPROBE(do_mov_4344)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xd23")
int BPF_KPROBE(do_mov_4345)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xd41")
int BPF_KPROBE(do_mov_4346)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xd66")
int BPF_KPROBE(do_mov_4347)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xdb2")
int BPF_KPROBE(do_mov_4348)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xdbc")
int BPF_KPROBE(do_mov_4349)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xdc8")
int BPF_KPROBE(do_mov_4350)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xdd0")
int BPF_KPROBE(do_mov_4351)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xddc")
int BPF_KPROBE(do_mov_4352)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xdfe")
int BPF_KPROBE(do_mov_4353)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xe49")
int BPF_KPROBE(do_mov_4354)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xe7f")
int BPF_KPROBE(do_mov_4355)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xe82")
int BPF_KPROBE(do_mov_4356)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xe90")
int BPF_KPROBE(do_mov_4357)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xebe")
int BPF_KPROBE(do_mov_4358)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xef8")
int BPF_KPROBE(do_mov_4359)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xf0e")
int BPF_KPROBE(do_mov_4360)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_add + 0xf15")
int BPF_KPROBE(do_mov_4361)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_lookup + 0x27")
int BPF_KPROBE(do_mov_4362)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_lookup + 0x3f")
int BPF_KPROBE(do_mov_4363)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_lookup + 0x4b")
int BPF_KPROBE(do_mov_4364)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_lookup + 0x52")
int BPF_KPROBE(do_mov_4365)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_node_lookup + 0x5d")
int BPF_KPROBE(do_mov_4366)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x27")
int BPF_KPROBE(do_mov_4367)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0xbd")
int BPF_KPROBE(do_mov_4368)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0xd2")
int BPF_KPROBE(do_mov_4369)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0xd5")
int BPF_KPROBE(do_mov_4370)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x14d")
int BPF_KPROBE(do_mov_4371)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x154")
int BPF_KPROBE(do_mov_4372)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x158")
int BPF_KPROBE(do_mov_4373)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x15b")
int BPF_KPROBE(do_mov_4374)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x15f")
int BPF_KPROBE(do_mov_4375)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x16f")
int BPF_KPROBE(do_mov_4376)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x1ab")
int BPF_KPROBE(do_mov_4377)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x1b4")
int BPF_KPROBE(do_mov_4378)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x1fd")
int BPF_KPROBE(do_mov_4379)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x20c")
int BPF_KPROBE(do_mov_4380)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x215")
int BPF_KPROBE(do_mov_4381)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x21e")
int BPF_KPROBE(do_mov_4382)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x22b")
int BPF_KPROBE(do_mov_4383)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x2a1")
int BPF_KPROBE(do_mov_4384)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x2ab")
int BPF_KPROBE(do_mov_4385)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x2bd")
int BPF_KPROBE(do_mov_4386)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x2c6")
int BPF_KPROBE(do_mov_4387)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x2cf")
int BPF_KPROBE(do_mov_4388)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x316")
int BPF_KPROBE(do_mov_4389)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x31f")
int BPF_KPROBE(do_mov_4390)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x33b")
int BPF_KPROBE(do_mov_4391)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x349")
int BPF_KPROBE(do_mov_4392)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_del + 0x360")
int BPF_KPROBE(do_mov_4393)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x1c")
int BPF_KPROBE(do_mov_4394)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x26")
int BPF_KPROBE(do_mov_4395)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x2e")
int BPF_KPROBE(do_mov_4396)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x36")
int BPF_KPROBE(do_mov_4397)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x41")
int BPF_KPROBE(do_mov_4398)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x5e")
int BPF_KPROBE(do_mov_4399)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0xbc")
int BPF_KPROBE(do_mov_4400)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0xee")
int BPF_KPROBE(do_mov_4401)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_clean_node + 0x151")
int BPF_KPROBE(do_mov_4402)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_run_gc + 0x34")
int BPF_KPROBE(do_mov_4403)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_run_gc + 0x5f")
int BPF_KPROBE(do_mov_4404)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_run_gc + 0x63")
int BPF_KPROBE(do_mov_4405)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/fib6_run_gc + 0x79")
int BPF_KPROBE(do_mov_4406)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_mcast_join_leave + 0x1c")
int BPF_KPROBE(do_mov_4407)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_mcast_join_leave + 0x58")
int BPF_KPROBE(do_mov_4408)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_mcast_join_leave + 0x64")
int BPF_KPROBE(do_mov_4409)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_mcast_join_leave + 0x6c")
int BPF_KPROBE(do_mov_4410)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_mcast_join_leave + 0x1c")
int BPF_KPROBE(do_mov_4411)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_mcast_join_leave + 0x47")
int BPF_KPROBE(do_mov_4412)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x25")
int BPF_KPROBE(do_mov_4413)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0xf5")
int BPF_KPROBE(do_mov_4414)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x138")
int BPF_KPROBE(do_mov_4415)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x141")
int BPF_KPROBE(do_mov_4416)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x14b")
int BPF_KPROBE(do_mov_4417)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x155")
int BPF_KPROBE(do_mov_4418)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x15f")
int BPF_KPROBE(do_mov_4419)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x169")
int BPF_KPROBE(do_mov_4420)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x173")
int BPF_KPROBE(do_mov_4421)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x17d")
int BPF_KPROBE(do_mov_4422)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x187")
int BPF_KPROBE(do_mov_4423)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x191")
int BPF_KPROBE(do_mov_4424)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x19b")
int BPF_KPROBE(do_mov_4425)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1a5")
int BPF_KPROBE(do_mov_4426)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1af")
int BPF_KPROBE(do_mov_4427)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1b9")
int BPF_KPROBE(do_mov_4428)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1c3")
int BPF_KPROBE(do_mov_4429)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1cd")
int BPF_KPROBE(do_mov_4430)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1dd")
int BPF_KPROBE(do_mov_4431)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1ec")
int BPF_KPROBE(do_mov_4432)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_set_mcast_msfilter + 0x1fc")
int BPF_KPROBE(do_mov_4433)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1e")
int BPF_KPROBE(do_mov_4434)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x80")
int BPF_KPROBE(do_mov_4435)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x9d")
int BPF_KPROBE(do_mov_4436)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xb5")
int BPF_KPROBE(do_mov_4437)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xbd")
int BPF_KPROBE(do_mov_4438)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xc4")
int BPF_KPROBE(do_mov_4439)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xcd")
int BPF_KPROBE(do_mov_4440)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xd7")
int BPF_KPROBE(do_mov_4441)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xe1")
int BPF_KPROBE(do_mov_4442)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xeb")
int BPF_KPROBE(do_mov_4443)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xf5")
int BPF_KPROBE(do_mov_4444)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0xff")
int BPF_KPROBE(do_mov_4445)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x109")
int BPF_KPROBE(do_mov_4446)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x113")
int BPF_KPROBE(do_mov_4447)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x11d")
int BPF_KPROBE(do_mov_4448)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x127")
int BPF_KPROBE(do_mov_4449)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x131")
int BPF_KPROBE(do_mov_4450)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x13b")
int BPF_KPROBE(do_mov_4451)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x145")
int BPF_KPROBE(do_mov_4452)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x14f")
int BPF_KPROBE(do_mov_4453)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x159")
int BPF_KPROBE(do_mov_4454)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x166")
int BPF_KPROBE(do_mov_4455)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x176")
int BPF_KPROBE(do_mov_4456)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x186")
int BPF_KPROBE(do_mov_4457)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x196")
int BPF_KPROBE(do_mov_4458)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1a6")
int BPF_KPROBE(do_mov_4459)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1b6")
int BPF_KPROBE(do_mov_4460)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1c6")
int BPF_KPROBE(do_mov_4461)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1d6")
int BPF_KPROBE(do_mov_4462)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1e6")
int BPF_KPROBE(do_mov_4463)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x1f6")
int BPF_KPROBE(do_mov_4464)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x206")
int BPF_KPROBE(do_mov_4465)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x216")
int BPF_KPROBE(do_mov_4466)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x226")
int BPF_KPROBE(do_mov_4467)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x236")
int BPF_KPROBE(do_mov_4468)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x246")
int BPF_KPROBE(do_mov_4469)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x256")
int BPF_KPROBE(do_mov_4470)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/copy_group_source_from_sockptr + 0x266")
int BPF_KPROBE(do_mov_4471)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_mcast_group_source + 0x2d")
int BPF_KPROBE(do_mov_4472)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x19")
int BPF_KPROBE(do_mov_4473)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x1d")
int BPF_KPROBE(do_mov_4474)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x2b")
int BPF_KPROBE(do_mov_4475)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x53")
int BPF_KPROBE(do_mov_4476)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x6c")
int BPF_KPROBE(do_mov_4477)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x84")
int BPF_KPROBE(do_mov_4478)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x8c")
int BPF_KPROBE(do_mov_4479)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xa0")
int BPF_KPROBE(do_mov_4480)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xad")
int BPF_KPROBE(do_mov_4481)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xbc")
int BPF_KPROBE(do_mov_4482)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xc9")
int BPF_KPROBE(do_mov_4483)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xd6")
int BPF_KPROBE(do_mov_4484)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xe3")
int BPF_KPROBE(do_mov_4485)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xeb")
int BPF_KPROBE(do_mov_4486)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0xf8")
int BPF_KPROBE(do_mov_4487)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x105")
int BPF_KPROBE(do_mov_4488)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x112")
int BPF_KPROBE(do_mov_4489)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x11f")
int BPF_KPROBE(do_mov_4490)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x12c")
int BPF_KPROBE(do_mov_4491)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x139")
int BPF_KPROBE(do_mov_4492)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x146")
int BPF_KPROBE(do_mov_4493)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x153")
int BPF_KPROBE(do_mov_4494)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x163")
int BPF_KPROBE(do_mov_4495)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x173")
int BPF_KPROBE(do_mov_4496)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x183")
int BPF_KPROBE(do_mov_4497)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x20e")
int BPF_KPROBE(do_mov_4498)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x21e")
int BPF_KPROBE(do_mov_4499)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/compat_ipv6_get_msfilter + 0x22c")
int BPF_KPROBE(do_mov_4500)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x19")
int BPF_KPROBE(do_mov_4501)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x1d")
int BPF_KPROBE(do_mov_4502)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x22")
int BPF_KPROBE(do_mov_4503)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x30")
int BPF_KPROBE(do_mov_4504)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x5a")
int BPF_KPROBE(do_mov_4505)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x68")
int BPF_KPROBE(do_mov_4506)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x106")
int BPF_KPROBE(do_mov_4507)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x115")
int BPF_KPROBE(do_mov_4508)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x12f")
int BPF_KPROBE(do_mov_4509)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x13b")
int BPF_KPROBE(do_mov_4510)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_get_msfilter + 0x157")
int BPF_KPROBE(do_mov_4511)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ra_control + 0x85")
int BPF_KPROBE(do_mov_4512)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ra_control + 0xcf")
int BPF_KPROBE(do_mov_4513)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ra_control + 0xdf")
int BPF_KPROBE(do_mov_4514)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ra_control + 0xe3")
int BPF_KPROBE(do_mov_4515)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_ra_control + 0xea")
int BPF_KPROBE(do_mov_4516)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_update_options + 0x57")
int BPF_KPROBE(do_mov_4517)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_update_options + 0x61")
int BPF_KPROBE(do_mov_4518)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_update_options + 0x89")
int BPF_KPROBE(do_mov_4519)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x38")
int BPF_KPROBE(do_mov_4520)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x60")
int BPF_KPROBE(do_mov_4521)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x8b")
int BPF_KPROBE(do_mov_4522)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xa0")
int BPF_KPROBE(do_mov_4523)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xc5")
int BPF_KPROBE(do_mov_4524)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xca")
int BPF_KPROBE(do_mov_4525)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xcf")
int BPF_KPROBE(do_mov_4526)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x194")
int BPF_KPROBE(do_mov_4527)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1c1")
int BPF_KPROBE(do_mov_4528)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1c6")
int BPF_KPROBE(do_mov_4529)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1cb")
int BPF_KPROBE(do_mov_4530)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x268")
int BPF_KPROBE(do_mov_4531)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x26d")
int BPF_KPROBE(do_mov_4532)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x295")
int BPF_KPROBE(do_mov_4533)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x2da")
int BPF_KPROBE(do_mov_4534)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x2df")
int BPF_KPROBE(do_mov_4535)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x32c")
int BPF_KPROBE(do_mov_4536)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x368")
int BPF_KPROBE(do_mov_4537)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x375")
int BPF_KPROBE(do_mov_4538)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x3c6")
int BPF_KPROBE(do_mov_4539)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x466")
int BPF_KPROBE(do_mov_4540)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x472")
int BPF_KPROBE(do_mov_4541)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x47e")
int BPF_KPROBE(do_mov_4542)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x4b3")
int BPF_KPROBE(do_mov_4543)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x4b8")
int BPF_KPROBE(do_mov_4544)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x503")
int BPF_KPROBE(do_mov_4545)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x50f")
int BPF_KPROBE(do_mov_4546)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x51b")
int BPF_KPROBE(do_mov_4547)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x5ac")
int BPF_KPROBE(do_mov_4548)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x5fa")
int BPF_KPROBE(do_mov_4549)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x640")
int BPF_KPROBE(do_mov_4550)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x66b")
int BPF_KPROBE(do_mov_4551)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x6a1")
int BPF_KPROBE(do_mov_4552)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x6d7")
int BPF_KPROBE(do_mov_4553)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x6fd")
int BPF_KPROBE(do_mov_4554)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x72a")
int BPF_KPROBE(do_mov_4555)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x751")
int BPF_KPROBE(do_mov_4556)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x760")
int BPF_KPROBE(do_mov_4557)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x78f")
int BPF_KPROBE(do_mov_4558)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x794")
int BPF_KPROBE(do_mov_4559)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x79f")
int BPF_KPROBE(do_mov_4560)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x7bb")
int BPF_KPROBE(do_mov_4561)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x7d9")
int BPF_KPROBE(do_mov_4562)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x7f4")
int BPF_KPROBE(do_mov_4563)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x807")
int BPF_KPROBE(do_mov_4564)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x829")
int BPF_KPROBE(do_mov_4565)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x836")
int BPF_KPROBE(do_mov_4566)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x83e")
int BPF_KPROBE(do_mov_4567)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x8c3")
int BPF_KPROBE(do_mov_4568)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x8f1")
int BPF_KPROBE(do_mov_4569)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x929")
int BPF_KPROBE(do_mov_4570)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x959")
int BPF_KPROBE(do_mov_4571)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x9ad")
int BPF_KPROBE(do_mov_4572)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x9df")
int BPF_KPROBE(do_mov_4573)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xa5d")
int BPF_KPROBE(do_mov_4574)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xa85")
int BPF_KPROBE(do_mov_4575)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xab2")
int BPF_KPROBE(do_mov_4576)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xae1")
int BPF_KPROBE(do_mov_4577)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb06")
int BPF_KPROBE(do_mov_4578)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb31")
int BPF_KPROBE(do_mov_4579)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb5c")
int BPF_KPROBE(do_mov_4580)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb81")
int BPF_KPROBE(do_mov_4581)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb8e")
int BPF_KPROBE(do_mov_4582)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb94")
int BPF_KPROBE(do_mov_4583)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xb9a")
int BPF_KPROBE(do_mov_4584)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xbd6")
int BPF_KPROBE(do_mov_4585)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xc61")
int BPF_KPROBE(do_mov_4586)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xc88")
int BPF_KPROBE(do_mov_4587)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xcb2")
int BPF_KPROBE(do_mov_4588)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xd02")
int BPF_KPROBE(do_mov_4589)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xd29")
int BPF_KPROBE(do_mov_4590)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xd4a")
int BPF_KPROBE(do_mov_4591)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xd72")
int BPF_KPROBE(do_mov_4592)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xd99")
int BPF_KPROBE(do_mov_4593)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xdbb")
int BPF_KPROBE(do_mov_4594)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xde2")
int BPF_KPROBE(do_mov_4595)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xe2e")
int BPF_KPROBE(do_mov_4596)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xe67")
int BPF_KPROBE(do_mov_4597)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xea3")
int BPF_KPROBE(do_mov_4598)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0xf83")
int BPF_KPROBE(do_mov_4599)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1077")
int BPF_KPROBE(do_mov_4600)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1088")
int BPF_KPROBE(do_mov_4601)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x108d")
int BPF_KPROBE(do_mov_4602)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1092")
int BPF_KPROBE(do_mov_4603)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x10ce")
int BPF_KPROBE(do_mov_4604)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x10d9")
int BPF_KPROBE(do_mov_4605)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x10ee")
int BPF_KPROBE(do_mov_4606)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1104")
int BPF_KPROBE(do_mov_4607)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1110")
int BPF_KPROBE(do_mov_4608)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x111c")
int BPF_KPROBE(do_mov_4609)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x113a")
int BPF_KPROBE(do_mov_4610)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1195")
int BPF_KPROBE(do_mov_4611)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x11ac")
int BPF_KPROBE(do_mov_4612)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x11b0")
int BPF_KPROBE(do_mov_4613)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x11cc")
int BPF_KPROBE(do_mov_4614)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x11fb")
int BPF_KPROBE(do_mov_4615)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1247")
int BPF_KPROBE(do_mov_4616)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1287")
int BPF_KPROBE(do_mov_4617)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x129f")
int BPF_KPROBE(do_mov_4618)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x12c8")
int BPF_KPROBE(do_mov_4619)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x13c5")
int BPF_KPROBE(do_mov_4620)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1435")
int BPF_KPROBE(do_mov_4621)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x143a")
int BPF_KPROBE(do_mov_4622)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1445")
int BPF_KPROBE(do_mov_4623)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x14b9")
int BPF_KPROBE(do_mov_4624)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x14c4")
int BPF_KPROBE(do_mov_4625)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x14e1")
int BPF_KPROBE(do_mov_4626)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1504")
int BPF_KPROBE(do_mov_4627)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1572")
int BPF_KPROBE(do_mov_4628)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x157f")
int BPF_KPROBE(do_mov_4629)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1587")
int BPF_KPROBE(do_mov_4630)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x158f")
int BPF_KPROBE(do_mov_4631)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x15f1")
int BPF_KPROBE(do_mov_4632)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x15fa")
int BPF_KPROBE(do_mov_4633)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1606")
int BPF_KPROBE(do_mov_4634)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_setsockopt + 0x1616")
int BPF_KPROBE(do_mov_4635)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x3d")
int BPF_KPROBE(do_mov_4636)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x78")
int BPF_KPROBE(do_mov_4637)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x9d")
int BPF_KPROBE(do_mov_4638)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa2")
int BPF_KPROBE(do_mov_4639)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa7")
int BPF_KPROBE(do_mov_4640)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x113")
int BPF_KPROBE(do_mov_4641)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x118")
int BPF_KPROBE(do_mov_4642)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x1ac")
int BPF_KPROBE(do_mov_4643)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x1bc")
int BPF_KPROBE(do_mov_4644)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x1c1")
int BPF_KPROBE(do_mov_4645)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x1e6")
int BPF_KPROBE(do_mov_4646)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x203")
int BPF_KPROBE(do_mov_4647)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x21d")
int BPF_KPROBE(do_mov_4648)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x22e")
int BPF_KPROBE(do_mov_4649)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x258")
int BPF_KPROBE(do_mov_4650)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x269")
int BPF_KPROBE(do_mov_4651)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x2a5")
int BPF_KPROBE(do_mov_4652)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x2b9")
int BPF_KPROBE(do_mov_4653)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x2cc")
int BPF_KPROBE(do_mov_4654)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x2f8")
int BPF_KPROBE(do_mov_4655)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x305")
int BPF_KPROBE(do_mov_4656)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x30a")
int BPF_KPROBE(do_mov_4657)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x30f")
int BPF_KPROBE(do_mov_4658)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x314")
int BPF_KPROBE(do_mov_4659)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x344")
int BPF_KPROBE(do_mov_4660)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x364")
int BPF_KPROBE(do_mov_4661)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x393")
int BPF_KPROBE(do_mov_4662)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x3a7")
int BPF_KPROBE(do_mov_4663)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x3bb")
int BPF_KPROBE(do_mov_4664)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x3ce")
int BPF_KPROBE(do_mov_4665)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x3d7")
int BPF_KPROBE(do_mov_4666)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x3dc")
int BPF_KPROBE(do_mov_4667)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x408")
int BPF_KPROBE(do_mov_4668)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x40c")
int BPF_KPROBE(do_mov_4669)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x43a")
int BPF_KPROBE(do_mov_4670)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x44e")
int BPF_KPROBE(do_mov_4671)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x462")
int BPF_KPROBE(do_mov_4672)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x473")
int BPF_KPROBE(do_mov_4673)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x487")
int BPF_KPROBE(do_mov_4674)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x494")
int BPF_KPROBE(do_mov_4675)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x4a5")
int BPF_KPROBE(do_mov_4676)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x4b9")
int BPF_KPROBE(do_mov_4677)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x4cd")
int BPF_KPROBE(do_mov_4678)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x4ee")
int BPF_KPROBE(do_mov_4679)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x4fa")
int BPF_KPROBE(do_mov_4680)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x506")
int BPF_KPROBE(do_mov_4681)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x512")
int BPF_KPROBE(do_mov_4682)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x522")
int BPF_KPROBE(do_mov_4683)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x540")
int BPF_KPROBE(do_mov_4684)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x548")
int BPF_KPROBE(do_mov_4685)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x554")
int BPF_KPROBE(do_mov_4686)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x560")
int BPF_KPROBE(do_mov_4687)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x56c")
int BPF_KPROBE(do_mov_4688)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x57d")
int BPF_KPROBE(do_mov_4689)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x59c")
int BPF_KPROBE(do_mov_4690)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x5da")
int BPF_KPROBE(do_mov_4691)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x61f")
int BPF_KPROBE(do_mov_4692)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x633")
int BPF_KPROBE(do_mov_4693)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x647")
int BPF_KPROBE(do_mov_4694)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x657")
int BPF_KPROBE(do_mov_4695)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x66a")
int BPF_KPROBE(do_mov_4696)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x6a9")
int BPF_KPROBE(do_mov_4697)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x6b7")
int BPF_KPROBE(do_mov_4698)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x6cb")
int BPF_KPROBE(do_mov_4699)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x6e2")
int BPF_KPROBE(do_mov_4700)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x6f1")
int BPF_KPROBE(do_mov_4701)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x705")
int BPF_KPROBE(do_mov_4702)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x71c")
int BPF_KPROBE(do_mov_4703)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x72a")
int BPF_KPROBE(do_mov_4704)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x73a")
int BPF_KPROBE(do_mov_4705)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x742")
int BPF_KPROBE(do_mov_4706)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x74e")
int BPF_KPROBE(do_mov_4707)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x75a")
int BPF_KPROBE(do_mov_4708)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x766")
int BPF_KPROBE(do_mov_4709)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x796")
int BPF_KPROBE(do_mov_4710)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x79d")
int BPF_KPROBE(do_mov_4711)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x7ce")
int BPF_KPROBE(do_mov_4712)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x80e")
int BPF_KPROBE(do_mov_4713)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x822")
int BPF_KPROBE(do_mov_4714)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x830")
int BPF_KPROBE(do_mov_4715)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x904")
int BPF_KPROBE(do_mov_4716)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x92b")
int BPF_KPROBE(do_mov_4717)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x92f")
int BPF_KPROBE(do_mov_4718)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x959")
int BPF_KPROBE(do_mov_4719)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x967")
int BPF_KPROBE(do_mov_4720)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x993")
int BPF_KPROBE(do_mov_4721)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x9c3")
int BPF_KPROBE(do_mov_4722)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x9c8")
int BPF_KPROBE(do_mov_4723)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0x9cd")
int BPF_KPROBE(do_mov_4724)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa0d")
int BPF_KPROBE(do_mov_4725)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa15")
int BPF_KPROBE(do_mov_4726)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa27")
int BPF_KPROBE(do_mov_4727)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa32")
int BPF_KPROBE(do_mov_4728)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa37")
int BPF_KPROBE(do_mov_4729)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa65")
int BPF_KPROBE(do_mov_4730)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa74")
int BPF_KPROBE(do_mov_4731)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa7c")
int BPF_KPROBE(do_mov_4732)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xa93")
int BPF_KPROBE(do_mov_4733)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xaa5")
int BPF_KPROBE(do_mov_4734)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xaeb")
int BPF_KPROBE(do_mov_4735)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xafa")
int BPF_KPROBE(do_mov_4736)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xb02")
int BPF_KPROBE(do_mov_4737)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xb19")
int BPF_KPROBE(do_mov_4738)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xb2b")
int BPF_KPROBE(do_mov_4739)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xb75")
int BPF_KPROBE(do_mov_4740)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xb7a")
int BPF_KPROBE(do_mov_4741)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xbca")
int BPF_KPROBE(do_mov_4742)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xbd4")
int BPF_KPROBE(do_mov_4743)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xbde")
int BPF_KPROBE(do_mov_4744)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc15")
int BPF_KPROBE(do_mov_4745)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc1e")
int BPF_KPROBE(do_mov_4746)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc24")
int BPF_KPROBE(do_mov_4747)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc5b")
int BPF_KPROBE(do_mov_4748)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc64")
int BPF_KPROBE(do_mov_4749)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc6a")
int BPF_KPROBE(do_mov_4750)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc83")
int BPF_KPROBE(do_mov_4751)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc92")
int BPF_KPROBE(do_mov_4752)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xc9a")
int BPF_KPROBE(do_mov_4753)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xca7")
int BPF_KPROBE(do_mov_4754)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xcb6")
int BPF_KPROBE(do_mov_4755)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xcbe")
int BPF_KPROBE(do_mov_4756)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xcf2")
int BPF_KPROBE(do_mov_4757)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xcfa")
int BPF_KPROBE(do_mov_4758)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/do_ipv6_getsockopt + 0xd0a")
int BPF_KPROBE(do_mov_4759)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_getsockopt + 0x2d")
int BPF_KPROBE(do_mov_4760)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_getsockopt + 0x94")
int BPF_KPROBE(do_mov_4761)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x61")
int BPF_KPROBE(do_mov_4762)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x6d")
int BPF_KPROBE(do_mov_4763)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0xbb")
int BPF_KPROBE(do_mov_4764)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0xd6")
int BPF_KPROBE(do_mov_4765)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0xdd")
int BPF_KPROBE(do_mov_4766)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0xe5")
int BPF_KPROBE(do_mov_4767)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0xf3")
int BPF_KPROBE(do_mov_4768)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0xf9")
int BPF_KPROBE(do_mov_4769)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x103")
int BPF_KPROBE(do_mov_4770)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x10b")
int BPF_KPROBE(do_mov_4771)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x116")
int BPF_KPROBE(do_mov_4772)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x120")
int BPF_KPROBE(do_mov_4773)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x127")
int BPF_KPROBE(do_mov_4774)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x12f")
int BPF_KPROBE(do_mov_4775)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x13d")
int BPF_KPROBE(do_mov_4776)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x152")
int BPF_KPROBE(do_mov_4777)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x15a")
int BPF_KPROBE(do_mov_4778)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x172")
int BPF_KPROBE(do_mov_4779)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x187")
int BPF_KPROBE(do_mov_4780)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_mc_map + 0x18e")
int BPF_KPROBE(do_mov_4781)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_error_report + 0x2c")
int BPF_KPROBE(do_mov_4782)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_destructor + 0x1e")
int BPF_KPROBE(do_mov_4783)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_destructor + 0x3f")
int BPF_KPROBE(do_mov_4784)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_destructor + 0x47")
int BPF_KPROBE(do_mov_4785)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_destructor + 0x51")
int BPF_KPROBE(do_mov_4786)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_constructor + 0x1e")
int BPF_KPROBE(do_mov_4787)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_constructor + 0x3f")
int BPF_KPROBE(do_mov_4788)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_constructor + 0x47")
int BPF_KPROBE(do_mov_4789)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/pndisc_constructor + 0x51")
int BPF_KPROBE(do_mov_4790)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ndisc_fill_addr_option + 0x2d")
int BPF_KPROBE(do_mov_4791)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ndisc_fill_addr_option + 0x43")
int BPF_KPROBE(do_mov_4792)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ndisc_fill_addr_option + 0x47")
int BPF_KPROBE(do_mov_4793)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ndisc_fill_addr_option + 0x54")
int BPF_KPROBE(do_mov_4794)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_alloc_skb + 0x61")
int BPF_KPROBE(do_mov_4795)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_alloc_skb + 0x6c")
int BPF_KPROBE(do_mov_4796)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_alloc_skb + 0x8b")
int BPF_KPROBE(do_mov_4797)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_alloc_skb + 0x9b")
int BPF_KPROBE(do_mov_4798)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_net_init + 0x32")
int BPF_KPROBE(do_mov_4799)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_net_init + 0x4c")
int BPF_KPROBE(do_mov_4800)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_net_init + 0x77")
int BPF_KPROBE(do_mov_4801)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_allow_add + 0x46")
int BPF_KPROBE(do_mov_4802)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x34")
int BPF_KPROBE(do_mov_4803)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x52")
int BPF_KPROBE(do_mov_4804)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x5b")
int BPF_KPROBE(do_mov_4805)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x7f")
int BPF_KPROBE(do_mov_4806)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0xb4")
int BPF_KPROBE(do_mov_4807)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0xcd")
int BPF_KPROBE(do_mov_4808)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0xdd")
int BPF_KPROBE(do_mov_4809)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x108")
int BPF_KPROBE(do_mov_4810)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x115")
int BPF_KPROBE(do_mov_4811)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x135")
int BPF_KPROBE(do_mov_4812)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x165")
int BPF_KPROBE(do_mov_4813)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x192")
int BPF_KPROBE(do_mov_4814)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1a4")
int BPF_KPROBE(do_mov_4815)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1aa")
int BPF_KPROBE(do_mov_4816)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1b2")
int BPF_KPROBE(do_mov_4817)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1b5")
int BPF_KPROBE(do_mov_4818)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1c1")
int BPF_KPROBE(do_mov_4819)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1c5")
int BPF_KPROBE(do_mov_4820)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1d2")
int BPF_KPROBE(do_mov_4821)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_skb + 0x1d6")
int BPF_KPROBE(do_mov_4822)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0x22")
int BPF_KPROBE(do_mov_4823)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0x26")
int BPF_KPROBE(do_mov_4824)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0x8b")
int BPF_KPROBE(do_mov_4825)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0x92")
int BPF_KPROBE(do_mov_4826)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0x95")
int BPF_KPROBE(do_mov_4827)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0x99")
int BPF_KPROBE(do_mov_4828)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0xcb")
int BPF_KPROBE(do_mov_4829)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0xd2")
int BPF_KPROBE(do_mov_4830)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ns_create + 0xda")
int BPF_KPROBE(do_mov_4831)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x45")
int BPF_KPROBE(do_mov_4832)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0xb4")
int BPF_KPROBE(do_mov_4833)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0xc5")
int BPF_KPROBE(do_mov_4834)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0xec")
int BPF_KPROBE(do_mov_4835)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x12f")
int BPF_KPROBE(do_mov_4836)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x154")
int BPF_KPROBE(do_mov_4837)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x16a")
int BPF_KPROBE(do_mov_4838)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x17f")
int BPF_KPROBE(do_mov_4839)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x18d")
int BPF_KPROBE(do_mov_4840)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x198")
int BPF_KPROBE(do_mov_4841)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x1e2")
int BPF_KPROBE(do_mov_4842)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x22a")
int BPF_KPROBE(do_mov_4843)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x23c")
int BPF_KPROBE(do_mov_4844)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x26a")
int BPF_KPROBE(do_mov_4845)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x27e")
int BPF_KPROBE(do_mov_4846)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x2b2")
int BPF_KPROBE(do_mov_4847)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x2d8")
int BPF_KPROBE(do_mov_4848)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x2e4")
int BPF_KPROBE(do_mov_4849)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x2f7")
int BPF_KPROBE(do_mov_4850)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x377")
int BPF_KPROBE(do_mov_4851)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x383")
int BPF_KPROBE(do_mov_4852)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x396")
int BPF_KPROBE(do_mov_4853)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x3c1")
int BPF_KPROBE(do_mov_4854)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x3d4")
int BPF_KPROBE(do_mov_4855)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x400")
int BPF_KPROBE(do_mov_4856)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x412")
int BPF_KPROBE(do_mov_4857)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x42b")
int BPF_KPROBE(do_mov_4858)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x436")
int BPF_KPROBE(do_mov_4859)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x457")
int BPF_KPROBE(do_mov_4860)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x462")
int BPF_KPROBE(do_mov_4861)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_constructor + 0x472")
int BPF_KPROBE(do_mov_4862)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ifinfo_sysctl_change + 0x2a")
int BPF_KPROBE(do_mov_4863)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ifinfo_sysctl_change + 0x2e")
int BPF_KPROBE(do_mov_4864)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ifinfo_sysctl_change + 0x35")
int BPF_KPROBE(do_mov_4865)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ifinfo_sysctl_change + 0xc3")
int BPF_KPROBE(do_mov_4866)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_ifinfo_sysctl_change + 0xca")
int BPF_KPROBE(do_mov_4867)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x39")
int BPF_KPROBE(do_mov_4868)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x49")
int BPF_KPROBE(do_mov_4869)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x137")
int BPF_KPROBE(do_mov_4870)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x15a")
int BPF_KPROBE(do_mov_4871)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x167")
int BPF_KPROBE(do_mov_4872)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x170")
int BPF_KPROBE(do_mov_4873)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x183")
int BPF_KPROBE(do_mov_4874)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x1b5")
int BPF_KPROBE(do_mov_4875)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_parse_options + 0x1c2")
int BPF_KPROBE(do_mov_4876)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_redirect_rcv + 0x2e")
int BPF_KPROBE(do_mov_4877)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_redirect_rcv + 0xee")
int BPF_KPROBE(do_mov_4878)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x2d")
int BPF_KPROBE(do_mov_4879)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0xce")
int BPF_KPROBE(do_mov_4880)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x10e")
int BPF_KPROBE(do_mov_4881)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x12d")
int BPF_KPROBE(do_mov_4882)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x15b")
int BPF_KPROBE(do_mov_4883)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x2d5")
int BPF_KPROBE(do_mov_4884)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x2e3")
int BPF_KPROBE(do_mov_4885)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x2ea")
int BPF_KPROBE(do_mov_4886)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x33e")
int BPF_KPROBE(do_mov_4887)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x384")
int BPF_KPROBE(do_mov_4888)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_na + 0x3e8")
int BPF_KPROBE(do_mov_4889)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_rs + 0x33")
int BPF_KPROBE(do_mov_4890)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x33")
int BPF_KPROBE(do_mov_4891)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x6c")
int BPF_KPROBE(do_mov_4892)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x11b")
int BPF_KPROBE(do_mov_4893)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x14a")
int BPF_KPROBE(do_mov_4894)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x1cf")
int BPF_KPROBE(do_mov_4895)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x1ea")
int BPF_KPROBE(do_mov_4896)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x229")
int BPF_KPROBE(do_mov_4897)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x266")
int BPF_KPROBE(do_mov_4898)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x26d")
int BPF_KPROBE(do_mov_4899)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x2cf")
int BPF_KPROBE(do_mov_4900)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x30e")
int BPF_KPROBE(do_mov_4901)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x358")
int BPF_KPROBE(do_mov_4902)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x35c")
int BPF_KPROBE(do_mov_4903)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x3d5")
int BPF_KPROBE(do_mov_4904)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x3d8")
int BPF_KPROBE(do_mov_4905)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x3df")
int BPF_KPROBE(do_mov_4906)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x44b")
int BPF_KPROBE(do_mov_4907)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x461")
int BPF_KPROBE(do_mov_4908)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x471")
int BPF_KPROBE(do_mov_4909)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x478")
int BPF_KPROBE(do_mov_4910)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x482")
int BPF_KPROBE(do_mov_4911)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x606")
int BPF_KPROBE(do_mov_4912)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x628")
int BPF_KPROBE(do_mov_4913)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x692")
int BPF_KPROBE(do_mov_4914)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x6b1")
int BPF_KPROBE(do_mov_4915)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x6cd")
int BPF_KPROBE(do_mov_4916)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x6d6")
int BPF_KPROBE(do_mov_4917)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x6df")
int BPF_KPROBE(do_mov_4918)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x6ea")
int BPF_KPROBE(do_mov_4919)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x706")
int BPF_KPROBE(do_mov_4920)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x72a")
int BPF_KPROBE(do_mov_4921)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x731")
int BPF_KPROBE(do_mov_4922)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x777")
int BPF_KPROBE(do_mov_4923)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x834")
int BPF_KPROBE(do_mov_4924)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x868")
int BPF_KPROBE(do_mov_4925)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x8a4")
int BPF_KPROBE(do_mov_4926)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0x9fe")
int BPF_KPROBE(do_mov_4927)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xa09")
int BPF_KPROBE(do_mov_4928)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xa21")
int BPF_KPROBE(do_mov_4929)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xa62")
int BPF_KPROBE(do_mov_4930)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xa6d")
int BPF_KPROBE(do_mov_4931)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xa97")
int BPF_KPROBE(do_mov_4932)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xa9f")
int BPF_KPROBE(do_mov_4933)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xad2")
int BPF_KPROBE(do_mov_4934)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xb0f")
int BPF_KPROBE(do_mov_4935)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xb8b")
int BPF_KPROBE(do_mov_4936)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xbf2")
int BPF_KPROBE(do_mov_4937)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xbfd")
int BPF_KPROBE(do_mov_4938)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xc08")
int BPF_KPROBE(do_mov_4939)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xc0f")
int BPF_KPROBE(do_mov_4940)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xc44")
int BPF_KPROBE(do_mov_4941)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xc54")
int BPF_KPROBE(do_mov_4942)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xc5b")
int BPF_KPROBE(do_mov_4943)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xc93")
int BPF_KPROBE(do_mov_4944)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xd05")
int BPF_KPROBE(do_mov_4945)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_router_discovery + 0xd0c")
int BPF_KPROBE(do_mov_4946)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x31")
int BPF_KPROBE(do_mov_4947)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x39")
int BPF_KPROBE(do_mov_4948)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x42")
int BPF_KPROBE(do_mov_4949)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x4f")
int BPF_KPROBE(do_mov_4950)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0xff")
int BPF_KPROBE(do_mov_4951)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x109")
int BPF_KPROBE(do_mov_4952)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x10e")
int BPF_KPROBE(do_mov_4953)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x114")
int BPF_KPROBE(do_mov_4954)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x118")
int BPF_KPROBE(do_mov_4955)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x239")
int BPF_KPROBE(do_mov_4956)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x246")
int BPF_KPROBE(do_mov_4957)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x24b")
int BPF_KPROBE(do_mov_4958)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x256")
int BPF_KPROBE(do_mov_4959)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_na + 0x25d")
int BPF_KPROBE(do_mov_4960)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_unsol_na + 0x35")
int BPF_KPROBE(do_mov_4961)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x2e")
int BPF_KPROBE(do_mov_4962)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x3f")
int BPF_KPROBE(do_mov_4963)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x13f")
int BPF_KPROBE(do_mov_4964)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x145")
int BPF_KPROBE(do_mov_4965)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x15f")
int BPF_KPROBE(do_mov_4966)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x16b")
int BPF_KPROBE(do_mov_4967)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x1f2")
int BPF_KPROBE(do_mov_4968)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x206")
int BPF_KPROBE(do_mov_4969)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x20d")
int BPF_KPROBE(do_mov_4970)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x25e")
int BPF_KPROBE(do_mov_4971)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x265")
int BPF_KPROBE(do_mov_4972)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x289")
int BPF_KPROBE(do_mov_4973)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x2c4")
int BPF_KPROBE(do_mov_4974)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x2cb")
int BPF_KPROBE(do_mov_4975)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x2d2")
int BPF_KPROBE(do_mov_4976)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x357")
int BPF_KPROBE(do_mov_4977)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x3cf")
int BPF_KPROBE(do_mov_4978)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x3e3")
int BPF_KPROBE(do_mov_4979)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x41f")
int BPF_KPROBE(do_mov_4980)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x426")
int BPF_KPROBE(do_mov_4981)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x4d6")
int BPF_KPROBE(do_mov_4982)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x549")
int BPF_KPROBE(do_mov_4983)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x589")
int BPF_KPROBE(do_mov_4984)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x5e0")
int BPF_KPROBE(do_mov_4985)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x5e7")
int BPF_KPROBE(do_mov_4986)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x5ee")
int BPF_KPROBE(do_mov_4987)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x63b")
int BPF_KPROBE(do_mov_4988)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x642")
int BPF_KPROBE(do_mov_4989)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x64c")
int BPF_KPROBE(do_mov_4990)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x656")
int BPF_KPROBE(do_mov_4991)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x6f4")
int BPF_KPROBE(do_mov_4992)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x6fb")
int BPF_KPROBE(do_mov_4993)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x753")
int BPF_KPROBE(do_mov_4994)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x772")
int BPF_KPROBE(do_mov_4995)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x7d3")
int BPF_KPROBE(do_mov_4996)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x804")
int BPF_KPROBE(do_mov_4997)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x810")
int BPF_KPROBE(do_mov_4998)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x81a")
int BPF_KPROBE(do_mov_4999)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x840")
int BPF_KPROBE(do_mov_5000)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x84c")
int BPF_KPROBE(do_mov_5001)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_recv_ns + 0x85c")
int BPF_KPROBE(do_mov_5002)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_ns + 0x2e")
int BPF_KPROBE(do_mov_5003)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_ns + 0x83")
int BPF_KPROBE(do_mov_5004)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_solicit + 0x34")
int BPF_KPROBE(do_mov_5005)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_solicit + 0xb2")
int BPF_KPROBE(do_mov_5006)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_solicit + 0xbb")
int BPF_KPROBE(do_mov_5007)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_solicit + 0xc5")
int BPF_KPROBE(do_mov_5008)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_rs + 0x44")
int BPF_KPROBE(do_mov_5009)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_rs + 0xcc")
int BPF_KPROBE(do_mov_5010)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x30")
int BPF_KPROBE(do_mov_5011)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x3a")
int BPF_KPROBE(do_mov_5012)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x84")
int BPF_KPROBE(do_mov_5013)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x199")
int BPF_KPROBE(do_mov_5014)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x19e")
int BPF_KPROBE(do_mov_5015)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x1a8")
int BPF_KPROBE(do_mov_5016)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x1ca")
int BPF_KPROBE(do_mov_5017)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x221")
int BPF_KPROBE(do_mov_5018)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x274")
int BPF_KPROBE(do_mov_5019)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x2a8")
int BPF_KPROBE(do_mov_5020)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x2f0")
int BPF_KPROBE(do_mov_5021)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x316")
int BPF_KPROBE(do_mov_5022)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x332")
int BPF_KPROBE(do_mov_5023)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x39d")
int BPF_KPROBE(do_mov_5024)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x3a6")
int BPF_KPROBE(do_mov_5025)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x3ad")
int BPF_KPROBE(do_mov_5026)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x3b1")
int BPF_KPROBE(do_mov_5027)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x3b4")
int BPF_KPROBE(do_mov_5028)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x3b8")
int BPF_KPROBE(do_mov_5029)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x423")
int BPF_KPROBE(do_mov_5030)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x442")
int BPF_KPROBE(do_mov_5031)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x47e")
int BPF_KPROBE(do_mov_5032)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x488")
int BPF_KPROBE(do_mov_5033)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x48f")
int BPF_KPROBE(do_mov_5034)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x493")
int BPF_KPROBE(do_mov_5035)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x49a")
int BPF_KPROBE(do_mov_5036)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x4c8")
int BPF_KPROBE(do_mov_5037)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x4d8")
int BPF_KPROBE(do_mov_5038)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x4ed")
int BPF_KPROBE(do_mov_5039)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x4fb")
int BPF_KPROBE(do_mov_5040)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x517")
int BPF_KPROBE(do_mov_5041)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x522")
int BPF_KPROBE(do_mov_5042)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_send_redirect + 0x533")
int BPF_KPROBE(do_mov_5043)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_rcv + 0x67")
int BPF_KPROBE(do_mov_5044)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_rcv + 0xcb")
int BPF_KPROBE(do_mov_5045)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ndisc_rcv + 0xd7")
int BPF_KPROBE(do_mov_5046)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_init_sock + 0xd")
int BPF_KPROBE(do_mov_5047)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_init_sock + 0x14")
int BPF_KPROBE(do_mov_5048)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_init_sock + 0x22")
int BPF_KPROBE(do_mov_5049)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_init_sock + 0x30")
int BPF_KPROBE(do_mov_5050)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x4f")
int BPF_KPROBE(do_mov_5051)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x58")
int BPF_KPROBE(do_mov_5052)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x64")
int BPF_KPROBE(do_mov_5053)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x6b")
int BPF_KPROBE(do_mov_5054)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x10c")
int BPF_KPROBE(do_mov_5055)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x121")
int BPF_KPROBE(do_mov_5056)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x145")
int BPF_KPROBE(do_mov_5057)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x195")
int BPF_KPROBE(do_mov_5058)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x19b")
int BPF_KPROBE(do_mov_5059)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x19f")
int BPF_KPROBE(do_mov_5060)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x1c0")
int BPF_KPROBE(do_mov_5061)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x1f9")
int BPF_KPROBE(do_mov_5062)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x288")
int BPF_KPROBE(do_mov_5063)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x344")
int BPF_KPROBE(do_mov_5064)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x355")
int BPF_KPROBE(do_mov_5065)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x365")
int BPF_KPROBE(do_mov_5066)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x3eb")
int BPF_KPROBE(do_mov_5067)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_send_skb + 0x3f7")
int BPF_KPROBE(do_mov_5068)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_push_pending_frames + 0x70")
int BPF_KPROBE(do_mov_5069)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_push_pending_frames + 0x7e")
int BPF_KPROBE(do_mov_5070)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x1f")
int BPF_KPROBE(do_mov_5071)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x24")
int BPF_KPROBE(do_mov_5072)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x32")
int BPF_KPROBE(do_mov_5073)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x3e")
int BPF_KPROBE(do_mov_5074)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x5b")
int BPF_KPROBE(do_mov_5075)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x68")
int BPF_KPROBE(do_mov_5076)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x75")
int BPF_KPROBE(do_mov_5077)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x9e")
int BPF_KPROBE(do_mov_5078)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0xf1")
int BPF_KPROBE(do_mov_5079)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0xf6")
int BPF_KPROBE(do_mov_5080)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x10d")
int BPF_KPROBE(do_mov_5081)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x178")
int BPF_KPROBE(do_mov_5082)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x1d4")
int BPF_KPROBE(do_mov_5083)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x223")
int BPF_KPROBE(do_mov_5084)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x228")
int BPF_KPROBE(do_mov_5085)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x23e")
int BPF_KPROBE(do_mov_5086)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x275")
int BPF_KPROBE(do_mov_5087)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x27a")
int BPF_KPROBE(do_mov_5088)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x2a5")
int BPF_KPROBE(do_mov_5089)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x2bd")
int BPF_KPROBE(do_mov_5090)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x2c4")
int BPF_KPROBE(do_mov_5091)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x2eb")
int BPF_KPROBE(do_mov_5092)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x2ef")
int BPF_KPROBE(do_mov_5093)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x307")
int BPF_KPROBE(do_mov_5094)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x30f")
int BPF_KPROBE(do_mov_5095)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x314")
int BPF_KPROBE(do_mov_5096)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x339")
int BPF_KPROBE(do_mov_5097)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x33c")
int BPF_KPROBE(do_mov_5098)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x37b")
int BPF_KPROBE(do_mov_5099)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x3c0")
int BPF_KPROBE(do_mov_5100)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x3c8")
int BPF_KPROBE(do_mov_5101)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x422")
int BPF_KPROBE(do_mov_5102)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x427")
int BPF_KPROBE(do_mov_5103)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x42c")
int BPF_KPROBE(do_mov_5104)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x431")
int BPF_KPROBE(do_mov_5105)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x436")
int BPF_KPROBE(do_mov_5106)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x45e")
int BPF_KPROBE(do_mov_5107)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x472")
int BPF_KPROBE(do_mov_5108)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x542")
int BPF_KPROBE(do_mov_5109)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x5ca")
int BPF_KPROBE(do_mov_5110)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x5cf")
int BPF_KPROBE(do_mov_5111)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x5d4")
int BPF_KPROBE(do_mov_5112)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x60e")
int BPF_KPROBE(do_mov_5113)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x613")
int BPF_KPROBE(do_mov_5114)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x635")
int BPF_KPROBE(do_mov_5115)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x63a")
int BPF_KPROBE(do_mov_5116)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x66f")
int BPF_KPROBE(do_mov_5117)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x674")
int BPF_KPROBE(do_mov_5118)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x691")
int BPF_KPROBE(do_mov_5119)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x69b")
int BPF_KPROBE(do_mov_5120)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x6a2")
int BPF_KPROBE(do_mov_5121)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x6af")
int BPF_KPROBE(do_mov_5122)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x6eb")
int BPF_KPROBE(do_mov_5123)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x708")
int BPF_KPROBE(do_mov_5124)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_recvmsg + 0x72d")
int BPF_KPROBE(do_mov_5125)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_destroy_sock + 0x85")
int BPF_KPROBE(do_mov_5126)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_destroy_sock + 0x91")
int BPF_KPROBE(do_mov_5127)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_ehashfn + 0x2d")
int BPF_KPROBE(do_mov_5128)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x18")
int BPF_KPROBE(do_mov_5129)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x20")
int BPF_KPROBE(do_mov_5130)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x27")
int BPF_KPROBE(do_mov_5131)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x4d")
int BPF_KPROBE(do_mov_5132)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x15b")
int BPF_KPROBE(do_mov_5133)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x15f")
int BPF_KPROBE(do_mov_5134)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x18b")
int BPF_KPROBE(do_mov_5135)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_lib_lookup2 + 0x18f")
int BPF_KPROBE(do_mov_5136)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x312")
int BPF_KPROBE(do_mov_5137)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x337")
int BPF_KPROBE(do_mov_5138)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x34a")
int BPF_KPROBE(do_mov_5139)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x393")
int BPF_KPROBE(do_mov_5140)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x39b")
int BPF_KPROBE(do_mov_5141)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x3a6")
int BPF_KPROBE(do_mov_5142)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_one_skb + 0x3b1")
int BPF_KPROBE(do_mov_5143)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb + 0x86")
int BPF_KPROBE(do_mov_5144)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb + 0xb4")
int BPF_KPROBE(do_mov_5145)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb + 0x10c")
int BPF_KPROBE(do_mov_5146)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb + 0x123")
int BPF_KPROBE(do_mov_5147)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_queue_rcv_skb + 0x12d")
int BPF_KPROBE(do_mov_5148)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_unicast_rcv_skb + 0x80")
int BPF_KPROBE(do_mov_5149)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp6_unicast_rcv_skb + 0x95")
int BPF_KPROBE(do_mov_5150)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_lookup + 0x29")
int BPF_KPROBE(do_mov_5151)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_lookup + 0x36")
int BPF_KPROBE(do_mov_5152)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_lookup + 0x3a")
int BPF_KPROBE(do_mov_5153)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_lookup + 0x47")
int BPF_KPROBE(do_mov_5154)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_lookup + 0x58")
int BPF_KPROBE(do_mov_5155)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_lookup + 0x8e")
int BPF_KPROBE(do_mov_5156)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_get_port + 0x50")
int BPF_KPROBE(do_mov_5157)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x31")
int BPF_KPROBE(do_mov_5158)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x41")
int BPF_KPROBE(do_mov_5159)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x8c")
int BPF_KPROBE(do_mov_5160)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x97")
int BPF_KPROBE(do_mov_5161)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xa2")
int BPF_KPROBE(do_mov_5162)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xb3")
int BPF_KPROBE(do_mov_5163)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xc3")
int BPF_KPROBE(do_mov_5164)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xce")
int BPF_KPROBE(do_mov_5165)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xde")
int BPF_KPROBE(do_mov_5166)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xed")
int BPF_KPROBE(do_mov_5167)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x189")
int BPF_KPROBE(do_mov_5168)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x19e")
int BPF_KPROBE(do_mov_5169)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x1a8")
int BPF_KPROBE(do_mov_5170)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x1b0")
int BPF_KPROBE(do_mov_5171)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x1bd")
int BPF_KPROBE(do_mov_5172)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x1e9")
int BPF_KPROBE(do_mov_5173)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x1f6")
int BPF_KPROBE(do_mov_5174)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x22a")
int BPF_KPROBE(do_mov_5175)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x24b")
int BPF_KPROBE(do_mov_5176)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x283")
int BPF_KPROBE(do_mov_5177)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x294")
int BPF_KPROBE(do_mov_5178)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x2a2")
int BPF_KPROBE(do_mov_5179)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x32f")
int BPF_KPROBE(do_mov_5180)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x343")
int BPF_KPROBE(do_mov_5181)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x408")
int BPF_KPROBE(do_mov_5182)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x414")
int BPF_KPROBE(do_mov_5183)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x433")
int BPF_KPROBE(do_mov_5184)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x454")
int BPF_KPROBE(do_mov_5185)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x45c")
int BPF_KPROBE(do_mov_5186)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x474")
int BPF_KPROBE(do_mov_5187)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x482")
int BPF_KPROBE(do_mov_5188)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x4b9")
int BPF_KPROBE(do_mov_5189)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x4d7")
int BPF_KPROBE(do_mov_5190)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x4f3")
int BPF_KPROBE(do_mov_5191)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x517")
int BPF_KPROBE(do_mov_5192)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x524")
int BPF_KPROBE(do_mov_5193)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x52b")
int BPF_KPROBE(do_mov_5194)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x578")
int BPF_KPROBE(do_mov_5195)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x585")
int BPF_KPROBE(do_mov_5196)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x5aa")
int BPF_KPROBE(do_mov_5197)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x5dc")
int BPF_KPROBE(do_mov_5198)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x5e3")
int BPF_KPROBE(do_mov_5199)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x5ef")
int BPF_KPROBE(do_mov_5200)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x603")
int BPF_KPROBE(do_mov_5201)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x60f")
int BPF_KPROBE(do_mov_5202)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x625")
int BPF_KPROBE(do_mov_5203)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x629")
int BPF_KPROBE(do_mov_5204)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x636")
int BPF_KPROBE(do_mov_5205)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x649")
int BPF_KPROBE(do_mov_5206)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x67b")
int BPF_KPROBE(do_mov_5207)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x698")
int BPF_KPROBE(do_mov_5208)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x6ba")
int BPF_KPROBE(do_mov_5209)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x71b")
int BPF_KPROBE(do_mov_5210)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x74d")
int BPF_KPROBE(do_mov_5211)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x75d")
int BPF_KPROBE(do_mov_5212)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x7b7")
int BPF_KPROBE(do_mov_5213)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x7de")
int BPF_KPROBE(do_mov_5214)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x7fd")
int BPF_KPROBE(do_mov_5215)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x804")
int BPF_KPROBE(do_mov_5216)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x80f")
int BPF_KPROBE(do_mov_5217)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x818")
int BPF_KPROBE(do_mov_5218)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x823")
int BPF_KPROBE(do_mov_5219)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x82b")
int BPF_KPROBE(do_mov_5220)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x83d")
int BPF_KPROBE(do_mov_5221)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x853")
int BPF_KPROBE(do_mov_5222)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x886")
int BPF_KPROBE(do_mov_5223)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x891")
int BPF_KPROBE(do_mov_5224)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x89a")
int BPF_KPROBE(do_mov_5225)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x90b")
int BPF_KPROBE(do_mov_5226)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0x9f2")
int BPF_KPROBE(do_mov_5227)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xad1")
int BPF_KPROBE(do_mov_5228)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xae9")
int BPF_KPROBE(do_mov_5229)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xb34")
int BPF_KPROBE(do_mov_5230)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xb57")
int BPF_KPROBE(do_mov_5231)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xb77")
int BPF_KPROBE(do_mov_5232)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xbc8")
int BPF_KPROBE(do_mov_5233)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xbe3")
int BPF_KPROBE(do_mov_5234)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xc13")
int BPF_KPROBE(do_mov_5235)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xc3c")
int BPF_KPROBE(do_mov_5236)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xcdb")
int BPF_KPROBE(do_mov_5237)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udpv6_sendmsg + 0xcf3")
int BPF_KPROBE(do_mov_5238)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x23")
int BPF_KPROBE(do_mov_5239)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x26")
int BPF_KPROBE(do_mov_5240)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x31")
int BPF_KPROBE(do_mov_5241)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x35")
int BPF_KPROBE(do_mov_5242)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x46")
int BPF_KPROBE(do_mov_5243)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x7b")
int BPF_KPROBE(do_mov_5244)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0xb3")
int BPF_KPROBE(do_mov_5245)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0xb7")
int BPF_KPROBE(do_mov_5246)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x158")
int BPF_KPROBE(do_mov_5247)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_err + 0x33e")
int BPF_KPROBE(do_mov_5248)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x20")
int BPF_KPROBE(do_mov_5249)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x79")
int BPF_KPROBE(do_mov_5250)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x1bb")
int BPF_KPROBE(do_mov_5251)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x1e9")
int BPF_KPROBE(do_mov_5252)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x229")
int BPF_KPROBE(do_mov_5253)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x237")
int BPF_KPROBE(do_mov_5254)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x295")
int BPF_KPROBE(do_mov_5255)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x299")
int BPF_KPROBE(do_mov_5256)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x2df")
int BPF_KPROBE(do_mov_5257)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x3ce")
int BPF_KPROBE(do_mov_5258)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x3dd")
int BPF_KPROBE(do_mov_5259)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x402")
int BPF_KPROBE(do_mov_5260)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x40e")
int BPF_KPROBE(do_mov_5261)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x421")
int BPF_KPROBE(do_mov_5262)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x42c")
int BPF_KPROBE(do_mov_5263)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x43c")
int BPF_KPROBE(do_mov_5264)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x446")
int BPF_KPROBE(do_mov_5265)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x504")
int BPF_KPROBE(do_mov_5266)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x543")
int BPF_KPROBE(do_mov_5267)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x55f")
int BPF_KPROBE(do_mov_5268)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x76c")
int BPF_KPROBE(do_mov_5269)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x770")
int BPF_KPROBE(do_mov_5270)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x797")
int BPF_KPROBE(do_mov_5271)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x7e2")
int BPF_KPROBE(do_mov_5272)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x7f2")
int BPF_KPROBE(do_mov_5273)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x80a")
int BPF_KPROBE(do_mov_5274)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x82f")
int BPF_KPROBE(do_mov_5275)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x859")
int BPF_KPROBE(do_mov_5276)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x85d")
int BPF_KPROBE(do_mov_5277)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x860")
int BPF_KPROBE(do_mov_5278)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x874")
int BPF_KPROBE(do_mov_5279)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x8d6")
int BPF_KPROBE(do_mov_5280)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x91f")
int BPF_KPROBE(do_mov_5281)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x923")
int BPF_KPROBE(do_mov_5282)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x94c")
int BPF_KPROBE(do_mov_5283)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__udp6_lib_rcv + 0x950")
int BPF_KPROBE(do_mov_5284)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0xa0")
int BPF_KPROBE(do_mov_5285)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0xb0")
int BPF_KPROBE(do_mov_5286)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0x18e")
int BPF_KPROBE(do_mov_5287)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0x192")
int BPF_KPROBE(do_mov_5288)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0x1d0")
int BPF_KPROBE(do_mov_5289)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0x221")
int BPF_KPROBE(do_mov_5290)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udp_v6_early_demux + 0x225")
int BPF_KPROBE(do_mov_5291)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/udplitev6_sk_init + 0x12")
int BPF_KPROBE(do_mov_5292)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_mh_filter_register + 0xb")
int BPF_KPROBE(do_mov_5293)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_init_sk + 0x23")
int BPF_KPROBE(do_mov_5294)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_init_sk + 0x39")
int BPF_KPROBE(do_mov_5295)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_mh_filter_unregister + 0x6")
int BPF_KPROBE(do_mov_5296)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x28")
int BPF_KPROBE(do_mov_5297)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x41")
int BPF_KPROBE(do_mov_5298)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x69")
int BPF_KPROBE(do_mov_5299)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0xba")
int BPF_KPROBE(do_mov_5300)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0xc4")
int BPF_KPROBE(do_mov_5301)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0xd0")
int BPF_KPROBE(do_mov_5302)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0xd4")
int BPF_KPROBE(do_mov_5303)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0xe5")
int BPF_KPROBE(do_mov_5304)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0xe8")
int BPF_KPROBE(do_mov_5305)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x10b")
int BPF_KPROBE(do_mov_5306)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x119")
int BPF_KPROBE(do_mov_5307)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x129")
int BPF_KPROBE(do_mov_5308)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x12d")
int BPF_KPROBE(do_mov_5309)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_bind + 0x140")
int BPF_KPROBE(do_mov_5310)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_getfrag + 0x57")
int BPF_KPROBE(do_mov_5311)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_getfrag + 0x5b")
int BPF_KPROBE(do_mov_5312)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_getfrag + 0xa8")
int BPF_KPROBE(do_mov_5313)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_getfrag + 0xac")
int BPF_KPROBE(do_mov_5314)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_getfrag + 0xb0")
int BPF_KPROBE(do_mov_5315)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_getfrag + 0xdd")
int BPF_KPROBE(do_mov_5316)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_getsockopt + 0x25")
int BPF_KPROBE(do_mov_5317)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_getsockopt + 0xad")
int BPF_KPROBE(do_mov_5318)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x24")
int BPF_KPROBE(do_mov_5319)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x32")
int BPF_KPROBE(do_mov_5320)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x55")
int BPF_KPROBE(do_mov_5321)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x8b")
int BPF_KPROBE(do_mov_5322)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0xa9")
int BPF_KPROBE(do_mov_5323)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0xb8")
int BPF_KPROBE(do_mov_5324)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x13e")
int BPF_KPROBE(do_mov_5325)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x154")
int BPF_KPROBE(do_mov_5326)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x175")
int BPF_KPROBE(do_mov_5327)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x17c")
int BPF_KPROBE(do_mov_5328)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x180")
int BPF_KPROBE(do_mov_5329)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x196")
int BPF_KPROBE(do_mov_5330)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x1c3")
int BPF_KPROBE(do_mov_5331)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x1cb")
int BPF_KPROBE(do_mov_5332)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x1fd")
int BPF_KPROBE(do_mov_5333)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x207")
int BPF_KPROBE(do_mov_5334)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x280")
int BPF_KPROBE(do_mov_5335)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x29e")
int BPF_KPROBE(do_mov_5336)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x2df")
int BPF_KPROBE(do_mov_5337)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_recvmsg + 0x2f6")
int BPF_KPROBE(do_mov_5338)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x22")
int BPF_KPROBE(do_mov_5339)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x93")
int BPF_KPROBE(do_mov_5340)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0xd4")
int BPF_KPROBE(do_mov_5341)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x12d")
int BPF_KPROBE(do_mov_5342)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x13d")
int BPF_KPROBE(do_mov_5343)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x15d")
int BPF_KPROBE(do_mov_5344)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x1c6")
int BPF_KPROBE(do_mov_5345)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x1cf")
int BPF_KPROBE(do_mov_5346)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x1ea")
int BPF_KPROBE(do_mov_5347)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x1f6")
int BPF_KPROBE(do_mov_5348)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x221")
int BPF_KPROBE(do_mov_5349)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x232")
int BPF_KPROBE(do_mov_5350)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x264")
int BPF_KPROBE(do_mov_5351)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_setsockopt + 0x26f")
int BPF_KPROBE(do_mov_5352)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x31")
int BPF_KPROBE(do_mov_5353)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x44")
int BPF_KPROBE(do_mov_5354)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x96")
int BPF_KPROBE(do_mov_5355)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xa1")
int BPF_KPROBE(do_mov_5356)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xb2")
int BPF_KPROBE(do_mov_5357)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xc0")
int BPF_KPROBE(do_mov_5358)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xc7")
int BPF_KPROBE(do_mov_5359)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xe0")
int BPF_KPROBE(do_mov_5360)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xeb")
int BPF_KPROBE(do_mov_5361)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xf5")
int BPF_KPROBE(do_mov_5362)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x100")
int BPF_KPROBE(do_mov_5363)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x106")
int BPF_KPROBE(do_mov_5364)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x10d")
int BPF_KPROBE(do_mov_5365)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x15e")
int BPF_KPROBE(do_mov_5366)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x170")
int BPF_KPROBE(do_mov_5367)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x1c9")
int BPF_KPROBE(do_mov_5368)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x1da")
int BPF_KPROBE(do_mov_5369)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x1e1")
int BPF_KPROBE(do_mov_5370)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x230")
int BPF_KPROBE(do_mov_5371)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x24b")
int BPF_KPROBE(do_mov_5372)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x271")
int BPF_KPROBE(do_mov_5373)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x2e5")
int BPF_KPROBE(do_mov_5374)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x2ec")
int BPF_KPROBE(do_mov_5375)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x316")
int BPF_KPROBE(do_mov_5376)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x31a")
int BPF_KPROBE(do_mov_5377)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x343")
int BPF_KPROBE(do_mov_5378)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x378")
int BPF_KPROBE(do_mov_5379)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x384")
int BPF_KPROBE(do_mov_5380)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x3bb")
int BPF_KPROBE(do_mov_5381)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x3d2")
int BPF_KPROBE(do_mov_5382)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x41b")
int BPF_KPROBE(do_mov_5383)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x44a")
int BPF_KPROBE(do_mov_5384)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x465")
int BPF_KPROBE(do_mov_5385)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x470")
int BPF_KPROBE(do_mov_5386)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x4ad")
int BPF_KPROBE(do_mov_5387)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x4cb")
int BPF_KPROBE(do_mov_5388)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x55b")
int BPF_KPROBE(do_mov_5389)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x587")
int BPF_KPROBE(do_mov_5390)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x5b1")
int BPF_KPROBE(do_mov_5391)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x5db")
int BPF_KPROBE(do_mov_5392)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x603")
int BPF_KPROBE(do_mov_5393)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x60e")
int BPF_KPROBE(do_mov_5394)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x619")
int BPF_KPROBE(do_mov_5395)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x620")
int BPF_KPROBE(do_mov_5396)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x62b")
int BPF_KPROBE(do_mov_5397)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x639")
int BPF_KPROBE(do_mov_5398)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x692")
int BPF_KPROBE(do_mov_5399)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x6a8")
int BPF_KPROBE(do_mov_5400)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x6d3")
int BPF_KPROBE(do_mov_5401)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x6da")
int BPF_KPROBE(do_mov_5402)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x704")
int BPF_KPROBE(do_mov_5403)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x725")
int BPF_KPROBE(do_mov_5404)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x777")
int BPF_KPROBE(do_mov_5405)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x792")
int BPF_KPROBE(do_mov_5406)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x796")
int BPF_KPROBE(do_mov_5407)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x7e8")
int BPF_KPROBE(do_mov_5408)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x819")
int BPF_KPROBE(do_mov_5409)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x837")
int BPF_KPROBE(do_mov_5410)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x845")
int BPF_KPROBE(do_mov_5411)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x854")
int BPF_KPROBE(do_mov_5412)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x86e")
int BPF_KPROBE(do_mov_5413)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x8f0")
int BPF_KPROBE(do_mov_5414)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x8fa")
int BPF_KPROBE(do_mov_5415)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x92c")
int BPF_KPROBE(do_mov_5416)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x931")
int BPF_KPROBE(do_mov_5417)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x95a")
int BPF_KPROBE(do_mov_5418)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x9de")
int BPF_KPROBE(do_mov_5419)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x9fd")
int BPF_KPROBE(do_mov_5420)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xa04")
int BPF_KPROBE(do_mov_5421)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xa2e")
int BPF_KPROBE(do_mov_5422)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xb56")
int BPF_KPROBE(do_mov_5423)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xb62")
int BPF_KPROBE(do_mov_5424)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xb88")
int BPF_KPROBE(do_mov_5425)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xb96")
int BPF_KPROBE(do_mov_5426)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xbb5")
int BPF_KPROBE(do_mov_5427)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xbd3")
int BPF_KPROBE(do_mov_5428)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xbe1")
int BPF_KPROBE(do_mov_5429)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xc0a")
int BPF_KPROBE(do_mov_5430)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xc24")
int BPF_KPROBE(do_mov_5431)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xc31")
int BPF_KPROBE(do_mov_5432)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xc5f")
int BPF_KPROBE(do_mov_5433)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xce2")
int BPF_KPROBE(do_mov_5434)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xd91")
int BPF_KPROBE(do_mov_5435)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xdef")
int BPF_KPROBE(do_mov_5436)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xe20")
int BPF_KPROBE(do_mov_5437)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xe60")
int BPF_KPROBE(do_mov_5438)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xeab")
int BPF_KPROBE(do_mov_5439)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xec5")
int BPF_KPROBE(do_mov_5440)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xef6")
int BPF_KPROBE(do_mov_5441)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0xffd")
int BPF_KPROBE(do_mov_5442)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x1015")
int BPF_KPROBE(do_mov_5443)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x1036")
int BPF_KPROBE(do_mov_5444)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x103d")
int BPF_KPROBE(do_mov_5445)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x1044")
int BPF_KPROBE(do_mov_5446)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x104b")
int BPF_KPROBE(do_mov_5447)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x109b")
int BPF_KPROBE(do_mov_5448)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_sendmsg + 0x10ac")
int BPF_KPROBE(do_mov_5449)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x1c")
int BPF_KPROBE(do_mov_5450)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x20")
int BPF_KPROBE(do_mov_5451)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x24")
int BPF_KPROBE(do_mov_5452)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x27")
int BPF_KPROBE(do_mov_5453)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x33")
int BPF_KPROBE(do_mov_5454)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0xc9")
int BPF_KPROBE(do_mov_5455)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0xf7")
int BPF_KPROBE(do_mov_5456)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x117")
int BPF_KPROBE(do_mov_5457)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_icmp_error + 0x14f")
int BPF_KPROBE(do_mov_5458)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_rcv + 0x86")
int BPF_KPROBE(do_mov_5459)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_rcv + 0xf7")
int BPF_KPROBE(do_mov_5460)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_rcv + 0x2d0")
int BPF_KPROBE(do_mov_5461)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_rcv + 0x324")
int BPF_KPROBE(do_mov_5462)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_rcv + 0x361")
int BPF_KPROBE(do_mov_5463)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/rawv6_rcv + 0x377")
int BPF_KPROBE(do_mov_5464)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x1c")
int BPF_KPROBE(do_mov_5465)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x3c")
int BPF_KPROBE(do_mov_5466)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x50")
int BPF_KPROBE(do_mov_5467)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x73")
int BPF_KPROBE(do_mov_5468)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x77")
int BPF_KPROBE(do_mov_5469)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0xdc")
int BPF_KPROBE(do_mov_5470)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x11a")
int BPF_KPROBE(do_mov_5471)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x128")
int BPF_KPROBE(do_mov_5472)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x17a")
int BPF_KPROBE(do_mov_5473)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x199")
int BPF_KPROBE(do_mov_5474)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x1e9")
int BPF_KPROBE(do_mov_5475)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x20b")
int BPF_KPROBE(do_mov_5476)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x225")
int BPF_KPROBE(do_mov_5477)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x240")
int BPF_KPROBE(do_mov_5478)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x244")
int BPF_KPROBE(do_mov_5479)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x260")
int BPF_KPROBE(do_mov_5480)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x264")
int BPF_KPROBE(do_mov_5481)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x27b")
int BPF_KPROBE(do_mov_5482)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/raw6_local_deliver + 0x284")
int BPF_KPROBE(do_mov_5483)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_getfrag + 0x48")
int BPF_KPROBE(do_mov_5484)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_err_convert + 0x6")
int BPF_KPROBE(do_mov_5485)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_err_convert + 0x23")
int BPF_KPROBE(do_mov_5486)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_err_convert + 0x38")
int BPF_KPROBE(do_mov_5487)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_err_convert + 0x59")
int BPF_KPROBE(do_mov_5488)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_xrlim_allow + 0x2f")
int BPF_KPROBE(do_mov_5489)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_xrlim_allow + 0xfa")
int BPF_KPROBE(do_mov_5490)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_xrlim_allow + 0x103")
int BPF_KPROBE(do_mov_5491)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_xrlim_allow + 0x10d")
int BPF_KPROBE(do_mov_5492)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_route_lookup + 0x34")
int BPF_KPROBE(do_mov_5493)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_route_lookup + 0xb5")
int BPF_KPROBE(do_mov_5494)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_route_lookup + 0xd0")
int BPF_KPROBE(do_mov_5495)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_route_lookup + 0x17c")
int BPF_KPROBE(do_mov_5496)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_route_lookup + 0x1ad")
int BPF_KPROBE(do_mov_5497)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0x59")
int BPF_KPROBE(do_mov_5498)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0x5e")
int BPF_KPROBE(do_mov_5499)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0x92")
int BPF_KPROBE(do_mov_5500)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0xb8")
int BPF_KPROBE(do_mov_5501)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0xd8")
int BPF_KPROBE(do_mov_5502)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0xe4")
int BPF_KPROBE(do_mov_5503)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_push_pending_frames + 0xf8")
int BPF_KPROBE(do_mov_5504)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x28")
int BPF_KPROBE(do_mov_5505)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x35")
int BPF_KPROBE(do_mov_5506)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x3b")
int BPF_KPROBE(do_mov_5507)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x41")
int BPF_KPROBE(do_mov_5508)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x48")
int BPF_KPROBE(do_mov_5509)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x58")
int BPF_KPROBE(do_mov_5510)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x9d")
int BPF_KPROBE(do_mov_5511)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0xd6")
int BPF_KPROBE(do_mov_5512)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x12b")
int BPF_KPROBE(do_mov_5513)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x16f")
int BPF_KPROBE(do_mov_5514)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x27d")
int BPF_KPROBE(do_mov_5515)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x293")
int BPF_KPROBE(do_mov_5516)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x2a2")
int BPF_KPROBE(do_mov_5517)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x2a8")
int BPF_KPROBE(do_mov_5518)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x2c0")
int BPF_KPROBE(do_mov_5519)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x325")
int BPF_KPROBE(do_mov_5520)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x3c4")
int BPF_KPROBE(do_mov_5521)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x3d8")
int BPF_KPROBE(do_mov_5522)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x402")
int BPF_KPROBE(do_mov_5523)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x411")
int BPF_KPROBE(do_mov_5524)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x415")
int BPF_KPROBE(do_mov_5525)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x42d")
int BPF_KPROBE(do_mov_5526)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x431")
int BPF_KPROBE(do_mov_5527)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x440")
int BPF_KPROBE(do_mov_5528)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x44c")
int BPF_KPROBE(do_mov_5529)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x459")
int BPF_KPROBE(do_mov_5530)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x463")
int BPF_KPROBE(do_mov_5531)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x47a")
int BPF_KPROBE(do_mov_5532)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x488")
int BPF_KPROBE(do_mov_5533)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x4d6")
int BPF_KPROBE(do_mov_5534)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x4dd")
int BPF_KPROBE(do_mov_5535)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x4ea")
int BPF_KPROBE(do_mov_5536)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x4f8")
int BPF_KPROBE(do_mov_5537)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x516")
int BPF_KPROBE(do_mov_5538)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x52e")
int BPF_KPROBE(do_mov_5539)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x53e")
int BPF_KPROBE(do_mov_5540)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x54e")
int BPF_KPROBE(do_mov_5541)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x55b")
int BPF_KPROBE(do_mov_5542)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x568")
int BPF_KPROBE(do_mov_5543)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x571")
int BPF_KPROBE(do_mov_5544)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x57d")
int BPF_KPROBE(do_mov_5545)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x588")
int BPF_KPROBE(do_mov_5546)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x598")
int BPF_KPROBE(do_mov_5547)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x5d0")
int BPF_KPROBE(do_mov_5548)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x5e5")
int BPF_KPROBE(do_mov_5549)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x5fd")
int BPF_KPROBE(do_mov_5550)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x60b")
int BPF_KPROBE(do_mov_5551)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x654")
int BPF_KPROBE(do_mov_5552)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x6a9")
int BPF_KPROBE(do_mov_5553)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x6e1")
int BPF_KPROBE(do_mov_5554)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x72e")
int BPF_KPROBE(do_mov_5555)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x732")
int BPF_KPROBE(do_mov_5556)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x736")
int BPF_KPROBE(do_mov_5557)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x73a")
int BPF_KPROBE(do_mov_5558)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x7b1")
int BPF_KPROBE(do_mov_5559)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x856")
int BPF_KPROBE(do_mov_5560)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x866")
int BPF_KPROBE(do_mov_5561)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x884")
int BPF_KPROBE(do_mov_5562)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x8a8")
int BPF_KPROBE(do_mov_5563)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x8af")
int BPF_KPROBE(do_mov_5564)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmp6_send + 0x90b")
int BPF_KPROBE(do_mov_5565)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0x23")
int BPF_KPROBE(do_mov_5566)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0x35")
int BPF_KPROBE(do_mov_5567)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0xac")
int BPF_KPROBE(do_mov_5568)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0xdf")
int BPF_KPROBE(do_mov_5569)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0xf2")
int BPF_KPROBE(do_mov_5570)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0xfb")
int BPF_KPROBE(do_mov_5571)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0x107")
int BPF_KPROBE(do_mov_5572)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0x137")
int BPF_KPROBE(do_mov_5573)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0x143")
int BPF_KPROBE(do_mov_5574)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_err_gen_icmpv6_unreach + 0x208")
int BPF_KPROBE(do_mov_5575)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3f")
int BPF_KPROBE(do_mov_5576)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x45")
int BPF_KPROBE(do_mov_5577)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x66")
int BPF_KPROBE(do_mov_5578)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0xe9")
int BPF_KPROBE(do_mov_5579)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0xf5")
int BPF_KPROBE(do_mov_5580)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x101")
int BPF_KPROBE(do_mov_5581)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x10a")
int BPF_KPROBE(do_mov_5582)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x129")
int BPF_KPROBE(do_mov_5583)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x12c")
int BPF_KPROBE(do_mov_5584)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x13b")
int BPF_KPROBE(do_mov_5585)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x13f")
int BPF_KPROBE(do_mov_5586)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x14f")
int BPF_KPROBE(do_mov_5587)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x153")
int BPF_KPROBE(do_mov_5588)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x175")
int BPF_KPROBE(do_mov_5589)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x184")
int BPF_KPROBE(do_mov_5590)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x191")
int BPF_KPROBE(do_mov_5591)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x1a2")
int BPF_KPROBE(do_mov_5592)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x1d5")
int BPF_KPROBE(do_mov_5593)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x1ee")
int BPF_KPROBE(do_mov_5594)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x20a")
int BPF_KPROBE(do_mov_5595)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x211")
int BPF_KPROBE(do_mov_5596)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x234")
int BPF_KPROBE(do_mov_5597)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x26b")
int BPF_KPROBE(do_mov_5598)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x2b3")
int BPF_KPROBE(do_mov_5599)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x351")
int BPF_KPROBE(do_mov_5600)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x35c")
int BPF_KPROBE(do_mov_5601)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x36a")
int BPF_KPROBE(do_mov_5602)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x374")
int BPF_KPROBE(do_mov_5603)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x37f")
int BPF_KPROBE(do_mov_5604)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x38d")
int BPF_KPROBE(do_mov_5605)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x398")
int BPF_KPROBE(do_mov_5606)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3a5")
int BPF_KPROBE(do_mov_5607)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3b8")
int BPF_KPROBE(do_mov_5608)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3bf")
int BPF_KPROBE(do_mov_5609)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3cb")
int BPF_KPROBE(do_mov_5610)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3d2")
int BPF_KPROBE(do_mov_5611)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x3ff")
int BPF_KPROBE(do_mov_5612)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x420")
int BPF_KPROBE(do_mov_5613)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x42d")
int BPF_KPROBE(do_mov_5614)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_echo_reply + 0x4ca")
int BPF_KPROBE(do_mov_5615)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_notify + 0x23")
int BPF_KPROBE(do_mov_5616)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_notify + 0x37")
int BPF_KPROBE(do_mov_5617)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_notify + 0x6a")
int BPF_KPROBE(do_mov_5618)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_notify + 0xc2")
int BPF_KPROBE(do_mov_5619)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_notify + 0x183")
int BPF_KPROBE(do_mov_5620)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0xc7")
int BPF_KPROBE(do_mov_5621)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0xda")
int BPF_KPROBE(do_mov_5622)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x129")
int BPF_KPROBE(do_mov_5623)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x150")
int BPF_KPROBE(do_mov_5624)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x184")
int BPF_KPROBE(do_mov_5625)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x320")
int BPF_KPROBE(do_mov_5626)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x36b")
int BPF_KPROBE(do_mov_5627)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x36f")
int BPF_KPROBE(do_mov_5628)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x3a5")
int BPF_KPROBE(do_mov_5629)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x3e7")
int BPF_KPROBE(do_mov_5630)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x488")
int BPF_KPROBE(do_mov_5631)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x49b")
int BPF_KPROBE(do_mov_5632)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x538")
int BPF_KPROBE(do_mov_5633)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_rcv + 0x620")
int BPF_KPROBE(do_mov_5634)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x1c")
int BPF_KPROBE(do_mov_5635)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x26")
int BPF_KPROBE(do_mov_5636)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x42")
int BPF_KPROBE(do_mov_5637)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x46")
int BPF_KPROBE(do_mov_5638)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x51")
int BPF_KPROBE(do_mov_5639)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x55")
int BPF_KPROBE(do_mov_5640)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x59")
int BPF_KPROBE(do_mov_5641)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x5d")
int BPF_KPROBE(do_mov_5642)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/icmpv6_flow_init + 0x60")
int BPF_KPROBE(do_mov_5643)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init + 0x2f")
int BPF_KPROBE(do_mov_5644)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init + 0x3a")
int BPF_KPROBE(do_mov_5645)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init + 0x45")
int BPF_KPROBE(do_mov_5646)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init + 0x5a")
int BPF_KPROBE(do_mov_5647)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_icmp_sysctl_init + 0x61")
int BPF_KPROBE(do_mov_5648)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_markstate + 0x2b")
int BPF_KPROBE(do_mov_5649)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_markstate + 0x47")
int BPF_KPROBE(do_mov_5650)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_stop + 0x14")
int BPF_KPROBE(do_mov_5651)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_stop + 0x23")
int BPF_KPROBE(do_mov_5652)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_stop + 0x2b")
int BPF_KPROBE(do_mov_5653)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_stop + 0x14")
int BPF_KPROBE(do_mov_5654)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_stop + 0x1c")
int BPF_KPROBE(do_mov_5655)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0xad")
int BPF_KPROBE(do_mov_5656)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0xbe")
int BPF_KPROBE(do_mov_5657)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0xdc")
int BPF_KPROBE(do_mov_5658)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x10f")
int BPF_KPROBE(do_mov_5659)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x14e")
int BPF_KPROBE(do_mov_5660)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x155")
int BPF_KPROBE(do_mov_5661)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x15d")
int BPF_KPROBE(do_mov_5662)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x165")
int BPF_KPROBE(do_mov_5663)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x16d")
int BPF_KPROBE(do_mov_5664)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x175")
int BPF_KPROBE(do_mov_5665)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x17d")
int BPF_KPROBE(do_mov_5666)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x185")
int BPF_KPROBE(do_mov_5667)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x18e")
int BPF_KPROBE(do_mov_5668)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x191")
int BPF_KPROBE(do_mov_5669)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x19a")
int BPF_KPROBE(do_mov_5670)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/sf_setstate + 0x1a3")
int BPF_KPROBE(do_mov_5671)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_net_init + 0x74")
int BPF_KPROBE(do_mov_5672)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_net_init + 0x84")
int BPF_KPROBE(do_mov_5673)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_show + 0x63")
int BPF_KPROBE(do_mov_5674)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x2b")
int BPF_KPROBE(do_mov_5675)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x43")
int BPF_KPROBE(do_mov_5676)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x47")
int BPF_KPROBE(do_mov_5677)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x6b")
int BPF_KPROBE(do_mov_5678)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x71")
int BPF_KPROBE(do_mov_5679)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x76")
int BPF_KPROBE(do_mov_5680)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0x98")
int BPF_KPROBE(do_mov_5681)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0xa2")
int BPF_KPROBE(do_mov_5682)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0xa6")
int BPF_KPROBE(do_mov_5683)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0xb1")
int BPF_KPROBE(do_mov_5684)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_hdr.constprop.0 + 0xb5")
int BPF_KPROBE(do_mov_5685)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0 + 0x1f")
int BPF_KPROBE(do_mov_5686)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0 + 0x2f")
int BPF_KPROBE(do_mov_5687)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0 + 0x3c")
int BPF_KPROBE(do_mov_5688)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0 + 0x5f")
int BPF_KPROBE(do_mov_5689)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_get_next.isra.0 + 0x67")
int BPF_KPROBE(do_mov_5690)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start + 0x38")
int BPF_KPROBE(do_mov_5691)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start + 0x40")
int BPF_KPROBE(do_mov_5692)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start + 0x5a")
int BPF_KPROBE(do_mov_5693)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start + 0x81")
int BPF_KPROBE(do_mov_5694)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start + 0x85")
int BPF_KPROBE(do_mov_5695)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_start + 0xba")
int BPF_KPROBE(do_mov_5696)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next + 0x34")
int BPF_KPROBE(do_mov_5697)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next + 0x44")
int BPF_KPROBE(do_mov_5698)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next + 0x5f")
int BPF_KPROBE(do_mov_5699)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_next + 0x6a")
int BPF_KPROBE(do_mov_5700)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0x30")
int BPF_KPROBE(do_mov_5701)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0xbf")
int BPF_KPROBE(do_mov_5702)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0xca")
int BPF_KPROBE(do_mov_5703)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0x106")
int BPF_KPROBE(do_mov_5704)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0x167")
int BPF_KPROBE(do_mov_5705)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0x185")
int BPF_KPROBE(do_mov_5706)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_sendpack + 0x20f")
int BPF_KPROBE(do_mov_5707)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0x22")
int BPF_KPROBE(do_mov_5708)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0x3c")
int BPF_KPROBE(do_mov_5709)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0x62")
int BPF_KPROBE(do_mov_5710)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0x76")
int BPF_KPROBE(do_mov_5711)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0xaa")
int BPF_KPROBE(do_mov_5712)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0xba")
int BPF_KPROBE(do_mov_5713)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0xdd")
int BPF_KPROBE(do_mov_5714)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mc_seq_start + 0xe5")
int BPF_KPROBE(do_mov_5715)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x38")
int BPF_KPROBE(do_mov_5716)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x43")
int BPF_KPROBE(do_mov_5717)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x58")
int BPF_KPROBE(do_mov_5718)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x77")
int BPF_KPROBE(do_mov_5719)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0xf5")
int BPF_KPROBE(do_mov_5720)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x14d")
int BPF_KPROBE(do_mov_5721)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x16c")
int BPF_KPROBE(do_mov_5722)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x180")
int BPF_KPROBE(do_mov_5723)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x187")
int BPF_KPROBE(do_mov_5724)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x192")
int BPF_KPROBE(do_mov_5725)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x194")
int BPF_KPROBE(do_mov_5726)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x1a1")
int BPF_KPROBE(do_mov_5727)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x1ad")
int BPF_KPROBE(do_mov_5728)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x1b3")
int BPF_KPROBE(do_mov_5729)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x1db")
int BPF_KPROBE(do_mov_5730)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x24c")
int BPF_KPROBE(do_mov_5731)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x26a")
int BPF_KPROBE(do_mov_5732)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x28a")
int BPF_KPROBE(do_mov_5733)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_send + 0x3d0")
int BPF_KPROBE(do_mov_5734)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next + 0x29")
int BPF_KPROBE(do_mov_5735)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next + 0x31")
int BPF_KPROBE(do_mov_5736)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next + 0x4b")
int BPF_KPROBE(do_mov_5737)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next + 0x72")
int BPF_KPROBE(do_mov_5738)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next + 0x76")
int BPF_KPROBE(do_mov_5739)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_mcf_seq_next + 0x8c")
int BPF_KPROBE(do_mov_5740)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0x19")
int BPF_KPROBE(do_mov_5741)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0x5a")
int BPF_KPROBE(do_mov_5742)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0x8e")
int BPF_KPROBE(do_mov_5743)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0x97")
int BPF_KPROBE(do_mov_5744)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0xa0")
int BPF_KPROBE(do_mov_5745)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0xb0")
int BPF_KPROBE(do_mov_5746)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_clear_delrec + 0xf3")
int BPF_KPROBE(do_mov_5747)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0x3d")
int BPF_KPROBE(do_mov_5748)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0x50")
int BPF_KPROBE(do_mov_5749)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0x94")
int BPF_KPROBE(do_mov_5750)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0xb6")
int BPF_KPROBE(do_mov_5751)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0xf4")
int BPF_KPROBE(do_mov_5752)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0x148")
int BPF_KPROBE(do_mov_5753)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0x154")
int BPF_KPROBE(do_mov_5754)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_newpack.isra.0 + 0x173")
int BPF_KPROBE(do_mov_5755)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x30")
int BPF_KPROBE(do_mov_5756)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x33")
int BPF_KPROBE(do_mov_5757)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x37")
int BPF_KPROBE(do_mov_5758)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x42")
int BPF_KPROBE(do_mov_5759)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x46")
int BPF_KPROBE(do_mov_5760)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x67")
int BPF_KPROBE(do_mov_5761)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grhead + 0x6b")
int BPF_KPROBE(do_mov_5762)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x19")
int BPF_KPROBE(do_mov_5763)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1d")
int BPF_KPROBE(do_mov_5764)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x22")
int BPF_KPROBE(do_mov_5765)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x30")
int BPF_KPROBE(do_mov_5766)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x39")
int BPF_KPROBE(do_mov_5767)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x41")
int BPF_KPROBE(do_mov_5768)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x5d")
int BPF_KPROBE(do_mov_5769)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x75")
int BPF_KPROBE(do_mov_5770)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x98")
int BPF_KPROBE(do_mov_5771)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x108")
int BPF_KPROBE(do_mov_5772)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x114")
int BPF_KPROBE(do_mov_5773)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x188")
int BPF_KPROBE(do_mov_5774)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x193")
int BPF_KPROBE(do_mov_5775)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x19e")
int BPF_KPROBE(do_mov_5776)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1a6")
int BPF_KPROBE(do_mov_5777)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1b2")
int BPF_KPROBE(do_mov_5778)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1be")
int BPF_KPROBE(do_mov_5779)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x1e3")
int BPF_KPROBE(do_mov_5780)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x256")
int BPF_KPROBE(do_mov_5781)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x259")
int BPF_KPROBE(do_mov_5782)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x26f")
int BPF_KPROBE(do_mov_5783)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x274")
int BPF_KPROBE(do_mov_5784)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x2e2")
int BPF_KPROBE(do_mov_5785)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x2ee")
int BPF_KPROBE(do_mov_5786)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x31a")
int BPF_KPROBE(do_mov_5787)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x371")
int BPF_KPROBE(do_mov_5788)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x393")
int BPF_KPROBE(do_mov_5789)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3da")
int BPF_KPROBE(do_mov_5790)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x3e2")
int BPF_KPROBE(do_mov_5791)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x40a")
int BPF_KPROBE(do_mov_5792)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x42e")
int BPF_KPROBE(do_mov_5793)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/add_grec + 0x4d7")
int BPF_KPROBE(do_mov_5794)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_gq_work + 0x2e")
int BPF_KPROBE(do_mov_5795)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x58")
int BPF_KPROBE(do_mov_5796)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x65")
int BPF_KPROBE(do_mov_5797)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x74")
int BPF_KPROBE(do_mov_5798)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0xc8")
int BPF_KPROBE(do_mov_5799)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0xef")
int BPF_KPROBE(do_mov_5800)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x103")
int BPF_KPROBE(do_mov_5801)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x10a")
int BPF_KPROBE(do_mov_5802)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x112")
int BPF_KPROBE(do_mov_5803)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x124")
int BPF_KPROBE(do_mov_5804)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x131")
int BPF_KPROBE(do_mov_5805)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x143")
int BPF_KPROBE(do_mov_5806)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x147")
int BPF_KPROBE(do_mov_5807)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x153")
int BPF_KPROBE(do_mov_5808)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x157")
int BPF_KPROBE(do_mov_5809)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_del_delrec + 0x16d")
int BPF_KPROBE(do_mov_5810)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_mca_work + 0x74")
int BPF_KPROBE(do_mov_5811)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x30")
int BPF_KPROBE(do_mov_5812)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x3c")
int BPF_KPROBE(do_mov_5813)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x45")
int BPF_KPROBE(do_mov_5814)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x4a")
int BPF_KPROBE(do_mov_5815)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x68")
int BPF_KPROBE(do_mov_5816)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x75")
int BPF_KPROBE(do_mov_5817)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x7d")
int BPF_KPROBE(do_mov_5818)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x84")
int BPF_KPROBE(do_mov_5819)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x88")
int BPF_KPROBE(do_mov_5820)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x90")
int BPF_KPROBE(do_mov_5821)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x93")
int BPF_KPROBE(do_mov_5822)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x97")
int BPF_KPROBE(do_mov_5823)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x9c")
int BPF_KPROBE(do_mov_5824)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0xa6")
int BPF_KPROBE(do_mov_5825)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0xfe")
int BPF_KPROBE(do_mov_5826)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x109")
int BPF_KPROBE(do_mov_5827)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x111")
int BPF_KPROBE(do_mov_5828)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x118")
int BPF_KPROBE(do_mov_5829)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x11c")
int BPF_KPROBE(do_mov_5830)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x13d")
int BPF_KPROBE(do_mov_5831)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x1e6")
int BPF_KPROBE(do_mov_5832)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x1f3")
int BPF_KPROBE(do_mov_5833)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x215")
int BPF_KPROBE(do_mov_5834)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x23b")
int BPF_KPROBE(do_mov_5835)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x260")
int BPF_KPROBE(do_mov_5836)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x2ab")
int BPF_KPROBE(do_mov_5837)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x2b0")
int BPF_KPROBE(do_mov_5838)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x352")
int BPF_KPROBE(do_mov_5839)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x392")
int BPF_KPROBE(do_mov_5840)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x397")
int BPF_KPROBE(do_mov_5841)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_report_work + 0x3cb")
int BPF_KPROBE(do_mov_5842)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_event + 0x4e")
int BPF_KPROBE(do_mov_5843)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_added + 0x19")
int BPF_KPROBE(do_mov_5844)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_added + 0xa4")
int BPF_KPROBE(do_mov_5845)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_added + 0xd2")
int BPF_KPROBE(do_mov_5846)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ipv6_mc_netdev_event + 0xeb")
int BPF_KPROBE(do_mov_5847)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_dad_work + 0x79")
int BPF_KPROBE(do_mov_5848)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x20")
int BPF_KPROBE(do_mov_5849)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x27")
int BPF_KPROBE(do_mov_5850)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x40")
int BPF_KPROBE(do_mov_5851)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x5c")
int BPF_KPROBE(do_mov_5852)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x71")
int BPF_KPROBE(do_mov_5853)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0xaf")
int BPF_KPROBE(do_mov_5854)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x1a9")
int BPF_KPROBE(do_mov_5855)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x245")
int BPF_KPROBE(do_mov_5856)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x283")
int BPF_KPROBE(do_mov_5857)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x2be")
int BPF_KPROBE(do_mov_5858)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x2ec")
int BPF_KPROBE(do_mov_5859)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_ifc_work + 0x43a")
int BPF_KPROBE(do_mov_5860)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del1_src + 0x5a")
int BPF_KPROBE(do_mov_5861)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del1_src + 0x79")
int BPF_KPROBE(do_mov_5862)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del1_src + 0xac")
int BPF_KPROBE(do_mov_5863)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del1_src + 0xed")
int BPF_KPROBE(do_mov_5864)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del1_src + 0xf4")
int BPF_KPROBE(do_mov_5865)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del1_src + 0xfd")
int BPF_KPROBE(do_mov_5866)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x16")
int BPF_KPROBE(do_mov_5867)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x1b")
int BPF_KPROBE(do_mov_5868)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x20")
int BPF_KPROBE(do_mov_5869)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x7c")
int BPF_KPROBE(do_mov_5870)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x99")
int BPF_KPROBE(do_mov_5871)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0xaa")
int BPF_KPROBE(do_mov_5872)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x12d")
int BPF_KPROBE(do_mov_5873)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x13f")
int BPF_KPROBE(do_mov_5874)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x144")
int BPF_KPROBE(do_mov_5875)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x151")
int BPF_KPROBE(do_mov_5876)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x182")
int BPF_KPROBE(do_mov_5877)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x1a8")
int BPF_KPROBE(do_mov_5878)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x1ac")
int BPF_KPROBE(do_mov_5879)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x1b0")
int BPF_KPROBE(do_mov_5880)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x1e7")
int BPF_KPROBE(do_mov_5881)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x20c")
int BPF_KPROBE(do_mov_5882)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x210")
int BPF_KPROBE(do_mov_5883)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x214")
int BPF_KPROBE(do_mov_5884)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_add_src + 0x21d")
int BPF_KPROBE(do_mov_5885)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0x16")
int BPF_KPROBE(do_mov_5886)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0x67")
int BPF_KPROBE(do_mov_5887)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0xff")
int BPF_KPROBE(do_mov_5888)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0x11d")
int BPF_KPROBE(do_mov_5889)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0x128")
int BPF_KPROBE(do_mov_5890)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0x12b")
int BPF_KPROBE(do_mov_5891)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_del_src.isra.0 + 0x137")
int BPF_KPROBE(do_mov_5892)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_leave_src.isra.0 + 0x4e")
int BPF_KPROBE(do_mov_5893)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x1b")
int BPF_KPROBE(do_mov_5894)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x89")
int BPF_KPROBE(do_mov_5895)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x13d")
int BPF_KPROBE(do_mov_5896)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x16a")
int BPF_KPROBE(do_mov_5897)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x16e")
int BPF_KPROBE(do_mov_5898)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x178")
int BPF_KPROBE(do_mov_5899)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x17f")
int BPF_KPROBE(do_mov_5900)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x18d")
int BPF_KPROBE(do_mov_5901)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x191")
int BPF_KPROBE(do_mov_5902)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x1d2")
int BPF_KPROBE(do_mov_5903)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x1da")
int BPF_KPROBE(do_mov_5904)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x1de")
int BPF_KPROBE(do_mov_5905)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x1e6")
int BPF_KPROBE(do_mov_5906)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/igmp6_group_dropped + 0x1f8")
int BPF_KPROBE(do_mov_5907)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x48")
int BPF_KPROBE(do_mov_5908)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x152")
int BPF_KPROBE(do_mov_5909)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x15a")
int BPF_KPROBE(do_mov_5910)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x162")
int BPF_KPROBE(do_mov_5911)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x166")
int BPF_KPROBE(do_mov_5912)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x16a")
int BPF_KPROBE(do_mov_5913)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x17e")
int BPF_KPROBE(do_mov_5914)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x188")
int BPF_KPROBE(do_mov_5915)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x196")
int BPF_KPROBE(do_mov_5916)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x19d")
int BPF_KPROBE(do_mov_5917)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1a4")
int BPF_KPROBE(do_mov_5918)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1a8")
int BPF_KPROBE(do_mov_5919)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1b3")
int BPF_KPROBE(do_mov_5920)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1be")
int BPF_KPROBE(do_mov_5921)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1c2")
int BPF_KPROBE(do_mov_5922)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1e8")
int BPF_KPROBE(do_mov_5923)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x1f1")
int BPF_KPROBE(do_mov_5924)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x21e")
int BPF_KPROBE(do_mov_5925)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x290")
int BPF_KPROBE(do_mov_5926)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x2bb")
int BPF_KPROBE(do_mov_5927)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_dev_mc_inc + 0x306")
int BPF_KPROBE(do_mov_5928)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x26")
int BPF_KPROBE(do_mov_5929)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x43")
int BPF_KPROBE(do_mov_5930)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0xc8")
int BPF_KPROBE(do_mov_5931)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0xd7")
int BPF_KPROBE(do_mov_5932)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0xdb")
int BPF_KPROBE(do_mov_5933)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x10a")
int BPF_KPROBE(do_mov_5934)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x112")
int BPF_KPROBE(do_mov_5935)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x11a")
int BPF_KPROBE(do_mov_5936)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x12d")
int BPF_KPROBE(do_mov_5937)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x131")
int BPF_KPROBE(do_mov_5938)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x178")
int BPF_KPROBE(do_mov_5939)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/__ipv6_sock_mc_join + 0x1b4")
int BPF_KPROBE(do_mov_5940)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x30")
int BPF_KPROBE(do_mov_5941)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x3c")
int BPF_KPROBE(do_mov_5942)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x45")
int BPF_KPROBE(do_mov_5943)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x4a")
int BPF_KPROBE(do_mov_5944)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x6c")
int BPF_KPROBE(do_mov_5945)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x7a")
int BPF_KPROBE(do_mov_5946)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x82")
int BPF_KPROBE(do_mov_5947)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x89")
int BPF_KPROBE(do_mov_5948)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x8d")
int BPF_KPROBE(do_mov_5949)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x95")
int BPF_KPROBE(do_mov_5950)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x98")
int BPF_KPROBE(do_mov_5951)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x9c")
int BPF_KPROBE(do_mov_5952)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0xa1")
int BPF_KPROBE(do_mov_5953)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0xab")
int BPF_KPROBE(do_mov_5954)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0xd4")
int BPF_KPROBE(do_mov_5955)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0xe7")
int BPF_KPROBE(do_mov_5956)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x108")
int BPF_KPROBE(do_mov_5957)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x114")
int BPF_KPROBE(do_mov_5958)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x11f")
int BPF_KPROBE(do_mov_5959)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x126")
int BPF_KPROBE(do_mov_5960)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x12e")
int BPF_KPROBE(do_mov_5961)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x132")
int BPF_KPROBE(do_mov_5962)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x1a7")
int BPF_KPROBE(do_mov_5963)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x262")
int BPF_KPROBE(do_mov_5964)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x288")
int BPF_KPROBE(do_mov_5965)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x2ad")
int BPF_KPROBE(do_mov_5966)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x2ca")
int BPF_KPROBE(do_mov_5967)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x2de")
int BPF_KPROBE(do_mov_5968)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x3d3")
int BPF_KPROBE(do_mov_5969)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x414")
int BPF_KPROBE(do_mov_5970)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x41d")
int BPF_KPROBE(do_mov_5971)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x434")
int BPF_KPROBE(do_mov_5972)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x440")
int BPF_KPROBE(do_mov_5973)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x45a")
int BPF_KPROBE(do_mov_5974)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x4e2")
int BPF_KPROBE(do_mov_5975)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x53c")
int BPF_KPROBE(do_mov_5976)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x586")
int BPF_KPROBE(do_mov_5977)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x5bd")
int BPF_KPROBE(do_mov_5978)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x5ef")
int BPF_KPROBE(do_mov_5979)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x5fe")
int BPF_KPROBE(do_mov_5980)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x606")
int BPF_KPROBE(do_mov_5981)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x61d")
int BPF_KPROBE(do_mov_5982)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x644")
int BPF_KPROBE(do_mov_5983)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x691")
int BPF_KPROBE(do_mov_5984)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x6ae")
int BPF_KPROBE(do_mov_5985)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x74b")
int BPF_KPROBE(do_mov_5986)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x783")
int BPF_KPROBE(do_mov_5987)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x7b0")
int BPF_KPROBE(do_mov_5988)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x7bd")
int BPF_KPROBE(do_mov_5989)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x7f1")
int BPF_KPROBE(do_mov_5990)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x825")
int BPF_KPROBE(do_mov_5991)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x842")
int BPF_KPROBE(do_mov_5992)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x86b")
int BPF_KPROBE(do_mov_5993)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x87e")
int BPF_KPROBE(do_mov_5994)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x8f3")
int BPF_KPROBE(do_mov_5995)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x95d")
int BPF_KPROBE(do_mov_5996)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x984")
int BPF_KPROBE(do_mov_5997)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x9a0")
int BPF_KPROBE(do_mov_5998)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x9b7")
int BPF_KPROBE(do_mov_5999)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x9d7")
int BPF_KPROBE(do_mov_6000)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0x9f4")
int BPF_KPROBE(do_mov_6001)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0xa1a")
int BPF_KPROBE(do_mov_6002)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/mld_query_work + 0xa43")
int BPF_KPROBE(do_mov_6003)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_msfget + 0x28")
int BPF_KPROBE(do_mov_6004)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_msfget + 0xbd")
int BPF_KPROBE(do_mov_6005)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_msfget + 0xdb")
int BPF_KPROBE(do_mov_6006)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_msfget + 0x115")
int BPF_KPROBE(do_mov_6007)
{
    u64 addr = ctx->ax;
    if (check(addr)) bpf_printk("-\n");
    return 0;
}


SEC("kprobe/ip6_mc_msfget + 0x11d")
{
}


{
