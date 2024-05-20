
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <bpf/bpf_helpers.h>
#include <linux/fs.h>

const char perm_prefix[] = "perm_";

bool isStandalone(void) 
{
    const char curr_comm[20];
    bpf_get_current_comm(curr_comm, 20);
    u32 cmp = bpf_strncmp(curr_comm, 5, perm_prefix);
    return cmp == 0;
}

// static int bpf_prog_release(struct inode *inode, struct file *filp)
SEC("kprobe/bpf_prog_release")
int BPF_KPROBE(prog0, struct inode *inode, struct file *filp)
{
    
    // bpf_printk("%s: %d\n", curr_comm, (cmp==0));
    if (isStandalone()) {
        bpf_override_return(ctx, 0);
        bpf_printk("override bpf_prog_release\n");
    }

    return 0;
}

// static int bpf_link_release(struct inode *inode, struct file *filp)
SEC("kprobe/bpf_link_release")
int BPF_KPROBE(prog1)
{
    if (isStandalone()) {
        bpf_printk("override bpf_link_release\n");
        bpf_override_return(ctx, 0);
    }

    return 0;
}

// static int bpf_map_release(struct inode *inode, struct file *filp)
SEC("kprobe/bpf_map_release")
int BPF_KPROBE(prog2)
{
    if (isStandalone()) {
        bpf_printk("override bpf_map_release\n");
        bpf_override_return(ctx, 0);
    }

    return 0;
}

// static int btf_release(struct inode *inode, struct file *filp)
SEC("kprobe/btf_release")
int BPF_KPROBE(prog3)
{
    if (isStandalone()) {
        bpf_printk("override btf_release\n");
        bpf_override_return(ctx, 0);
    }

    return 0;
}

// SEC("kprobe/bpf_map_release")
// int BPF_KPROBE(prog3)
// {


//     return 0;
// }




char LICENSE[] SEC("license") = "Dual BSD/GPL";
