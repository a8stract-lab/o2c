
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

int count = 0;
// SEC("kprobe/__kmalloc")
// int bpf_prog1(struct pt_regs *ctx)
// {
//     ++count;
//     // if (count % 10 == 0)
//         bpf_printk("--%d--\n", count);
//     return 0;
// }

// ffffffff813916f0 <single_open>:
// ...
// ffffffff8139171a:       e8 31 f6 f1 ff          call   ffffffff812b0d50 <kmalloc_trace> ffffffff8139171b: R_X86_64_PLT32        kmalloc_trace-0x4
// ffffffff8139171f:       48 85 c0                test   %rax,%rax

// python3 -c 'print(hex(0xffffffff8139171a-0xffffffff813916f0))'
SEC("kprobe/single_open+0x5")
int BPF_KPROBE(prog2)
{
    bpf_printk("==%lx===\n", ctx->ip);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

