
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

int count = 0;

// struct callback_ctx {
// 	int output;
// };

// static int nested_callback1(__u32 index, void *data)
// {
//     bpf_printk("\t===%x===\n", index);
// 	return 0;
// }

// static int func_callback(__u32 index, void *data)
// {
//     // u32 num = *(u32 *)x;
//     struct callback_ctx *ctx = data;
//     bpf_printk("===%x===\n", index);
//     bpf_loop(index, nested_callback1, data, 0);
//     ctx->output += index;
//     // *(u32 *)x++;
//     return 0;
// }

// ffffffff813916f0 <single_open>:
// ...
// ffffffff8139171a:       e8 31 f6 f1 ff          call   ffffffff812b0d50 <kmalloc_trace> ffffffff8139171b: R_X86_64_PLT32        kmalloc_trace-0x4
// ffffffff8139171f:       48 85 c0                test   %rax,%rax

// python3 -c 'print(hex(0xffffffff8139171a-0xffffffff813916f0))'
// SEC("kprobe/single_open+0x2a")
// int BPF_KPROBE(prog2)
// {
//     // bpf_printk("==%lx===\n", ctx->ip);
//     u32 x = 10;
//     struct callback_ctx data = {};

//     bpf_loop(5, func_callback, &data, 0);
//     bpf_printk("output: %x\n", data.output);
//     return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("kretprobe/__pte_alloc_kernel")
int BPF_KRETPROBE(pte0)
{

    return 0;
}

// SEC("kretprobe/pte_alloc_one")
// int BPF_KRETPROBE(pte0)
// {
//     return 0;
// }

// SEC("kretprobe/__pmd_alloc")
// int BPF_KRETPROBE(pte0)
// {
//     return 0;
// }

// SEC("kretprobe/__pud_alloc")
// int BPF_KRETPROBE(pte0)
// {
//     return 0;
// }

// SEC("kretprobe/pgd_alloc")
// int BPF_KRETPROBE(pte0)
// {
//     return 0;
// }