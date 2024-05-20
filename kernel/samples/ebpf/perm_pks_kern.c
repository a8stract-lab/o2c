
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <bpf/bpf_helpers.h>


// ffffffff810013f0 <hackme_read>:
// ffffffff810013f0:       e8 0b 68 07 00          call   ffffffff81077c00 <__fentry__>    ffffffff810013f1: R_X86_64_PLT32        __fentry__-0x4
// ffffffff810013f5:       55                      push   %rbp
// ...
// ffffffff810014f1:       bf c0 0c 00 00          mov    $0xcc0,%edi
// ffffffff810014f6:       e8 f5 9a 2e 00          call   ffffffff812eaff0 <__get_free_pages>      ffffffff810014f7: R_X86_64_PLT32        __get_free_pages-0x4
// ffffffff810014fb:       48 c7 c7 7d 50 58 82    mov    $0xffffffff8258507d,%rdi ffffffff810014fe: R_X86_64_32S  .rodata+0x38507d
// ...
// ffffffff81001586:       e8 75 d1 2e 00          call   ffffffff812ee700 <free_pages>    ffffffff81001587: R_X86_64_PLT32        free_pages-0x4
// ffffffff8100158b:       be 80 00 00 00          mov    $0x80,%esi



SEC("kprobe/hackme_read+5")
int BPF_KPROBE(prog0)
{
    // struct task_struct *tsk = (struct task_struct *) bpf_get_current_task();
    // bpf_printk("%s\n", BPF_CORE_READ(tsk, comm));

    u64 pks = bpf_pks_get_pks();

    bpf_printk("pks: %016lx\n", pks);

    bpf_pks_set_pks(0x0f0ff0f0);

    pks = bpf_pks_get_pks();

    bpf_printk("pks: %016lx\n", pks);

    return 0;
}


// python -c 'print(hex(0xffffffff810014fb - 0xffffffff810013f0))'
SEC("kprobe/hackme_read+0x10b")
int BPF_KPROBE(prog1)
{
    u64 allocated_memory = ctx->ax;

    u64 pte = bpf_pks_get_pte(allocated_memory);

    bpf_printk("1: pte: %016lx\n", pte);

    return 0;   
}


// python -c 'print(hex(0xffffffff81001586 - 0xffffffff810013f0))'
SEC("kprobe/hackme_read+0x196")
int BPF_KPROBE(prog2)
{
    u64 allocated_memory = ctx->di;

    u64 pte = bpf_pks_get_pte(allocated_memory);

    bpf_printk("2: pte: %016lx\n", pte);

    bpf_pks_set_pte(allocated_memory, 2);

    pte = bpf_pks_get_pte(allocated_memory);

    bpf_printk("3: pte: %016lx\n", pte);

    bpf_pks_set_pks(0xc0);

    u64 pks = bpf_pks_get_pks();

    bpf_printk("4: pks: %016lx\n", pks);



    return 0;
}

        //   <...>-570     [001] d..31  7346.499844: bpf_trace_printk: pks: 00000000fffffff0

        //    <...>-570     [001] d..31  7346.499877: bpf_trace_printk: pks: 000000000f0ff0f0

        //    <...>-570     [001] d.Z21  7346.499967: bpf_trace_printk: 1: pte: 800000000771c163


        //    <...>-570     [001] d.Z21  7346.500307: bpf_trace_printk: 2: pte: 880000000771c163

        //    <...>-570     [001] d.Z21  7346.500335: bpf_trace_printk: 3: pte: 980000000771c163


        //    <...>-570     [001] d.Z21  7346.500354: bpf_trace_printk: 4: pks: 00000000000000f0


        //      cat-570     [001] d..31  7346.502148: bpf_trace_printk: pks: 00000000000000f0

        //      cat-570     [001] d..31  7346.502168: bpf_trace_printk: pks: 000000000f0ff0f0





char LICENSE[] SEC("license") = "Dual BSD/GPL";
