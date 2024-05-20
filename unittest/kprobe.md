# solution

**如何增加关中断和trampoline？**

- 所有的都用int3
- ftrace 替换成 func+0x1，相当于逃课
- kprobe优化：`jmp`, 测试短长度指令优化效果

- `do_int3` -> `kprobe_int3_handler` -> switch stack here

```
Replace breakpoints (INT3) with relative jumps (JMP.d32).
Caller must call with locking kprobe_mutex and text_mutex.

The caller will have installed a regular kprobe and after that issued
syncrhonize_rcu_tasks(), this ensures that the instruction(s) that live in
the 4 bytes after the INT3 are unused and can now be overwritten.
```

**kprobe优化：jmp handler， otherwise interrupt to handler**， after that 


```c
#0  kprobe_running () at ./include/linux/kprobes.h:402
#1  optimized_callback (op=0xffff888009cb83c0, regs=0xffffc900005b7b00) at arch/x86/kernel/kprobes/opt.c:183
#2  0xffffffffc0203039 in ?? ()


#0  kprobe_dispatcher (kp=0xffff888007626218, regs=0xffff888003e6bb38) at kernel/trace/trace_kprobe.c:1661
#1  0xffffffff8107aef5 in kprobe_int3_handler (regs=regs@entry=0xffff888003e6bb38) at arch/x86/kernel/kprobes/core.c:981
#2  0xffffffff810365ef in do_int3 (regs=regs@entry=0xffff888003e6bb38) at arch/x86/kernel/traps.c:800
#3  0xffffffff81cf7282 in exc_int3 (regs=0xffff888003e6bb38) at arch/x86/kernel/traps.c:846
#4  0xffffffff81e00aaa in asm_exc_int3 () at ./arch/x86/include/asm/idtentry.h:569
#5  0x0000000000000000 in ?? ()
```

pks测试，trigger page fault start
1GB page优化，新vmalloc 优化

jmp的指令到底是啥，为什么这么短？

无论是否优化最后都会到kprobe_dispatcher吗？

<!-- - the replaced instruction `jmp 0xffffffffc0203000`
- called from `0xffffffffc0203039`-> -->
* `jmp 0xffffffffc0203081` / `jmp 0xffffffffc0203102`

- `optimized_callback`->`opt_pre_handler`->`kprobe_dispatcher`->`kprobe_perf_func`->`trace_call_bpf`
	- `bpf_prog_run_array`->`bpf_prog_run`

```c
static struct kprobe *alloc_aggr_kprobe(struct kprobe *p)
	struct optimized_kprobe *op;
	op = kzalloc(sizeof(struct optimized_kprobe), GFP_KERNEL);
```

# kprobe 

kprobes will be optimized to `ftrace`(at the beginning) and `call`

```c
#0  alloc_aggr_kprobe (p=p@entry=0xffff88800a453d18) at kernel/kprobes.c:832
#1  0xffffffff811a0738 in try_to_optimize_kprobe (p=0xffff88800a453d18) at kernel/kprobes.c:866
#2  register_kprobe (p=0xffff88800a453d18) at kernel/kprobes.c:1666
#3  0xffffffff811fae44 in __register_trace_kprobe (tk=tk@entry=0xffff88800a453d00) at kernel/trace/trace_kprobe.c:510
#4  0xffffffff811fde01 in create_local_trace_kprobe (func=func@entry=0xffff88800678ea00 "single_open", addr=<optimized out>, offs=<optimized out>, 
    is_return=is_return@entry=false) at kernel/trace/trace_kprobe.c:1783
#5  0xffffffff811e2ce2 in perf_kprobe_init (p_event=p_event@entry=0xffff888003e761b0, is_retprobe=<optimized out>) at kernel/trace/trace_event_perf.c:271
#6  0xffffffff81263953 in perf_kprobe_event_init (event=0xffff888003e761b0) at kernel/events/core.c:10045
#7  0xffffffff812658aa in perf_try_init_event (pmu=pmu@entry=0xffffffff82fc7a20 <perf_kprobe>, event=event@entry=0xffff888003e761b0) at kernel/events/core.c:11427
#8  0xffffffff81269240 in perf_init_event (event=0xffff888003e761b0) at kernel/events/core.c:11491
#9  perf_event_alloc (attr=attr@entry=0xffffc9000017fe20, cpu=cpu@entry=0, task=task@entry=0x0 <fixed_percpu_data>, group_leader=0xffff888003e761b0, 
    group_leader@entry=0x0 <fixed_percpu_data>, parent_event=parent_event@entry=0x0 <fixed_percpu_data>, overflow_handler=<optimized out>, 
    overflow_handler@entry=0x0 <fixed_percpu_data>, context=<optimized out>, cgroup_fd=-1) at kernel/events/core.c:11782
#10 0xffffffff8126f1d4 in __do_sys_perf_event_open (attr_uptr=<optimized out>, pid=<optimized out>, cpu=0, group_fd=<optimized out>, flags=<optimized out>)
    at kernel/events/core.c:12318
#11 0xffffffff8126ffe2 in __se_sys_perf_event_open (flags=<optimized out>, group_fd=<optimized out>, cpu=<optimized out>, pid=<optimized out>, attr_uptr=<optimized out>)
    at kernel/events/core.c:12210
#12 __x64_sys_perf_event_open (regs=<optimized out>) at kernel/events/core.c:12210
#13 0xffffffff81cf7146 in do_syscall_x64 (nr=<optimized out>, regs=0xffffc9000017ff58) at arch/x86/entry/common.c:50
#14 do_syscall_64 (regs=0xffffc9000017ff58, nr=<optimized out>) at arch/x86/entry/common.c:80
#15 0xffffffff81e0006a in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:120
#16 0x0000000000000005 in fixed_percpu_data ()
#17 0x00007ffd2391cf30 in ?? ()
#18 0x0000000000000000 in ?? ()
```


- `register_kprobe` -> `try_to_optimize_kprobe`
    - `optimize_kprobe` -> `kick_kprobe_optimizer()`
    - `static DECLARE_DELAYED_WORK(optimizing_work, kprobe_optimizer);`
    - 

add trampoline，in `void arch_optimize_kprobes(struct list_head *oplist)`

optimized to `jmp` instruction.


## kprobes structures protection

-  `struct kprobe` 一般是静态定义的，在eBPF里面怎么搞成动态的？


## ftrace 

- `__register_ftrace_function`
- `register_ftrace_function`
- `unregister_ftrace_function`

```c
static void ftrace_update_trampoline(struct ftrace_ops *ops)
{
	unsigned long trampoline = ops->trampoline;

	arch_ftrace_update_trampoline(ops);
	if (ops->trampoline && ops->trampoline != trampoline &&
	    (ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP)) {
		/* Add to kallsyms before the perf events */
		ftrace_add_trampoline_to_kallsyms(ops);
		perf_event_ksymbol(PERF_RECORD_KSYMBOL_TYPE_OOL,
				   ops->trampoline, ops->trampoline_size, false,
				   FTRACE_TRAMPOLINE_SYM);
		/*
		 * Record the perf text poke event after the ksymbol register
		 * event.
		 */
		perf_event_text_poke((void *)ops->trampoline, NULL, 0,
				     (void *)ops->trampoline,
				     ops->trampoline_size);
	}
}
```

- `create_trampoline`, in ftrace 

```c
create_trampoline()

memcpy(trampoline + call_offset,
	       text_gen_insn(CALL_INSN_OPCODE,
			     trampoline + call_offset,
			     ftrace_ops_get_func(ops)), CALL_INSN_SIZE);
```