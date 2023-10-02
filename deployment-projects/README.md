# 如何部署

1. get all functions of a module / target function
2. get all structures, according to the step 1.
3. get all call / icall / ret / mov and generate bpf instrumentation
4. get all allocation site and generate bpf hotbpf according to step 2

## step 1: get all functions of a module / target function

```sh
cd net/ipv6/

find ./ -name "*.o" | xargs nm  | grep -i ' T ' |  awk '{print $3}' > ipv6-functions.txt


cd net/netfilter
find ./ -name "*.o" | xargs nm  | grep -i ' T ' |  awk '{print $3}' > netfilter-functions.txt


sudo bpftrace -l | grep kprobe | awk -F: '{print $2}' > kprobe_lists.txt




find ipc/ -name '*.o' | xargs nm -g | grep ' T ' |  awk '{print $3}' > exported_functions.txt
find arch/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
find block/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
find kernel/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
find mm/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
find security/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
find init/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
find virt/ -name '*.o' | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
ls net/*.o | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
ls net/core/*.o | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
ls fs/*.o | xargs nm -g | grep ' T '|  awk '{print $3}' >> exported_functions.txt
```

<!-- ## step 2: get all structures

python scripts is `get_all_structs.py`, we need set `llvm_ir_path` and `llvm_analyze_path` -->


## step 3: get all call / icall / ret / mov

ghidra scripts to get all related instructions into a csv.

we use python to extract the csv and generate the instrumented bpf.

## step 4: get all allocation site and generate bpf hotbpf

first of all, we need to get all allocations, make sure which objects are allocated by kmem_cache_alloc, remove them.

这个要不这样，先设置一个flag，在所有插装的里面都打开flag，如果flag被打开了，那么所有的object都在x中分配


## 0922主要挑战

给kmalloc插装查表开销太大了，一般能3%，osbench能到30-70%

这意味着mov instruction插装查表开销也太大了

最好能知道每个instruction 能写的类型是什么？ 相当于WIT有理论证明吗？ 看看uscope的基础项目


## 优化

只有`ctx->bp/sp + ctx->ax * x`,才需要监控，其他的`ctx->bp/sp + x`都没影响

常量写通常都是`ctx->ip + x` 其实相当于一个具体的地址，也不需要监控


# 1. analyzer 

## static analysis

- code / global: 100%
- slab: dedicate cache / types: alias analysis: ok
- struct page/folio: 100%
- vmalloc: already know the caller: 100%
---------
- slab: no types: assign an type after allocation, can also be analyzed
- buddy: assign an type after allocation, can also be analyzed

## dynamic analysis

optimization: 清楚地知道每条指令都在写什么，而且根据fuzzing假设，覆盖率都是100%

- code / global: 100%
- slab: dedicate cache/types: ok
- vmalloc: ok
- slab: module 分配的，hotbpf处理了
- slab no type： 多数其实被module分配的包含了，剩下的应该微不足道
- struct page/folio: 100%
- buddy: 记录分配地址和调用栈



## ML / working policy

## 1. general: 利用静态分析的结果
> todo: legal access range of an function!

```c
if (addr >= 0xffff888000000000 && addr < 0xffffc87fffffffff) {
    struct kmem_cache *s = bpf_get_slab_cache(addr);
    if (s) {
        // slab: match cache
        u64 cache = bpf_get_slab_cache(addr);
        u64 *pv = bpf_map_lookup_elem(&slabcaches, &cache);
        if (pv) {}
    } else {
        // buddy: match call trace
        u64 *pv = bpf_map_lookup_elem(&buddy, &addr);
        if (pv && stkid == *pv) {}
    } else {
        if (ML_enable) {
            bpf_map_update_elem(&ml_record, &addr, &val, BPF_ANY);
        }
    }
} else if (is_vmalloc()) {
    u64 vms = bpf_get_vm_struct(addr);
    u64 caller = BPF_CORE_READ(vms, caller);
    u64 *pv = bpf_map_lookup_elem(&map, &pv);
    if (pv);
}
```

## mov-to-stk (ctx->sp/bp + ctx->ax * x)

```c

u64 addr = ctx->sp/bp + ctx->ax * x;
if (addr >= ctx->sp && addr <= ctx->bp) {}

```

## mov-to-slab

```c
u64 cache = bpf_get_slab_cache(addr);
if (cache == HOTBPF_CACHE/DEDICATE_CACHE) {}
else {
    if (ML_enable) {
        u64 start = bpf_get_slab_start(addr);
        bpf_map_update_elem(&ml_record, &start, &val, BPF_ANY);
    } else { /* error happens */ }
}
```

## mov-to-buddy

```c
u64 *pv = bpf_map_lookup_elem(&buddy, &addr);
if (pv) {}
else {
    if (ML_enable) {
        bpf_map_update_elem(&ml_record, &addr, &val, BPF_ANY);
    } else { /* error happens */ }
}
```


## mov-to-vmalloc

```c
u64 vms = bpf_get_vm_struct(addr);
u64 caller = BPF_CORE_READ(vms, caller);
u64 *pv = bpf_map_lookup_elem(&map, &pv);
if (pv) {}
else { /* error happens */ }
```

## mov-to-vmem_map

```c
if (addr >= 0xffffea0000000000 && addr <= 0xffffeaffffffffff) {}
else { /* error happens */ }
```

> 1. timer to open & off ml policy
> 2. mm_page_alloc record allocations with specific id
> 3. hotbpf
> 4. callsite
> 5. write other
> 6. write stack
> 7. icall