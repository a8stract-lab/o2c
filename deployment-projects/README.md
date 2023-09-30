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

