# 如何部署

1. get all functions of a module / target function
2. get all structures, according to the step 1.
3. get all call / icall / ret / mov and generate bpf instrumentation
4. get all allocation site and generate bpf hotbpf according to step 2

## step 1: get all functions of a module / target function

```sh
cd net/ipv6/

find ./ -name "*.o" | xargs nm -g | grep ' T ' |  awk '{print $3}' > ipv6-function.txt
```

## step 2: get all structures

python scripts is `get_all_structs.py`, we need set `llvm_ir_path` and `llvm_analyze_path`


## step 3: get all call / icall / ret / mov

ghidra scripts to get all related instructions into a csv.

we use python to extract the csv and generate the instrumented bpf.

## step 4: get all allocation site and generate bpf hotbpf

first of all, we need to get all allocations, make sure which objects are allocated by kmem_cache_alloc, remove them.

这个要不这样，先设置一个flag，在所有插装的里面都打开flag，如果flag被打开了，那么所有的object都在x中分配