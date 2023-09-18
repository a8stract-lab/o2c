# LLVM PASS static analysis

based on hot_bpf_analyzer

tasks:
- input a function -> return which types of struct can be allocated.
- input function -> return which types of struct can be written / read

**此处是llvm版本更新之后存在的一个恶心问题，call kmalloc， 调试信息回被直接定位到include/linux/slab.h，callinst和bitcastinst都是一样的，free就没有这种问题**


```
./analyzer -struct bpf_prog `find ~/Documents/ebpf-detector/linux-llvm-6.1 -name "*.ll"`
./analyzer -struct  `find ~/Documents/ebpf-detector/linux-llvm-6.1 -name "*.ll"`

make -j32 && ./analyzer -struct msg_msg `find ~/Documents/ebpf-detector/linux-llvm-6.1/ipc -name "*.ll"`


make -j32 && ./analyzer -func2alloc load_msg `find ~/Documents/ebpf-detector/linux-llvm-6.1/ipc -name "*.ll"`
make -j32 && ./analyzer -func2struct load_msg `find ~/Documents/ebpf-detector/linux-llvm-6.1/ipc -name "*.ll"`
```