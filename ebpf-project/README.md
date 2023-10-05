# eBPF projects

fork from [![Github Actions](https://github.com/libbpf/libbpf-bootstrap/actions/workflows/build.yml/badge.svg)](https://github.com/libbpf/libbpf-bootstrap/actions/workflows/build.yml)



# 1. ksample

 dump `kmalloc-xxx` allocation **function and content** from kernel.

 set `ALLOC_SZ` in `ksample.h` to decide the sampling slub cache `kmalloc-ALLOC_SZ`

 store output files in the `make clean && make -j32 && sudo ./ksample > kmalloc-ALLOC_SZ.csv`

```sh
sudo bpftrace -e 'tracepoint:kmem:kmalloc { if ((args->gfp_flags & 0x400011) == 0){ @[args->bytes_alloc]=count(); }}'
Attaching 1 probe...
^C

@[32768]: 24
@[16384]: 1642


@[8192]: 1826
@[256]: 2042
@[1024]: 2138
@[512]: 4408
@[2048]: 8088
@[192]: 8163
@[32]: 12471
@[96]: 13404
@[128]: 14019
@[4096]: 17832
@[8]: 51556
@[64]: 55306
@[16]: 121119
```

# 2. klifecycle

calculate the lifecycle of each object allocated from `kmalloc-xxx`

because the data allocation is huge, we only measure 30s.

the results shows >= 96% object last less than 1s, average lifetime is 0.18s, median is 0.0025.

![distribution](../figs/lifecycle%20distribution.png)

```sh
sudo bpftrace -e '
tracepoint:kmem:kmalloc {@rec[args->ptr]=nsecs;}
tracepoint:kmem:kfree /@rec[args->ptr]!=0/{print(nsecs-@rec[args->ptr]); delete(@rec[args->ptr]);}
interval:s:1200 {exit();}
' -o trace-kmalloc.txt

sudo bpftrace -e '
tracepoint:kmem:kmem_cache_alloc {@rec[args->ptr]=nsecs;}
tracepoint:kmem:kmem_cache_free /@rec[args->ptr]!=0/{print(nsecs-@rec[args->ptr]); delete(@rec[args->ptr]);}
interval:s:1200 {exit();}
' -o trace-kmem_cache_alloc.txt

sudo bpftrace -e '
tracepoint:kmem:mm_page_alloc {@rec[args->pfn]=nsecs;}
tracepoint:kmem:mm_page_free /@rec[args->pfn]!=0/{print(nsecs-@rec[args->pfn]); delete(@rec[args->pfn]);}
interval:s:1200 {exit();}
' -o trace-mm_page_alloc.txt

# ===========================================

sudo bpftrace -e '
tracepoint:kmem:kmalloc {@rec[args->ptr]=nsecs;}
tracepoint:kmem:kfree /@rec[args->ptr]!=0/{$x=(nsecs-@rec[args->ptr]); if ($x > 10*1000000000){@[kstack()]=count();} delete(@rec[args->ptr]);}
interval:s:1200 {exit();}
' -o trace-kmalloc1.txt

sudo bpftrace -e '
tracepoint:kmem:kmem_cache_alloc {@rec[args->ptr]=nsecs;}
tracepoint:kmem:kmem_cache_free /@rec[args->ptr]!=0/{$x=(nsecs-@rec[args->ptr]); if ($x > 60*1000000000){@[kstack()]=count();} delete(@rec[args->ptr]);}
interval:s:1200 {exit();}
' -o trace-kmem_cache_alloc1.txt

sudo bpftrace -e '
tracepoint:kmem:mm_page_alloc {@rec[args->pfn]=nsecs;}
tracepoint:kmem:mm_page_free /@rec[args->pfn]!=0/{$x=(nsecs-@rec[args->pfn]); if ($x > 60*1000000000){@[kstack()]=count();} delete(@rec[args->pfn]);}
interval:s:1200 {exit();}
' -o trace-mm_page_alloc1.txt


```



# 3. count allocations per second

`sudo bpftrace -e 'tracepoint:kmem:kmalloc { @counts[args->bytes_alloc] = count(); @sum=count(); } interval:s:1 { print(@counts); print(@sum);clear(@sum); clear(@counts); printf("\n\n\n");}'`

- os: ubuntu-desktop 22.04 (tons of i1915 graphics objects)
- cpu: intel-i9 13900hx, 32 cores
- ram: 64GB


```c
Attaching 2 probes...
@counts[16384]: 2
@counts[8192]: 4
@counts[256]: 19
@counts[96]: 36
@counts[192]: 36
@counts[128]: 72
@counts[2048]: 80
@counts[8]: 110
@counts[16]: 245
@counts[1024]: 249
@counts[64]: 321
@counts[512]: 387
@counts[32]: 1245
@counts[4096]: 1323
@sum: 4165



@counts[16384]: 2
@counts[8192]: 5
@counts[256]: 15
@counts[96]: 29
@counts[192]: 45
@counts[2048]: 74
@counts[32]: 100
@counts[128]: 109
@counts[8]: 135
@counts[4096]: 199
@counts[16]: 200
@counts[1024]: 228
@counts[64]: 282
@counts[512]: 341
@sum: 1839



@counts[16384]: 1
@counts[8192]: 6
@counts[256]: 20
@counts[192]: 55
@counts[128]: 73
@counts[96]: 73
@counts[2048]: 95
@counts[8]: 187
@counts[1024]: 252
@counts[64]: 357
@counts[16]: 379
@counts[512]: 394
@counts[32]: 1314
@counts[4096]: 1362
@sum: 4642

```