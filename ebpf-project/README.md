# eBPF projects

fork from [![Github Actions](https://github.com/libbpf/libbpf-bootstrap/actions/workflows/build.yml/badge.svg)](https://github.com/libbpf/libbpf-bootstrap/actions/workflows/build.yml)



# ksample

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

# klifecycle

calculate the lifecycle of each object allocated from `kmalloc-xxx`

because the data allocation is huge, we only measure 30s.

the results shows >= 96% object last less than 1s, average lifetime is 0.18s, median is 0.0025.

![distribution](../figs/lifecycle%20distribution.png)