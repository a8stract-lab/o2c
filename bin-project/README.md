# statistic binary instructions and locate the runtime check positions (SFI).

## statistic binary instructions

- total instr
- memory access
- R/W/X
- indirect call
- call
- ret
....

## locate the runtime check positions (offset to function start, target address)

What we need is 
- memory write to memory instructions: e.g. `mov xx, (yy)`
- indirect call: e.g. `call *%rax`
- return: e.g. `ret`

little optimization required on memory access range: 
1. stack only?  `$rsp / $rbp`
2. global only?  `$rip / 0xaddr`
3. must not `stack / global / code`




### e.g. `mov    %rax,-0x30(%rbp)`

- it is an memory access instruction that I need to instrument
- `-0x30(%rbp)` is the target address, extract it and record `rbp-0x30` (for next step generation)
- the offset to the function start is `0x1a`, calculate and record `trace_call_bpf+0x1a`





```s
ffffffff811fb180 <trace_call_bpf>: // record ret addr
ffffffff811fb180:    push   %rbp
...
ffffffff811fb19a:    mov    %rax,-0x30(%rbp)  // check addr
ffffffff811fb19e:    xor    %eax,%eax
...
ffffffff811fb220:    mov    %rcx,0x1458(%rdx)  // check addr
...
ffffffff811fb2ac:    pop    %rbp
ffffffff811fb2ad:    ret                     // check return addr
...
ffffffff811fb2be:    call   *0x30(%rbx)      // check target addr
ffffffff811fb2c1:    mov    0x20(%rbx),%rbx  // read, it is memory access, but no need for our project
```

## technique details

memory write:

- must be global / stack: check global / stack
- rest: 
    - slub: phase0: ML , phase 1:slab caches according to the page
    - buddy: phase0: ML, phase 1: recorded
    - vmalloc: `__vmalloc_node` always have a caller `IP`
        

## optimization

119525 20603 {2: 9126, 4: 2802, 8: 483, 3: 3693, 11: 175, 5: 1241, 7: 623, 6: 920, 9: 297, 16: 99, 20: 39, 12: 147, 15: 86, 10: 261, 22: 15, 17: 54, 13: 125, 24: 16, 18: 36, 14: 105, 34: 4, 21: 31, 26: 9, 29: 12, 27: 14, 55: 2, 59: 1, 31: 9, 19: 33, 23: 21, 46: 3, 25: 22, 36: 5, 49: 4, 28: 10, 146: 1, 39: 4, 50: 1, 61: 2, 32: 9, 40: 3, 35: 7, 43: 2, 57: 2, 33: 6, 97: 1, 30: 9, 41: 5, 56: 3, 38: 1, 105: 1, 104: 1, 78: 1, 51: 2, 87: 1, 44: 2, 45: 2, 47: 3, 67: 2, 103: 1, 42: 1, 65: 1, 48: 2, 58: 1, 53: 2, 37: 1}

optimized:  20026 ,cannot optimized:  [577, 3575]