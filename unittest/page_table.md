# page table solution:

- change most page to 4K
## 1. kernel pages(except vmalloc): page table walk to get.
`bpf_loop` to get a page table walk.


## 2. user space page tables: 
- catch all pt allocation functions, 
    - `vm_area_struct`: there is a dedicate cache,  `vm_area_alloc`, protect the entire cache.
    - `mm_struct` : there is a dedicate cache, `mm_alloc`, protect the entire cache.
    - `pgd_alloc`
    - `__pud_alloc`
    - `__pmd_alloc`
    - `__pte_alloc`
- protect page tables
    - set PKS to protect
- only specific syscalls/operations are available to change with permission. 
    - clone
    - fork
    - mmap
    - munmap
    - mprotect
    - mremap
    - brk
    - exit
    - *handle_mm_fault*
    - execve
    - do_writepages
    - do_exit
    - exit_mmap
    - __x64_sys_exit_group
- verify page table update operations.
    - native_set_pte
    - native_set_pmd
    - native_set_pud
**此处为了便于eBPF捕捉，我们取消了native_set_\*的inline定义**
## 3. vmalloc 

as well as `module_alloc`, `__bpf_map_area_alloc`, 

- struct `vm_struct`, allocated from `__get_vm_area_node`, not in a dedicate cache
- `vmap_area` is the core structure, allocated from dedicate cache `alloc_vmap_area`
- catch all `__vmalloc_node_range`






```sh
bpftrace -e 'kprobe:mmap_region {@a[kstack]=count();  printf("-\n");}  kprobe:alloc_pmd_page {@b[kstack]=count();  printf("=\n");}  kprobe:alloc_pte_page {@c[kstack]=count();  printf("+\n");}  kprobe:alloc_pgtable_page {@d[kstack]=count();  printf("^\n");}'
bpftrace -e 'kprobe:alloc_pmd_page {@b[kstack]=count();  printf("=\n");}  kprobe:alloc_pte_page {@c[kstack]=count();  printf("+\n");}  kprobe:alloc_pgtable_page {@d[kstack]=count();  printf("^\n");}'
bpftrace -e 'kprobe:pgd_alloc {@e[kstack]=count(); printf("v\n");}'
bpftrace -e 'kprobe:pgd_alloc {@a[kstack]=count(); printf("a\n");}  kprobe:__pud_alloc {@fb[kstack]=count(); printf("b\n");}  kprobe:__pmd_alloc {@c[kstack]=count(); printf("c\n");}   kprobe:__pte_alloc {@d[kstack]=count(); printf("d\n");}'

bpftrace -e 'kprobe:set_pte {@e[kstack]=count(); printf("e\n");}'

bpftrace -e 'kprobe:native_set_pte {@f[kstack]=count(); }    kprobe:native_set_pmd {@g[kstack]=count(); }   kprobe:native_set_pud {@h[kstack]=count(); }' -o setpt.txt

bpftrace -e 'tracepoint:irq:irq_handler_entry {@cc[args->irq]=count();}     kprobe:native_set_pmd {@g[kstack]=count(); }   kprobe:native_set_pud {@h[kstack]=count(); }'

bpftrace -l | grep pmd_alloc

@a[
    pgd_alloc+1
    mm_alloc+78
    alloc_bprm+138
    do_execveat_common.isra.0+105
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 21405
@a[
    pgd_alloc+1
    dup_mm+82
    copy_process+3943
    kernel_clone+157
    __do_sys_clone+102
    __x64_sys_clone+37
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 33783
@c[
    __pmd_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
]: 435
@c[
    __pmd_alloc+1
    shift_arg_pages+230
    setup_arg_pages+679
    load_elf_binary+893
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 16690
@c[
    __pmd_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
    clear_user_rep_good+14
    load_elf_binary+5235
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 17694
@c[
    __pmd_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
    clear_user_rep_good+14
    load_elf_binary+1846
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 17783
@c[
    __pmd_alloc+1
    handle_mm_fault+186
    __get_user_pages+491
    __get_user_pages_remote+216
    get_user_pages_remote+33
    get_arg_page+99
    copy_string_kernel+171
    do_execveat_common.isra.0+285
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 21401
@c[
    __pmd_alloc+1
    dup_mmap+1192
    dup_mm+102
    copy_process+3943
    kernel_clone+157
    __do_sys_clone+102
    __x64_sys_clone+37
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 103447
@d[
    __pte_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
    __put_user_nocheck_8+3
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 12
@d[
    __pte_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
    copy_user_generic_string+49
    load_elf_binary+3632
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 28
@d[
    __pte_alloc+1
    shift_arg_pages+230
    setup_arg_pages+679
    load_elf_binary+893
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 17781
@d[
    __pte_alloc+1
    handle_mm_fault+186
    __get_user_pages+491
    __get_user_pages_remote+216
    get_user_pages_remote+33
    get_arg_page+99
    copy_string_kernel+171
    do_execveat_common.isra.0+285
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 21399
@d[
    __pte_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
]: 27065
@d[
    __pte_alloc+1
    dup_mmap+1192
    dup_mm+102
    copy_process+3943
    kernel_clone+157
    __do_sys_clone+102
    __x64_sys_clone+37
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 198586
@fb[
    __pud_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
]: 90
@fb[
    __pud_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
    clear_user_rep_good+14
    load_elf_binary+5235
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 9030
@fb[
    __pud_alloc+1
    handle_mm_fault+186
    do_user_addr_fault+446
    exc_page_fault+118
    asm_exc_page_fault+39
    clear_user_rep_good+14
    load_elf_binary+1846
    bprm_execve+638
    do_execveat_common.isra.0+415
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 17748
@fb[
    __pud_alloc+1
    handle_mm_fault+186
    __get_user_pages+491
    __get_user_pages_remote+216
    get_user_pages_remote+33
    get_arg_page+99
    copy_string_kernel+171
    do_execveat_common.isra.0+285
    __x64_sys_execve+55
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 21402
@fb[
    __pud_alloc+1
    dup_mmap+1192
    dup_mm+102
    copy_process+3943
    kernel_clone+157
    __do_sys_clone+102
    __x64_sys_clone+37
    do_syscall_64+86
    entry_SYSCALL_64_after_hwframe+70
]: 85941
```