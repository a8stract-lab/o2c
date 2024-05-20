
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <bpf/bpf_helpers.h>

int count = 0;



// #define PAGE_SHIFT		(unsigned long)12
// #define PAGE_SIZE		(unsigned long)(1 << PAGE_SHIFT)
// #define PAGE_MASK		(unsigned long)(~(PAGE_SIZE-1))
#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((((unsigned long)1 << __PHYSICAL_MASK_SHIFT) - 1))
#define PHYSICAL_PAGE_MASK	((PAGE_MASK) & __PHYSICAL_MASK)
// #define PTE_PFN_MASK		(PHYSICAL_PAGE_MASK)
// #define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

// #define _PAGE_BIT_PRESENT	0	/* is present */
// #define _PAGE_BIT_RW		1	/* writeable */
// #define _PAGE_BIT_USER		2	/* userspace addressable */
// #define _PAGE_BIT_PWT		3	/* page write through */
// #define _PAGE_BIT_PCD		4	/* page cache disabled */
// #define _PAGE_BIT_ACCESSED	5	/* was accessed (raised by CPU) */
// #define _PAGE_BIT_DIRTY		6	/* was written to (raised by CPU) */
// #define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page */
// #define _PAGE_BIT_PAT		7	/* on 4KB pages */
// #define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
// #define _PAGE_BIT_SOFTW1	9	/* available for programmer */
// #define _PAGE_BIT_SOFTW2	10	/* " */
// #define _PAGE_BIT_SOFTW3	11	/* " */
// #define _PAGE_BIT_PAT_LARGE	12	/* On 2MB or 1GB pages */
// #define _PAGE_BIT_SOFTW4	58	/* available for programmer */
// #define _PAGE_BIT_PKEY_BIT0	59	/* Protection Keys, bit 1/4 */
// #define _PAGE_BIT_PKEY_BIT1	60	/* Protection Keys, bit 2/4 */
// #define _PAGE_BIT_PKEY_BIT2	61	/* Protection Keys, bit 3/4 */
// #define _PAGE_BIT_PKEY_BIT3	62	/* Protection Keys, bit 4/4 */
// #define _PAGE_BIT_NX		63	/* No execute: only valid after cpuid check */

// #define _PAGE_PRESENT	((unsigned long) 1 << _PAGE_BIT_PRESENT)
// #define _PAGE_RW	((unsigned long) 1 << _PAGE_BIT_RW)
// #define _PAGE_USER	((unsigned long) 1 << _PAGE_BIT_USER)
// #define _PAGE_PWT	((unsigned long) 1 << _PAGE_BIT_PWT)
// #define _PAGE_PCD	((unsigned long) 1 << _PAGE_BIT_PCD)
// #define _PAGE_ACCESSED	((unsigned long) 1 << _PAGE_BIT_ACCESSED)
// #define _PAGE_DIRTY	((unsigned long) 1 << _PAGE_BIT_DIRTY)
// #define _PAGE_PSE	((unsigned long) 1 << _PAGE_BIT_PSE)
// #define _PAGE_GLOBAL	((unsigned long) 1 << _PAGE_BIT_GLOBAL)
// #define _PAGE_SOFTW1	((unsigned long) 1 << _PAGE_BIT_SOFTW1)
// #define _PAGE_SOFTW2	((unsigned long) 1 << _PAGE_BIT_SOFTW2)
// #define _PAGE_SOFTW3	((unsigned long) 1 << _PAGE_BIT_SOFTW3)
// #define _PAGE_PAT	((unsigned long) 1 << _PAGE_BIT_PAT)
// #define _PAGE_PAT_LARGE ((unsigned long) 1 << _PAGE_BIT_PAT_LARGE)
// #define _PAGE_PKEY_BIT0	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT0)
// #define _PAGE_PKEY_BIT1	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT1)
// #define _PAGE_PKEY_BIT2	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT2)
// #define _PAGE_PKEY_BIT3	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT3)

#define GB (u64) (1 << 30)
#define MB (u64) (1 << 20)
#define KB (u64) (1 << 10)

unsigned long pte_to_addr(unsigned long pte) {
    return bpf_get_va(pte & PTE_PFN_MASK);
}

struct pt_data {
    u32 pgd_idx;
    u32 pud_idx;
    u32 pmd_idx;
    u32 pte_idx;
    u64 pgd;
    u64 pud;
    u64 pmd;
    u64 pte;
};



struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // addr
	__type(value, struct pt_data); // pt data
	__uint(max_entries, 10000000);
} ptes SEC(".maps");

u64 get_mapping_range(struct pt_data *pt) 
{
    u64 addr = pt->pgd_idx * 512 * GB;
    addr += pt->pud_idx * GB;
    addr += pt->pmd_idx * 2 * MB;
    addr += pt->pte_idx * 4 * KB;
    addr += 0xffff000000000000;
    return addr;
}

int x = 0;


static int pte_walk_callback(__u32 index, void *data)
{
    struct pt_data *pt = (struct pt_data *) data;
    pt->pte_idx = index;
    u64 addr = pt->pte;
    u64 entry = 0;
    bpf_core_read(&entry, 8, addr + index * 8);
    u64 real_index = pt->pgd_idx * 512 * 512 * 512 + pt->pud_idx * 512 * 512 + pt->pmd_idx * 512 + pt->pte_idx;
    if (entry != 0) {
        // if (x == 1) {
            
        // }
        // else {
            // bpf_printk("\t\tpte[0x%lx]: %016lx\n", real_index, pte_to_addr(entry));
            // pt->pte = pte_to_addr(entry);
            u64 k = pt->pte;
            bpf_map_update_elem(&ptes, &k, pt, BPF_ANY);
            bpf_pks_set_pte(k, 1);
            // x = 1;
        // }
    }
    return 0;
}


static int pmd_walk_callback(__u32 index, void *data) 
{
    struct pt_data *pt = (struct pt_data *) data;
    pt->pmd_idx = index;
    u64 addr = pt->pmd;
    u64 entry = 0;
    u64 real_index = pt->pgd_idx * 512 * 512 + pt->pud_idx * 512 + pt->pmd_idx;
    bpf_core_read(&entry, 8, addr + index * 8);
    if (entry != 0) {
        if ((entry & _PAGE_PSE) != 0) {
        // bpf_printk("\t\tpmd[0x%lx]: %016lx, 2MB:%d\n", real_index, addr, (entry & _PAGE_PSE) != 0);
        // u64 range = get_mapping_range(pt);
        // bpf_printk("\t\t\t[%016lx, %016lx]\n", range, range + 2 * MB - 1);
            u64 k = addr + index * 8;
            bpf_map_update_elem(&ptes, &k, pt, BPF_ANY);
            bpf_pks_set_pte(k, 1);
        } else {
            pt->pte = pte_to_addr(entry);
            bpf_loop(512, pte_walk_callback, data, 0);
            
        }
        
    }
    return 0;
}

static int pud_walk_callback(__u32 index, void *data) 
{
    struct pt_data *pt = (struct pt_data *) data;
    pt->pud_idx = index;
    u64 addr = pt->pud;
    u64 entry = 0;
    bpf_core_read(&entry, 8, addr + index * 8);
    if (entry != 0) {
        if ((entry & _PAGE_PSE) != 0)
            bpf_printk("\tpud[%u]: %016lx, 1GB:%d\n", index, addr, (entry & _PAGE_PSE) != 0);
        // else {
        //     bpf_printk("\tpud[%u]: %016lx, 1GB:%d\n", index, addr, (entry & _PAGE_PSE) != 0);
        // }
        pt->pmd = pte_to_addr(entry);
        bpf_loop(512, pmd_walk_callback, data, 0);
    }
    return 0;
}


static int pgd_walk_callback(__u32 index, void *data)
{
    struct pt_data *pt = (struct pt_data *) data;
    pt->pgd_idx = index;
    u64 addr = pt->pgd;
    u64 entry = 0;
    bpf_core_read(&entry, 8, addr + index * 8);
    if (entry != 0) {
        // bpf_printk("pgd[%u]: %016lx\n", index, addr);
        // struct pud_data data = {};
        pt->pud = pte_to_addr(entry);
        bpf_loop(512, pud_walk_callback, data, 0);
    }
    
    return 0;
}


// python3 -c 'print(hex(0xffffffff8139171a-0xffffffff813916f0))'
SEC("kprobe/single_open")
// SEC("kprobe/hackme_read")
int BPF_KPROBE(prog2)
{
    struct task_struct *tsk = (struct task_struct *) bpf_get_current_task();
    u64 *pgds = BPF_CORE_READ(tsk, active_mm, pgd);
    struct pt_data pt = {0};
    pt.pgd = pgds;

    bpf_loop(512, pgd_walk_callback, &pt, 0);

    // bpf_printk("rdi: %lx\n", ctx->di);
    // bpf_printk("phys: %lx, virt: %lx\n", bpf_get_pa(ctx->di), bpf_get_va(bpf_get_pa(ctx->di)));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
