#include <stdio.h>

#define PAGE_SHIFT		(unsigned long)12
#define PAGE_SIZE		(unsigned long)(1 << PAGE_SHIFT)
#define PAGE_MASK		(unsigned long)(~(PAGE_SIZE-1))
#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((((unsigned long)1 << __PHYSICAL_MASK_SHIFT) - 1))
#define PHYSICAL_PAGE_MASK	((PAGE_MASK) & __PHYSICAL_MASK)
#define PTE_PFN_MASK		(PHYSICAL_PAGE_MASK)
#define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

#define _PAGE_BIT_PRESENT	0	/* is present */
#define _PAGE_BIT_RW		1	/* writeable */
#define _PAGE_BIT_USER		2	/* userspace addressable */
#define _PAGE_BIT_PWT		3	/* page write through */
#define _PAGE_BIT_PCD		4	/* page cache disabled */
#define _PAGE_BIT_ACCESSED	5	/* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY		6	/* was written to (raised by CPU) */
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page */
#define _PAGE_BIT_PAT		7	/* on 4KB pages */
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
#define _PAGE_BIT_SOFTW1	9	/* available for programmer */
#define _PAGE_BIT_SOFTW2	10	/* " */
#define _PAGE_BIT_SOFTW3	11	/* " */
#define _PAGE_BIT_PAT_LARGE	12	/* On 2MB or 1GB pages */
#define _PAGE_BIT_SOFTW4	58	/* available for programmer */
#define _PAGE_BIT_PKEY_BIT0	59	/* Protection Keys, bit 1/4 */
#define _PAGE_BIT_PKEY_BIT1	60	/* Protection Keys, bit 2/4 */
#define _PAGE_BIT_PKEY_BIT2	61	/* Protection Keys, bit 3/4 */
#define _PAGE_BIT_PKEY_BIT3	62	/* Protection Keys, bit 4/4 */
#define _PAGE_BIT_NX		63	/* No execute: only valid after cpuid check */

#define _PAGE_PRESENT	((unsigned long) 1 << _PAGE_BIT_PRESENT)
#define _PAGE_RW	((unsigned long) 1 << _PAGE_BIT_RW)
#define _PAGE_USER	((unsigned long) 1 << _PAGE_BIT_USER)
#define _PAGE_PWT	((unsigned long) 1 << _PAGE_BIT_PWT)
#define _PAGE_PCD	((unsigned long) 1 << _PAGE_BIT_PCD)
#define _PAGE_ACCESSED	((unsigned long) 1 << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY	((unsigned long) 1 << _PAGE_BIT_DIRTY)
#define _PAGE_PSE	((unsigned long) 1 << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL	((unsigned long) 1 << _PAGE_BIT_GLOBAL)
#define _PAGE_SOFTW1	((unsigned long) 1 << _PAGE_BIT_SOFTW1)
#define _PAGE_SOFTW2	((unsigned long) 1 << _PAGE_BIT_SOFTW2)
#define _PAGE_SOFTW3	((unsigned long) 1 << _PAGE_BIT_SOFTW3)
#define _PAGE_PAT	((unsigned long) 1 << _PAGE_BIT_PAT)
#define _PAGE_PAT_LARGE ((unsigned long) 1 << _PAGE_BIT_PAT_LARGE)
#define _PAGE_PKEY_BIT0	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT0)
#define _PAGE_PKEY_BIT1	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT1)
#define _PAGE_PKEY_BIT2	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT2)
#define _PAGE_PKEY_BIT3	((unsigned long) 1 << _PAGE_BIT_PKEY_BIT3)


// #define _PAGE_SPECIAL	((unsigned long) 1 << _PAGE_BIT_SPECIAL)
// #define _PAGE_CPA_TEST	((unsigned long) 1 << _PAGE_BIT_CPA_TEST)

unsigned long __va(unsigned long addr) {
    return addr + 0xffff888000000000;
}

unsigned long __pa(unsigned long addr) {
    return addr - 0xffff888000000000;
}

unsigned long pte_to_addr(unsigned long pte) {
    return __va(pte & PTE_PFN_MASK);
}

// unsigned long 
int main() {
    // printf("%016lx\n%016lx\n%016lx\n%016lx\n%016lx\n", PAGE_SHIFT, PAGE_SIZE, PAGE_MASK, __PHYSICAL_MASK, PHYSICAL_PAGE_MASK);
    unsigned long x = 0x03c3b067;
    printf("%016lx\n%016lx\nPGD:%d\nRW:%d\nUSER:%d\npresent:%d\naccessed:%d\ndirty:%d\n", x, pte_to_addr(x), 
                                                        (x&_PAGE_PSE) != 0, 
                                                        (x&_PAGE_RW) != 0,
                                                        (x&_PAGE_USER) != 0,
                                                        (x&_PAGE_PRESENT) != 0,
                                                        (x&_PAGE_ACCESSED) != 0,
                                                        (x&_PAGE_DIRTY) != 0
                                                        );
    return 0;
}