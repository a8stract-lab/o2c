#ifndef __KLIFECYCLE_H
#define __KLIFECYCLE_H

#define ALLOC_SZ 96

struct event {
	unsigned long call_site;
    char cache[32];
    unsigned long sz;
    unsigned long alloc_ns;
    unsigned long free_ns;
    unsigned long life_ns;
};

#define ___GFP_DMA		0x01u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_ACCOUNT		0x400000u

#define KMALLOC_NOT_NORMAL_BITS	 (___GFP_RECLAIMABLE | ___GFP_DMA | ___GFP_ACCOUNT)

// #define STRNCMP_STR_SZ 32
// const char cache32[STRNCMP_STR_SZ] = "kmalloc-cg-32";
// char filename[STRNCMP_STR_SZ];


#endif /* __KLIFECYCLE_H */