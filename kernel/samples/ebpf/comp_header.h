#ifndef _COMP_HEADER_H
#define _COMP_HEADER_H

#define ALLOC_SZ 8192

// only generic slab and buddy need this.
struct event {
    unsigned long alloc_addr;       // allocated address
	unsigned long call_site;        // caller site
    char cache[32];                 // cache name, for buddy, page_alloc
    unsigned long cache_addr;       // cache addr, though duplicated, but need for phase2 policies check, 0 for buddy
    unsigned long sz;               // cache size
	unsigned long content[ALLOC_SZ];// cache content, all 8192 bytes
    unsigned int isCompartment;     // if current object belongs to the compartment
};

struct ip2type {
    unsigned long ip;
    unsigned long type;
    unsigned long identifier;        // cache address / caller / page alloc
};
// type:
    // 0-> slab - generic cache
    // 1-> slab - dedicate cache
    // 2-> buddy
    // 3-> vmalloc - caller
    // 4-> pages
    // 5-> undefined



#endif //  _COMP_HEADER_H