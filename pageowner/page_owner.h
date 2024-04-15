// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef PAGEOWNER_PAGE_OWNER_H_
#define PAGEOWNER_PAGE_OWNER_H_

#include "parser_defs.h"
#include <linux/types.h>

#define PAGE_EXT_INVALID (0x1)

void parser_page_owner_main(void);
void parser_page_owner_usage(void);

struct pageowner_data_t {
    int pid;
    ulong page;
    int dumptop;
    ulong *top;
    ulong top_size;

    ulong max_pfn;
    ulong min_low_pfn;
    ulong stack_slabs;
    ulong page_owner_ops_offset;
    ulong mem_section;
    ulong page_ext_size;
    int depot_index;

    long PAGE_EXT_OWNER;
    long PAGE_EXT_OWNER_ALLOCATED;

    int CONFIG_PAGE_EXTENSION;
    int CONFIG_SPARSEMEM_EXTREME;
    int CONFIG_SPARSEMEM;
};

int parser_page_owner_data_init(struct pageowner_data_t* pageowner_data);
void parser_page_owner_dump(struct pageowner_data_t* pageowner_data);

ulong parser_page_ext_get(struct pageowner_data_t* pageowner_data, ulong page, ulong pfn);
ulong parser_lookup_page_ext(struct pageowner_data_t* pageowner_data, ulong page, ulong pfn);

ulong parser_pfn_to_section(struct pageowner_data_t* pageowner_data, ulong pfn);
ulong parser_nr_to_section(struct pageowner_data_t* pageowner_data, ulong nr);
ulong parser_get_page_owner(struct pageowner_data_t* pageowner_data, ulong page_ext);
ulong parser_page_owner_get_entry(struct pageowner_data_t* pageowner_data, ulong base, ulong index);
bool parser_page_ext_invalid(ulong page_ext);
void parser_print_page_owner(struct pageowner_data_t* pageowner_data, ulong pfn, ulong page, ulong page_owner, int handle);

void parser_stack_depot_print(struct pageowner_data_t* pageowner_data, int stack);
void parser_stack_trace_print(unsigned long entries, unsigned int nr_entries, int spaces);
unsigned int parser_stack_depot_fetch(struct pageowner_data_t* pageowner_data, int handle, unsigned long *entries);

#define STACK_ALLOC_ALIGN 4
union handle_parts {
    unsigned int handle;
    struct {
        unsigned int slabindex : 21;
        unsigned int offset : 10;
        unsigned int valid : 1;
    };
};

union handle_parts_6_1 {
    unsigned int handle;
    struct {
        unsigned int slabindex : 16;
        unsigned int offset : 10;
        unsigned int valid : 1;
        unsigned int extra : 5;
    };
};

#endif //  PAGEOWNER_PAGE_OWNER_H_
