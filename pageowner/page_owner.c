// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "page_owner.h"
#include "bits.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

int parser_page_owner_data_init(struct pageowner_data_t* pageowner_data) {
    pageowner_data->CONFIG_PAGE_EXTENSION = get_kernel_config("CONFIG_PAGE_EXTENSION", NULL);
    if (pageowner_data->CONFIG_PAGE_EXTENSION == IKCONFIG_N)
        return -1;

    pageowner_data->CONFIG_SPARSEMEM_EXTREME = get_kernel_config("CONFIG_SPARSEMEM_EXTREME", NULL);
    pageowner_data->CONFIG_SPARSEMEM = get_kernel_config("CONFIG_SPARSEMEM", NULL);

    if (pageowner_data->CONFIG_SPARSEMEM_EXTREME == IKCONFIG_N)
        return -1;

    readmem(symbol_value("mem_section"), KVADDR, &pageowner_data->mem_section, sizeof(ulong), "mem_section", FAULT_ON_ERROR);

    readmem(symbol_value("max_pfn"), KVADDR, &pageowner_data->max_pfn, sizeof(ulong), "max_pfn", FAULT_ON_ERROR);
    readmem(symbol_value("min_low_pfn"), KVADDR, &pageowner_data->min_low_pfn, sizeof(ulong), "min_low_pfn", FAULT_ON_ERROR);

    readmem(symbol_value("page_ext_size"), KVADDR, &pageowner_data->page_ext_size, sizeof(ulong), "page_ext_size", FAULT_ON_ERROR);
    readmem(symbol_value("page_owner_ops") + PARSER_OFFSET(page_ext_operations_offset), KVADDR,
            &pageowner_data->page_owner_ops_offset, PARSER_SIZE(page_ext_operations_offset), "page_ext_operations_offset", FAULT_ON_ERROR);

    if (symbol_exists("depot_index"))
        readmem(symbol_value("depot_index"), KVADDR, &pageowner_data->depot_index, sizeof(int), "depot_index", FAULT_ON_ERROR);
    if (symbol_exists("stack_slabs"))
        pageowner_data->stack_slabs = symbol_value("stack_slabs");

    if (symbol_exists("pool_index"))
        readmem(symbol_value("pool_index"), KVADDR, &pageowner_data->depot_index, sizeof(int), "pool_index", FAULT_ON_ERROR);
    if (symbol_exists("stack_pools"))
        pageowner_data->stack_slabs = symbol_value("stack_pools");

    enumerator_value("PAGE_EXT_OWNER", &pageowner_data->PAGE_EXT_OWNER);
    enumerator_value("PAGE_EXT_OWNER_ALLOCATED", &pageowner_data->PAGE_EXT_OWNER_ALLOCATED);
    return 0;
}

void parser_page_owner_dump(struct pageowner_data_t* pageowner_data) {
    ulong page;
    ulong page_ext;
    ulong page_owner;
    ulong flags;
    ulong order;
    int handle;
    ulong pfn = pageowner_data->min_low_pfn;
    ulong max_pfn = pageowner_data->max_pfn;

    for(; pfn < max_pfn; pfn++) {
        page = 0x0;
        phys_to_page(PTOB(pfn), &page);
        if (!page) continue;

        if (pageowner_data->page && pageowner_data->page != page)
            continue;

        page_ext = parser_page_ext_get(pageowner_data, page, pfn);
        if (!page_ext) continue;

        readmem(page_ext + PARSER_OFFSET(page_ext_flags), KVADDR,
                &flags, PARSER_SIZE(page_ext_flags), "page_ext_flags", FAULT_ON_ERROR);

        if (!test_bit(pageowner_data->PAGE_EXT_OWNER, &flags)) continue;
        if (!test_bit(pageowner_data->PAGE_EXT_OWNER_ALLOCATED, &flags)) continue;

        page_owner = parser_get_page_owner(pageowner_data, page_ext);
        readmem(page_owner + PARSER_OFFSET(page_owner_order), KVADDR,
                &order, PARSER_SIZE(page_owner_order), "page_owner_order", FAULT_ON_ERROR);

        if (!IS_ALIGNED(pfn, 1 << order)) continue;

        readmem(page_owner + PARSER_OFFSET(page_owner_handle), KVADDR,
                &handle, PARSER_SIZE(page_owner_handle), "page_owner_handle", FAULT_ON_ERROR);
        if (!handle) continue;

        parser_print_page_owner(pageowner_data, pfn, page, page_owner, handle);
    }
}

void parser_page_owner_top_print(ulong pages, int pid) {
    struct task_context *tc = NULL;
    if (pages) {
        tc = pid_to_context(pid);
        if (!tc) {
            fprintf(fp, "PID:%-5d                  alloc %lu pages\n", pid, pages);
        } else {
            fprintf(fp, "PID:%-5d %-16s alloc %lu pages\n", pid, tc->comm, pages);
        }
    }
}

void parser_page_owner_main(void) {
    struct pageowner_data_t page_owner_data;
    BZERO(&page_owner_data, sizeof(page_owner_data));

    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"page",   required_argument,  0, 1},
        {"pid",    required_argument,  0, 2},
        {"top",    required_argument,  0,'t'},
        {0,         0,                 0, 0}
    };

    while ((opt = getopt_long(argcnt - 1, &args[1], "t:",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 1:
                if (args[optind]) {
                    page_owner_data.page = htol(args[optind], FAULT_ON_ERROR, NULL);
                } break;
            case 2:
                if (args[optind]) page_owner_data.pid = atoi(args[optind]);
                break;
            case 't': {
                if (args[optind]) {
                    page_owner_data.dumptop = atoi(args[optind]);
                } else {
                    page_owner_data.dumptop = 1;
                }
            } break;
        }
    }

    if (!parser_page_owner_data_init(&page_owner_data)) {
        if (page_owner_data.dumptop) {
            if (page_owner_data.pid) {
                page_owner_data.dumptop = 1;
                page_owner_data.top = (ulong *)malloc(1 * sizeof(ulong));
                BZERO(page_owner_data.top, 1 * sizeof(ulong));
                page_owner_data.top_size = 1;
            } else {
                page_owner_data.top = (ulong *)malloc(32768 * sizeof(ulong));
                BZERO(page_owner_data.top, 32768 * sizeof(ulong));
                page_owner_data.top_size = 32768;
            }
        }

        parser_page_owner_dump(&page_owner_data);

        if (page_owner_data.dumptop) {
            if (page_owner_data.pid) {
                parser_page_owner_top_print(page_owner_data.top[0], page_owner_data.pid);
            } else {
                ulong last_pages = ~0UL;
                for (int s = 0; s < page_owner_data.dumptop; ++s) {
                    ulong max_pages = 0;
                    int max_pid = 0;
                    for (int p = 0; p < page_owner_data.top_size; ++p) {
                        if (page_owner_data.top[p] > max_pages
                                && page_owner_data.top[p] < last_pages) {
                            max_pid = p;
                            max_pages = page_owner_data.top[p];
                        }
                    }
                    last_pages = max_pages;
                    parser_page_owner_top_print(max_pages, max_pid);
                }
            }
            if (page_owner_data.top) free(page_owner_data.top);
        }
    }
}

void parser_page_owner_usage(void) {
    fprintf(fp, "Usage: lp page_owner [OPTION] ...\n");
    fprintf(fp, "Option:\n");
    fprintf(fp, "         --page   dump page alloc stack.\n");
    fprintf(fp, "         --pid    cloc pid pages.\n");
    fprintf(fp, "    -t, --top     cloc top pages.\n");
}

ulong parser_page_ext_get(struct pageowner_data_t* pageowner_data, ulong page, ulong pfn) {
    ulong page_ext;
    page_ext = parser_lookup_page_ext(pageowner_data, page, pfn);
    return page_ext;
}

ulong parser_lookup_page_ext(struct pageowner_data_t* pageowner_data, ulong page, ulong pfn) {
    if (pageowner_data->CONFIG_SPARSEMEM == IKCONFIG_N)
        return 0x0;

    ulong section = parser_pfn_to_section(pageowner_data, pfn);
    if (!section) return 0x0;

    ulong page_ext;
    readmem(section + PARSER_OFFSET(mem_section_page_ext), KVADDR,
            &page_ext, PARSER_SIZE(mem_section_page_ext), "mem_section_page_ext", FAULT_ON_ERROR);

    if (parser_page_ext_invalid(page_ext)) return 0x0;
    return parser_page_owner_get_entry(pageowner_data, page_ext, pfn);
}

ulong parser_pfn_to_section(struct pageowner_data_t* pageowner_data, ulong pfn) {
    return parser_nr_to_section(pageowner_data, pfn_to_section_nr(pfn));
}

ulong parser_nr_to_section(struct pageowner_data_t* pageowner_data, ulong nr) {
    ulong root = SECTION_NR_TO_ROOT(nr);
    ulong root_value = 0x0;
    if (root >= NR_SECTION_ROOTS()) {
        return 0x0;
    }

    if (pageowner_data->CONFIG_SPARSEMEM_EXTREME == IKCONFIG_N)
        return 0x0;

    readmem(pageowner_data->mem_section + root * sizeof(void *), KVADDR, &root_value, sizeof(ulong), "root", FAULT_ON_ERROR);
    if (!root_value)
        return 0x0;

    ulong section_nr = nr & SECTION_ROOT_MASK();
    return root_value + PARSER_SIZE(mem_section) * section_nr;
}

bool parser_page_ext_invalid(ulong page_ext) {
    return !page_ext || ((page_ext & PAGE_EXT_INVALID) == PAGE_EXT_INVALID);
}

ulong parser_get_page_owner(struct pageowner_data_t* pageowner_data, ulong page_ext) {
    return page_ext + pageowner_data->page_owner_ops_offset;
}

ulong parser_page_owner_get_entry(struct pageowner_data_t* pageowner_data, ulong base, ulong index) {
    return base + pageowner_data->page_ext_size * index;
}

void parser_print_page_owner(struct pageowner_data_t* pageowner_data, ulong pfn, ulong page, ulong page_owner, int handle) {
    struct task_context *tc = NULL;
    char page_owner_buf[64];
    BZERO(page_owner_buf, sizeof(page_owner_buf));
    readmem(page_owner, KVADDR, page_owner_buf, PARSER_SIZE(page_owner), "page_owner", FAULT_ON_ERROR);

    short order = SHORT(page_owner_buf + PARSER_OFFSET(page_owner_order));
    int gfp_mask = INT(page_owner_buf + PARSER_OFFSET(page_owner_gfp_mask));
    int pid = INT(page_owner_buf + PARSER_OFFSET(page_owner_pid));
    int tgid = INT(page_owner_buf + PARSER_OFFSET(page_owner_tgid));
    char *comm = page_owner_buf + PARSER_OFFSET(page_owner_comm);
    ulong ts_nsec = ULONG(page_owner_buf + PARSER_OFFSET(page_owner_ts_nsec));

    if (!PARSER_VALID_MEMBER(page_owner_tgid)) {
        tc = pid_to_context(pid);
        if (tc) {
            tgid = task_tgid(tc->task);
            comm = tc->comm;
        }
    }

    if (pageowner_data->pid && pageowner_data->pid != tgid) return;
    if (pageowner_data->dumptop) {
        if (pageowner_data->pid) {
            pageowner_data->top[0] += 1;
        } else {
            pageowner_data->top[tgid] += 1;
        }
        return;
    }

    char header[256];
    snprintf(header, sizeof(header), "PFN:0x%lx PAGE:0x%lx ORDER:%d PID:%d TGID:%d COMM:%s SEC:%lu GFP:0x%x\n",
            pfn, page, order, pid, tgid, comm, ts_nsec, gfp_mask);
    fprintf(fp, "%s", header);
    parser_stack_depot_print(pageowner_data, handle);
}

void parser_stack_depot_print(struct pageowner_data_t* pageowner_data, int stack) {
    unsigned long entries;
    unsigned int nr_entries;
    nr_entries = parser_stack_depot_fetch(pageowner_data, stack, &entries);
    if (nr_entries) parser_stack_trace_print(entries, nr_entries, 0);
}

void parser_stack_trace_print(unsigned long entries, unsigned int nr_entries, int spaces) {
    unsigned int i;
    if (!entries) return;

    for (i = 0; i < nr_entries; i++) {
        ulong symbols;
        struct syment *sp;
        ulong offset;
        readmem(entries + i * sizeof(void *), KVADDR, &symbols, sizeof(ulong), "symbols", FAULT_ON_ERROR);
        sp = value_search(symbols, &offset);
        if (sp) {
            fprintf(fp, "      [<%lx>] %s+0x%lx\n", symbols, sp->name, offset);
        } else {
            fprintf(fp, "      [<%lx>] %p\n", symbols, sp);
        }
    }
    fprintf(fp, "\n");
}

unsigned int parser_stack_depot_fetch(struct pageowner_data_t* pageowner_data, int handle, unsigned long *entries) {
    int depot_index = pageowner_data->depot_index;
    ulong stack_slabs = pageowner_data->stack_slabs;
    ulong sr_size;
    ulong slab;
    ulong offset;
    ulong slabindex;

    union handle_parts parts = { .handle = handle };
    if (THIS_KERNEL_VERSION >= LINUX(6,1,0)) {
        offset = parts.v6_1.offset << STACK_ALLOC_ALIGN;
        slabindex = parts.v6_1.slabindex;
    } else {
        offset = parts.v0.offset << STACK_ALLOC_ALIGN;
        slabindex = parts.v0.slabindex;
    }

    *entries = 0x0;
    if (!handle) return 0;
    if (slabindex > depot_index) return 0;

    readmem(stack_slabs + slabindex * sizeof(void *), KVADDR, &slab, sizeof(ulong), "slab", FAULT_ON_ERROR);
    if (!slab) return 0;

    ulong stack = slab + offset;
    *entries = stack + PARSER_OFFSET(stack_record_entries);
    readmem(stack + PARSER_OFFSET(stack_record_size), KVADDR,
            &sr_size, PARSER_SIZE(stack_record_size), "stack_record_size", FAULT_ON_ERROR);

    return sr_size;
}
