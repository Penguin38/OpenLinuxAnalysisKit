// Copyright (C) 2025-present, Guanyou.Chen. All rights reserved.

#include "cmdline/cmd.h"
#include "zram/zram.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void parser_cmdline_main(void) {
    struct task_context *tc = NULL;
    struct task_mem_usage task_mem_usage, *tm;
    ulong arg_start_addr = 0x0;
    ulong arg_end_addr = 0x0;
    char anon[ANON_BUFSIZE];
    int current_offset = 0;
    int pid = CURRENT_PID();
    unsigned char* page_buf;
    bool parse_zram = true;

    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"task",   required_argument,  0,'t'},
        {"pid",    required_argument,  0,'p'},
        {0,         0,                 0, 0 },
    };

    while ((opt = getopt_long(argcnt - 1, &args[1], "t:p:",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                pid = atoi(optarg);
                break;
            case 't':
                tc = task_to_context(htol(optarg, FAULT_ON_ERROR, NULL));
                break;
        }
    }

    if (!tc) {
        tc = pid_to_context(pid);
        if (!tc) {
            fprintf(fp, "No such pid: %d\n", pid);
            return;
        }
    }

    set_context(tc->task, NO_PID, FALSE);

    tm = &task_mem_usage;
    get_task_mem_usage(tc->task, tm);
    if (!tm->mm_struct_addr) {
        fprintf(fp, "%lx no virtual memory space.\n", tc->task);
        return;
    }

    readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_arg_start), KVADDR,
            &arg_start_addr, PARSER_SIZE(mm_struct_arg_start), "mm_struct_arg_start", FAULT_ON_ERROR);
    readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_arg_end), KVADDR,
            &arg_end_addr, PARSER_SIZE(mm_struct_arg_end), "mm_struct_arg_end", FAULT_ON_ERROR);

    BZERO(anon, ANON_BUFSIZE);
#if defined(__LP64__)
    arg_start_addr &= (USERSPACE_TOP - 1);
    arg_end_addr &= (USERSPACE_TOP - 1);
#endif
    int count = 2;
    uint64_t anon_buf_off = 0;
    uint64_t anon_buf_use = ANON_BUFSIZE - 1;
    page_buf = (unsigned char *)malloc(PAGESIZE());
    do {
        memset(page_buf, 0x0, PAGESIZE());
        physaddr_t paddr = (physaddr_t)0x0;
        int page_exist = uvtop(tc, arg_start_addr + anon_buf_off, &paddr, 0);
        ulong off = PAGEOFFSET(arg_start_addr + anon_buf_off);
        uint64_t read_size = (PAGESIZE() - off > anon_buf_use) ? anon_buf_use : (PAGESIZE() - off);
        if (!read_size)
            break;

        if (paddr) {
            if (page_exist) {
                readmem(paddr, PHYSADDR, &anon[anon_buf_off], read_size, "read cmdline name", FAULT_ON_ERROR);
            } else if (parse_zram) {
                parser_zram_init();
                ulong zram_offset = SWP_OFFSET(paddr);
                ulong swap_type = SWP_TYPE(paddr);
                parser_zram_read_page(swap_type, zram_offset, page_buf, FAULT_ON_ERROR);
                memcpy(&anon[anon_buf_off], page_buf + off, read_size);
            }
        }

        // next page
        if (anon[read_size - 1] != 0x0) {
            anon_buf_off += read_size;
            anon_buf_use -= read_size;
        } else
            break;

        count--;
    } while(count);

    anon[ANON_BUFSIZE - 1] = '\0';
    free(page_buf);

    int length = arg_end_addr - arg_start_addr;
    do {
        fprintf(fp, "%s ", &anon[current_offset]);
        current_offset += strlen(&anon[current_offset]) + 1;
    } while (current_offset < length);
    fprintf(fp, "\n");
}

void parser_cmdline_usage(void) {
    fprintf(fp, "Usage: lp cmdline [OPTION] ...\n");
    fprintf(fp, "Option:\n");
    fprintf(fp, "    -t,  --task   print task_struct cmdline\n");
    fprintf(fp, "    -p,  --pid    print pid cmdline\n");
}
