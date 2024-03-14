// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void parser_core_main(void) {
    ulong thread_info_flags = 0x0;
    unsigned int flags = 0x0;

    struct core_data_t core_data;
    memset(&core_data, 0x0, sizeof(core_data));

    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"pid",   required_argument, 0, 'p'},
        {"file",  required_argument, 0, 'f'},
        {"zram",  no_argument,       0,  1 },
        {"shmem", no_argument,       0,  2 },
        {0,       0,                 0,  0 }
    };

    core_data.pid = CURRENT_PID();
    while ((opt = getopt_long(argcnt - 1, &args[1], "p:f:012",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                if (args[optind]) core_data.pid = atoi(args[optind]);
                break;
            case 'f':
                if (args[optind]) core_data.file = args[optind];
                break;
            case 1:
                core_data.parse_zram = 1;
                break;
            case 2:
                core_data.parse_shmem = 1;
                break;
        }
    }

    core_data.tc = pid_to_context(core_data.pid);
    if (!core_data.tc) {
        fprintf(fp, "No such pid: %d\n", core_data.pid);
        return;
    }
    set_context(core_data.tc->task, NO_PID);

    readmem(core_data.tc->task + PARSER_OFFSET(task_struct_flags), KVADDR,
            &flags, sizeof(flags), "task_struct flags", FAULT_ON_ERROR);
    if (flags & PF_KTHREAD) {
        fprintf(fp, "%d kernel thread not support coredump.\n", core_data.pid);
        return;
    }

    struct task_mem_usage task_mem_usage, *tm;
    tm = &task_mem_usage;
    get_task_mem_usage(core_data.tc->task, tm);
    if (!tm->mm_struct_addr) {
        fprintf(fp, "%d no virtual memory space.\n", core_data.pid);
        return;
    }

    fill_thread_info(core_data.tc->thread_info);
    thread_info_flags = UINT(tt->thread_info + PARSER_OFFSET(thread_info_flags));

    if (BITS64()) {
        if (machine_type("ARM64")) {
            if (thread_info_flags & (1 << 22)) { // TIF_32BIT
                core_data.class = ELFCLASS32;
                core_data.machine = EM_ARM;
                core_data.compat = 1;
                core_data.parser_core_dump = parser_core_dump32;
                core_data.parser_core_prstatus = parser_arm_core_prstatus;
                core_data.parser_write_core_prstatus = parser_write_arm_core_prstatus;
            } else {
                core_data.class = ELFCLASS64;
                core_data.machine = EM_AARCH64;
                core_data.parser_core_dump = parser_core_dump64;
                core_data.parser_core_prstatus = parser_arm64_core_prstatus;
                core_data.parser_write_core_prstatus = parser_write_arm64_core_prstatus;
            }
        } else if (machine_type("X86_64")) {
            if (thread_info_flags & (1 << 29)) { // TIF_ADDR32
                core_data.class = ELFCLASS32;
                core_data.machine = EM_386;
                core_data.compat = 1;
                core_data.parser_core_dump = parser_core_dump32;
                core_data.parser_core_prstatus = parser_x86_core_prstatus;
                core_data.parser_write_core_prstatus = parser_write_x86_core_prstatus;
            } else {
                core_data.class = ELFCLASS64;
                core_data.machine = EM_X86_64;
                core_data.parser_core_dump = parser_core_dump64;
                core_data.parser_core_prstatus = parser_x86_64_core_prstatus;
                core_data.parser_write_core_prstatus = parser_write_x86_64_core_prstatus;
            }
        } else {
            fprintf(fp, "Not support machine %s\n", MACHINE_TYPE);
        }
    } else {
        if (machine_type("ARM")) {
            core_data.class = ELFCLASS32;
            core_data.machine = EM_ARM;
            core_data.parser_core_dump = parser_core_dump32;
            core_data.parser_core_prstatus = parser_arm_core_prstatus;
            core_data.parser_write_core_prstatus = parser_write_arm_core_prstatus;
        } else if (machine_type("X86")) {
            core_data.class = ELFCLASS32;
            core_data.machine = EM_386;
            core_data.parser_core_dump = parser_core_dump32;
            core_data.parser_core_prstatus = parser_x86_core_prstatus;
            core_data.parser_write_core_prstatus = parser_write_x86_core_prstatus;
        } else {
            fprintf(fp, "Not support machine %s\n", MACHINE_TYPE);
        }
    }
    core_data.clean = parser_core_clean;
    core_data.parser_core_dump(&core_data);
}

void parser_core_clean(struct core_data_t* core_data) {
    if (core_data->fp) fclose(core_data->fp);
    if (core_data->vma_cache) free(core_data->vma_cache);
    if (core_data->prstatus_cache) free(core_data->prstatus_cache);
    if (core_data->auxv_cache) free(core_data->auxv_cache);
    if (core_data->load_cache) free(core_data->load_cache);
}

void parser_core_usage(void) {
    fprintf(fp, "Usage core -p <PID> [--file|-f <FILE_PATH>] [option]\n");
    fprintf(fp, "   Option:\n");
    fprintf(fp, "       --zram: decompress zram page\n");
    fprintf(fp, "       --shmem: decompress shared memory on zram page\n");
}
