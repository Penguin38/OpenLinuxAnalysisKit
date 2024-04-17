// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"
#include "zram/zram.h"
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
        {"pid",         required_argument, 0, 'p'},
        {"output",      required_argument, 0, 'o'},
        {"zram",        no_argument,       0,  1 },
        {"shmem",       no_argument,       0,  2 },
        {"filter",      required_argument, 0, 'f'},
        {0,             0,                 0,  0 }
    };

    core_data.error_handle = QUIET;
    core_data.pid = CURRENT_PID();
    while ((opt = getopt_long(argcnt - 1, &args[1], "p:o:f:012",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                if (args[optind]) core_data.pid = atoi(args[optind]);
                break;
            case 'o':
                if (args[optind]) core_data.file = args[optind];
                break;
            case 'f':
                if (args[optind]) core_data.filter_flags = htol(args[optind], FAULT_ON_ERROR, NULL);
                break;
            case 1:
                core_data.parse_zram = 1;
                parser_zram_init();
                break;
            case 2:
                core_data.parse_shmem = 1;
                parser_zram_init();
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

    readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_start_stack), KVADDR,
            &core_data.mm_start_stack, PARSER_SIZE(mm_struct_start_stack), "mm_struct_start_stack", FAULT_ON_ERROR);
    readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_start_brk), KVADDR,
            &core_data.mm_start_brk, PARSER_SIZE(mm_struct_start_brk), "mm_struct_start_brk", FAULT_ON_ERROR);
    readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_brk), KVADDR,
            &core_data.mm_brk, PARSER_SIZE(mm_struct_brk), "mm_struct_brk", FAULT_ON_ERROR);

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
    core_data.fill_vma_name = parser_core_fill_vma_name;
    core_data.filter_vma = parser_core_filter_vma;
    core_data.parser_core_dump(&core_data);
}

void parser_core_clean(struct core_data_t* core_data) {
    if (core_data->fp) fclose(core_data->fp);
    if (core_data->vma_cache) free(core_data->vma_cache);
    if (core_data->prstatus_cache) free(core_data->prstatus_cache);
    if (core_data->auxv_cache) free(core_data->auxv_cache);
    if (core_data->load_cache) free(core_data->load_cache);
}

void parser_core_fill_vma_name(struct core_data_t* core_data) {
    char *file_buf;
    char anon[BUFSIZE];
    ulong dentry, vfsmnt;
    physaddr_t paddr;
    unsigned char page_buf[4096];

    for (int index = 0; index < core_data->vma_count; ++index) {
        file_buf = NULL;
        BZERO(anon, BUFSIZE);
        dentry = vfsmnt = 0;

        if (core_data->vma_cache[index].vm_file) {
            file_buf = fill_file_cache(core_data->vma_cache[index].vm_file);
            dentry = ULONG(file_buf + OFFSET(file_f_dentry));

            if (dentry) {
                if (VALID_MEMBER(file_f_vfsmnt)) {
                    vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
                    get_pathname(dentry, core_data->vma_cache[index].buf, BUFSIZE, 1, vfsmnt);
                } else
                    get_pathname(dentry, core_data->vma_cache[index].buf, BUFSIZE, 1, 0);
            }

        } else if (core_data->vma_cache[index].anon_name) {
            if (PARSER_VALID_MEMBER(anon_vma_name_name)) {
                readmem(core_data->vma_cache[index].anon_name + PARSER_OFFSET(anon_vma_name_name), KVADDR,
                        anon, BUFSIZE, "anon_name", core_data->error_handle);
            } else if (IS_KVADDR(core_data->vma_cache[index].anon_name)) {
                readmem(core_data->vma_cache[index].anon_name, KVADDR,
                        anon, BUFSIZE, "anon_name", core_data->error_handle);
            } else {
#ifdef ARM64
                core_data->vma_cache[index].anon_name &= ((1ULL << machdep->machspec->VA_BITS_ACTUAL) - 1);
#endif
                memset(&page_buf, 0x0, sizeof(page_buf));
                paddr = (physaddr_t)0x0;
                int page_exist = uvtop(core_data->tc, core_data->vma_cache[index].anon_name, &paddr, 0);

                if (paddr) {
                    if (page_exist) {
                        readmem(paddr, PHYSADDR, anon, BUFSIZE, "read anon_name", core_data->error_handle);
                    } else if (core_data->parse_zram) {
                        ulong zram_offset = SWP_OFFSET(paddr);
                        ulong swap_type = SWP_TYPE(paddr);
                        parser_zram_read_page(swap_type, zram_offset, page_buf, core_data->error_handle);
                        ulong off = PAGEOFFSET(core_data->vma_cache[index].anon_name);
                        memcpy(anon, page_buf + off, (PAGESIZE() - off > BUFSIZE) ? BUFSIZE : (PAGESIZE() - off));
                    }
                }
            }
            snprintf(core_data->vma_cache[index].buf, BUFSIZE + 7, "[anon:%s]", anon);
        } else {
            if (core_data->vma_cache[index].vm_start < core_data->mm_brk
                    && core_data->vma_cache[index].vm_end > core_data->mm_start_brk) {
                snprintf(core_data->vma_cache[index].buf, BUFSIZE, "[heap]");
            }

            if (core_data->vma_cache[index].vm_start <= core_data->mm_start_stack
                    && core_data->vma_cache[index].vm_end >= core_data->mm_start_stack) {
                snprintf(core_data->vma_cache[index].buf, BUFSIZE, "[stack]");
            }
        }

        core_data->fileslen += strlen(core_data->vma_cache[index].buf) + 1;
        // fprintf(fp, "%lx %s\n", core_data->vma_cache[index].vm_start, core_data->vma_cache[index].buf);
    }
}

int parser_core_filter_vma(struct core_data_t* core_data, int index) {
    if (core_data->filter_flags & FILTER_SPECIAL_VMA) {
        if (!strcmp(core_data->vma_cache[index].buf, "/dev/binderfs/hwbinder")
                || !strcmp(core_data->vma_cache[index].buf, "/dev/binderfs/binder")
                || !strcmp(core_data->vma_cache[index].buf, "/dev/mali0"))
            return 1;
    }

    if (core_data->filter_flags & FILTER_FILE_VMA) {
        if (!core_data->vma_cache[index].anon_vma)
            return 1;
    }

    if (core_data->filter_flags & FILTER_SHARED_VMA) {
        if (core_data->vma_cache[index].vm_flags & (VM_SHARED | VM_MAYSHARE))
            return 1;
    }

    if (core_data->filter_flags &  FILTER_SANITIZER_SHADOW_VMA) {
        if (!strcmp(core_data->vma_cache[index].buf, "[anon:low shadow]")
                || !strcmp(core_data->vma_cache[index].buf, "[anon:high shadow]")
                || !strncmp(core_data->vma_cache[index].buf, "[anon:hwasan", 12))
            return 1;
    }

    if (core_data->filter_flags & FILTER_NON_READ_VMA) {
        if (!(core_data->vma_cache[index].vm_flags & VM_READ))
            return 1;
    }

    return 0;
}

void parser_core_usage(void) {
    fprintf(fp, "Usage: core -p <PID> [--output|-o <FILE_PATH>] [option]\n");
    fprintf(fp, "   Option:\n");
    fprintf(fp, "       --zram: decompress zram page\n");
    fprintf(fp, "       --shmem: decompress shared memory on zram page\n");
    fprintf(fp, "       --filter|-f: filter vma flags\n");
    fprintf(fp, "   Filter Vma:\n");
    fprintf(fp, "       0x01: filter-special-vma\n");
    fprintf(fp, "       0x02: filter-file-vma\n");
    fprintf(fp, "       0x04: filter-shared-vma\n");
    fprintf(fp, "       0x08: filter-sanitizer-shadow-vma\n");
    fprintf(fp, "       0x10: filter-non-read-vma\n");
    fprintf(fp, "   Example:\n");
    fprintf(fp, "       lp core -p 1 --zram --shmem -f 0x1b\n");
}
