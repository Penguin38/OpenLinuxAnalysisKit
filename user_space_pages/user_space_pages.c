// Copyright (C) 2025-present, Guanyou.Chen. All rights reserved.

#include "user_space_pages/user_space_pages.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void parser_user_space_pages_main(void) {
    int i, cur;
    int flags;

    int total_anon_pages = 0;
    int total_file_pages = 0;
    struct task_context *tc = FIRST_CONTEXT();
    fprintf(fp, "    PID                COMM      ANON      FILE\n");

    for (i = cur = 0; i < RUNNING_TASKS(); i++, tc++) {
        if (tc->pid == task_tgid(tc->task)) {
            readmem(tc->task + PARSER_OFFSET(task_struct_flags), KVADDR,
                    &flags, sizeof(flags), "task_struct flags", FAULT_ON_ERROR);
            if (flags & PF_KTHREAD)
                continue;

            set_context(tc->task, NO_PID, FALSE);

            struct vma_cache_data *vma_cache = NULL;
            int vma_count = 0;
            physaddr_t paddr;
            uint64_t vaddr;
            int idx, i;
            int anon_pages = 0;
            int file_pages = 0;

            char *file_buf = NULL;
            ulong dentry, vfsmnt;
            int cur_file_pages = 0;

            vma_count = parser_vma_caches(tc, &vma_cache);
            for (idx = 0; idx < vma_count; ++idx) {
                cur_file_pages = 0;
                int count = (vma_cache[idx].vm_end - vma_cache[idx].vm_start) / PAGESIZE();
                for (i = 0; i < count; ++i) {
                    vaddr = vma_cache[idx].vm_start + i * PAGESIZE();
                    paddr = (physaddr_t)0x0;
                    int page_exist = uvtop(tc, vaddr, &paddr, 0);
                    if (page_exist) {
                        if (vma_cache[idx].vm_file) {
                            file_pages++;
                            cur_file_pages++;
                        }
                        else
                            anon_pages++;
                    }
                }

                if (vma_cache[idx].vm_file && cur_file_pages) {
                    file_buf = fill_file_cache(vma_cache[idx].vm_file);
                    dentry = ULONG(file_buf + OFFSET(file_f_dentry));

                    if (IS_KVADDR(dentry)) {
                        if (VALID_MEMBER(file_f_vfsmnt)) {
                            vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
                            get_pathname(dentry, vma_cache[idx].buf, BUFSIZE, 1, vfsmnt);
                        } else
                            get_pathname(dentry, vma_cache[idx].buf, BUFSIZE, 1, 0);

                        fprintf(fp, "                                       %8d  %s\n", cur_file_pages, vma_cache[idx].buf);
                    }
                }

            }

            if (vma_cache) free(vma_cache);
            cur++;

            fprintf(fp, "%7ld  %18s  %8d  %8d\n", tc->pid, tc->comm, anon_pages, file_pages);
            total_anon_pages += anon_pages;
            total_file_pages += file_pages;
        }
    }

    fprintf(fp, "total_pages %d, (%d, %d)\n", total_anon_pages + total_file_pages, total_anon_pages, total_file_pages);
}

void parser_user_space_pages_usage(void) {
    fprintf(fp, "Usage: lp user_space_pages [OPTION] ...\n");
}
