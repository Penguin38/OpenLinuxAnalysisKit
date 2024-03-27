// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "parser_defs.h"
#include "core/core.h"
#include "zram/zram.h"
#include "shmem/shmem.h"
#include <linux/types.h>
#include <string.h>
#include <elf.h>

void parser_init(void);
void parser_fini(void);

void cmd_parser(void);
char *help_parser[];
void parser_help_main(void);

static void parser_offset_table_init(void);
static void parser_size_table_init(void);

static struct command_table_entry command_table[] = {
    { "lp", cmd_parser, help_parser, 0 },
    { NULL }
};

void __attribute__((constructor)) parser_init(void) {
    parser_offset_table_init();
    parser_size_table_init();
    parser_zram_data_init();
    register_extension(command_table);
}

void __attribute__((destructor)) parser_fini(void) {
    parser_zram_data_uninit();
}

struct parser_commands g_parser_commands[] = {
    {"core", parser_core_main, parser_core_usage},
    {"zram", parser_zram_main, parser_zram_usage},
    {"shmem", parser_shmem_main, parser_shmem_usage},
    {"binder", NULL, NULL},
    {"meminfo", NULL, NULL},
    {"page_owner", NULL, NULL},
    {"dmabuf", NULL, NULL},
    {"help", parser_help_main, NULL}
};

void cmd_parser(void) {
    if (argcnt < 1) return;

    int count = sizeof(g_parser_commands)/sizeof(g_parser_commands[0]);
    for (int i = 0; i < count; ++i) {
        if (!strcmp(g_parser_commands[i].cmd, args[1])) {
            if (g_parser_commands[i].main)
                g_parser_commands[i].main();
            break;
        }
    }
}

void parser_help_main(void) {
    int count = sizeof(g_parser_commands)/sizeof(g_parser_commands[0]);
    if (argcnt < 3) {
        for (int i = 0; i < count; ++i) {
            fprintf(fp, "%-12s", g_parser_commands[i].cmd);
            if (!((i+1) % 4)) fprintf(fp, "\n");
        }
    } else {
        for (int i = 0; i < count; ++i) {
            if (!strcmp(g_parser_commands[i].cmd, args[2])) {
                if (g_parser_commands[i].usage)
                    g_parser_commands[i].usage();
                break;
            }
        }
    }
}

char *help_parser[] = {
    "linux-parser",
    "Base on crash-utility project, apply analysis Linux kernel core.",
    "[COMMAND] ...",
    "  linux-parser version 1.0",
    "  Command: [core, ...]",
};

struct parser_offset_table parser_offset_table = {0};
struct parser_size_table parser_size_table = {0};

static void parser_offset_table_init(void) {
    BZERO(&parser_offset_table, sizeof(parser_offset_table));
    PARSER_MEMBER_OFFSET_INIT(mm_struct_saved_auxv, "mm_struct", "saved_auxv");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_task_size, "mm_struct", "task_size");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_mmap, "mm_struct", "mmap");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_mm_mt, "mm_struct", "mm_mt");
    PARSER_MEMBER_OFFSET_INIT(thread_info_flags, "thread_info", "flags");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_next, "vm_area_struct", "vm_next");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_start, "vm_area_struct", "vm_start");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_end, "vm_area_struct", "vm_end");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_flags, "vm_area_struct", "vm_flags");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_file, "vm_area_struct", "vm_file");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_pgoff, "vm_area_struct", "vm_pgoff");
    PARSER_MEMBER_OFFSET_INIT(task_struct_flags, "task_struct", "flags");
    PARSER_MEMBER_OFFSET_INIT(task_struct_thread, "task_struct", "thread");
    PARSER_MEMBER_OFFSET_INIT(thread_struct_sctlr_user, "thread_struct", "sctlr_user");
    PARSER_MEMBER_OFFSET_INIT(thread_struct_mte_ctrl, "thread_struct", "mte_ctrl");
    PARSER_MEMBER_OFFSET_INIT(swap_info_struct_bdev, "swap_info_struct", "bdev");
    PARSER_MEMBER_OFFSET_INIT(swap_info_struct_swap_file, "swap_info_struct", "swap_file");
    PARSER_MEMBER_OFFSET_INIT(swap_info_struct_swap_vfsmnt, "swap_info_struct", "swap_vfsmnt");
    PARSER_MEMBER_OFFSET_INIT(swap_info_struct_old_block_size, "swap_info_struct", "old_block_size");
    PARSER_MEMBER_OFFSET_INIT(swap_info_struct_pages, "swap_info_struct", "pages");
    PARSER_MEMBER_OFFSET_INIT(block_device_bd_disk, "block_device", "bd_disk");
    PARSER_MEMBER_OFFSET_INIT(gendisk_private_data, "gendisk", "private_data");
    PARSER_MEMBER_OFFSET_INIT(page_private, "page", "private");
    PARSER_MEMBER_OFFSET_INIT(page_freelist, "page", "freelist");
    PARSER_MEMBER_OFFSET_INIT(page_index, "page", "index");
    PARSER_MEMBER_OFFSET_INIT(file_f_inode, "file", "f_inode");
    PARSER_MEMBER_OFFSET_INIT(inode_i_mapping, "inode", "i_mapping");
    PARSER_MEMBER_OFFSET_INIT(address_space_i_pages, "address_space", "i_pages");
}

static void parser_size_table_init(void) {
    BZERO(&parser_size_table, sizeof(parser_size_table));
    PARSER_MEMBER_SIZE_INIT(mm_struct_saved_auxv, "mm_struct", "saved_auxv");
    PARSER_MEMBER_SIZE_INIT(mm_struct_task_size, "mm_struct", "task_size");
    PARSER_MEMBER_SIZE_INIT(mm_struct_mmap, "mm_struct", "mmap");
    PARSER_MEMBER_SIZE_INIT(mm_struct_mm_mt, "mm_struct", "mm_mt");
    PARSER_MEMBER_SIZE_INIT(thread_info_flags, "thread_info", "flags");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_next, "vm_area_struct", "vm_next");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_start, "vm_area_struct", "vm_start");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_end, "vm_area_struct", "vm_end");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_flags, "vm_area_struct", "vm_flags");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_file, "vm_area_struct", "vm_file");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_pgoff, "vm_area_struct", "vm_pgoff");
    PARSER_MEMBER_SIZE_INIT(task_struct_flags, "task_struct", "flags");
    PARSER_MEMBER_SIZE_INIT(task_struct_thread, "task_struct", "thread");
    PARSER_MEMBER_SIZE_INIT(thread_struct_sctlr_user, "thread_struct", "sctlr_user");
    PARSER_MEMBER_SIZE_INIT(thread_struct_mte_ctrl, "thread_struct", "mte_ctrl");

    PARSER_STRUCT_SIZE_INIT(pt_regs, "pt_regs");
    PARSER_STRUCT_SIZE_INIT(swap_info_struct, "swap_info_struct");
    PARSER_MEMBER_SIZE_INIT(swap_info_struct_bdev, "swap_info_struct", "bdev");
    PARSER_MEMBER_SIZE_INIT(swap_info_struct_swap_file, "swap_info_struct", "swap_file");
    PARSER_MEMBER_SIZE_INIT(swap_info_struct_swap_vfsmnt, "swap_info_struct", "swap_vfsmnt");
    PARSER_MEMBER_SIZE_INIT(swap_info_struct_old_block_size, "swap_info_struct", "old_block_size");
    PARSER_MEMBER_SIZE_INIT(swap_info_struct_pages, "swap_info_struct", "pages");
    PARSER_MEMBER_SIZE_INIT(block_device_bd_disk, "block_device", "bd_disk");
    PARSER_MEMBER_SIZE_INIT(gendisk_private_data, "gendisk", "private_data");
    PARSER_STRUCT_SIZE_INIT(page, "page");
    PARSER_MEMBER_SIZE_INIT(page_private, "page", "private");
    PARSER_MEMBER_SIZE_INIT(page_freelist, "page", "freelist");
    PARSER_MEMBER_SIZE_INIT(page_index, "page", "index");
    PARSER_MEMBER_SIZE_INIT(file_f_inode, "file", "f_inode");
    PARSER_MEMBER_SIZE_INIT(inode_i_mapping, "inode", "i_mapping");
    PARSER_MEMBER_SIZE_INIT(address_space_i_pages, "address_space", "i_pages");
}

uint64_t align_down(uint64_t x, uint64_t n) {
    return (x & -n);
}

uint64_t align_up(uint64_t x, uint64_t n) {
    return align_down(x + n - 1, n);
}

void parser_convert_ascii(ulong value, char *ascii) {
    for (int j = 0; j < 8; j++) {
        char byte = (value >> (8 * j)) & 0xFF;
        if (byte > 0x20 && byte < 0x7F) {
            ascii[j] = byte;
        } else {
            ascii[j] = '.';
        }
    }
}

int parser_vma_caches(struct task_context *tc, struct vma_cache_data **vma_cache) {
    int vma_count = 0;
    ulong tmp, vma, vm_next, mm_mt, entry_num;
    char *vma_buf;
    struct list_pair *entry_list;
    struct task_mem_usage task_mem_usage, *tm;

    tm = &task_mem_usage;
    get_task_mem_usage(tc->task, tm);

    if (!PARSER_VALID_MEMBER(mm_struct_mmap)
            && PARSER_VALID_MEMBER(mm_struct_mm_mt)) {
        mm_mt = tm->mm_struct_addr + PARSER_OFFSET(mm_struct_mm_mt);
        entry_num = do_maple_tree(mm_mt, MAPLE_TREE_COUNT, NULL);
        if (entry_num) {
            entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
            do_maple_tree(mm_mt, MAPLE_TREE_GATHER, entry_list);

            int index;
            for (index = 0; index < entry_num; index++) {
                tmp = (ulong)entry_list[index].value;
                if (!tmp) continue;
                vma_count++;
            }

            if (!vma_count) {
                error(INFO, "vma_area empty.\n");
                return 0;
            }

            *vma_cache = (struct vma_cache_data *)malloc(vma_count * sizeof(struct vma_cache_data));
            int idx = 0;
            for (index = 0; index < entry_num; index++) {
                tmp = (ulong)entry_list[index].value;
                if (!tmp) continue;
                vma_buf = fill_vma_cache(tmp);
                (*vma_cache)[idx].vm_start = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_start));
                (*vma_cache)[idx].vm_end = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_end));
                (*vma_cache)[idx].vm_flags = ULONG(vma_buf+ PARSER_OFFSET(vm_area_struct_vm_flags));
                (*vma_cache)[idx].vm_file = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_file));
                (*vma_cache)[idx].vm_pgoff = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_pgoff));
                idx++;
            }
            FREEBUF(entry_list);
        }
    } else {
        readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_mmap), KVADDR,
                &vma, sizeof(void *), "mm_struct mmap", FAULT_ON_ERROR);

        for (tmp = vma; tmp; tmp = vm_next) {
            vma_count++;
            vma_buf = fill_vma_cache(tmp);
            vm_next = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_next));
        }

        if (!vma_count) {
            error(INFO, "vma_area empty.\n");
            return 0;
        }

        *vma_cache = (struct vma_cache_data *)malloc(vma_count * sizeof(struct vma_cache_data));
        int idx = 0;
        for (tmp = vma; tmp; tmp = vm_next) {
            vma_buf = fill_vma_cache(tmp);
            (*vma_cache)[idx].vm_start = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_start));
            (*vma_cache)[idx].vm_end = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_end));
            (*vma_cache)[idx].vm_flags = ULONG(vma_buf+ PARSER_OFFSET(vm_area_struct_vm_flags));
            (*vma_cache)[idx].vm_file = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_file));
            (*vma_cache)[idx].vm_pgoff = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_pgoff));
            idx++;
            vm_next = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_next));
        }
    }
    return vma_count;
}
