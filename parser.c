// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "parser_defs.h"
#include "core/core.h"
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
    register_extension(command_table);
}

void __attribute__((destructor)) parser_fini(void) {}

struct parser_commands g_parser_commands[] = {
    {"core", parser_core_main, parser_core_usage},
    {"zram", NULL, NULL},
    {"shmem", NULL, NULL},
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
}

static void parser_size_table_init(void) {
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
}

uint64_t align_down(uint64_t x, uint64_t n) {
    return (x & -n);
}

uint64_t align_up(uint64_t x, uint64_t n) {
    return align_down(x + n - 1, n);
}
