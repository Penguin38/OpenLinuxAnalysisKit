// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "parser_defs.h"
#include "core/core.h"
#include "zram/zram.h"
#include "shmem/shmem.h"
#include "binder/binder.h"
#include "pageowner/page_owner.h"
#include "trace/trace.h"
#include "cpu/cpu.h"
#include "time/time.h"
#include "cmdline/cmd.h"
#include "user_space_pages/user_space_pages.h"
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

static const char* sched_name[] = {
    "SCHED_NORMAL",
    "SCHED_FIFO",
    "SCHED_RR",
    "SCHED_BATCH",
    "SCHED_ISO",
    "SCHED_IDLE",
    "SCHED_DEADLINE",
};

void __attribute__((constructor)) parser_init(void) {
    parser_offset_table_init();
    parser_size_table_init();
    parser_zram_data_init();
    register_extension(command_table);
}

void __attribute__((destructor)) parser_fini(void) {
    parser_zram_data_uninit();
    parser_cpu_cache_clean();
}

struct parser_commands g_parser_commands[] = {
    {"core", parser_core_main, parser_core_usage},
    {"zram", parser_zram_main, parser_zram_usage},
    {"shmem", parser_shmem_main, parser_shmem_usage},
    {"binder", parser_binder_main, parser_binder_usage},
    {"meminfo", NULL, NULL},
    {"page_owner", parser_page_owner_main, parser_page_owner_usage},
    {"dmabuf", NULL, NULL},
    {"trace", parser_trace_main, parser_trace_usage},
    {"cpu", parser_cpu_main, parser_cpu_usage},
    {"time", parser_time_main, parser_time_usage},
    {"cmdline", parser_cmdline_main, parser_cmdline_usage},
    {"user_space_pages", parser_user_space_pages_main, parser_user_space_pages_usage},
    {"help", parser_help_main, NULL}
};

void cmd_parser(void) {
    if (argcnt < 2) return;

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
    "  linux-parser version 1.0.5, target crash-android version 8.0.6",
    "  Command: [core, ...]",
	"Exp:",
	"crash> lp [help] [COMMAND] [OPTION]",
};

struct parser_offset_table parser_offset_table = {0};
struct parser_size_table parser_size_table = {0};

static void parser_offset_table_init(void) {
    BZERO(&parser_offset_table, sizeof(parser_offset_table));
    PARSER_MEMBER_OFFSET_INIT(mm_struct_saved_auxv, "mm_struct", "saved_auxv");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_task_size, "mm_struct", "task_size");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_mmap, "mm_struct", "mmap");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_mm_mt, "mm_struct", "mm_mt");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_start_stack, "mm_struct", "start_stack");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_start_brk, "mm_struct", "start_brk");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_brk, "mm_struct", "brk");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_arg_start, "mm_struct", "arg_start");
    PARSER_MEMBER_OFFSET_INIT(mm_struct_arg_end, "mm_struct", "arg_end");
    PARSER_MEMBER_OFFSET_INIT(thread_info_flags, "thread_info", "flags");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_next, "vm_area_struct", "vm_next");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_start, "vm_area_struct", "vm_start");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_end, "vm_area_struct", "vm_end");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_flags, "vm_area_struct", "vm_flags");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_file, "vm_area_struct", "vm_file");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_pgoff, "vm_area_struct", "vm_pgoff");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_anon_name, "vm_area_struct", "anon_name");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_anon_vma, "vm_area_struct", "anon_vma");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_vm_mm, "vm_area_struct", "vm_mm");
    PARSER_MEMBER_OFFSET_INIT(vm_area_struct_detached, "vm_area_struct", "detached");
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
    PARSER_MEMBER_OFFSET_INIT(anon_vma_name_name, "anon_vma_name", "name");
    PARSER_MEMBER_OFFSET_INIT(inode_i_mapping, "inode", "i_mapping");
    PARSER_MEMBER_OFFSET_INIT(address_space_i_pages, "address_space", "page_tree");
    if (!PARSER_VALID_MEMBER(address_space_i_pages))
        PARSER_MEMBER_OFFSET_INIT(address_space_i_pages, "address_space", "i_pages");
    PARSER_MEMBER_OFFSET_INIT(binder_proc_proc_node, "binder_proc", "proc_node");
    PARSER_MEMBER_OFFSET_INIT(binder_proc_pid, "binder_proc", "pid");
    PARSER_MEMBER_OFFSET_INIT(binder_proc_context, "binder_proc", "context");
    PARSER_MEMBER_OFFSET_INIT(binder_proc_threads, "binder_proc", "threads");
    PARSER_MEMBER_OFFSET_INIT(binder_proc_todo, "binder_proc", "todo");
    PARSER_MEMBER_OFFSET_INIT(binder_context_name, "binder_context", "name");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_rb_node, "binder_thread", "rb_node");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_pid, "binder_thread", "pid");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_looper, "binder_thread", "looper");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_looper_need_return, "binder_thread", "looper_need_return");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_tmp_ref, "binder_thread", "tmp_ref");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_transaction_stack, "binder_thread", "transaction_stack");
    PARSER_MEMBER_OFFSET_INIT(binder_thread_proc, "binder_thread", "proc");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_from, "binder_transaction", "from");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_from_parent, "binder_transaction", "from_parent");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_to_thread, "binder_transaction", "to_thread");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_to_parent, "binder_transaction", "to_parent");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_to_proc, "binder_transaction", "to_proc");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_code, "binder_transaction", "code");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_flags, "binder_transaction", "flags");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_priority, "binder_transaction", "priority");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_debug_id, "binder_transaction", "debug_id");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_need_reply, "binder_transaction", "need_reply");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_buffer, "binder_transaction", "buffer");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_work, "binder_transaction", "work");
    PARSER_MEMBER_OFFSET_INIT(binder_transaction_start_time, "binder_transaction", "start_time");
    PARSER_MEMBER_OFFSET_INIT(binder_node_debug_id, "binder_node", "debug_id");
    PARSER_MEMBER_OFFSET_INIT(binder_node_work, "binder_node", "work");
    PARSER_MEMBER_OFFSET_INIT(binder_node_ptr, "binder_node", "ptr");
    PARSER_MEMBER_OFFSET_INIT(binder_node_cookie, "binder_node", "cookie");
    PARSER_MEMBER_OFFSET_INIT(mem_section_page_ext, "mem_section", "page_ext");
    PARSER_MEMBER_OFFSET_INIT(page_ext_flags, "page_ext", "flags");
    PARSER_MEMBER_OFFSET_INIT(page_ext_operations_offset, "page_ext_operations", "offset");
    PARSER_MEMBER_OFFSET_INIT(page_owner_order, "page_owner", "order");
    PARSER_MEMBER_OFFSET_INIT(page_owner_gfp_mask, "page_owner", "gfp_mask");
    PARSER_MEMBER_OFFSET_INIT(page_owner_handle, "page_owner", "handle");
    PARSER_MEMBER_OFFSET_INIT(page_owner_ts_nsec, "page_owner", "ts_nsec");
    PARSER_MEMBER_OFFSET_INIT(page_owner_free_ts_nsec, "page_owner", "free_ts_nsec");
    PARSER_MEMBER_OFFSET_INIT(page_owner_comm, "page_owner", "comm");
    PARSER_MEMBER_OFFSET_INIT(page_owner_pid, "page_owner", "pid");
    PARSER_MEMBER_OFFSET_INIT(page_owner_tgid, "page_owner", "tgid");
    PARSER_MEMBER_OFFSET_INIT(stack_record_entries, "stack_record", "entries");
    PARSER_MEMBER_OFFSET_INIT(stack_record_size, "stack_record", "size");
    PARSER_MEMBER_OFFSET_INIT(tk_core_seq, "tk_core", "seq");
    PARSER_MEMBER_OFFSET_INIT(tk_core_timekeeper, "tk_core", "timekeeper");
    PARSER_MEMBER_OFFSET_INIT(timekeeper_tkr_mono, "timekeeper", "tkr_mono");
    PARSER_MEMBER_OFFSET_INIT(tk_read_base_xtime_nsec, "tk_read_base", "xtime_nsec");
    PARSER_MEMBER_OFFSET_INIT(tk_read_base_base, "tk_read_base", "base");
    PARSER_MEMBER_OFFSET_INIT(tk_read_base_shift, "tk_read_base", "shift");
    PARSER_MEMBER_OFFSET_INIT(trace_array_array_buffer, "trace_array", "array_buffer");
    PARSER_MEMBER_OFFSET_INIT(trace_array_buffer_disabled, "trace_array", "buffer_disabled");
    PARSER_MEMBER_OFFSET_INIT(trace_array_current_trace, "trace_array", "current_trace");
    PARSER_MEMBER_OFFSET_INIT(array_buffer_buffer, "array_buffer", "buffer");
    PARSER_MEMBER_OFFSET_INIT(trace_buffer_record_disabled, "trace_buffer", "record_disabled");
    PARSER_MEMBER_OFFSET_INIT(tracer_name, "tracer", "name");
}

static void parser_size_table_init(void) {
    BZERO(&parser_size_table, sizeof(parser_size_table));
    PARSER_MEMBER_SIZE_INIT(mm_struct_saved_auxv, "mm_struct", "saved_auxv");
    PARSER_MEMBER_SIZE_INIT(mm_struct_task_size, "mm_struct", "task_size");
    PARSER_MEMBER_SIZE_INIT(mm_struct_mmap, "mm_struct", "mmap");
    PARSER_MEMBER_SIZE_INIT(mm_struct_mm_mt, "mm_struct", "mm_mt");
    PARSER_MEMBER_SIZE_INIT(mm_struct_start_stack, "mm_struct", "start_stack");
    PARSER_MEMBER_SIZE_INIT(mm_struct_start_brk, "mm_struct", "start_brk");
    PARSER_MEMBER_SIZE_INIT(mm_struct_brk, "mm_struct", "brk");
    PARSER_MEMBER_SIZE_INIT(mm_struct_arg_start, "mm_struct", "arg_start");
    PARSER_MEMBER_SIZE_INIT(mm_struct_arg_end, "mm_struct", "arg_end");
    PARSER_MEMBER_SIZE_INIT(thread_info_flags, "thread_info", "flags");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_next, "vm_area_struct", "vm_next");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_start, "vm_area_struct", "vm_start");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_end, "vm_area_struct", "vm_end");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_flags, "vm_area_struct", "vm_flags");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_file, "vm_area_struct", "vm_file");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_pgoff, "vm_area_struct", "vm_pgoff");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_anon_name, "vm_area_struct", "anon_name");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_anon_vma, "vm_area_struct", "anon_vma");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_vm_mm, "vm_area_struct", "vm_mm");
    PARSER_MEMBER_SIZE_INIT(vm_area_struct_detached, "vm_area_struct", "detached");
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
    PARSER_MEMBER_SIZE_INIT(anon_vma_name_name, "anon_vma_name", "name");
    PARSER_MEMBER_SIZE_INIT(inode_i_mapping, "inode", "i_mapping");
    PARSER_STRUCT_SIZE_INIT(address_space, "address_space");
    PARSER_MEMBER_SIZE_INIT(address_space_i_pages, "address_space", "i_pages");
    PARSER_STRUCT_SIZE_INIT(binder_proc, "binder_proc");
    PARSER_MEMBER_SIZE_INIT(binder_proc_pid, "binder_proc", "pid");
    PARSER_MEMBER_SIZE_INIT(binder_proc_context, "binder_proc", "context");
    PARSER_MEMBER_SIZE_INIT(binder_proc_threads, "binder_proc", "threads");
    PARSER_MEMBER_SIZE_INIT(binder_proc_todo, "binder_proc", "todo");
    PARSER_MEMBER_SIZE_INIT(binder_context_name, "binder_context", "name");
    PARSER_STRUCT_SIZE_INIT(binder_thread, "binder_thread");
    PARSER_MEMBER_SIZE_INIT(binder_thread_pid, "binder_thread", "pid");
    PARSER_MEMBER_SIZE_INIT(binder_thread_looper, "binder_thread", "looper");
    PARSER_MEMBER_SIZE_INIT(binder_thread_looper_need_return, "binder_thread", "looper_need_return");
    PARSER_MEMBER_SIZE_INIT(binder_thread_tmp_ref, "binder_thread", "tmp_ref");
    PARSER_MEMBER_SIZE_INIT(binder_thread_transaction_stack, "binder_thread", "transaction_stack");
    PARSER_MEMBER_SIZE_INIT(binder_thread_proc, "binder_thread", "proc");
    PARSER_STRUCT_SIZE_INIT(binder_transaction, "binder_transaction");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_from, "binder_transaction", "from");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_from_parent, "binder_transaction", "from_parent");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_to_thread, "binder_transaction", "to_thread");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_to_parent, "binder_transaction", "to_parent");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_to_proc, "binder_transaction", "to_proc");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_code, "binder_transaction", "code");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_flags, "binder_transaction", "flags");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_priority, "binder_transaction", "priority");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_debug_id, "binder_transaction", "debug_id");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_need_reply, "binder_transaction", "need_reply");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_buffer, "binder_transaction", "buffer");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_work, "binder_transaction", "work");
    PARSER_MEMBER_SIZE_INIT(binder_transaction_start_time, "binder_transaction", "start_time");
    PARSER_MEMBER_SIZE_INIT(binder_node_debug_id, "binder_node", "debug_id");
    PARSER_MEMBER_SIZE_INIT(binder_node_work, "binder_node", "work");
    PARSER_MEMBER_SIZE_INIT(binder_node_ptr, "binder_node", "ptr");
    PARSER_MEMBER_SIZE_INIT(binder_node_cookie, "binder_node", "cookie");
    PARSER_STRUCT_SIZE_INIT(page_owner, "page_owner");
    PARSER_STRUCT_SIZE_INIT(mem_section, "mem_section");
    PARSER_STRUCT_SIZE_INIT(page_ext, "page_ext");
    PARSER_MEMBER_SIZE_INIT(mem_section_page_ext, "mem_section", "page_ext");
    PARSER_MEMBER_SIZE_INIT(page_ext_flags, "page_ext", "flags");
    PARSER_MEMBER_SIZE_INIT(page_ext_operations_offset, "page_ext_operations", "offset");
    PARSER_MEMBER_SIZE_INIT(page_owner_order, "page_owner", "order");
    PARSER_MEMBER_SIZE_INIT(page_owner_gfp_mask, "page_owner", "gfp_mask");
    PARSER_MEMBER_SIZE_INIT(page_owner_handle, "page_owner", "handle");
    PARSER_MEMBER_SIZE_INIT(page_owner_ts_nsec, "page_owner", "ts_nsec");
    PARSER_MEMBER_SIZE_INIT(page_owner_free_ts_nsec, "page_owner", "free_ts_nsec");
    PARSER_MEMBER_SIZE_INIT(page_owner_comm, "page_owner", "comm");
    PARSER_MEMBER_SIZE_INIT(page_owner_pid, "page_owner", "pid");
    PARSER_MEMBER_SIZE_INIT(page_owner_tgid, "page_owner", "tgid");
    PARSER_MEMBER_SIZE_INIT(stack_record_size, "stack_record", "size");
    PARSER_STRUCT_SIZE_INIT(tk_core, "tk_core");
    PARSER_MEMBER_SIZE_INIT(tk_core_seq, "tk_core", "seq");
    PARSER_MEMBER_SIZE_INIT(tk_core_timekeeper, "tk_core", "timekeeper");
    PARSER_MEMBER_SIZE_INIT(timekeeper_tkr_mono, "timekeeper", "tkr_mono");
    PARSER_MEMBER_SIZE_INIT(tk_read_base_xtime_nsec, "tk_read_base", "xtime_nsec");
    PARSER_MEMBER_SIZE_INIT(tk_read_base_base, "tk_read_base", "base");
    PARSER_MEMBER_SIZE_INIT(tk_read_base_shift, "tk_read_base", "shift");
    PARSER_MEMBER_SIZE_INIT(trace_array_array_buffer, "trace_array", "array_buffer");
    PARSER_MEMBER_SIZE_INIT(trace_array_buffer_disabled, "trace_array", "buffer_disabled");
    PARSER_MEMBER_SIZE_INIT(trace_array_current_trace, "trace_array", "current_trace");
    PARSER_MEMBER_SIZE_INIT(array_buffer_buffer, "array_buffer", "buffer");
    PARSER_MEMBER_SIZE_INIT(trace_buffer_record_disabled, "trace_buffer", "record_disabled");
    PARSER_MEMBER_SIZE_INIT(tracer_name, "tracer", "name");
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

const char* convert_sched(int i) {
    return sched_name[i];
}

int parser_vma_caches(struct task_context *tc, struct vma_cache_data **vma_cache) {
    int vma_count = 0;
    ulong tmp, vma, vm_next, mm_mt, entry_num, vm_mm;
    char *vma_buf;
    struct list_pair *entry_list;
    struct task_mem_usage task_mem_usage, *tm;
    bool detached = false;

    tm = &task_mem_usage;
    get_task_mem_usage(tc->task, tm);
    if (!tm->mm_struct_addr)
        return vma_count;

    if (!PARSER_VALID_MEMBER(mm_struct_mmap)
            && PARSER_VALID_MEMBER(mm_struct_mm_mt)) {
        mm_mt = tm->mm_struct_addr + PARSER_OFFSET(mm_struct_mm_mt);
        entry_num = do_maple_tree(mm_mt, MAPLE_TREE_COUNT, NULL);
        if (entry_num) {
            entry_list = (struct list_pair *)malloc(entry_num * sizeof(struct list_pair));
            do_maple_tree(mm_mt, MAPLE_TREE_GATHER, entry_list);

            int index;
            for (index = 0; index < entry_num; index++) {
                tmp = (ulong)entry_list[index].value;
                if (!tmp || !IS_KVADDR(tmp))
                    continue;
                readmem(tmp + PARSER_OFFSET(vm_area_struct_vm_mm), KVADDR,
                        &vm_mm, sizeof(void *), "vm_area_struct vm_mm", FAULT_ON_ERROR);
                if (!IS_KVADDR(vm_mm) || tm->mm_struct_addr != vm_mm) {
                    fprintf(fp, "skip vma %lx, reason vma.vm_mm != task.mm\n", tmp);
                    continue;
                }
                if (PARSER_VALID_MEMBER(vm_area_struct_detached)) {
                    readmem(tmp + PARSER_OFFSET(vm_area_struct_detached), KVADDR,
                            &detached, 1, "vm_area_struct detached", FAULT_ON_ERROR);
                    if (detached) {
                        fprintf(fp, "skip vma %lx, reason detached\n", tmp);
                        continue;
                    }
                }
                vma_count++;
            }

            if (!vma_count) {
                error(INFO, "vma_area empty.\n");
                return 0;
            }

            *vma_cache = (struct vma_cache_data *)malloc(vma_count * sizeof(struct vma_cache_data));
            BZERO(*vma_cache, vma_count * sizeof(struct vma_cache_data));
            int idx = 0;
            for (index = 0; index < entry_num; index++) {
                tmp = (ulong)entry_list[index].value;
                if (!tmp || !IS_KVADDR(tmp))
                    continue;
                vma_buf = fill_vma_cache(tmp);
                vm_mm = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_mm));
                if (!IS_KVADDR(vm_mm) || tm->mm_struct_addr != vm_mm)
                    continue;
                if (PARSER_VALID_MEMBER(vm_area_struct_detached)) {
                    detached = BOOL(vma_buf + PARSER_OFFSET(vm_area_struct_detached));
                    if (detached)
                        continue;
                }
                (*vma_cache)[idx].vm_start = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_start));
                (*vma_cache)[idx].vm_end = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_end));
                (*vma_cache)[idx].vm_flags = ULONG(vma_buf+ PARSER_OFFSET(vm_area_struct_vm_flags));
                (*vma_cache)[idx].vm_file = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_file));
                (*vma_cache)[idx].vm_pgoff = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_pgoff));
                (*vma_cache)[idx].anon_name = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_anon_name));
                (*vma_cache)[idx].anon_vma = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_anon_vma));
                (*vma_cache)[idx].vm_mm = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_mm));
                idx++;
            }
            free(entry_list);
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
        BZERO(*vma_cache, vma_count * sizeof(struct vma_cache_data));
        int idx = 0;
        for (tmp = vma; tmp; tmp = vm_next) {
            vma_buf = fill_vma_cache(tmp);
            (*vma_cache)[idx].vm_start = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_start));
            (*vma_cache)[idx].vm_end = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_end));
            (*vma_cache)[idx].vm_flags = ULONG(vma_buf+ PARSER_OFFSET(vm_area_struct_vm_flags));
            (*vma_cache)[idx].vm_file = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_file));
            (*vma_cache)[idx].vm_pgoff = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_pgoff));
            (*vma_cache)[idx].anon_name = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_anon_name));
            (*vma_cache)[idx].anon_vma = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_anon_vma));
            (*vma_cache)[idx].vm_mm = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_mm));
            idx++;
            vm_next = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_next));
        }
    }
    return vma_count;
}
