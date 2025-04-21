// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef PARSER_DEFS_H_
#define PARSER_DEFS_H_

#include "defs.h"

#define PARSER_OFFSET(X) (OFFSET_verify(parser_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define PARSER_SIZE(X) (SIZE_verify(parser_size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define PARSER_VALID_MEMBER(X) (parser_offset_table.X >= 0)
#define PARSER_ASSIGN_OFFSET(X) (parser_offset_table.X)
#define PARSER_MEMBER_OFFSET_INIT(X, Y, Z) (PARSER_ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define PARSER_ASSIGN_SIZE(X) (parser_size_table.X)
#define PARSER_MEMBER_SIZE_INIT(X, Y, Z) (PARSER_ASSIGN_SIZE(X) = MEMBER_SIZE(Y, Z))
#define PARSER_STRUCT_SIZE_INIT(X, Y) (PARSER_ASSIGN_SIZE(X) = STRUCT_SIZE(Y))

#define VM_READ     0x00000001
#define VM_WRITE    0x00000002
#define VM_EXEC     0x00000004
#define VM_SHARED   0x00000008

#define VM_MAYREAD  0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE 0x00000020
#define VM_MAYEXEC  0x00000040
#define VM_MAYSHARE 0x00000080

#define ANON_BUFSIZE (1024)

struct parser_offset_table {
    long mm_struct_saved_auxv;
    long mm_struct_task_size;
    long mm_struct_mmap;
    long mm_struct_mm_mt;
    long mm_struct_start_stack;
    long mm_struct_start_brk;
    long mm_struct_brk;
    long mm_struct_arg_start;
    long mm_struct_arg_end;
    long thread_info_flags;
    long vm_area_struct_vm_next;
    long vm_area_struct_vm_start;
    long vm_area_struct_vm_end;
    long vm_area_struct_vm_flags;
    long vm_area_struct_vm_file;
    long vm_area_struct_vm_pgoff;
    long vm_area_struct_anon_name;
    long vm_area_struct_anon_vma;
    long vm_area_struct_vm_mm;
    long vm_area_struct_detached;
    long task_struct_flags;
    long task_struct_thread;
    long thread_struct_sctlr_user;
    long thread_struct_mte_ctrl;
    long swap_info_struct_bdev;
    long swap_info_struct_swap_file;
    long swap_info_struct_swap_vfsmnt;
    long swap_info_struct_old_block_size;
    long swap_info_struct_pages;
    long block_device_bd_disk;
    long gendisk_private_data;
    long page_private;
    long page_freelist;
    long page_index;
    long file_f_inode;
    long anon_vma_name_name;
    long inode_i_mapping;
    long address_space_page_tree;
    long address_space_i_pages;
    long binder_proc_proc_node;
    long binder_proc_pid;
    long binder_proc_context;
    long binder_proc_threads;
    long binder_proc_todo;
    long binder_context_name;
    long binder_thread_rb_node;
    long binder_thread_pid;
    long binder_thread_looper;
    long binder_thread_looper_need_return;
    long binder_thread_tmp_ref;
    long binder_thread_transaction_stack;
    long binder_thread_proc;
    long binder_transaction_from;
    long binder_transaction_from_parent;
    long binder_transaction_to_thread;
    long binder_transaction_to_parent;
    long binder_transaction_to_proc;
    long binder_transaction_code;
    long binder_transaction_flags;
    long binder_transaction_priority;
    long binder_transaction_debug_id;
    long binder_transaction_need_reply;
    long binder_transaction_buffer;
    long binder_transaction_work;
    long binder_transaction_start_time;
    long binder_node_debug_id;
    long binder_node_work;
    long binder_node_ptr;
    long binder_node_cookie;
    long page_owner_order;
    long page_owner_gfp_mask;
    long page_owner_handle;
    long page_owner_ts_nsec;
    long page_owner_free_ts_nsec;
    long page_owner_comm;
    long page_owner_pid;
    long page_owner_tgid;
    long mem_section_page_ext;
    long page_ext_flags;
    long page_ext_operations_offset;
    long stack_record_entries;
    long stack_record_size;
    long tk_core_seq;
    long tk_core_timekeeper;
    long timekeeper_tkr_mono;
    long tk_read_base_base;
    long tk_read_base_xtime_nsec;
    long tk_read_base_shift;

    // zram
    long zram_disksize;
    long zram_compressor;
    long zram_table;
    long zram_mem_pool;
    long zram_comp;
    long zram_comps;
    long zram_table_entry_flags;
    long zram_table_entry_handle;
    long zram_table_entry_element;
    long zcomp_name;

    // zsmalloc
    long zspool_size_class;
    long size_class_size;
    long zspage_huge;
};

struct parser_size_table {
    long mm_struct_saved_auxv;
    long mm_struct_task_size;
    long mm_struct_mmap;
    long mm_struct_mm_mt;
    long mm_struct_start_stack;
    long mm_struct_start_brk;
    long mm_struct_brk;
    long mm_struct_arg_start;
    long mm_struct_arg_end;
    long thread_info_flags;
    long vm_area_struct_vm_next;
    long vm_area_struct_vm_start;
    long vm_area_struct_vm_end;
    long vm_area_struct_vm_flags;
    long vm_area_struct_vm_file;
    long vm_area_struct_vm_pgoff;
    long vm_area_struct_anon_name;
    long vm_area_struct_anon_vma;
    long vm_area_struct_vm_mm;
    long vm_area_struct_detached;
    long task_struct_flags;
    long task_struct_thread;
    long thread_struct_sctlr_user;
    long thread_struct_mte_ctrl;
    long pt_regs;
    long swap_info_struct;
    long swap_info_struct_bdev;
    long swap_info_struct_swap_file;
    long swap_info_struct_swap_vfsmnt;
    long swap_info_struct_old_block_size;
    long swap_info_struct_pages;
    long block_device_bd_disk;
    long gendisk_private_data;
    long page;
    long page_private;
    long page_freelist;
    long page_index;
    long file_f_inode;
    long anon_vma_name_name;
    long inode_i_mapping;
    long address_space;
    long address_space_i_pages;
    long binder_proc;
    long binder_proc_pid;
    long binder_proc_context;
    long binder_proc_threads;
    long binder_proc_todo;
    long binder_context_name;
    long binder_thread;
    long binder_thread_pid;
    long binder_thread_looper;
    long binder_thread_looper_need_return;
    long binder_thread_tmp_ref;
    long binder_thread_transaction_stack;
    long binder_thread_proc;
    long binder_transaction;
    long binder_transaction_from;
    long binder_transaction_from_parent;
    long binder_transaction_to_thread;
    long binder_transaction_to_parent;
    long binder_transaction_to_proc;
    long binder_transaction_code;
    long binder_transaction_flags;
    long binder_transaction_priority;
    long binder_transaction_debug_id;
    long binder_transaction_need_reply;
    long binder_transaction_buffer;
    long binder_transaction_work;
    long binder_transaction_start_time;
    long binder_node_debug_id;
    long binder_node_work;
    long binder_node_ptr;
    long binder_node_cookie;
    long page_owner;
    long page_owner_order;
    long page_owner_gfp_mask;
    long page_owner_handle;
    long page_owner_ts_nsec;
    long page_owner_free_ts_nsec;
    long page_owner_comm;
    long page_owner_pid;
    long page_owner_tgid;
    long mem_section;
    long mem_section_page_ext;
    long page_ext;
    long page_ext_flags;
    long page_ext_operations_offset;
    long stack_record_entries;
    long stack_record_size;
    long tk_core;
    long tk_core_seq;
    long tk_core_timekeeper;
    long timekeeper_tkr_mono;
    long tk_read_base_base;
    long tk_read_base_xtime_nsec;
    long tk_read_base_shift;

    // zram
    long zram;
    long zram_disksize;
    long zram_compressor;
    long zram_table;
    long zram_mem_pool;
    long zram_comp;
    long zram_comps;
    long zram_table_entry;
    long zram_table_entry_flags;
    long zram_table_entry_handle;
    long zram_table_entry_element;
    long zcomp_name;

    // zsmalloc
    long zspool_size_class;
    long size_class_size;
    long zspage_huge;
};

extern struct parser_offset_table parser_offset_table;
extern struct parser_size_table parser_size_table;

typedef void (*parser_main)();
typedef void (*parser_usage)();

struct parser_commands {
    char* cmd;
    parser_main main;
    parser_usage usage;
};

struct vma_cache_data {
    ulong vm_start;
    ulong vm_end;
    ulong vm_flags;
    ulong vm_pgoff;
    ulong vm_file;
    ulong anon_name;
    ulong anon_vma;
    ulong vm_mm;
    char  buf[BUFSIZE];
};

uint64_t align_down(uint64_t x, uint64_t n);
uint64_t align_up(uint64_t x, uint64_t n);
void parser_convert_ascii(ulong value, char *ascii);
int parser_vma_caches(struct task_context *tc, struct vma_cache_data **vma_cache);

// crypto
void *crypto_comp_get_decompress(const char* name);

// sched
const char* convert_sched(int i);

#endif // PARSER_DEFS_H_
