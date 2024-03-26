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

#define GENMASK(h, l) (((1ULL<<(h+1))-1)&(~((1ULL<<l)-1)))

struct parser_offset_table {
    long mm_struct_saved_auxv;
    long mm_struct_task_size;
    long mm_struct_mmap;
    long mm_struct_mm_mt;
    long thread_info_flags;
    long vm_area_struct_vm_next;
    long vm_area_struct_vm_start;
    long vm_area_struct_vm_end;
    long vm_area_struct_vm_flags;
    long vm_area_struct_vm_file;
    long vm_area_struct_vm_pgoff;
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

    // zram
    long zram_disksize;
    long zram_compressor;
    long zram_table;
    long zram_mem_pool;
    long zram_comp;
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
    long thread_info_flags;
    long vm_area_struct_vm_next;
    long vm_area_struct_vm_start;
    long vm_area_struct_vm_end;
    long vm_area_struct_vm_flags;
    long vm_area_struct_vm_file;
    long vm_area_struct_vm_pgoff;
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

    // zram
    long zram;
    long zram_disksize;
    long zram_compressor;
    long zram_table;
    long zram_mem_pool;
    long zram_comp;
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

uint64_t align_down(uint64_t x, uint64_t n);
uint64_t align_up(uint64_t x, uint64_t n);
void parser_convert_ascii(ulong value, char *ascii);

#define BIT(nr)         (1UL << (nr))
#define BIT_ULL(nr)     (1ULL << (nr))

// crypto
void *crypto_comp_get_decompress(const char* name);

#endif // PARSER_DEFS_H_
