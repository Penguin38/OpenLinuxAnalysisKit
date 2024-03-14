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
    long pt_regs;
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

#endif // PARSER_DEFS_H_
