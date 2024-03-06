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

struct parser_offset_table {
    long mm_struct_saved_auxv;
    long mm_struct_task_size;
    long mm_struct_mmap;
    long mm_struct_mm_mt;
};

struct parser_size_table {
    long mm_struct_saved_auxv;
    long mm_struct_task_size;
    long mm_struct_mmap;
    long mm_struct_mm_mt;
};

struct parser_vma_cache_data {
    ulong vm_start;
    ulong vm_end;
    ulong vm_flags;
    ulong vm_pgoff;
    ulong vm_file;
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

#endif // PARSER_DEFS_H_
