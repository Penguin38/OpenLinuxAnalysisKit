// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef CORE_CORE_H_
#define CORE_CORE_H_

#include "parser_defs.h"
#include <linux/types.h>
#include <elf.h>

void parser_core_main(void);
void parser_core_usage(void);

struct vma_cache_data {
    ulong vm_start;
    ulong vm_end;
    ulong vm_flags;
    ulong vm_pgoff;
    ulong vm_file;
};

struct core_data_t {
    // env
    struct task_context *tc;
    int pid;
    char* file;
    char parse_zram;
    char parse_shmem;

    // core
    int class;
    int machine;
    char compat;  /* 32-bit address space on 64 bits */
    FILE* fp;
    int phnum;
    int prnum;
    int auxvnum;
    int fileslen;
    int vma_count;
    struct vma_cache_data *vma_cache;
    void* load_cache;
    void* prstatus_cache;
    int prstatus_sizeof;
    void* auxv_cache;
    int extra_note_filesz;
    void (*parser_core_dump)(struct core_data_t* core_data);
    void (*parser_core_prstatus)(struct core_data_t* core_data);
    void (*parser_write_core_prstatus)(struct core_data_t* core_data);
    void (*clean)(struct core_data_t* core_data);
};

void parser_core_clean(struct core_data_t* core_data);
void parser_core_dump64(struct core_data_t* core_data);
void parser_core_dump32(struct core_data_t* core_data);

void parser_arm64_core_prstatus(struct core_data_t* core_data);
void parser_write_arm64_core_prstatus(struct core_data_t* core_data);
void parser_arm_core_prstatus(struct core_data_t* core_data);
void parser_write_arm_core_prstatus(struct core_data_t* core_data);
void parser_x86_64_core_prstatus(struct core_data_t* core_data);
void parser_write_x86_64_core_prstatus(struct core_data_t* core_data);
void parser_x86_core_prstatus(struct core_data_t* core_data);
void parser_write_x86_core_prstatus(struct core_data_t* core_data);

typedef struct elf64_auxv {
    uint64_t a_type;
    uint64_t a_val;
} Elf64_auxv;

typedef struct elf32_auxv {
    uint64_t a_type;
    uint64_t a_val;
} Elf32_auxv;

#define ELFCOREMAGIC "CORE"
#define NOTE_CORE_NAME_SZ 5
#define ELFLINUXMAGIC "LINUX"
#define NOTE_LINUX_NAME_SZ 6

#define VM_READ     0x00000001
#define VM_WRITE    0x00000002
#define VM_EXEC     0x00000004

#ifndef NT_ARM_PAC_MASK
#define NT_ARM_PAC_MASK 0x406
#endif
#ifndef NT_ARM_TAGGED_ADDR_CTRL
#define NT_ARM_TAGGED_ADDR_CTRL 0x409
#endif
#ifndef NT_ARM_PAC_ENABLED_KEYS
#define NT_ARM_PAC_ENABLED_KEYS 0x40A
#endif

#endif //  CORE_CORE_H_
