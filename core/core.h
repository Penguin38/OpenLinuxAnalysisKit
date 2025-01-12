// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef CORE_CORE_H_
#define CORE_CORE_H_

#include "parser_defs.h"
#include <linux/types.h>
#include <elf.h>

void parser_core_main(void);
void parser_core_usage(void);

#define FILTER_SPECIAL_VMA          (1 << 0)
#define FILTER_FILE_VMA             (1 << 1)
#define FILTER_SHARED_VMA           (1 << 2)
#define FILTER_SANITIZER_SHADOW_VMA (1 << 3)
#define FILTER_NON_READ_VMA         (1 << 4)
#define FILTER_SIGNAL_CONTEXT       (1 << 5)    // unused
#define FILTER_MINIDUMP             (1 << 6)    // unused

struct core_data_t {
    // env
    struct task_context *tc;
    int pid;
    char* file;
    int filter_flags;
    char parse_zram;
    char parse_shmem;
    ulong error_handle;

    ulong mm_start_stack;
    ulong mm_start_brk;
    ulong mm_brk;

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
    unsigned char* zero_buf;
    unsigned char* page_buf;
    int align_size;
    int page_size;

    void (*parser_core_dump)(struct core_data_t* core_data);
    void (*parser_core_prstatus)(struct core_data_t* core_data);
    void (*parser_write_core_prstatus)(struct core_data_t* core_data);
    void (*clean)(struct core_data_t* core_data);
    void (*fill_vma_name)(struct core_data_t* core_data);
    int (*filter_vma)(struct core_data_t* core_data, int index);
};

void parser_core_clean(struct core_data_t* core_data);
void parser_core_fill_vma_name(struct core_data_t* core_data);
int parser_core_filter_vma(struct core_data_t* core_data, int index);

#if defined(__LP64__)
void parser_core_dump64(struct core_data_t* core_data);
void parser_core_dump32(struct core_data_t* core_data);
#else
void parser_core_dump32(struct core_data_t* core_data);
#endif

#if defined(ARM64)
void parser_arm64_core_prstatus(struct core_data_t* core_data);
void parser_write_arm64_core_prstatus(struct core_data_t* core_data);
void parser_arm_core_prstatus(struct core_data_t* core_data);
void parser_write_arm_core_prstatus(struct core_data_t* core_data);
#elif defined(ARM)
void parser_arm_core_prstatus(struct core_data_t* core_data);
void parser_write_arm_core_prstatus(struct core_data_t* core_data);
#endif

#if defined(X86_64)
void parser_x86_64_core_prstatus(struct core_data_t* core_data);
void parser_write_x86_64_core_prstatus(struct core_data_t* core_data);
void parser_x86_core_prstatus(struct core_data_t* core_data);
void parser_write_x86_core_prstatus(struct core_data_t* core_data);
#elif defined(X86)
void parser_x86_core_prstatus(struct core_data_t* core_data);
void parser_write_x86_core_prstatus(struct core_data_t* core_data);
#endif

typedef struct elf64_auxv {
    uint64_t a_type;
    uint64_t a_val;
} Elf64_auxv;

typedef struct elf32_auxv {
    uint64_t a_type;
    uint64_t a_val;
} Elf32_auxv;

typedef struct elf64_ntfile{
    uint64_t start;
    uint64_t end;
    uint64_t fileofs;
} Elf64_ntfile;

typedef struct elf32_ntfile{
    uint32_t start;
    uint32_t end;
    uint32_t fileofs;
} Elf32_ntfile;

#define ELFCOREMAGIC "CORE"
#define NOTE_CORE_NAME_SZ 5
#define ELFLINUXMAGIC "LINUX"
#define NOTE_LINUX_NAME_SZ 6

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
