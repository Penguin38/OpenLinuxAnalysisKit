// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"

struct pt_regs {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t orig_rax;
    uint64_t rip;
    uint32_t cs;
    uint32_t __cs;
    uint64_t flags;
    uint64_t rsp;
    uint32_t ss;
    uint32_t __ss;
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t ds;
    uint32_t __ds;
    uint32_t es;
    uint32_t __es;
    uint32_t fs;
    uint32_t __fs;
    uint32_t gs;
    uint32_t __gs;
};

typedef struct elf64_prstatus {
    uint32_t             pr_si_signo;
    uint32_t             pr_si_code;
    uint32_t             pr_si_errno;
    uint16_t             pr_cursig;
    uint64_t             pr_sigpend;
    uint64_t             pr_sighold;
    uint32_t             pr_pid;
    uint32_t             pr_ppid;
    uint32_t             pr_pgrp;
    uint32_t             pd_sid;
    uint64_t             pr_utime[2];
    uint64_t             pr_stime[2];
    uint64_t             pr_cutime[2];
    uint64_t             pr_cstime[2];
    struct pt_regs       pr_reg;
    uint32_t             pr_fpvalid;
} Elf64_prstatus;

void parser_x86_64_core_prstatus(struct core_data_t* core_data) {
    core_data->prstatus_sizeof = sizeof(Elf64_prstatus);
    if (!core_data->prnum) return;

    int i, cur;
    core_data->prstatus_cache = malloc(core_data->prnum * sizeof(Elf64_prstatus));
    memset(core_data->prstatus_cache, 0, core_data->prnum * sizeof(Elf64_prstatus));
    Elf64_prstatus *elf_prstatus = core_data->prstatus_cache;

    int tgid = task_tgid(core_data->tc->task);
    struct task_context *tc = FIRST_CONTEXT();
    for (i = cur = 0; i < RUNNING_TASKS(); i++, tc++) {
        if (task_tgid(tc->task) == tgid) {
            elf_prstatus[cur].pr_pid = tc->pid;

            readmem(machdep->get_stacktop(tc->task) - PARSER_SIZE(pt_regs), KVADDR,
                    &elf_prstatus[cur].pr_reg, sizeof(struct pt_regs), "gpr_get: user_pt_regs",
                    FAULT_ON_ERROR);
            cur++;
        }
    }
}

void parser_write_x86_64_core_prstatus(struct core_data_t* core_data) {
    if (!core_data->prnum) return;

    Elf64_Nhdr nhdr;
    nhdr.n_namesz = NT_GNU_PROPERTY_TYPE_0;
    nhdr.n_descsz = core_data->prstatus_sizeof;
    nhdr.n_type = NT_PRSTATUS;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, NOTE_CORE_NAME_SZ, ELFCOREMAGIC);

    int index = 0;
    while (index < core_data->prnum) {
        fwrite(&nhdr, sizeof(Elf64_Nhdr), 1, core_data->fp);
        fwrite(magic, sizeof(magic), 1, core_data->fp);
        fwrite((char *)core_data->prstatus_cache + nhdr.n_descsz * index, nhdr.n_descsz, 1, core_data->fp);
        index++;
    }
}
