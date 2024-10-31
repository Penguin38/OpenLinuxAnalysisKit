// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"

struct x86_64_pt_regs {
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

struct pt_regs {
    uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
    uint16_t ds, __ds, es, __es;
    uint16_t fs, __fs, gs, __gs;
    uint32_t orig_eax, eip;
    uint16_t cs, __cs;
    uint32_t eflags, esp;
    uint16_t ss, __ss;
};

typedef struct elf32_prstatus {
    uint32_t             pr_si_signo;
    uint32_t             pr_si_code;
    uint32_t             pr_si_errno;
    uint16_t             pr_cursig;
    uint16_t             __padding1;
    uint32_t             pr_sigpend;
    uint32_t             pr_sighold;
    uint32_t             pr_pid;
    uint32_t             pr_ppid;
    uint32_t             pr_pgrp;
    uint32_t             pd_sid;
    uint64_t             pr_utime;
    uint64_t             pr_stime;
    uint64_t             pr_cutime;
    uint64_t             pr_cstime;
    struct pt_regs       pr_reg;
    uint32_t             pr_fpvalid;
} Elf32_prstatus;

void parser_x86_core_prstatus(struct core_data_t* core_data) {
    core_data->prstatus_sizeof = sizeof(Elf32_prstatus);
    if (!core_data->prnum) return;

    int i, cur;
    struct x86_64_pt_regs regs;
    core_data->prstatus_cache = malloc(core_data->prnum * sizeof(Elf32_prstatus));
    memset(core_data->prstatus_cache, 0, core_data->prnum * sizeof(Elf32_prstatus));
    Elf32_prstatus *prstatus = core_data->prstatus_cache;

    int tgid = task_tgid(core_data->tc->task);
    struct task_context *tc = FIRST_CONTEXT();
    for (i = cur = 0; i < RUNNING_TASKS(); i++, tc++) {
        if (task_tgid(tc->task) == tgid) {
            prstatus[cur].pr_pid = tc->pid;

            if (!core_data->compat) {
                readmem(machdep->get_stacktop(tc->task) - PARSER_SIZE(pt_regs), KVADDR,
                        &prstatus[cur].pr_reg, sizeof(struct pt_regs), "gpr_get: user_pt_regs",
                        core_data->error_handle);
            } else {
                memset(&regs, 0x0, sizeof(struct x86_64_pt_regs));
                readmem(machdep->get_stacktop(tc->task) - PARSER_SIZE(pt_regs), KVADDR,
                        &regs, sizeof(struct x86_64_pt_regs), "gpr_get: user_pt_regs",
                        core_data->error_handle);

                prstatus[cur].pr_reg.ebx = regs.rbx;
                prstatus[cur].pr_reg.ecx = regs.rcx;
                prstatus[cur].pr_reg.edx = regs.rdx;
                prstatus[cur].pr_reg.esi = regs.rsi;
                prstatus[cur].pr_reg.edi = regs.rdi;
                prstatus[cur].pr_reg.ebp = regs.rbp;
                prstatus[cur].pr_reg.eax = regs.rax;
                prstatus[cur].pr_reg.ds = regs.ds;
                prstatus[cur].pr_reg.es = regs.es;
                prstatus[cur].pr_reg.fs = regs.fs;
                prstatus[cur].pr_reg.gs = regs.gs;
                prstatus[cur].pr_reg.orig_eax = regs.orig_rax;
                prstatus[cur].pr_reg.eip = regs.rip;
                prstatus[cur].pr_reg.cs = regs.cs;
                prstatus[cur].pr_reg.eflags = regs.flags;
                prstatus[cur].pr_reg.esp = regs.rsp;
                prstatus[cur].pr_reg.ss = regs.ss;
            }
            cur++;
        }
    }
}

void parser_write_x86_core_prstatus(struct core_data_t* core_data) {
    if (!core_data->prnum) return;

    Elf32_Nhdr nhdr;
    nhdr.n_namesz = NT_GNU_PROPERTY_TYPE_0;
    nhdr.n_descsz = core_data->prstatus_sizeof;
    nhdr.n_type = NT_PRSTATUS;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, NOTE_CORE_NAME_SZ, ELFCOREMAGIC);

    int index = 0;
    while (index < core_data->prnum) {
        fwrite(&nhdr, sizeof(Elf32_Nhdr), 1, core_data->fp);
        fwrite(magic, sizeof(magic), 1, core_data->fp);
        fwrite((char *)core_data->prstatus_cache + nhdr.n_descsz * index, nhdr.n_descsz, 1, core_data->fp);
        index++;
    }
}
