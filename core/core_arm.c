// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"

struct parser_arm64_pt_regs {
    uint64_t  regs[31];
    uint64_t  sp;
    uint64_t  pc;
    uint64_t  pstate;
};

struct pt_regs {
    uint32_t  regs[13];
    uint32_t  sp;
    uint32_t  lr;
    uint32_t  pc;
    uint32_t  cpsr;
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
    uint32_t             __padding2;
} __attribute__((packed, aligned(1))) Elf32_prstatus;

void parser_arm_core_prstatus(struct core_data_t* core_data) {
    core_data->prstatus_sizeof = sizeof(Elf32_prstatus);
    if (!core_data->prnum) return;

    int i, cur;
    struct parser_arm64_pt_regs regs;
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
                memset(&regs, 0x0, sizeof(struct parser_arm64_pt_regs));
                readmem(machdep->get_stacktop(tc->task) - PARSER_SIZE(pt_regs), KVADDR,
                        &regs, sizeof(struct parser_arm64_pt_regs), "gpr_get: user_pt_regs",
                        core_data->error_handle);

                prstatus[cur].pr_reg.regs[0] = regs.regs[0];
                prstatus[cur].pr_reg.regs[1] = regs.regs[1];
                prstatus[cur].pr_reg.regs[2] = regs.regs[2];
                prstatus[cur].pr_reg.regs[3] = regs.regs[3];
                prstatus[cur].pr_reg.regs[4] = regs.regs[4];
                prstatus[cur].pr_reg.regs[5] = regs.regs[5];
                prstatus[cur].pr_reg.regs[6] = regs.regs[6];
                prstatus[cur].pr_reg.regs[7] = regs.regs[7];
                prstatus[cur].pr_reg.regs[8] = regs.regs[8];
                prstatus[cur].pr_reg.regs[9] = regs.regs[9];
                prstatus[cur].pr_reg.regs[10] = regs.regs[10];
                prstatus[cur].pr_reg.regs[11] = regs.regs[11];
                prstatus[cur].pr_reg.regs[12] = regs.regs[12];
                prstatus[cur].pr_reg.sp = regs.regs[13];
                prstatus[cur].pr_reg.lr = regs.regs[14];
                prstatus[cur].pr_reg.pc = regs.pc;
                prstatus[cur].pr_reg.cpsr = regs.pstate;
            }
            cur++;
        }
    }
}

void parser_write_arm_core_prstatus(struct core_data_t* core_data) {
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
