// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"

#define TIF_TAGGED_ADDR	26

struct pt_regs {
    uint64_t  regs[31];
    uint64_t  sp;
    uint64_t  pc;
    uint64_t  pstate;
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

struct user_pac_mask {
    uint64_t data_mask;
    uint64_t insn_mask;
};

void parser_arm64_core_prstatus(struct core_data_t* core_data) {
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

    int CONFIG_ARM64_PTR_AUTH = get_kernel_config("CONFIG_ARM64_PTR_AUTH", NULL);
    int CONFIG_ARM64_TAGGED_ADDR_ABI = get_kernel_config("CONFIG_ARM64_TAGGED_ADDR_ABI", NULL);
    if (CONFIG_ARM64_PTR_AUTH) {
        core_data->extra_note_filesz += ((sizeof(struct user_pac_mask) + sizeof(Elf64_Nhdr) + 8)  // NT_ARM_PAC_MASK
                                     + (sizeof(uint64_t) + sizeof(Elf64_Nhdr) + 8)       // NT_ARM_PAC_ENABLED_KEYS
                                     ) * core_data->prnum;
    }

    if (CONFIG_ARM64_TAGGED_ADDR_ABI) {
        core_data->extra_note_filesz += (sizeof(uint64_t) + sizeof(Elf64_Nhdr) + 8) * core_data->prnum;  // NT_ARM_TAGGED_ADDR_CTRL
    }
}

void parser_write_arm64_core_pac(struct core_data_t* core_data) {
    // NT_ARM_PAC_MASK
    Elf64_Nhdr nhdr;
    nhdr.n_namesz = NOTE_LINUX_NAME_SZ;
    nhdr.n_descsz = sizeof(struct user_pac_mask);
    nhdr.n_type = NT_ARM_PAC_MASK;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, NOTE_LINUX_NAME_SZ, ELFLINUXMAGIC);

    fwrite(&nhdr, sizeof(Elf64_Nhdr), 1, core_data->fp);
    fwrite(magic, sizeof(magic), 1, core_data->fp);

    struct user_pac_mask uregs;
    ulong vabits_actual;
    readmem(symbol_value("vabits_actual"), KVADDR, &vabits_actual, sizeof(ulong), "vabits_actual", FAULT_ON_ERROR);
    uint64_t mask = GENMASK(54, 39);
    if (vabits_actual) mask = GENMASK(54, vabits_actual);
    uregs.data_mask = mask;
    uregs.insn_mask = mask;
    fwrite(&uregs, sizeof(struct user_pac_mask), 1, core_data->fp);

    // NT_ARM_PAC_ENABLED_KEYS
    nhdr.n_descsz = sizeof(uint64_t);
    nhdr.n_type = NT_ARM_PAC_ENABLED_KEYS;

    fwrite(&nhdr, sizeof(Elf64_Nhdr), 1, core_data->fp);
    fwrite(magic, sizeof(magic), 1, core_data->fp);

    uint64_t pac_enabled_keys;
    pac_enabled_keys = 0;
    fwrite(&pac_enabled_keys, sizeof(uint64_t), 1, core_data->fp);
}

void parser_write_arm64_core_mte(struct core_data_t* core_data) {
    // NT_ARM_TAGGED_ADDR_CTRL
    Elf64_Nhdr nhdr;
    nhdr.n_namesz = NOTE_LINUX_NAME_SZ;
    nhdr.n_descsz = sizeof(uint64_t);
    nhdr.n_type = NT_ARM_TAGGED_ADDR_CTRL;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, NOTE_LINUX_NAME_SZ, ELFLINUXMAGIC);

    fwrite(&nhdr, sizeof(Elf64_Nhdr), 1, core_data->fp);
    fwrite(magic, sizeof(magic), 1, core_data->fp);

    uint64_t tagged_addr_ctrl = 0;
    fwrite(&tagged_addr_ctrl, sizeof(uint64_t), 1, core_data->fp);
}

void parser_write_arm64_core_prstatus(struct core_data_t* core_data) {
    if (!core_data->prnum) return;

    int CONFIG_ARM64_PTR_AUTH = get_kernel_config("CONFIG_ARM64_PTR_AUTH", NULL);
    int CONFIG_ARM64_TAGGED_ADDR_ABI = get_kernel_config("CONFIG_ARM64_TAGGED_ADDR_ABI", NULL);

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
        if (CONFIG_ARM64_PTR_AUTH) parser_write_arm64_core_pac(core_data);
        if (CONFIG_ARM64_TAGGED_ADDR_ABI) parser_write_arm64_core_mte(core_data);
        index++;
    }
}
