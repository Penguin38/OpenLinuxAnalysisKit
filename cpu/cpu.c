// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "cpu/cpu.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <linux/elf.h>

struct cpu_bitmap {
    int is_set;
    void *precpu_cache;
    void *panic_cache;
};

static struct cpu_bitmap* cpu_cache = NULL;
static void* cpu_panic_task_regs_cache = NULL;
struct cpu_bitmap* get_cpu_cache(void) {
    if (!cpu_cache) {
        int size = NR_CPUS * sizeof(struct cpu_bitmap);
        cpu_cache = (struct cpu_bitmap *)malloc(size);
        memset(cpu_cache, 0x0, size);
    }
    return cpu_cache;
}

struct vmcore_data {
    ulong flags;
    int ndfd;
    FILE *ofp;
    uint header_size;
    char *elf_header;
    uint num_pt_load_segments;
    struct pt_load_segment *pt_load_segments;
    Elf32_Ehdr *elf32;
    Elf32_Phdr *notes32;
    Elf32_Phdr *load32;
    Elf64_Ehdr *elf64;
    Elf64_Phdr *notes64;
    Elf64_Phdr *load64;
    Elf64_Shdr *sect0_64;
    void *nt_prstatus;
    void *nt_prpsinfo;
    void *nt_taskstruct;
    ulong task_struct;
    uint page_size;
    ulong switch_stack;
    uint num_prstatus_notes;
    void *nt_prstatus_percpu[NR_CPUS];
    void *vmcoreinfo;
    uint size_vmcoreinfo;
};

void parser_cpu_main(void) {
    int cpu_idx = -1;
    char* cmm = NULL;
    bool reset_cpu = false;
    int cpu_lv = 1;

    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"cmm",   required_argument, 0,  1 },
        {"cpu",   required_argument, 0, 'c'},
        {"reset", no_argument,       0, 'r'},
        {"lv",    required_argument, 0, 'l'},
    };

    while ((opt = getopt_long(argcnt - 1, &args[1], "c:rl:",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 1:
                if (args[optind]) {
                    cmm = optarg;
                } break;
            case 'c':
                if (args[optind]) {
                    cpu_idx = htol(args[optind], FAULT_ON_ERROR, NULL);
                } break;
            case 'r':
                reset_cpu = true;
                break;
            case 'l':
                if (args[optind]) {
                    cpu_lv = htol(args[optind], FAULT_ON_ERROR, NULL);
                    cpu_lv %= 4;
                } break;
        }
    }

    if (cpu_idx < 0)
        error(FATAL, "cpu id not set!\n");

    if (!machine_type("ARM64"))
        error(FATAL, "Only support machine arm64.\n");

    if (cmm)
        parser_cpu_set(cmm, cpu_idx, cpu_lv);
    else if (reset_cpu)
        parser_cpu_reset(cpu_idx);
}

struct arm64_reg_map {
    char regs[16];
    int position;
};

static struct arm64_reg_map arm64_reg_maps[] = {
    {"x0", 0},   {"x1", 1},   {"x2", 2},   {"x3", 3},
    {"x4", 4},   {"x5", 5},   {"x6", 6},   {"x7", 7},
    {"x8", 8},   {"x9", 9},   {"x10", 10}, {"x11", 11},
    {"x12", 12}, {"x13", 13}, {"x14", 14}, {"x15", 15},
    {"x16", 16}, {"x17", 17}, {"x18", 18}, {"x19", 19},
    {"x20", 20}, {"x21", 21}, {"x22", 22}, {"x23", 23},
    {"x24", 24}, {"x25", 25}, {"x26", 26}, {"x27", 27},
    {"x28", 28}, {"x29", 29}, {"x30", 30}, {"pc", 32},
    {"sp", 31},  {"pstate", 33}, {"spsr", 33},
};

static struct arm64_reg_map arm64_reg_sp_maps[] = {
    {"sp_el0", 31}, {"sp_el1", 31}, {"sp_el2", 31}, {"sp_el3", 31},
    {"spsr_el0", 33}, {"spsr_el1", 33}, {"spsr_el2", 33}, {"spsr_el3", 33},
};

void parser_cpu_reset(int idx) {
    struct vmcore_data *vmd = get_kdump_vmcore_data();
    struct cpu_bitmap* cache = get_cpu_cache();
    if (cache[idx].is_set) {
        free(vmd->nt_prstatus_percpu[idx]);
        vmd->nt_prstatus_percpu[idx] = cache[idx].precpu_cache;
        cache[idx].precpu_cache = 0;
        cache[idx].is_set = 0;
#ifdef ARM64
        if (cache[idx].panic_cache)
            BCOPY(cache[idx].panic_cache, &machdep->machspec->panic_task_regs[idx], sizeof(struct arm64_pt_regs));
        else
            BZERO(&machdep->machspec->panic_task_regs[idx], sizeof(struct arm64_pt_regs));
#endif
    }
}

void parser_cpu_set(char* cmm, int idx, int lv) {
    struct vmcore_data *vmd = get_kdump_vmcore_data();
    size_t len;
    uint64_t addr;
    char regs_name[16];
    char type_name[16];
    char line[1024];
    char* user_regs;
    char* user_data;

    user_data = (char *)malloc(SIZE(elf_prstatus) + sizeof(Elf64_Nhdr) + 8);
    Elf64_Nhdr note64;
    note64.n_namesz = 5;
    note64.n_descsz = SIZE(elf_prstatus);
    note64.n_type = NT_PRSTATUS;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, 5, "CPU%d", idx);

    len = sizeof(Elf64_Nhdr);
    len = roundup(len + note64.n_namesz, 4);
    len = roundup(len + note64.n_descsz, 4);
    user_regs = user_data + len - SIZE(elf_prstatus) + OFFSET(elf_prstatus_pr_reg);

    memset(user_data, 0x0, SIZE(elf_prstatus) + sizeof(Elf64_Nhdr) + 8);
    memcpy(user_data, &note64, sizeof(Elf64_Nhdr));
    memcpy(user_data + sizeof(Elf64_Nhdr), magic, 8);

    int count = sizeof(arm64_reg_maps)/sizeof(arm64_reg_maps[0]);

    FILE *ofp = fopen(cmm, "r");
    if (ofp) {
        while (fgets(line, sizeof(line), ofp)) {
            sscanf(line, "%s %s %lx", type_name, regs_name, &addr);
            regs_name[15] = '\0';
            type_name[15] = '\0';

            if (!strcmp("r.s", type_name)) {
                for (int index = 0; index < count; ++index) {
                    if (!strcmp(arm64_reg_maps[index].regs, regs_name)) {
                        memcpy(user_regs + sizeof(ulong) * arm64_reg_maps[index].position, &addr, sizeof(ulong));
                        break;
                    }

                    if (!strcmp(arm64_reg_sp_maps[lv].regs, regs_name)) {
                        memcpy(user_regs + sizeof(ulong) * arm64_reg_sp_maps[lv].position, &addr, sizeof(ulong));
                        break;
                    }

                    if (!strcmp(arm64_reg_sp_maps[lv + 4].regs, regs_name)) {
                        memcpy(user_regs + sizeof(ulong) * arm64_reg_sp_maps[lv + 4].position, &addr, sizeof(ulong));
                        break;
                    }
                }
            }
        }
        fclose(ofp);

        struct cpu_bitmap* cache = get_cpu_cache();
        if (!cache[idx].is_set) {
            cache[idx].is_set = 1;
            cache[idx].precpu_cache = vmd->nt_prstatus_percpu[idx];
#ifdef ARM64
            if (machdep->machspec->panic_task_regs
                    && cpu_panic_task_regs_cache != machdep->machspec->panic_task_regs)
                cache[idx].panic_cache = &machdep->machspec->panic_task_regs[idx];
#endif
        } else {
            free(vmd->nt_prstatus_percpu[idx]);
            vmd->nt_prstatus_percpu[idx] = 0x0;
        }
#ifdef ARM64
        if (!machdep->machspec->panic_task_regs) {
            machdep->machspec->panic_task_regs = calloc((size_t)kt->cpus, sizeof(struct arm64_pt_regs));
            memset(machdep->machspec->panic_task_regs, 0x0, (size_t)kt->cpus * sizeof(struct arm64_pt_regs));
            cpu_panic_task_regs_cache = machdep->machspec->panic_task_regs;
        }
        if (machdep->machspec->panic_task_regs)
            BCOPY(user_regs, &machdep->machspec->panic_task_regs[idx], sizeof(struct arm64_pt_regs));
#endif
        vmd->nt_prstatus_percpu[idx] = user_data;
    }
}

void parser_cpu_cache_clean(void) {
    if (cpu_cache) {
        free(cpu_cache);
        cpu_cache = NULL;
    }
    if (cpu_panic_task_regs_cache) {
        free(cpu_panic_task_regs_cache);
        cpu_panic_task_regs_cache = NULL;
#ifdef ARM64
        machdep->machspec->panic_task_regs = NULL;
#endif
    }
}

void parser_cpu_usage(void) {
    fprintf(fp, "Usage: cpu [option] ...\n");
    fprintf(fp, "Option:\n");
    fprintf(fp, "  --cmm <PATH>: core_regs.cmm\n");
    fprintf(fp, "  --cpu <ID>\n");
    fprintf(fp, "  --lv <EXC LEVEL>\n");
    fprintf(fp, "  --reset\n");
}
