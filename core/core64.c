// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"
#include "parser_defs.h"
#include <elf.h>

void parser_core_vmas64(struct core_data_t* core_data) {
    ulong tmp, vma, vm_next, mm_mt, entry_num;
    char *vma_buf;
    struct list_pair *entry_list;
    struct task_mem_usage task_mem_usage, *tm;

    tm = &task_mem_usage;
    get_task_mem_usage(core_data->tc->task, tm);

    if (!PARSER_VALID_MEMBER(mm_struct_mmap)
            && PARSER_VALID_MEMBER(mm_struct_mm_mt)) {
        mm_mt = tm->mm_struct_addr + PARSER_OFFSET(mm_struct_mm_mt);
        entry_num = do_maple_tree(mm_mt, MAPLE_TREE_COUNT, NULL);
        if (entry_num) {
            entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
            do_maple_tree(mm_mt, MAPLE_TREE_GATHER, entry_list);

            int index;
            for (index = 0; index < entry_num; index++) {
                tmp = (ulong)entry_list[index].value;
                if (!tmp) continue;
                core_data->vma_count++;
            }

            if (!core_data->vma_count) {
                error(INFO, "vma_area empty.\n");
                return;
            }

            core_data->load_cache = malloc(core_data->vma_count * sizeof(Elf64_Phdr));
            core_data->vma_cache = (struct vma_cache_data *)malloc(core_data->vma_count * sizeof(struct vma_cache_data));
            int idx = 0;
            for (index = 0; index < entry_num; index++) {
                tmp = (ulong)entry_list[index].value;
                if (!tmp) continue;
                vma_buf = fill_vma_cache(tmp);
                core_data->vma_cache[idx].vm_start = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_start));
                core_data->vma_cache[idx].vm_end = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_end));
                core_data->vma_cache[idx].vm_flags = ULONG(vma_buf+ PARSER_OFFSET(vm_area_struct_vm_flags));
                core_data->vma_cache[idx].vm_file = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_file));
                core_data->vma_cache[idx].vm_pgoff = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_pgoff));
                idx++;
            }
            FREEBUF(entry_list);
        }
    } else {
        readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_mmap), KVADDR,
                &vma, sizeof(void *), "mm_struct mmap", FAULT_ON_ERROR);

        for (tmp = vma; tmp; tmp = vm_next) {
            core_data->vma_count++;
            vma_buf = fill_vma_cache(tmp);
            vm_next = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_next));
        }

        if (!core_data->vma_count) {
            error(INFO, "vma_area empty.\n");
            return;
        }

        core_data->load_cache = malloc(core_data->vma_count * sizeof(Elf64_Phdr));
        core_data->vma_cache = (struct vma_cache_data *)malloc(core_data->vma_count * sizeof(struct vma_cache_data));
        int idx = 0;
        for (tmp = vma; tmp; tmp = vm_next) {
            vma_buf = fill_vma_cache(tmp);
            core_data->vma_cache[idx].vm_start = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_start));
            core_data->vma_cache[idx].vm_end = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_end));
            core_data->vma_cache[idx].vm_flags = ULONG(vma_buf+ PARSER_OFFSET(vm_area_struct_vm_flags));
            core_data->vma_cache[idx].vm_file = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_file));
            core_data->vma_cache[idx].vm_pgoff = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_pgoff));
            idx++;
            vm_next = ULONG(vma_buf + PARSER_OFFSET(vm_area_struct_vm_next));
        }
    }
}

void parser_core_header64(struct core_data_t* core_data, Elf64_Ehdr *ehdr) {
    snprintf((char *)ehdr->e_ident, 5, ELFMAG);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;

    ehdr->e_type = ET_CORE;
    ehdr->e_machine = core_data->machine;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = 0x0;
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_shoff = 0x0;
    ehdr->e_flags = 0x0;
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = core_data->phnum;
    ehdr->e_shentsize = 0x0;
    ehdr->e_shnum = 0x0;
    ehdr->e_shstrndx = 0x0;
}

void parser_write_core_header64(struct core_data_t* core_data, Elf64_Ehdr *ehdr) {
    fwrite(ehdr, sizeof(Elf64_Ehdr), 1, core_data->fp);
}

void parser_core_note64(struct core_data_t* core_data, Elf64_Phdr *note) {
    note->p_type = PT_NOTE;
    note->p_offset = sizeof(Elf64_Ehdr) + core_data->phnum * sizeof(Elf64_Phdr);
}

void parser_write_core_note64(struct core_data_t* core_data, Elf64_Phdr *note) {
    note->p_filesz += (core_data->prstatus_sizeof + sizeof(Elf64_Nhdr) + 8) * core_data->prnum;
    note->p_filesz += sizeof(Elf64_auxv) * core_data->auxvnum + sizeof(Elf64_Nhdr) + 8;
    note->p_filesz += core_data->extra_note_filesz;
    fwrite(note, sizeof(Elf64_Phdr), 1, core_data->fp);
}

void parser_core_prstatus64(struct core_data_t* core_data) {
    int tgid = task_tgid(core_data->tc->task);
    struct task_context *tc = FIRST_CONTEXT();
    for (int i = core_data->prnum = 0; i < RUNNING_TASKS(); i++, tc++) {
        if (task_tgid(tc->task) == tgid) {
            core_data->prnum++;
        }
    }
    core_data->parser_core_prstatus(core_data);
}

void parser_core_auxv64(struct core_data_t* core_data) {
    core_data->auxvnum = PARSER_SIZE(mm_struct_saved_auxv) / sizeof(Elf64_auxv);

    core_data->auxv_cache = malloc(core_data->auxvnum * sizeof(Elf64_auxv));
    struct task_mem_usage task_mem_usage, *tm;
    tm = &task_mem_usage;
    get_task_mem_usage(core_data->tc->task, tm);
    readmem(tm->mm_struct_addr + PARSER_OFFSET(mm_struct_saved_auxv), KVADDR,
          core_data->auxv_cache, core_data->auxvnum * sizeof(Elf64_auxv), "mm_struct saved_auxv", FAULT_ON_ERROR);
}

void parser_core_load_vma64(struct core_data_t* core_data, int index) {
    Elf64_Phdr* phdr = &((Elf64_Phdr* )core_data->load_cache)[index];
    memset(phdr, 0x0, sizeof(Elf64_Phdr));

    phdr->p_type = PT_LOAD;
    phdr->p_vaddr = (Elf64_Addr)core_data->vma_cache[index].vm_start;
    phdr->p_paddr = 0x0;
    phdr->p_memsz = (Elf64_Addr)core_data->vma_cache[index].vm_end
                    - (Elf64_Addr)core_data->vma_cache[index].vm_start;

    phdr->p_flags = 0x0;
    if (core_data->vma_cache[index].vm_flags & VM_READ)
        phdr->p_flags |= PF_R;

    if (core_data->vma_cache[index].vm_flags & VM_WRITE)
        phdr->p_flags |= PF_W;

    if (core_data->vma_cache[index].vm_flags & VM_EXEC)
        phdr->p_flags |= PF_X;

    if ((phdr->p_flags) & PF_R)
        phdr->p_filesz = phdr->p_memsz;

    phdr->p_align = PAGESIZE();
}

void parser_write_core_program_headers64(struct core_data_t* core_data, Elf64_Phdr *note) {
    if (!core_data->vma_count) return;

    Elf64_Phdr* prev;
    parser_core_load_vma64(core_data, 0);
    Elf64_Phdr* phdr = &((Elf64_Phdr*)core_data->load_cache)[0];
    phdr->p_offset = align_up(note->p_offset + note->p_filesz, PAGESIZE());
    fwrite(phdr, sizeof(Elf64_Phdr), 1, core_data->fp);

    for (int index = 1; index < core_data->vma_count; ++index) {
        prev = &((Elf64_Phdr*)core_data->load_cache)[index - 1];
        phdr = &((Elf64_Phdr*)core_data->load_cache)[index];
        parser_core_load_vma64(core_data, index);
        phdr->p_offset = prev->p_offset + prev->p_filesz;
        fwrite(phdr, sizeof(Elf64_Phdr), 1, core_data->fp);
    }
}

void parser_write_core_auxv64(struct core_data_t* core_data) {
    Elf64_Nhdr nhdr;
    nhdr.n_namesz = NT_GNU_PROPERTY_TYPE_0;
    nhdr.n_descsz = sizeof(Elf64_auxv) * core_data->auxvnum;
    nhdr.n_type = NT_AUXV;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, NOTE_CORE_NAME_SZ, ELFCOREMAGIC);

    fwrite(&nhdr, sizeof(Elf64_Nhdr), 1, core_data->fp);
    fwrite(magic, sizeof(magic), 1, core_data->fp);

    int index = 0;
    while (index < core_data->auxvnum) {
        fwrite((char *)core_data->auxv_cache + index * sizeof(Elf64_auxv), sizeof(Elf64_auxv), 1, core_data->fp);
        index++;
    }
}

void parser_core_note_align64(struct core_data_t* core_data, Elf64_Phdr *note) {
    unsigned char zero[4096];
    memset(&zero, 0x0, sizeof(zero));
    uint64_t offset = align_up(note->p_offset + note->p_filesz, PAGESIZE());
    uint64_t size = offset - (note->p_offset + note->p_filesz);
    fwrite(zero, size, 1, core_data->fp);
}

void parser_write_core_load64(struct core_data_t* core_data) {
    unsigned char page_buf[4096];
    physaddr_t paddr;
    uint64_t vaddr;
    int idx, i;

    for (idx = 0; idx < core_data->vma_count; ++idx) {
        Elf64_Phdr* phdr = &((Elf64_Phdr*)core_data->load_cache)[idx];
        if (!phdr->p_filesz) continue;

        int count = phdr->p_memsz / sizeof(page_buf);
        for (i = 0; i < count; ++i) {
            memset(&page_buf, 0x0, sizeof(page_buf));
            vaddr = phdr->p_vaddr + i * sizeof(page_buf);
            paddr = (physaddr_t)0x0;
            int page_exist = uvtop(core_data->tc, vaddr, &paddr, 0);

            if (paddr) {
                if (page_exist) {
                    readmem(paddr, PHYSADDR, page_buf, sizeof(page_buf), "write load64", QUIET);
                }
            }
            fwrite(page_buf, sizeof(page_buf), 1, core_data->fp);
        }
    }
}

void parser_core_dump64(struct core_data_t* core_data) {
    Elf64_Ehdr ehdr;
    Elf64_Phdr note;
    memset(&ehdr, 0, sizeof(Elf64_Ehdr));
    memset(&note, 0, sizeof(Elf64_Phdr));

    char* corefile = NULL;
    char filename[32];
    if (core_data->file) {
        corefile = core_data->file;
    } else {
        snprintf(filename, sizeof(filename), "%d.core", core_data->pid);
        corefile = filename;
    }

    core_data->fp = fopen(corefile, "wb");
    if (!core_data->fp) {
        error(INFO, "Can't open %s\n", corefile);
        return;
    }

    parser_core_vmas64(core_data);
    core_data->phnum = core_data->vma_count + 1;
    parser_core_header64(core_data, &ehdr);
    parser_core_note64(core_data, &note);
    parser_core_prstatus64(core_data);
    parser_core_auxv64(core_data);

    parser_write_core_header64(core_data, &ehdr);
    parser_write_core_note64(core_data, &note);
    parser_write_core_program_headers64(core_data, &note);
    core_data->parser_write_core_prstatus(core_data);
    parser_write_core_auxv64(core_data);
    parser_core_note_align64(core_data, &note);
    parser_write_core_load64(core_data);

    fprintf(fp, "Saved [%s].\n", corefile);
    core_data->clean(core_data);
}
