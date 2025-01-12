// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "core.h"
#include "zram/zram.h"
#include "shmem/shmem.h"
#include "parser_defs.h"
#include <elf.h>

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
    note->p_filesz += sizeof(Elf64_ntfile) * core_data->vma_count + sizeof(Elf64_Nhdr) + 8 + 2 * 8 + align_up(core_data->fileslen, 4);
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
          core_data->auxv_cache, core_data->auxvnum * sizeof(Elf64_auxv), "mm_struct saved_auxv", core_data->error_handle);
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

    phdr->p_align = core_data->align_size;

    if (!core_data->filter_vma(core_data, index))
        phdr->p_filesz = phdr->p_memsz;
}

void parser_write_core_program_headers64(struct core_data_t* core_data, Elf64_Phdr *note) {
    if (!core_data->vma_count) return;

    Elf64_Phdr* prev;
    parser_core_load_vma64(core_data, 0);
    Elf64_Phdr* phdr = &((Elf64_Phdr*)core_data->load_cache)[0];
    phdr->p_offset = align_up(note->p_offset + note->p_filesz, core_data->align_size);
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
    nhdr.n_namesz = NOTE_CORE_NAME_SZ;
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

void parser_write_core_file64(struct core_data_t* core_data, Elf64_Phdr *note) {
    Elf64_Nhdr nhdr;
    nhdr.n_namesz = NOTE_CORE_NAME_SZ;
    nhdr.n_descsz = sizeof(Elf64_ntfile) * core_data->vma_count + 2 * 8 + align_up(core_data->fileslen, 4);
    nhdr.n_type = NT_FILE;

    char magic[8];
    memset(magic, 0, sizeof(magic));
    snprintf(magic, NOTE_CORE_NAME_SZ, ELFCOREMAGIC);

    fwrite(&nhdr, sizeof(Elf64_Nhdr), 1, core_data->fp);
    fwrite(magic, sizeof(magic), 1, core_data->fp);

    uint64_t number = core_data->vma_count;
    fwrite(&number, 8, 1, core_data->fp);
    uint64_t page_size = core_data->page_size;
    fwrite(&page_size, 8, 1, core_data->fp);

    int index = 0;
    while(index < core_data->vma_count) {
        Elf64_ntfile ntfile;
        ntfile.start = core_data->vma_cache[index].vm_start;
        ntfile.end = core_data->vma_cache[index].vm_end;
        ntfile.fileofs = 0x0;
        if (core_data->vma_cache[index].vm_file)
            ntfile.fileofs = core_data->vma_cache[index].vm_pgoff;
        fwrite(&ntfile, sizeof(Elf64_ntfile), 1, core_data->fp);
        index++;
    }

    index = 0;
    while(index < core_data->vma_count) {
        fwrite(core_data->vma_cache[index].buf,
               strlen(core_data->vma_cache[index].buf) + 1,
               1, core_data->fp);
        index++;
    }
}

void parser_core_note_align64(struct core_data_t* core_data, Elf64_Phdr *note) {
    memset(core_data->zero_buf, 0x0, core_data->align_size);
    uint64_t align_filesz = note->p_filesz - align_up(core_data->fileslen, 4) + core_data->fileslen;
    uint64_t offset = align_up(note->p_offset + align_filesz, core_data->align_size);
    uint64_t size = offset - (note->p_offset + align_filesz);
    fwrite(core_data->zero_buf, size, 1, core_data->fp);
}

void parser_write_core_load64(struct core_data_t* core_data) {
    physaddr_t paddr;
    uint64_t vaddr;
    int idx, i;
    struct list_pair *shmem_page_list;
    int shmem_page_count;

    for (idx = 0; idx < core_data->vma_count; ++idx) {
        Elf64_Phdr* phdr = &((Elf64_Phdr*)core_data->load_cache)[idx];
        if (!phdr->p_filesz) continue;

        // shmem cache init
        shmem_page_count = 0;
        shmem_page_list = NULL;

        int count = phdr->p_memsz / core_data->page_size;
        for (i = 0; i < count; ++i) {
            memset(core_data->page_buf, 0x0, core_data->page_size);
            vaddr = phdr->p_vaddr + i * core_data->page_size;
            paddr = (physaddr_t)0x0;
            int page_exist = uvtop(core_data->tc, vaddr, &paddr, 0);

            if (paddr) {
                if (page_exist) {
                    readmem(paddr, PHYSADDR, core_data->page_buf, core_data->page_size, "write load64", QUIET);
                } else if (core_data->parse_zram) {
                    ulong zram_offset = SWP_OFFSET(paddr);
                    ulong swap_type = SWP_TYPE(paddr);
                    parser_zram_read_page(swap_type, zram_offset, core_data->page_buf, QUIET);
                }
            } else {
                if (core_data->parse_shmem) {
                    if (!shmem_page_list) {
                        shmem_page_count = parser_shmem_get_page_cache(&core_data->vma_cache[idx], &shmem_page_list, QUIET);
                    }

                    if (shmem_page_count) {
                        parser_shmem_read_page_cache(vaddr, &core_data->vma_cache[idx], shmem_page_count,
                                                     shmem_page_list, core_data->page_buf, QUIET);
                    }
                }
            }
            fwrite(core_data->page_buf, core_data->page_size, 1, core_data->fp);
        }
        if (shmem_page_list) free(shmem_page_list);
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

    core_data->vma_count = parser_vma_caches(core_data->tc, &core_data->vma_cache);
    core_data->load_cache = malloc(core_data->vma_count * sizeof(Elf64_Phdr));
    core_data->phnum = core_data->vma_count + 1;
    core_data->fill_vma_name(core_data);
    parser_core_header64(core_data, &ehdr);
    parser_core_note64(core_data, &note);
    parser_core_prstatus64(core_data);
    parser_core_auxv64(core_data);

    parser_write_core_header64(core_data, &ehdr);
    parser_write_core_note64(core_data, &note);
    parser_write_core_program_headers64(core_data, &note);
    core_data->parser_write_core_prstatus(core_data);
    parser_write_core_auxv64(core_data);
    parser_write_core_file64(core_data, &note);
    parser_core_note_align64(core_data, &note);
    parser_write_core_load64(core_data);

    fprintf(fp, "Saved [%s].\n", corefile);
    core_data->clean(core_data);
}
