// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "shmem.h"
#include "zram/zram.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void parser_shmem_main(void) {
    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"read",   required_argument,  0, 'r'},
        {"end",    required_argument,  0, 'e'},
        {0,         0,                 0,  0 }
    };

    ulong vaddr = 0x0;
    ulong eaddr = 0x0;
    while ((opt = getopt_long(argcnt - 1, &args[1], "r:e:",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 'r':
                if (args[optind]) {
                    vaddr = htol(args[optind], FAULT_ON_ERROR, NULL);
                    eaddr = vaddr + 0x10;
                } break;
            case 'e':
                if (args[optind]) {
                    eaddr = htol(args[optind], FAULT_ON_ERROR, NULL);
                } break;
        }
    }

    unsigned char *value = (unsigned char *)malloc(PAGESIZE());
    memset(value, 0x0, PAGESIZE());
    int shmem_parse_ret = 0;
    char ascii1[9] = {'.', '.', '.', '.', '.', '.', '.', '.', '\0'};
    char ascii2[9] = {'.', '.', '.', '.', '.', '.', '.', '.', '\0'};
    ulong off = PAGEOFFSET(vaddr) / 0x8;

    struct shmem_data_t shmem_data;
    memset(&shmem_data, 0x0, sizeof(shmem_data));
    shmem_data.tc = CURRENT_CONTEXT();
    if (!shmem_data.tc) return;

    shmem_data.pid = shmem_data.tc->pid;
    shmem_data.vma_count = parser_vma_caches(shmem_data.tc, &shmem_data.vma_cache);

    for (int index = 0; index < shmem_data.vma_count; ++index) {
        if (vaddr >= shmem_data.vma_cache[index].vm_start
                && vaddr < shmem_data.vma_cache[index].vm_end) {
            parser_zram_init();
            shmem_parse_ret = parser_shmem_read_page(vaddr, &shmem_data.vma_cache[index], value, FAULT_ON_ERROR);
        }
    }

    if (shmem_data.vma_cache) free(shmem_data.vma_cache);

    if (!shmem_parse_ret) return;
    int count = (eaddr - vaddr) / 8;
    for (int index = 0; index < count; index += 2) {
        parser_convert_ascii(((ulong *)value)[index + off], ascii1);
        parser_convert_ascii(((ulong *)value)[index + 1 + off], ascii2);
        fprintf(fp, "        %lx:  %016lx %016lx  %s%s\n", vaddr + index * 0x8,
                ((ulong *)value)[index + off], ((ulong *)value)[index + 1 + off], ascii1, ascii2);
    }
}

void parser_shmem_usage(void) {
    fprintf(fp, "Usage: lp shmem [OPTION] ...\n");
    fprintf(fp, "Option:\n");
    fprintf(fp, "    -r, --read <VADDR>   read vaddr memory\n");
    fprintf(fp, "    -e, --end <VADDR>    read endvaddr memory\n");
}

int parser_shmem_read_page(ulong vaddr, struct vma_cache_data* vma_cache,
                           unsigned char* value, ulong error_handle) {
    if (!vma_cache->vm_file
            || !(vma_cache->vm_flags & (VM_SHARED | VM_MAYSHARE)))
        return 0;

    ulong vm_pgoff = vma_cache->vm_pgoff << PAGESHIFT();
    int idx = (vaddr - vma_cache->vm_start + vm_pgoff) >> PAGESHIFT();

    ulong f_inode;
    ulong i_mapping;

    readmem(vma_cache->vm_file + PARSER_OFFSET(file_f_inode), KVADDR,
            &f_inode, PARSER_SIZE(file_f_inode), "file f_inode", error_handle);

    readmem(f_inode + PARSER_OFFSET(inode_i_mapping), KVADDR,
            &i_mapping, PARSER_SIZE(inode_i_mapping), "inode i_mapping", error_handle);

    ulong i_pages = i_mapping + PARSER_OFFSET(address_space_i_pages);
    struct list_pair lp;
    lp.index = idx;

    if (!IS_KVADDR(i_pages))
        return 0;

    if (do_xarray(i_pages, XARRAY_SEARCH, &lp)) {
        ulong page = (ulong)lp.value;
        if (page & 1) {
            ulong paddr = (page >> 1) << 8;
            ulong zram_offset = SWP_OFFSET(paddr);
            ulong swap_type = SWP_TYPE(paddr);
            return parser_zram_read_page(swap_type, zram_offset, value, error_handle);
        }
    }
    return 0;
}

int parser_shmem_get_page_cache(struct vma_cache_data* vma_cache,
                           struct list_pair **page_list, ulong error_handle) {
    if (!vma_cache->vm_file
            || !(vma_cache->vm_flags & (VM_SHARED | VM_MAYSHARE)))
        return 0;

    ulong f_inode;
    ulong i_mapping;
    ulong xarray;
    ulong root_rnode;
    int count;

    readmem(vma_cache->vm_file + PARSER_OFFSET(file_f_inode), KVADDR,
            &f_inode, PARSER_SIZE(file_f_inode), "file f_inode", error_handle);

    readmem(f_inode + PARSER_OFFSET(inode_i_mapping), KVADDR,
            &i_mapping, PARSER_SIZE(inode_i_mapping), "inode i_mapping", error_handle);

    xarray = root_rnode = count = 0;
    if (MEMBER_EXISTS("address_space", "i_pages") &&
        (STREQ(MEMBER_TYPE_NAME("address_space", "i_pages"), "xarray") ||
        (STREQ(MEMBER_TYPE_NAME("address_space", "i_pages"), "radix_tree_root") &&
         MEMBER_EXISTS("radix_tree_root", "xa_head"))))
        xarray = i_mapping + PARSER_OFFSET(address_space_i_pages);
    else
        root_rnode = i_mapping + PARSER_OFFSET(address_space_i_pages);

    if (root_rnode) {
        if (IS_KVADDR(root_rnode)) {
            count = do_radix_tree(root_rnode, RADIX_TREE_COUNT, NULL);
            if (count) {
                *page_list = (struct list_pair *)malloc(sizeof(struct list_pair) * count);
                do_radix_tree(root_rnode, RADIX_TREE_GATHER, *page_list);
            }
        }
    } else {
        if (IS_KVADDR(xarray)) {
            count = do_xarray(xarray, XARRAY_COUNT, NULL);
            if (count) {
                *page_list = (struct list_pair *)malloc(sizeof(struct list_pair) * count);
                do_xarray(xarray, XARRAY_GATHER, *page_list);
            }
        }
    }
    return count;
}

int parser_shmem_read_page_cache(ulong vaddr, struct vma_cache_data* vma_cache, int count,
                struct list_pair *page_list, unsigned char* value, ulong error_handle) {
    ulong vm_pgoff = vma_cache->vm_pgoff << PAGESHIFT();
    int idx = (vaddr - vma_cache->vm_start + vm_pgoff) >> PAGESHIFT();
    ulong page = 0x0;
    for (int i = 0; i < count; ++i) {
        if (page_list[i].index == idx) {
            page = (ulong)page_list[i].value;
            break;
        }
    }

    if (page & 1) {
        ulong paddr = (page >> 1) << 8;
        ulong zram_offset = SWP_OFFSET(paddr);
        ulong swap_type = SWP_TYPE(paddr);
        return parser_zram_read_page(swap_type, zram_offset, value, error_handle);
    }
    return 0;
}
