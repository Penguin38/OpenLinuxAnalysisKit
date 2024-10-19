// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "zram.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

struct zram_data_t* zram_data_cache = NULL;
struct pagecache_data_t* pagecache_data_cache = NULL;
ulong PARSER_ZRAM_FLAG_SHIFT = 0;
ulong PARSER_ZRAM_FLAG_SAME_BIT = 0;
ulong PARSER_ZRAM_FLAG_WB_BIT = 0;
ulong PARSER_ZRAM_COMP_PRIORITY_BIT1 = 0;
ulong PARSER_ZRAM_COMP_PRIORITY_MASK = 0;
static int zram_total = 0;
static int zram_ready = 0;
static int zsmalloc_ready = 0;

void parser_zram_main(void) {
    parser_zram_init();

    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"read",   required_argument,  0, 'r'},
        {"end",    required_argument,  0, 'e'},
        {"offset", required_argument,  0, 'o'},
        {"type",   required_argument,  0, 't'},
        {"file",   required_argument,  0, 'f'},
        {"data",   no_argument,        0, 'd'},
        {0,         0,                 0,  0 }
    };

    ulong vaddr = 0x0;
    ulong eaddr = 0x0;
    ulong zram_off = 0x0;
    int dump_zram_off = 0;
    int swap_type = 0;
    char *filename = NULL;
    int debug_data = 0;
    while ((opt = getopt_long(argcnt - 1, &args[1], "r:e:o:t:f:d",
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
            case 'o':
                if (args[optind]) {
                    zram_off = htol(args[optind], FAULT_ON_ERROR, NULL);
                    dump_zram_off = 1;
                    vaddr = 0x0;
                    eaddr = 0x1000;
                } break;
            case 't':
                if (args[optind]) {
                    swap_type = htol(args[optind], FAULT_ON_ERROR, NULL);
                } break;
            case 'f':
                if (args[optind]) {
                    filename = args[optind];
                } break;
            case 'd':
                debug_data = 1;
                break;
        }
    }

    if (debug_data) {
        for (int i = 0; i < zram_total; ++i) {
            fprintf(fp, "zram_data_cache[%d].zram: %lx\n", i, zram_data_cache[i].zram);
            fprintf(fp, "zram_data_cache[%d].comp_count: %ld\n", i, zram_data_cache[i].comp_count);
            for (int k = 0; k < zram_data_cache[i].comp_count; k++) {
                fprintf(fp, "zram_data_cache[%d].comp[%d]: %lx\n", i, k, zram_data_cache[i].comp[k]);
            }
            fprintf(fp, "zram_data_cache[%d].pages: %lx\n", i, zram_data_cache[i].pages);
            fprintf(fp, "pagecache_data_cache[%d].space: %lx\n", i, pagecache_data_cache[i].space);
            fprintf(fp, "pagecache_data_cache[%d].cache_count: %d\n", i, pagecache_data_cache[i].cache_count);
            fprintf(fp, "pagecache_data_cache[%d].cache: %p\n", i, pagecache_data_cache[i].cache);
            for (int j = 0; j < pagecache_data_cache[i].cache_count; ++j) {
                fprintf(fp, "pagecache_data_cache[%d].cache[%d].page_count: %d\n", i, j, pagecache_data_cache[i].cache[j].page_count);
                fprintf(fp, "pagecache_data_cache[%d].cache[%d].pages: %p\n", i, j, pagecache_data_cache[i].cache[j].pages);
            }
        }
        return;
    }

    unsigned char value[4096];
    memset(value, 0x0, 4096);
    int zram_parse_ret = 0;
    char ascii1[9] = {'.', '.', '.', '.', '.', '.', '.', '.', '\0'};
    char ascii2[9] = {'.', '.', '.', '.', '.', '.', '.', '.', '\0'};
    ulong off = PAGEOFFSET(vaddr) / 0x8;

    if (dump_zram_off) {
        zram_parse_ret = parser_zram_read_page(swap_type, zram_off, value, FAULT_ON_ERROR);
    } else {
        zram_parse_ret = parser_zram_read_buf(vaddr, value, FAULT_ON_ERROR);
    }

    if (!filename) {
        if (!zram_parse_ret) return;
        int count = (eaddr - vaddr) / 8;
        for (int index = 0; index < count; index += 2) {
            parser_convert_ascii(((ulong *)value)[index + off], ascii1);
            parser_convert_ascii(((ulong *)value)[index + 1 + off], ascii2);
            fprintf(fp, "        %lx:  %016lx %016lx  %s%s\n", vaddr + index * 0x8,
                    ((ulong *)value)[index + off], ((ulong *)value)[index + 1 + off], ascii1, ascii2);
        }
    } else {
        FILE *output = fopen(filename, "wb");
        if (output) {
            if (zram_data_cache[swap_type].zram) {
                for(int i = 0; i < zram_data_cache[swap_type].pages + 1; i++) {
                    memset(value, 0x0, 4096);
                    parser_zram_read_page(swap_type, i, value, QUIET);
                    fwrite(value, sizeof(value), 1, output);
                }
                fprintf(fp, "Saved [%s].\n", filename);
            }
            fclose(output);
        }
    }
}

void parser_zram_usage(void) {
    fprintf(fp, "Usage: zram [option] ...\n");
    fprintf(fp, "   Option:\n");
    fprintf(fp, "       --read|-r <VADDR>: read vaddr memory.\n");
    fprintf(fp, "       --end|-e <VADDR>: read endvaddr memory.\n");
    fprintf(fp, "       --offset|-o <OFFSET>: read zram page.\n");
    fprintf(fp, "       --type|-t <TYPE>: zram<TYPE>, def: 0.\n");
    fprintf(fp, "       --file|-f <FILE>: save zram.bin to file.\n");
}

void parser_zram_init(void) {
    // zram.ko
    unsigned char *fill_zram_buf = NULL;
    ulong nameptr;
    char name[128];

    if (!zram_ready) {
        PARSER_MEMBER_OFFSET_INIT(zram_disksize, "zram", "disksize");
        // PARSER_MEMBER_OFFSET_INIT(zram_compressor, "zram", "compressor");
        PARSER_MEMBER_OFFSET_INIT(zram_table, "zram", "table");
        PARSER_MEMBER_OFFSET_INIT(zram_mem_pool, "zram", "mem_pool");
        PARSER_MEMBER_OFFSET_INIT(zram_comp, "zram", "comp");
        PARSER_MEMBER_OFFSET_INIT(zram_comps, "zram", "comps");
        PARSER_MEMBER_OFFSET_INIT(zram_table_entry_flags, "zram_table_entry", "flags");
        PARSER_MEMBER_OFFSET_INIT(zram_table_entry_handle, "zram_table_entry", "handle");
        PARSER_MEMBER_OFFSET_INIT(zram_table_entry_element, "zram_table_entry", "element");
        PARSER_MEMBER_OFFSET_INIT(zcomp_name, "zcomp", "name");

        PARSER_MEMBER_SIZE_INIT(zram_disksize, "zram", "disksize");
        // PARSER_MEMBER_SIZE_INIT(zram_compressor, "zram", "compressor");
        PARSER_MEMBER_SIZE_INIT(zram_table, "zram", "table");
        PARSER_MEMBER_SIZE_INIT(zram_mem_pool, "zram", "mem_pool");
        PARSER_MEMBER_SIZE_INIT(zram_comp, "zram", "comp");
        PARSER_MEMBER_SIZE_INIT(zram_comps, "zram", "comps");
        PARSER_MEMBER_SIZE_INIT(zram_table_entry_flags, "zram_table_entry", "flags");
        PARSER_MEMBER_SIZE_INIT(zram_table_entry_handle, "zram_table_entry", "handle");
        PARSER_MEMBER_SIZE_INIT(zram_table_entry_element, "zram_table_entry", "element");
        PARSER_MEMBER_SIZE_INIT(zcomp_name, "zcomp", "name");

        PARSER_STRUCT_SIZE_INIT(zram, "zram");
        PARSER_STRUCT_SIZE_INIT(zram_table_entry, "zram_table_entry");

        // check zram.ko ready
        if (!PARSER_VALID_MEMBER(zram_disksize)) {
            error(FATAL, "Please run mod -s zram.\n");
        }

        long zram_flag_shift;
        if (enumerator_value("ZRAM_LOCK", &zram_flag_shift)) {
            ; // do nothing
        } else if (THIS_KERNEL_VERSION >= LINUX(6,1,0)) {
            zram_flag_shift = PAGESHIFT() + 1;
        } else {
            zram_flag_shift = 24;
        }
        PARSER_ZRAM_FLAG_SHIFT = 1 << zram_flag_shift;
        PARSER_ZRAM_FLAG_SAME_BIT = 1 << (zram_flag_shift + 1);
        PARSER_ZRAM_FLAG_WB_BIT = 1 << (zram_flag_shift + 2);
        PARSER_ZRAM_COMP_PRIORITY_BIT1 = zram_flag_shift + 7;
        PARSER_ZRAM_COMP_PRIORITY_MASK = 0x3;

        for (int i = 0; i < zram_total; ++i) {
            if (!zram_data_cache[i].zram) continue;
            fill_zram_buf = (unsigned char *)GETBUF(PARSER_SIZE(zram));
            BZERO(fill_zram_buf, PARSER_SIZE(zram));
            readmem(zram_data_cache[i].zram, KVADDR, fill_zram_buf, PARSER_SIZE(zram), "fill_zram_buf", FAULT_ON_ERROR);
            if (!PARSER_VALID_MEMBER(zram_comps)) {
                zram_data_cache[i].comp_count = 1;
                zram_data_cache[i].comp[0] = ULONG(fill_zram_buf + PARSER_OFFSET(zram_comp));
            } else {
                zram_data_cache[i].comp_count = PARSER_SIZE(zram_comps) / sizeof(void *);
                for (int k = 0; k < zram_data_cache[i].comp_count; k++) {
                    zram_data_cache[i].comp[k] = ULONG(fill_zram_buf + PARSER_OFFSET(zram_comps) + 8 * k);
                }
            }
            zram_data_cache[i].table = ULONG(fill_zram_buf + PARSER_OFFSET(zram_table));
            zram_data_cache[i].mem_pool = ULONG(fill_zram_buf + PARSER_OFFSET(zram_mem_pool));
            FREEBUF(fill_zram_buf);

            // crypto decompress
            for (int k = 0; k < zram_data_cache[i].comp_count; k++) {
                memset(name, 0x0, sizeof(name));
                if (zram_data_cache[i].comp[k]) {
                    readmem(zram_data_cache[i].comp[k] + PARSER_OFFSET(zcomp_name), KVADDR,
                            &nameptr, PARSER_SIZE(zcomp_name), "zcomp_name", FAULT_ON_ERROR);
                    readmem(nameptr, KVADDR, name, sizeof(name), "compress name", FAULT_ON_ERROR);
                }
                zram_data_cache[i].decompress[k] = crypto_comp_get_decompress(name);
            }
        }
        zram_ready = 1;
    }

    // zsmalloc.ko
    if (!zsmalloc_ready) {
        PARSER_MEMBER_OFFSET_INIT(zspool_size_class, "zs_pool", "size_class");
        PARSER_MEMBER_OFFSET_INIT(size_class_size, "size_class", "size");
        PARSER_MEMBER_OFFSET_INIT(zspage_huge, "zspage", "huge");

        // check zsmalloc.ko ready
        if (!PARSER_VALID_MEMBER(zspool_size_class)) {
            error(FATAL, "Please run mod -s zsmalloc.\n");
        }
        zsmalloc_ready = 1;
    }
}

void parser_zram_data_init(void) {
    if (zram_data_cache) return;

    unsigned char *swap_info_buf = NULL;
    ulong swap_info_ptr;
    ulong swap_info;
    ulong swap_file;
    ulong vfsmnt;
    ulong bdev;
    ulong bd_disk;
    ulong swp_space_ptr = 0x0;
    ulong swp_space;
    int nr_swapfiles;
    char buf[BUFSIZE];

    if (!symbol_exists("nr_swapfiles"))
        error(FATAL, "nr_swapfiles doesn't exist in this kernel!\n");

    if (!symbol_exists("swap_info"))
        error(FATAL, "swap_info doesn't exist in this kernel!\n");

    if (symbol_exists("swapper_spaces"))
        swp_space_ptr = symbol_value("swapper_spaces");

    swap_info_init();
    swap_info_ptr = symbol_value("swap_info");
    readmem(symbol_value("nr_swapfiles"), KVADDR, &nr_swapfiles, sizeof(int), "nr_swapfiles", FAULT_ON_ERROR);

    zram_data_cache = (struct zram_data_t*)malloc(nr_swapfiles * sizeof(struct zram_data_t));
    BZERO(zram_data_cache, nr_swapfiles * sizeof(struct zram_data_t));
    pagecache_data_cache = (struct pagecache_data_t*)malloc(nr_swapfiles * sizeof(struct pagecache_data_t));
    BZERO(pagecache_data_cache, nr_swapfiles * sizeof(struct pagecache_data_t));
    zram_total = nr_swapfiles;
    for (int i = 0; i < nr_swapfiles; i++) {
        readmem(swap_info_ptr + i * sizeof(void *), KVADDR,
                &swap_info, sizeof(void *), "swap_info_struct", FAULT_ON_ERROR);

        swap_info_buf = (unsigned char *)GETBUF(PARSER_SIZE(swap_info_struct));
        readmem(swap_info, KVADDR, swap_info_buf, PARSER_SIZE(swap_info_struct), "swap_info_buf", FAULT_ON_ERROR);
        swap_file = ULONG(swap_info_buf + PARSER_OFFSET(swap_info_struct_swap_file));
        zram_data_cache[i].pages = UINT(swap_info_buf + PARSER_OFFSET(swap_info_struct_pages));

        if (swp_space_ptr) {
            swp_space = swp_space_ptr + i * sizeof(void *);
            readmem(swp_space, KVADDR, &pagecache_data_cache[i].space, sizeof(void *), "swp_spaces", FAULT_ON_ERROR);
            if (pagecache_data_cache[i].space) {
                pagecache_data_cache[i].cache_count = (zram_data_cache[i].pages + 1)/(1<<SWAP_ADDRESS_SPACE_SHIFT);
                pagecache_data_cache[i].cache = (struct swap_space_cache_data_t*)malloc(
                                                pagecache_data_cache[i].cache_count * sizeof(struct swap_space_cache_data_t));
                BZERO(pagecache_data_cache[i].cache, pagecache_data_cache[i].cache_count * sizeof(struct swap_space_cache_data_t));
            }
        }

        if (!swap_file) continue;
        if (PARSER_VALID_MEMBER(swap_info_struct_swap_vfsmnt)) {
            readmem(swap_info_ptr + PARSER_OFFSET(swap_info_struct_swap_vfsmnt), KVADDR,
                    &vfsmnt, PARSER_SIZE(swap_info_struct_swap_vfsmnt), "swap_info_struct_swap_vfsmnt", FAULT_ON_ERROR);
            get_pathname(swap_file, buf, BUFSIZE, 1, vfsmnt);
        } else if (PARSER_VALID_MEMBER(swap_info_struct_old_block_size)) {
            get_pathname(file_to_dentry(swap_file), buf, BUFSIZE, 1, file_to_vfsmnt(swap_file));
        } else {
            get_pathname(swap_file, buf, BUFSIZE, 1, 0);
        }

        if (!strstr(buf, "zram")) continue;
        bdev = ULONG(swap_info_buf + PARSER_OFFSET(swap_info_struct_bdev));

        if (!bdev) continue;
        readmem(bdev + PARSER_OFFSET(block_device_bd_disk), KVADDR,
                &bd_disk, PARSER_SIZE(block_device_bd_disk), "block_device_bd_disk", FAULT_ON_ERROR);

        if (!bd_disk) continue;
        readmem(bd_disk + PARSER_OFFSET(gendisk_private_data), KVADDR,
                &zram_data_cache[i].zram, PARSER_SIZE(gendisk_private_data), "gendisk_private_data", FAULT_ON_ERROR);

        FREEBUF(swap_info_buf);
    }
}

void parser_zram_data_uninit(void) {
    if (zram_data_cache) free(zram_data_cache);
    if (pagecache_data_cache) {
        for (int i = 0; i < zram_total; ++i) {
            if (!pagecache_data_cache[i].cache) continue;
            for (int j = 0; j < pagecache_data_cache[i].cache_count; ++j) {
                if (pagecache_data_cache[i].cache[j].pages)
                    free(pagecache_data_cache[i].cache[j].pages);
            }
            free(pagecache_data_cache[i].cache);
        }
        free(pagecache_data_cache);
    }
}

int parser_zram_read_buf(ulong vaddr, unsigned char* value, ulong error_handle) {
    ulong paddr;
    ulong zram_offset;
    int swap_type;

    struct task_context *tc = CURRENT_CONTEXT();
    if (!tc) return 0;
    if (!IS_UVADDR(vaddr, tc)) return 0;
    if (uvtop(tc, vaddr, &paddr, 0) || !paddr) return 0;

    zram_offset = SWP_OFFSET(paddr);
    swap_type = SWP_TYPE(paddr);
    return parser_zram_read_page(swap_type, zram_offset, value, error_handle);
}
