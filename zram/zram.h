// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef ZRAM_ZRAM_H_
#define ZRAM_ZRAM_H_

#include "parser_defs.h"
#include <linux/types.h>

void parser_zram_main(void);
void parser_zram_usage(void);

void parser_zram_init(void);
void parser_zram_data_init(void);
void parser_zram_data_uninit(void);
int parser_zram_read_buf(ulong vaddr, unsigned char* value, ulong error_handle);
int parser_zram_read_page(int swap_index, ulong zram_offset, unsigned char* value, ulong error_handle);

struct swap_space_cache_data_t {
    int page_count;
    struct list_pair* pages;
};

struct pagecache_data_t {
    ulong space;
    int cache_count;
    struct swap_space_cache_data_t* cache;
};

struct zram_data_t {
    ulong zram;
    ulong pages;
    ulong comp;
    ulong mem_pool;
    ulong table;
    int (*decompress)(unsigned char *source, unsigned char *dest,
                      int compressedSize, int maxDecompressedSize);
};

extern struct zram_data_t* zram_data_cache;
extern struct pagecache_data_t* pagecache_data_cache;
extern ulong PARSER_ZRAM_FLAG_SHIFT;
extern ulong PARSER_ZRAM_FLAG_SAME_BIT;
extern ulong PARSER_ZRAM_FLAG_WB_BIT;

#endif //  ZRAM_ZRAM_H_
