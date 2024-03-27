// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef SHMEM_SHMEM_H_
#define SHMEM_SHMEM_H_

#include "parser_defs.h"
#include <linux/types.h>

void parser_shmem_main(void);
void parser_shmem_usage(void);

int parser_shmem_read_page(ulong vaddr, struct vma_cache_data* cache,
                           unsigned char* value, ulong error_handle);

int parser_shmem_get_page_cache(struct vma_cache_data* cache,
                           struct list_pair **page_list, ulong error_handle);
int parser_shmem_read_page_cache(ulong vaddr, struct vma_cache_data* cache, int count,
                struct list_pair *page_list, unsigned char* value, ulong error_handle);

struct shmem_data_t {
    struct task_context *tc;
    int pid;
    int vma_count;
    struct vma_cache_data *vma_cache;
};

#endif //  SHMEM_SHMEM_H_
