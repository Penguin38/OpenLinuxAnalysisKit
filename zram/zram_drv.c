// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "zram.h"

void parser_zram_obj_to_location(ulong obj, ulong *page, unsigned int* obj_idx) {
    obj >>= OBJ_TAG_BITS;
    phys_to_page(PTOB(obj >> OBJ_INDEX_BITS), page);
    *obj_idx = (obj & OBJ_INDEX_MASK);
}

unsigned char *parser_zram_zs_map_object(ulong pool, ulong handle, unsigned char *zram_buf, ulong error_handle) {
    ulong obj, off, class, page, zspage;
    struct zspage zspage_s;
    struct zspage_5_17 zspage_5_17_s;
    physaddr_t paddr;
    unsigned int obj_idx, class_idx, size;
    ulong pages[2], sizes[2];
    ulong zs_magic;

    readmem(handle, KVADDR, &obj, sizeof(void *), "zram entry", error_handle);
    parser_zram_obj_to_location(obj, &page, &obj_idx);

    readmem(page + PARSER_OFFSET(page_private), KVADDR, &zspage,
            PARSER_SIZE(page_private), "page_private", error_handle);

    if (PARSER_VALID_MEMBER(zspage_huge)) {
        readmem(zspage, KVADDR, &zspage_5_17_s, sizeof(struct zspage_5_17), "zspage_5_17", error_handle);
        class_idx = zspage_5_17_s.class;
        zs_magic = zspage_5_17_s.magic;
    } else {
        readmem(zspage, KVADDR, &zspage_s, sizeof(struct zspage), "zspage", error_handle);
        class_idx = zspage_s.class;
        zs_magic = zspage_s.magic;
    }

    if (zs_magic != ZSPAGE_MAGIC) {
        if (error_handle == FAULT_ON_ERROR)
            error(INFO, "0x%lx zspage magic incorrect: %x\n", zspage, zs_magic);
        return NULL;
    }

    class = pool + PARSER_OFFSET(zspool_size_class);
    class += (class_idx * sizeof(void *));
    readmem(class, KVADDR, &class, sizeof(void *), "size_class", error_handle);
    readmem(class + PARSER_OFFSET(size_class_size), KVADDR,
            &size, sizeof(unsigned int), "size of class_size", error_handle);
    off = (size * obj_idx) & (~machdep->pagemask);
    if (off + size <= PAGESIZE()) {
        if (!is_page_ptr(page, &paddr)) {
            if (error_handle == FAULT_ON_ERROR)
                error(INFO, "zspage: %lx: not a page pointer\n", page);
            return NULL;
        }
        readmem(paddr + off, PHYSADDR, zram_buf, size, "zram buffer", error_handle);
        goto out;
    }

    pages[0] = page;
    if (PARSER_VALID_MEMBER(page_freelist)) {
        readmem(page + PARSER_OFFSET(page_freelist), KVADDR, &pages[1],
                sizeof(void *), "page_freelist", error_handle);
    } else {
        readmem(page + PARSER_OFFSET(page_index), KVADDR, &pages[1],
                sizeof(void *), "page_index", error_handle);
    }

    sizes[0] = PAGESIZE() - off;
    sizes[1] = size - sizes[0];
    if (!is_page_ptr(pages[0], &paddr)) {
        if (error_handle == FAULT_ON_ERROR)
            error(INFO, "pages[0]: %lx: not a page pointer\n", pages[0]);
        return NULL;
    }

    readmem(paddr + off, PHYSADDR, zram_buf, sizes[0], "zram buffer[0]", error_handle);
    if (!is_page_ptr(pages[1], &paddr)) {
        if (error_handle == FAULT_ON_ERROR)
            error(INFO, "pages[1]: %lx: not a page pointer\n", pages[1]);
        return NULL;
    }

    readmem(paddr, PHYSADDR, zram_buf + sizes[0], sizes[1], "zram buffer[1]", error_handle);

out:
    if (!PARSER_VALID_MEMBER(zspage_huge)) {
        readmem(page, KVADDR, &obj, sizeof(void *), "page flags", error_handle);
        if (!(obj & (1 << 10))) { //PG_OwnerPriv1 flag
            return (zram_buf + ZS_HANDLE_SIZE);
        }
    } else {
        if (!zspage_5_17_s.huge) {
            return (zram_buf + ZS_HANDLE_SIZE);
        }
    }
    return zram_buf;
}

int parser_zram_read_page(int swap_index, ulong zram_offset, unsigned char* value, ulong error_handle) {
    unsigned char *src = NULL;
    unsigned char *zram_buf = NULL;
    unsigned char *entry_buf = NULL;

    ulong outsize;
    ulong sector;
    ulong index;
    ulong entry;
    ulong flags;
    ulong objsize;
    ulong handle;
    ulong element;

    sector = zram_offset << (PAGESHIFT() - 9);
    index = sector >> SECTORS_PER_PAGE_SHIFT;
    outsize = PAGESIZE();

    // zram_table_entry parse
    entry = zram_data_cache[swap_index].table + index * PARSER_SIZE(zram_table_entry);
    entry_buf = (unsigned char *)GETBUF(PARSER_SIZE(zram_table_entry));
    BZERO(entry_buf, PARSER_SIZE(zram_table_entry));
    readmem(entry, KVADDR, entry_buf, PARSER_SIZE(zram_table_entry), "zram_table_entry", error_handle);
    flags = ULONG(entry_buf + PARSER_OFFSET(zram_table_entry_flags));
    handle = ULONG(entry_buf + PARSER_OFFSET(zram_table_entry_handle));
    element = ULONG(entry_buf + PARSER_OFFSET(zram_table_entry_element));
    objsize = flags & (PARSER_ZRAM_FLAG_SHIFT - 1);
    FREEBUF(entry_buf);

    // ZRAM_WB
    if ((flags & PARSER_ZRAM_FLAG_WB_BIT)
            || !handle) {
        if (error_handle == FAULT_ON_ERROR)
            error(INFO, "Not support read zram offset %ld.\n", zram_offset);
        return 0;
    }

    // ZRAM_SAME
    if (flags & PARSER_ZRAM_FLAG_SAME_BIT) {
        unsigned long *same_buf = NULL;
        unsigned long buf = handle ? element : 0;
        same_buf = (unsigned long *)GETBUF(PAGESIZE());
        for (int count = 0; count < PAGESIZE() / sizeof(unsigned long); count++) {
            same_buf[count] = buf;
        }
        memcpy(value, same_buf, outsize);
        FREEBUF(same_buf);
        return 1;
    }

    zram_buf = (unsigned char *)GETBUF(PAGESIZE());
    BZERO(zram_buf, PAGESIZE());
    src = parser_zram_zs_map_object(zram_data_cache[swap_index].mem_pool, handle, zram_buf, error_handle);
    if (!src) {
        FREEBUF(zram_buf);
        return 0;
    }

    if (objsize == PAGESIZE()) {
        memcpy(value, src, outsize);
    } else {
        if (zram_data_cache[swap_index].decompress)
            zram_data_cache[swap_index].decompress(src, value, objsize, outsize);
    }
    FREEBUF(zram_buf);
    return 1;
}
