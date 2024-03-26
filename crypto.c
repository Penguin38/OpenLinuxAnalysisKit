// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "parser_defs.h"
#include "lzo/lzo.h"
#include <dlfcn.h>
#include <errno.h>

int crypto_lzo1x_decompress_safe(unsigned char *source, unsigned char *dest,
                                 int compressedSize, int maxDecompressedSize) {
    int err;
    size_t tmp_len = maxDecompressedSize;
    err = lzo1x_decompress_safe(source, compressedSize, dest, &tmp_len);
    if (err != 0) {
        tmp_len = 0;
        error(WARNING, "lzo1x_decompress_safe error(%d)\n", err);
    }
    return tmp_len;
}

void *crypto_comp_get_decompress(const char* name) {
    if (STREQ(name, "lz4")) {
        void *handle = dlopen("liblz4.so", RTLD_LAZY);
        if (handle) {
            return dlsym(handle, "LZ4_decompress_safe");
        } else {
            fprintf(fp, "Please sudo apt-get install liblz4-dev\n");
        }
    } else if (STREQ(name, "lzo") || STREQ(name, "lzo-rle")) {
        return &crypto_lzo1x_decompress_safe;
    } else {
        fprintf(fp, "Not support %s decompress\n", name);
    }
    return NULL;
}
