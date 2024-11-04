// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef CPU_CPU_H_
#define CPU_CPU_H_

#include "parser_defs.h"
#include <linux/types.h>

void parser_cpu_main(void);
void parser_cpu_usage(void);
void parser_cpu_set(char* cmm, int idx, int lv);
void parser_cpu_reset(int idx);
void parser_cpu_cache_clean(void);

#endif //  CPU_CPU_H_
