// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef TIME_TIME_H_
#define TIME_TIME_H_

#include "parser_defs.h"
#include <linux/types.h>

void parser_time_main(void);
void parser_time_usage(void);

// API
ulong parser_ktime_get(void);

#endif // TIME_TIME_H_
