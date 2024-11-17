// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "trace.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void parser_trace_main(void) {
    parser_trace_init();
}

void parser_trace_usage(void) {
    fprintf(fp, "Usage: lp trace [OPTION] ...\n");
}

void parser_trace_init(void) {
    // trace.ko
}
