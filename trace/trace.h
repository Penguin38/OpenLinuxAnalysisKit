// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef TRACE_TRACE_H_
#define TRACE_TRACE_H_

#include "parser_defs.h"
#include <linux/types.h>

#define RB_BUFFER_OFF       (1 << 20)

void parser_trace_main(void);
void parser_trace_usage(void);
void parser_trace_init(void);

bool parser_tracer_tracing_is_on(ulong tr);
bool parser_ring_buffer_record_is_set_on(ulong buffer);
int parser_tracer_show(ulong tracer);

#endif //  TRACE_TRACE_H_
