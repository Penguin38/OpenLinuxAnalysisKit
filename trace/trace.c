// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "trace.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

bool parser_ring_buffer_record_is_set_on(ulong buffer) {
    int record_disabled;

    readmem(buffer + PARSER_OFFSET(trace_buffer_record_disabled), KVADDR, &record_disabled,
            PARSER_SIZE(trace_buffer_record_disabled), "trace_buffer_record_disabled", FAULT_ON_ERROR);

    return !(record_disabled & RB_BUFFER_OFF);
}

bool parser_tracer_tracing_is_on(ulong tr) {
    ulong array_buffer_buffer = 0;
    int buffer_disabled = 1;

    readmem(tr + PARSER_OFFSET(trace_array_array_buffer) + PARSER_OFFSET(array_buffer_buffer),
            KVADDR, &array_buffer_buffer, PARSER_SIZE(array_buffer_buffer), "array_buffer_buffer", FAULT_ON_ERROR);

    if (array_buffer_buffer)
        return parser_ring_buffer_record_is_set_on(array_buffer_buffer);

    readmem(tr + PARSER_OFFSET(trace_array_buffer_disabled), KVADDR, &buffer_disabled,
            PARSER_SIZE(trace_array_buffer_disabled), "trace_array_buffer_disabled", FAULT_ON_ERROR);
    return !buffer_disabled;
}

int parser_tracer_show(ulong tracer) {
    char tracer_name[256];
    ulong tracer_name_ptr;

    memset(tracer_name, 0x0, sizeof(tracer_name));
    readmem(tracer + PARSER_OFFSET(tracer_name), KVADDR, &tracer_name_ptr,
            PARSER_SIZE(tracer_name), "tracer_name_ptr", FAULT_ON_ERROR);
    readmem(tracer_name_ptr, KVADDR, tracer_name,
            sizeof(tracer_name), "tracer_name", FAULT_ON_ERROR);
    tracer_name[255] = 0;

    fprintf(fp, "# tracer: %s\n", tracer_name);
    return 0;
}

void parser_trace_main(void) {
    parser_trace_init();

    ulong global_trace;
    ulong current_trace;

    if (!symbol_exists("global_trace")) {
        error(INFO, "no found symbol global_trace.\n");
        return;
    }
    global_trace = symbol_value("global_trace");
    readmem(global_trace + PARSER_OFFSET(trace_array_current_trace), KVADDR, &current_trace,
            PARSER_SIZE(trace_array_current_trace), "trace_array_current_trace", FAULT_ON_ERROR);

    parser_tracer_show(current_trace);
}

void parser_trace_usage(void) {
    fprintf(fp, "Usage: lp trace [OPTION] ...\n");
}

void parser_trace_init(void) {
    // trace.ko
}
