// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "time.h"

static ulong tk_core_cache = 0x0;
static ulong get_tk_core(void) {
    if (!tk_core_cache)
        tk_core_cache = symbol_value("tk_core");
    return tk_core_cache;
}

void parser_time_main(void) {
    float current_time = parser_ktime_get() * 1.0F / 1000000 / 1000;
    fprintf(fp, "Current time: [%.6f]\n", current_time);
}

ulong parser_ktime_get(void) {
    ulong base;
    ulong nescs;
    uint shift;
    ulong timekeeper;
    ulong tkr_mono;

    ulong tk_core = get_tk_core();
    timekeeper = tk_core + /*PARSER_OFFSET(tk_core_timekeeper)*/ 8;
    tkr_mono = timekeeper + PARSER_OFFSET(timekeeper_tkr_mono);

    readmem(tkr_mono + PARSER_OFFSET(tk_read_base_base), KVADDR, &base,
            PARSER_SIZE(tk_read_base_base), "tk_read_base_base", FAULT_ON_ERROR);
    readmem(tkr_mono + PARSER_OFFSET(tk_read_base_shift), KVADDR, &shift,
            PARSER_SIZE(tk_read_base_shift), "tk_read_base_shift", FAULT_ON_ERROR);
    readmem(tkr_mono + PARSER_OFFSET(tk_read_base_xtime_nsec), KVADDR, &nescs,
            PARSER_SIZE(tk_read_base_xtime_nsec), "tk_read_base_xtime_nsec", FAULT_ON_ERROR);

    return base + (nescs >> shift);
}

void parser_time_usage(void) {}
