// Copyright (C) 2025-present, Guanyou.Chen. All rights reserved.

#ifndef CMDLINE_CMD_H_
#define CMDLINE_CMD_H_

#include "parser_defs.h"
#include <linux/types.h>

void parser_cmdline_main(void);
void parser_cmdline_usage(void);

void parser_cmdline_form_context(struct task_context* tc);

#endif // CMDLINE_CMD_H_
