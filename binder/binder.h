// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef BINDER_BINDER_H_
#define BINDER_BINDER_H_

#include "parser_defs.h"
#include <linux/types.h>

void parser_binder_main(void);
void parser_binder_usage(void);

struct binder_data_t {
    struct task_context *tc;
    int pid;
    int dump_all;
};

/**
 * struct binder_priority - scheduler policy and priority
 * @sched_policy            scheduler policy
 * @prio                    [100..139] for SCHED_NORMAL, [0..99] for FIFO/RT
 *
 * The binder driver supports inheriting the following scheduler policies:
 * SCHED_NORMAL
 * SCHED_BATCH
 * SCHED_FIFO
 * SCHED_RR
 */
struct binder_priority {
    unsigned int sched_policy;
    int prio;
};

struct binder_buffer {
    struct kernel_list_head entry; /* free and allocated entries by address */
    struct rb_node rb_node; /* free entry by size or allocated entry */
    /* by address */
    unsigned free:1;
    unsigned clear_on_free:1;
    unsigned allow_user_free:1;
    unsigned async_transaction:1;
    unsigned oneway_spam_suspect:1;
    unsigned debug_id:27;

    struct binder_transaction *transaction;

    struct binder_node *target_node;
    size_t data_size;
    size_t offsets_size;
    size_t extra_buffers_size;
    void   *user_data;
    int    pid;
};

/**
 * struct binder_work - work enqueued on a worklist
 * @entry:             node enqueued on list
 * @type:              type of work to be performed
 *
 * There are separate work lists for proc, thread, and node (async).
 */
struct binder_work {
    struct kernel_list_head entry;
    enum binder_work_type {
        BINDER_WORK_TRANSACTION = 1,
        BINDER_WORK_TRANSACTION_COMPLETE,
        BINDER_WORK_TRANSACTION_PENDING,
        BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT,
        BINDER_WORK_RETURN_ERROR,
        BINDER_WORK_NODE,
        BINDER_WORK_DEAD_BINDER,
        BINDER_WORK_DEAD_BINDER_AND_CLEAR,
        BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
    } type;
};

struct binder_error {
    struct binder_work work;
    unsigned int cmd;
};

void parser_binder_proc_show(struct binder_data_t* binder_data);
void parser_binder_print_binder_proc(ulong proc);
void parser_binder_print_binder_thread_ilocked(ulong thread);
void parser_binder_print_binder_transaction_ilocked(ulong proc, const char* prefix, ulong transaction);
void parser_binder_print_binder_work_ilocked(ulong proc, const char* prefix, const char* transaction_prefix, ulong work);

#endif //  BINDER_BINDER_H_
