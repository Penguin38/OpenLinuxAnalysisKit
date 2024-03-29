// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#include "binder.h"
#include <unistd.h>
#include <getopt.h>
#include <string.h>

void parser_binder_main(void) {
    int opt;
    int option_index = 0;
    optind = 0; // reset
    static struct option long_options[] = {
        {"pid",    required_argument,  0, 'p'},
        {"all",    no_argument,        0, 'a'},
        {0,         0,                 0,  0 }
    };

    struct binder_data_t binder_data;
    memset(&binder_data, 0x0, sizeof(binder_data));

    while ((opt = getopt_long(argcnt - 1, &args[1], "p:a",
                long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                if (args[optind]) binder_data.pid = atoi(args[optind]);
                break;
            case 'a':
                binder_data.dump_all = 1;
                break;
        }
    }

    if (!binder_data.dump_all && binder_data.pid) {
        binder_data.tc = pid_to_context(binder_data.pid);
        if (!binder_data.tc) {
            fprintf(fp, "No such pid: %d\n", binder_data.pid);
            return;
        }
    }

    parser_binder_proc_show(&binder_data);
}

void parser_binder_usage(void) {
    fprintf(fp, "Usage: binder [option] ...\n");
    fprintf(fp, "   Option:\n");
    fprintf(fp, "       --pid|-p <PID>: read target binder info.\n");
    fprintf(fp, "       --all|-a : read all binder info.\n");
}

void parser_binder_proc_show(struct binder_data_t* binder_data) {
    if (!symbol_exists("binder_procs"))
        error(FATAL, "binder_procs doesn't exist in this kernel!\n");

    ulong binder_procs = symbol_value("binder_procs");
    if (!binder_procs) return;
    ulong first;
    readmem(binder_procs, KVADDR, &first, sizeof(void *), "binder_procs_first", FAULT_ON_ERROR);

    struct list_data ld;
    memset(&ld, 0x0, sizeof(ld));

    ld.flags |= LIST_ALLOCATE;
    ld.start = first;
    ld.member_offset = PARSER_OFFSET(binder_proc_proc_node);
    if (empty_list(ld.start)) return;

    int cnt = do_list(&ld);
    int i;
    int pid;
    for (i = 0; i < cnt; ++i) {
        if (!ld.list_ptr[i]) continue;
        readmem(ld.list_ptr[i] + PARSER_OFFSET(binder_proc_pid), KVADDR,
                &pid, PARSER_SIZE(binder_proc_pid), "binder_proc_pid", FAULT_ON_ERROR);
        if (binder_data->dump_all || binder_data->pid == pid) {
            fprintf(fp, "binder proc state:\n");
            parser_binder_print_binder_proc(ld.list_ptr[i]);
        }
    }
    FREEBUF(ld.list_ptr);
}

void parser_binder_print_binder_proc(ulong proc) {
    unsigned char *binder_proc_buf = NULL;
    binder_proc_buf = (unsigned char *)GETBUF(PARSER_SIZE(binder_proc));
    readmem(proc, KVADDR, binder_proc_buf, PARSER_SIZE(binder_proc), "binder_proc", FAULT_ON_ERROR);
    ulong context = ULONG(binder_proc_buf + PARSER_OFFSET(binder_proc_context));
    ulong threads = ULONG(binder_proc_buf + PARSER_OFFSET(binder_proc_threads));
    ulong todo = ULONG(binder_proc_buf + PARSER_OFFSET(binder_proc_todo));
    ulong nameptr;
    char name[16];
    readmem(context + PARSER_OFFSET(binder_context_name), KVADDR,
            &nameptr, PARSER_SIZE(binder_context_name), "binder_context_name", FAULT_ON_ERROR);
    readmem(nameptr, KVADDR, name, sizeof(name), "name", FAULT_ON_ERROR);
    fprintf(fp, "proc %d\n", UINT(binder_proc_buf + PARSER_OFFSET(binder_proc_pid)));
    fprintf(fp, "context %s\n", name);

    struct tree_data td;
    ulong *list_ptr = NULL;
    int i, cnt;
    memset(&td, 0x0, sizeof(td));
    // td.flags |= VERBOSE | TREE_POSITION_DISPLAY | TREE_LINEAR_ORDER;
    td.flags |= TREE_NODE_POINTER;
    td.start = threads;
    td.node_member_offset = PARSER_OFFSET(binder_thread_rb_node);
    hq_open();
    cnt = do_rbtree(&td);
    if (cnt) {
        list_ptr = (ulong *)GETBUF(cnt * sizeof(void *));
        BZERO(list_ptr, cnt * sizeof(void *));
        retrieve_list(list_ptr, cnt);

        for (i = 0; i < cnt; ++i) {
            if (!list_ptr[i]) continue;
            parser_binder_print_binder_thread_ilocked(list_ptr[i] - td.node_member_offset);
        }
        FREEBUF(list_ptr);
    }
    hq_close();

    struct list_data ld;
    memset(&ld, 0x0, sizeof(ld));
    ld.flags |= LIST_ALLOCATE | LIST_HEAD_POINTER;
    ld.start = todo;
    if (empty_list(ld.start)) {
        FREEBUF(binder_proc_buf);
        fprintf(fp, "\n");
        return;
    }
    cnt = do_list(&ld);
    for (i = 0; i < cnt; ++i) {
        if (!ld.list_ptr[i]) continue;
        parser_binder_print_binder_work_ilocked(proc, "    ", "    pending transaction", ld.list_ptr[i]);
    }
    FREEBUF(ld.list_ptr);
    FREEBUF(binder_proc_buf);
    fprintf(fp, "\n");
}

void parser_binder_print_binder_thread_ilocked(ulong thread) {
    unsigned char *binder_thread_buf = NULL;
    binder_thread_buf = (unsigned char *)GETBUF(PARSER_SIZE(binder_thread));
    readmem(thread, KVADDR, binder_thread_buf, PARSER_SIZE(binder_thread), "binder_thread", FAULT_ON_ERROR);

    int pid = UINT(binder_thread_buf + PARSER_OFFSET(binder_thread_pid));
    int looper = UINT(binder_thread_buf + PARSER_OFFSET(binder_thread_looper));
    char looper_need_return = BOOL(binder_thread_buf + PARSER_OFFSET(binder_thread_looper_need_return));
    int tmp_ref = UINT(binder_thread_buf + PARSER_OFFSET(binder_thread_tmp_ref));
    fprintf(fp, "  thread %d: l %02x need_return %d tr %d\n",
            pid, looper, looper_need_return, tmp_ref);

    ulong proc = ULONG(binder_thread_buf + PARSER_OFFSET(binder_thread_proc));
    ulong transaction_stack = ULONG(binder_thread_buf + PARSER_OFFSET(binder_thread_transaction_stack));
    ulong t = transaction_stack;
    while (t) {
        ulong from;
        ulong to_thread;
        readmem(t + PARSER_OFFSET(binder_transaction_from), KVADDR,
                &from, PARSER_SIZE(binder_transaction_from), "binder_transaction_from", FAULT_ON_ERROR);
        readmem(t + PARSER_OFFSET(binder_transaction_to_thread), KVADDR,
                &to_thread, PARSER_SIZE(binder_transaction_to_thread), "binder_transaction_to_thread", FAULT_ON_ERROR);
        if (from == thread) {
            parser_binder_print_binder_transaction_ilocked(proc, "    outgoing transaction", t);
            ulong from_parent;
            readmem(t + PARSER_OFFSET(binder_transaction_from_parent), KVADDR,
                    &from_parent, PARSER_SIZE(binder_transaction_from_parent), "binder_transaction_from_parent", FAULT_ON_ERROR);
            t = from_parent;
        } else if (to_thread == thread) {
            parser_binder_print_binder_transaction_ilocked(proc, "    incoming transaction", t);
            ulong to_parent;
            readmem(t + PARSER_OFFSET(binder_transaction_to_parent), KVADDR,
                    &to_parent, PARSER_SIZE(binder_transaction_to_parent), "binder_transaction_to_parent", FAULT_ON_ERROR);
            t = to_parent;
        } else {
            parser_binder_print_binder_transaction_ilocked(proc, "    bad transaction", t);
            t = 0x0;
        }
    }
    FREEBUF(binder_thread_buf);
}

void parser_binder_print_binder_transaction_ilocked(ulong proc, const char* prefix, ulong transaction) {
    unsigned char *binder_transaction_buf = NULL;
    binder_transaction_buf = (unsigned char *)GETBUF(PARSER_SIZE(binder_transaction));
    readmem(transaction, KVADDR, binder_transaction_buf, PARSER_SIZE(binder_transaction), "binder_transaction", FAULT_ON_ERROR);

    int debug_id = INT(binder_transaction_buf + PARSER_OFFSET(binder_transaction_debug_id));
    ulong from = ULONG(binder_transaction_buf + PARSER_OFFSET(binder_transaction_from));
    ulong to_proc = ULONG(binder_transaction_buf + PARSER_OFFSET(binder_transaction_to_proc));
    ulong to_thread = ULONG(binder_transaction_buf + PARSER_OFFSET(binder_transaction_to_thread));
    uint code = UINT(binder_transaction_buf + PARSER_OFFSET(binder_transaction_code));
    uint flags = UINT(binder_transaction_buf + PARSER_OFFSET(binder_transaction_flags));
    char need_reply = BOOL(binder_transaction_buf + PARSER_OFFSET(binder_transaction_need_reply));

    struct binder_priority priority;
    memcpy(&priority, binder_transaction_buf + PARSER_OFFSET(binder_transaction_priority), sizeof(priority));

    ulong from_proc;
    int from_proc_pid;
    int from_pid;
    if (from) {
        readmem(from + PARSER_OFFSET(binder_thread_proc), KVADDR,
                &from_proc, PARSER_SIZE(binder_thread_proc), "binder_thread_proc", FAULT_ON_ERROR);
        readmem(from_proc + PARSER_OFFSET(binder_proc_pid), KVADDR,
                &from_proc_pid, PARSER_SIZE(binder_proc_pid), "binder_proc_pid", FAULT_ON_ERROR);
        readmem(from + PARSER_OFFSET(binder_thread_pid), KVADDR,
                &from_pid, PARSER_SIZE(binder_thread_pid), "binder_thread_pid", FAULT_ON_ERROR);
    }

    int to_proc_pid;
    if (to_proc) {
        readmem(to_proc + PARSER_OFFSET(binder_proc_pid), KVADDR,
                &to_proc_pid, PARSER_SIZE(binder_proc_pid), "binder_proc_pid", FAULT_ON_ERROR);
    }

    int to_thread_pid;
    if (to_thread) {
        readmem(to_thread + PARSER_OFFSET(binder_thread_pid), KVADDR,
                &to_thread_pid, PARSER_SIZE(binder_thread_pid), "binder_thread_pid", FAULT_ON_ERROR);
    }

    fprintf(fp, "%s %d: 0x%lx from %d:%d to %d:%d code %x flags %x pri %s:%d r%d",
            prefix, debug_id, transaction,
            from ? from_proc_pid : 0,
            from ? from_pid : 0,
            to_proc ? to_proc_pid : 0,
            to_thread ? to_thread_pid : 0,
            code, flags, convert_sched(priority.sched_policy),
            priority.prio, need_reply);

    if (proc != to_proc) {
        fprintf(fp, "\n");
        FREEBUF(binder_transaction_buf);
        return;
    }

    ulong buffer = ULONG(binder_transaction_buf + PARSER_OFFSET(binder_transaction_buffer));
    if (!buffer) {
        fprintf(fp, " buffer free\n");
        FREEBUF(binder_transaction_buf);
        return;
    }

    struct binder_buffer b_buf;
    readmem(buffer, KVADDR, &b_buf, sizeof(struct binder_buffer), "binder_buffer", FAULT_ON_ERROR);

    if (b_buf.target_node) {
        int node_debug_id;
        readmem((ulong)b_buf.target_node + PARSER_OFFSET(binder_node_debug_id), KVADDR,
                &node_debug_id, PARSER_SIZE(binder_node_debug_id), "binder_node_debug_id", FAULT_ON_ERROR);
        fprintf(fp, " node %d", node_debug_id);
    }

    fprintf(fp, " size %zd:%zd data %p\n",
            b_buf.data_size, b_buf.offsets_size, b_buf.user_data);

    FREEBUF(binder_transaction_buf);
}

void parser_binder_print_binder_work_ilocked(ulong proc, const char* prefix, const char* transaction_prefix, ulong work) {
    ulong transaction;
    struct binder_work w;
    readmem(work, KVADDR, &w, sizeof(struct binder_work), "binder_work", FAULT_ON_ERROR);

    switch(w.type) {
        case BINDER_WORK_TRANSACTION:
            transaction = work - PARSER_OFFSET(binder_transaction_work);
            parser_binder_print_binder_transaction_ilocked(proc, transaction_prefix, transaction);
            break;
        case BINDER_WORK_RETURN_ERROR: {
            ulong error = work - offsetof(struct binder_error, work);
            struct binder_error e;
            readmem(error, KVADDR, &e, sizeof(struct binder_error), "binder_error", FAULT_ON_ERROR);
            fprintf(fp, "%stransaction error: %u\n", prefix, e.cmd);
        } break;
        case BINDER_WORK_TRANSACTION_COMPLETE:
            fprintf(fp, "%stransaction complete\n", prefix);
            break;
        case BINDER_WORK_NODE: {
            ulong node = work - PARSER_OFFSET(binder_node_work);
            int debug_id;
            ulong ptr;
            ulong cookie;
            readmem(node + PARSER_OFFSET(binder_node_debug_id), KVADDR,
                    &debug_id, PARSER_SIZE(binder_node_debug_id), "binder_node_debug_id", FAULT_ON_ERROR);
            readmem(node + PARSER_OFFSET(binder_node_ptr), KVADDR,
                    &ptr, PARSER_SIZE(binder_node_ptr), "binder_node_ptr", FAULT_ON_ERROR);
            readmem(node + PARSER_OFFSET(binder_node_cookie), KVADDR,
                    &cookie, PARSER_SIZE(binder_node_cookie), "binder_node_cookie", FAULT_ON_ERROR);
            fprintf(fp, "%snode work %d: u%016lx c%016lx\n", prefix, debug_id, ptr, cookie);
        } break;
        case BINDER_WORK_DEAD_BINDER:
            fprintf(fp, "%shas dead binder\n", prefix);
            break;
        case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
            fprintf(fp, "%shas cleared dead binder\n", prefix);
            break;
        case BINDER_WORK_CLEAR_DEATH_NOTIFICATION:
            fprintf(fp, "%shas cleared death notification\n", prefix);
            break;
        default:
            fprintf(fp, "%sunknown work: type %d\n", prefix, w.type);
            break;
    }
}
