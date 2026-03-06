// Copyright (C) 2026-present, Guanyou.Chen. All rights reserved.

#include "dmabuf.h"

#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define DMABUF_NAME_MAX 256
#define DMABUF_MAX_BUFS 65536

struct dmabuf_obj {
    ulong dma_buf;       // dma_buf*
    ulong file;          // dma_buf->file
    ulong size_bytes;    // dma_buf->size
    ulong f_count;       // file->f_count (kernel ref count)
    int proc_ref;        // number of processes holding FDs to this buffer
    char exp_name[DMABUF_NAME_MAX];
    char buf_name[DMABUF_NAME_MAX];
};

struct pid_entry {
    int pid;
    char comm[TASK_COMM_LEN];
    int *buf_indices;    // indices into dmabuf_obj array
    int buf_count;
    int buf_cap;
    unsigned long long rss_bytes;
    unsigned long long pss_bytes;
};

static int pid_entry_add_buf(struct pid_entry *pe, int buf_idx) {
    for (int i = 0; i < pe->buf_count; i++) {
        if (pe->buf_indices[i] == buf_idx)
            return 0;
    }
    if (pe->buf_count == pe->buf_cap) {
        int new_cap = pe->buf_cap ? pe->buf_cap * 2 : 32;
        int *n = (int *)realloc(pe->buf_indices, new_cap * sizeof(int));
        if (!n)
            return -1;
        pe->buf_indices = n;
        pe->buf_cap = new_cap;
    }
    pe->buf_indices[pe->buf_count++] = buf_idx;
    return 1;
}

static struct pid_entry *pid_find_or_add(struct pid_entry **arr, int *count, int *cap,
                                         int pid, const char *comm) {
    for (int i = 0; i < *count; i++) {
        if ((*arr)[i].pid == pid)
            return &(*arr)[i];
    }

    if (*count >= *cap) {
        int new_cap = *cap ? *cap * 2 : 256;
        struct pid_entry *n = (struct pid_entry *)realloc(*arr, new_cap * sizeof(struct pid_entry));
        if (!n)
            return NULL;
        memset(n + *cap, 0, (new_cap - *cap) * sizeof(struct pid_entry));
        *arr = n;
        *cap = new_cap;
    }

    struct pid_entry *pe = &(*arr)[(*count)++];
    pe->pid = pid;
    strncpy(pe->comm, comm ? comm : "", TASK_COMM_LEN - 1);
    pe->comm[TASK_COMM_LEN - 1] = '\0';
    return pe;
}

/*
 * Read file->f_count.counter (atomic_long_t).
 */
static ulong read_file_f_count(ulong file) {
    if (!IS_KVADDR(file))
        return 0;
    if (!VALID_MEMBER(file_f_count))
        return 0;
    long counter = 0;
    readmem(file + OFFSET(file_f_count), KVADDR, &counter, sizeof(long),
            "file f_count", RETURN_ON_ERROR);
    return (ulong)counter;
}

/*
 * Fill a dmabuf_obj from a known dma_buf pointer.
 * Returns 1 on success, 0 if the dma_buf looks invalid.
 */
static int dmabuf_fill_obj(struct dmabuf_obj *o, ulong dma_buf, ulong file) {
    o->dma_buf = dma_buf;
    o->file = file;

    /* Read dma_buf->size (size_t = unsigned long on arm64) */
    o->size_bytes = 0;
    if (PARSER_VALID_MEMBER(dma_buf_size))
        readmem(dma_buf + PARSER_OFFSET(dma_buf_size), KVADDR, &o->size_bytes,
                sizeof(ulong), "dma_buf size", RETURN_ON_ERROR);

    /* Sanity check: size must be non-zero and < 64GB */
    if (!o->size_bytes || o->size_bytes > (1ULL << 36))
        return 0;

    /* Read file->f_count */
    o->f_count = read_file_f_count(file);

    /* Read dma_buf->exp_name */
    o->exp_name[0] = '\0';
    if (PARSER_VALID_MEMBER(dma_buf_exp_name)) {
        ulong exp_ptr = 0;
        readmem(dma_buf + PARSER_OFFSET(dma_buf_exp_name), KVADDR, &exp_ptr,
                sizeof(void *), "dma_buf exp_name", RETURN_ON_ERROR);
        if (IS_KVADDR(exp_ptr)) {
            read_string(exp_ptr, o->exp_name, DMABUF_NAME_MAX - 1);
            o->exp_name[DMABUF_NAME_MAX - 1] = '\0';
        }
    }

    /* Read dma_buf->name (user-set name via DMA_BUF_SET_NAME ioctl) */
    o->buf_name[0] = '\0';
    if (PARSER_VALID_MEMBER(dma_buf_name)) {
        ulong name_ptr = 0;
        readmem(dma_buf + PARSER_OFFSET(dma_buf_name), KVADDR, &name_ptr,
                sizeof(void *), "dma_buf name", RETURN_ON_ERROR);
        if (IS_KVADDR(name_ptr)) {
            read_string(name_ptr, o->buf_name, DMABUF_NAME_MAX - 1);
            o->buf_name[DMABUF_NAME_MAX - 1] = '\0';
        }
    }

    o->proc_ref = 0;
    return 1;
}

/*
 * Find dmabuf_obj index by dma_buf pointer (dedup key).
 */
static int dmabuf_find_by_ptr(struct dmabuf_obj *arr, int count, ulong dma_buf) {
    for (int i = 0; i < count; i++) {
        if (arr[i].dma_buf == dma_buf)
            return i;
    }
    return -1;
}

/*
 * Approach 1: Enumerate all dma_buf objects via kernel global db_list.
 *
 * db_list is a list_head in drivers/dma-buf/dma-buf.c.
 * Each dma_buf is linked via dma_buf.list_node.
 * This is a static symbol and may not be available in all kernels.
 */
static int dmabuf_enumerate_db_list(struct dmabuf_obj **out_arr, int *out_count) {
    *out_arr = NULL;
    *out_count = 0;

    if (!symbol_exists("db_list"))
        return 0;

    if (!PARSER_VALID_MEMBER(dma_buf_size) || !PARSER_VALID_MEMBER(dma_buf_file))
        return 0;

    if (!PARSER_VALID_MEMBER(dma_buf_list_node))
        return 0;

    ulong db_list_addr = symbol_value("db_list");
    if (!IS_KVADDR(db_list_addr))
        return 0;

    struct list_data ld;
    memset(&ld, 0, sizeof(ld));
    ld.flags |= LIST_ALLOCATE;
    ld.start = db_list_addr;
    ld.member_offset = PARSER_OFFSET(dma_buf_list_node);

    if (empty_list(ld.start))
        return 0;

    int cnt = do_list(&ld);
    if (cnt <= 0)
        return 0;

    struct dmabuf_obj *arr = (struct dmabuf_obj *)malloc(cnt * sizeof(struct dmabuf_obj));
    if (!arr) {
        FREEBUF(ld.list_ptr);
        return -1;
    }
    memset(arr, 0, cnt * sizeof(struct dmabuf_obj));

    int valid = 0;
    for (int i = 0; i < cnt; i++) {
        ulong dma_buf = ld.list_ptr[i];
        if (!dma_buf || !IS_KVADDR(dma_buf))
            continue;

        /* Read dma_buf->file */
        ulong file = 0;
        readmem(dma_buf + PARSER_OFFSET(dma_buf_file), KVADDR, &file,
                sizeof(void *), "dma_buf file", RETURN_ON_ERROR);
        if (!IS_KVADDR(file))
            continue;

        if (dmabuf_fill_obj(&arr[valid], dma_buf, file))
            valid++;
    }

    FREEBUF(ld.list_ptr);
    *out_arr = arr;
    *out_count = valid;
    return 1;
}

/*
 * Global dma_buf_fops address, resolved once.
 * Used by is_dma_buf_file() to check file->f_op == &dma_buf_fops,
 * same as the kernel's own is_dma_buf_file() implementation.
 */
static ulong g_dma_buf_fops = 0;
static bool g_dma_buf_fops_resolved = false;

static ulong get_dma_buf_fops(void) {
    if (!g_dma_buf_fops_resolved) {
        g_dma_buf_fops_resolved = true;
        if (symbol_exists("dma_buf_fops"))
            g_dma_buf_fops = symbol_value("dma_buf_fops");
    }
    return g_dma_buf_fops;
}

/*
 * Check if a file* is a dma_buf file.
 *
 * Method 1 (preferred): file->f_op == &dma_buf_fops
 *   Same as the kernel's is_dma_buf_file(). Requires dma_buf_fops symbol.
 *
 * Method 2 (fallback): circular reference file->private_data->file == file
 *   dma_buf_export() sets file->private_data = dmabuf and dmabuf->file = file.
 *
 * Returns the dma_buf pointer (file->private_data) if valid, 0 otherwise.
 */
static ulong dmabuf_validate_file(ulong file) {
    if (!IS_KVADDR(file))
        return 0;
    if (!PARSER_VALID_MEMBER(file_private_data))
        return 0;

    ulong fops = get_dma_buf_fops();
    bool is_dmabuf = false;

    /* Method 1: file->f_op == &dma_buf_fops */
    if (fops && PARSER_VALID_MEMBER(file_f_op)) {
        ulong f_op = 0;
        readmem(file + PARSER_OFFSET(file_f_op), KVADDR, &f_op,
                sizeof(void *), "file f_op", RETURN_ON_ERROR);
        if (f_op == fops)
            is_dmabuf = true;
    }

    /* Method 2 (fallback): circular reference check */
    if (!is_dmabuf && PARSER_VALID_MEMBER(dma_buf_file)) {
        ulong priv = 0;
        readmem(file + PARSER_OFFSET(file_private_data), KVADDR, &priv,
                sizeof(void *), "file private_data", RETURN_ON_ERROR);
        if (IS_KVADDR(priv)) {
            ulong back_file = 0;
            readmem(priv + PARSER_OFFSET(dma_buf_file), KVADDR, &back_file,
                    sizeof(void *), "dma_buf file", RETURN_ON_ERROR);
            if (back_file == file)
                is_dmabuf = true;
        }
    }

    if (!is_dmabuf)
        return 0;

    /* Read file->private_data as dma_buf* */
    ulong dma_buf = 0;
    readmem(file + PARSER_OFFSET(file_private_data), KVADDR, &dma_buf,
            sizeof(void *), "file private_data", RETURN_ON_ERROR);
    if (!IS_KVADDR(dma_buf))
        return 0;

    return dma_buf;
}

/*
 * Approach 2 (fallback): Enumerate dma_buf objects by walking all process fdtables.
 *
 * For each file in every process fdtable, use the circular reference check
 * (file->private_data->file == file) to identify dma_buf files.
 * Simultaneously records per-process mapping.
 *
 * Limitation: only finds dma_bufs with at least one open FD.
 */
static int dmabuf_enumerate_fdtable(struct dmabuf_obj **out_dmabufs, int *out_dmabuf_count,
                                    struct pid_entry **out_pids, int *out_pid_count) {
    int dmabuf_cap = 0;
    int pid_cap = 0;
    *out_dmabufs = NULL;
    *out_dmabuf_count = 0;
    *out_pids = NULL;
    *out_pid_count = 0;

    if (!PARSER_VALID_MEMBER(task_struct_files) || !PARSER_VALID_MEMBER(files_struct_fdt) ||
        !PARSER_VALID_MEMBER(fdtable_fd) || !PARSER_VALID_MEMBER(fdtable_max_fds)) {
        fprintf(fp, "dmabuf: missing fdtable offsets\n");
        return 0;
    }

    if (!PARSER_VALID_MEMBER(dma_buf_file) || !PARSER_VALID_MEMBER(dma_buf_size)) {
        fprintf(fp, "dmabuf: missing dma_buf struct offsets\n");
        return 0;
    }

    struct task_context *tc = FIRST_CONTEXT();
    for (int i = 0; i < RUNNING_TASKS(); i++, tc++) {
        if (tc->pid != (int)task_tgid(tc->task))
            continue;

        ulong files = 0;
        readmem(tc->task + PARSER_OFFSET(task_struct_files), KVADDR, &files,
                sizeof(void *), "task_struct files", RETURN_ON_ERROR);
        if (!IS_KVADDR(files))
            continue;

        ulong fdt = 0;
        readmem(files + PARSER_OFFSET(files_struct_fdt), KVADDR, &fdt,
                sizeof(void *), "files_struct fdt", RETURN_ON_ERROR);
        if (!IS_KVADDR(fdt))
            continue;

        unsigned int max_fds = 0;
        readmem(fdt + PARSER_OFFSET(fdtable_max_fds), KVADDR, &max_fds,
                PARSER_SIZE(fdtable_max_fds), "fdtable max_fds", RETURN_ON_ERROR);

        ulong fd_arr = 0;
        readmem(fdt + PARSER_OFFSET(fdtable_fd), KVADDR, &fd_arr,
                sizeof(void *), "fdtable fd", RETURN_ON_ERROR);
        if (!IS_KVADDR(fd_arr) || !max_fds)
            continue;

        struct pid_entry *pe = NULL;

        for (unsigned int fd = 0; fd < max_fds; fd++) {
            ulong file = 0;
            readmem(fd_arr + fd * sizeof(void *), KVADDR, &file,
                    sizeof(void *), "fdtable file", RETURN_ON_ERROR);
            if (!IS_KVADDR(file))
                continue;

            ulong dma_buf = dmabuf_validate_file(file);
            if (!dma_buf)
                continue;

            /* Find or create dmabuf_obj (dedup by dma_buf pointer) */
            int idx = dmabuf_find_by_ptr(*out_dmabufs, *out_dmabuf_count, dma_buf);
            if (idx < 0) {
                /* New dma_buf discovered */
                if (*out_dmabuf_count >= dmabuf_cap) {
                    int new_cap = dmabuf_cap ? dmabuf_cap * 2 : 256;
                    if (new_cap > DMABUF_MAX_BUFS) new_cap = DMABUF_MAX_BUFS;
                    if (*out_dmabuf_count >= new_cap)
                        continue;
                    struct dmabuf_obj *n = (struct dmabuf_obj *)realloc(
                        *out_dmabufs, new_cap * sizeof(struct dmabuf_obj));
                    if (!n)
                        return -1;
                    memset(n + dmabuf_cap, 0, (new_cap - dmabuf_cap) * sizeof(struct dmabuf_obj));
                    *out_dmabufs = n;
                    dmabuf_cap = new_cap;
                }
                idx = *out_dmabuf_count;
                if (!dmabuf_fill_obj(&(*out_dmabufs)[idx], dma_buf, file))
                    continue;  /* invalid dma_buf, skip */
                (*out_dmabuf_count)++;
            }

            /* Map this process to this buffer */
            if (!pe) {
                pe = pid_find_or_add(out_pids, out_pid_count, &pid_cap,
                                     (int)tc->pid, tc->comm);
                if (!pe)
                    return -1;
            }

            if (pid_entry_add_buf(pe, idx) > 0)
                (*out_dmabufs)[idx].proc_ref++;
        }
    }

    if (*out_dmabuf_count == 0) {
        fprintf(fp, "dmabuf: no dma_buf found in any process fdtable\n");
        return 0;
    }

    return 1;
}

/*
 * Find which dmabuf_obj index a given file* belongs to.
 */
static int dmabuf_find_by_file(struct dmabuf_obj *arr, int count, ulong file) {
    for (int i = 0; i < count; i++) {
        if (arr[i].file == file)
            return i;
    }
    return -1;
}

/*
 * Map dma_buf objects (obtained from db_list) to processes by walking fdtables.
 */
static int dmabuf_map_to_processes(struct dmabuf_obj *dmabufs, int dmabuf_count,
                                   struct pid_entry **out_pids, int *out_pid_count) {
    int pid_cap = 0;
    *out_pids = NULL;
    *out_pid_count = 0;

    if (!PARSER_VALID_MEMBER(task_struct_files) || !PARSER_VALID_MEMBER(files_struct_fdt) ||
        !PARSER_VALID_MEMBER(fdtable_fd) || !PARSER_VALID_MEMBER(fdtable_max_fds))
        return 0;

    struct task_context *tc = FIRST_CONTEXT();
    for (int i = 0; i < RUNNING_TASKS(); i++, tc++) {
        if (tc->pid != (int)task_tgid(tc->task))
            continue;

        ulong files = 0;
        readmem(tc->task + PARSER_OFFSET(task_struct_files), KVADDR, &files,
                sizeof(void *), "task_struct files", RETURN_ON_ERROR);
        if (!IS_KVADDR(files))
            continue;

        ulong fdt = 0;
        readmem(files + PARSER_OFFSET(files_struct_fdt), KVADDR, &fdt,
                sizeof(void *), "files_struct fdt", RETURN_ON_ERROR);
        if (!IS_KVADDR(fdt))
            continue;

        unsigned int max_fds = 0;
        readmem(fdt + PARSER_OFFSET(fdtable_max_fds), KVADDR, &max_fds,
                PARSER_SIZE(fdtable_max_fds), "fdtable max_fds", RETURN_ON_ERROR);

        ulong fd_arr = 0;
        readmem(fdt + PARSER_OFFSET(fdtable_fd), KVADDR, &fd_arr,
                sizeof(void *), "fdtable fd", RETURN_ON_ERROR);
        if (!IS_KVADDR(fd_arr) || !max_fds)
            continue;

        struct pid_entry *pe = NULL;

        for (unsigned int fd = 0; fd < max_fds; fd++) {
            ulong file = 0;
            readmem(fd_arr + fd * sizeof(void *), KVADDR, &file,
                    sizeof(void *), "fdtable file", RETURN_ON_ERROR);
            if (!IS_KVADDR(file))
                continue;

            int idx = dmabuf_find_by_file(dmabufs, dmabuf_count, file);
            if (idx < 0)
                continue;

            if (!pe) {
                pe = pid_find_or_add(out_pids, out_pid_count, &pid_cap,
                                     (int)tc->pid, tc->comm);
                if (!pe)
                    return -1;
            }

            if (pid_entry_add_buf(pe, idx) > 0)
                dmabufs[idx].proc_ref++;
        }
    }

    return 1;
}

static void dmabuf_compute_totals(struct dmabuf_obj *dmabufs, int dmabuf_count,
                                  struct pid_entry *pids, int pid_count,
                                  unsigned long long *sys_total) {
    *sys_total = 0;
    for (int i = 0; i < dmabuf_count; i++)
        *sys_total += dmabufs[i].size_bytes;

    for (int p = 0; p < pid_count; p++) {
        unsigned long long rss = 0;
        unsigned long long pss = 0;
        for (int k = 0; k < pids[p].buf_count; k++) {
            int idx = pids[p].buf_indices[k];
            if (idx < 0 || idx >= dmabuf_count)
                continue;
            struct dmabuf_obj *o = &dmabufs[idx];
            rss += o->size_bytes;
            if (o->proc_ref > 0)
                pss += o->size_bytes / (unsigned long long)o->proc_ref;
        }
        pids[p].rss_bytes = rss;
        pids[p].pss_bytes = pss;
    }
}

static int cmp_pid_rss_desc(const void *a, const void *b) {
    const struct pid_entry *pa = (const struct pid_entry *)a;
    const struct pid_entry *pb = (const struct pid_entry *)b;
    if (pa->rss_bytes < pb->rss_bytes) return 1;
    if (pa->rss_bytes > pb->rss_bytes) return -1;
    return (pa->pid - pb->pid);
}

static int cmp_pid_pss_desc(const void *a, const void *b) {
    const struct pid_entry *pa = (const struct pid_entry *)a;
    const struct pid_entry *pb = (const struct pid_entry *)b;
    if (pa->pss_bytes < pb->pss_bytes) return 1;
    if (pa->pss_bytes > pb->pss_bytes) return -1;
    return (pa->pid - pb->pid);
}

static void dmabuf_print_attachments(ulong dma_buf) {
    if (!IS_KVADDR(dma_buf) || !PARSER_VALID_MEMBER(dma_buf_attachments))
        return;

    if (!MEMBER_EXISTS("dma_buf_attachment", "node")) {
        fprintf(fp, "        attachments: <unsupported: missing dma_buf_attachment.node>\n");
        return;
    }

    long node_off = MEMBER_OFFSET("dma_buf_attachment", "node");
    if (node_off < 0)
        return;

    ulong head = dma_buf + PARSER_OFFSET(dma_buf_attachments);
    ulong next = 0;
    readmem(head, KVADDR, &next, sizeof(void *), "list_head next", RETURN_ON_ERROR);

    int n = 0;
    while (IS_KVADDR(next) && next != head) {
        ulong att = next - (ulong)node_off;
        fprintf(fp, "        attachment[%d]: %lx\n", n++, att);
        readmem(next, KVADDR, &next, sizeof(void *), "list_head next", RETURN_ON_ERROR);
        if (n > 4096) {
            fprintf(fp, "        attachments: <abort: too many>\n");
            break;
        }
    }

    if (n == 0)
        fprintf(fp, "        attachments: (none)\n");
}

static void dmabuf_print_summary(struct dmabuf_obj *dmabufs, int dmabuf_count,
                                 struct pid_entry *pids, int pid_count,
                                 int topn, bool sort_pss) {
    unsigned long long sys_total = 0;
    dmabuf_compute_totals(dmabufs, dmabuf_count, pids, pid_count, &sys_total);

    if (sort_pss)
        qsort(pids, pid_count, sizeof(struct pid_entry), cmp_pid_pss_desc);
    else
        qsort(pids, pid_count, sizeof(struct pid_entry), cmp_pid_rss_desc);

    fprintf(fp, "%-8s %-16s %-8s %-12s %-12s\n",
            "PID", "COMM", "DMABUF", "RSS_KB", "PSS_KB");

    int lines = 0;
    for (int i = 0; i < pid_count; i++) {
        if (topn > 0 && lines >= topn)
            break;
        if (pids[i].buf_count == 0)
            continue;
        fprintf(fp, "%-8d %-16s %-8d %-12llu %-12llu\n",
                pids[i].pid,
                pids[i].comm,
                pids[i].buf_count,
                (unsigned long long)(pids[i].rss_bytes / 1024ULL),
                (unsigned long long)(pids[i].pss_bytes / 1024ULL));
        lines++;
    }

    fprintf(fp, "\nSystem dmabuf total: %llu KB (%d buffers)\n",
            (unsigned long long)(sys_total / 1024ULL), dmabuf_count);
}

static void dmabuf_print_pid_detail(int pid,
                                    struct dmabuf_obj *dmabufs, int dmabuf_count,
                                    struct pid_entry *pids, int pid_count,
                                    bool with_attach) {
    struct pid_entry *pe = NULL;
    for (int i = 0; i < pid_count; i++) {
        if (pids[i].pid == pid) {
            pe = &pids[i];
            break;
        }
    }

    if (!pe) {
        fprintf(fp, "dmabuf: pid %d not found or has no dmabuf\n", pid);
        return;
    }

    unsigned long long sys_total = 0;
    dmabuf_compute_totals(dmabufs, dmabuf_count, pids, pid_count, &sys_total);

    fprintf(fp, "PID %d (%s) dmabuf_cnt=%d rss_kb=%llu pss_kb=%llu\n\n",
            pe->pid, pe->comm, pe->buf_count,
            (unsigned long long)(pe->rss_bytes / 1024ULL),
            (unsigned long long)(pe->pss_bytes / 1024ULL));

    fprintf(fp, "%-18s %-10s %-24s %-8s %-8s %s\n",
            "DMABUF", "SIZE_KB", "EXP_NAME", "F_COUNT", "PROCS", "NAME");

    for (int k = 0; k < pe->buf_count; k++) {
        int idx = pe->buf_indices[k];
        if (idx < 0 || idx >= dmabuf_count)
            continue;
        struct dmabuf_obj *o = &dmabufs[idx];

        fprintf(fp, "%016lx  %-10llu %-24s %-8lu %-8d %s\n",
                o->dma_buf,
                (unsigned long long)(o->size_bytes / 1024ULL),
                o->exp_name[0] ? o->exp_name : "<unknown>",
                o->f_count,
                o->proc_ref,
                o->buf_name[0] ? o->buf_name : "");

        if (with_attach)
            dmabuf_print_attachments(o->dma_buf);
    }
}

static void dmabuf_print_all_bufs(struct dmabuf_obj *dmabufs, int dmabuf_count,
                                  bool with_attach) {
    unsigned long long sys_total = 0;
    for (int i = 0; i < dmabuf_count; i++)
        sys_total += dmabufs[i].size_bytes;

    fprintf(fp, "%-18s %-10s %-24s %-8s %-8s %s\n",
            "DMABUF", "SIZE_KB", "EXP_NAME", "F_COUNT", "PROCS", "NAME");

    for (int i = 0; i < dmabuf_count; i++) {
        struct dmabuf_obj *o = &dmabufs[i];
        fprintf(fp, "%016lx  %-10llu %-24s %-8lu %-8d %s\n",
                o->dma_buf,
                (unsigned long long)(o->size_bytes / 1024ULL),
                o->exp_name[0] ? o->exp_name : "<unknown>",
                o->f_count,
                o->proc_ref,
                o->buf_name[0] ? o->buf_name : "");

        if (with_attach)
            dmabuf_print_attachments(o->dma_buf);
    }

    fprintf(fp, "\nSystem dmabuf total: %llu KB (%d buffers)\n",
            (unsigned long long)(sys_total / 1024ULL), dmabuf_count);
}

static void free_pids(struct pid_entry *pids, int pid_count) {
    if (!pids) return;
    for (int i = 0; i < pid_count; i++)
        free(pids[i].buf_indices);
    free(pids);
}

void parser_dmabuf_usage(void) {
    fprintf(fp, "Usage: lp dmabuf [OPTION] ...\n");
    fprintf(fp, "Option:\n");
    fprintf(fp, "    -a                 per-process summary + system total\n");
    fprintf(fp, "    -b                 list all dma_buf objects in the system\n");
    fprintf(fp, "    --pid <PID>        show per-dmabuf details for PID\n");
    fprintf(fp, "    --top <N>          show top N processes (default sort by RSS)\n");
    fprintf(fp, "    --sort rss|pss     sort for --top/summary (default rss)\n");
    fprintf(fp, "    --attach           dump dma_buf attachments (best-effort)\n");
}

void parser_dmabuf_main(void) {
    if (!fp)
        return;

    if (argcnt < 2 || !args[1]) {
        parser_dmabuf_usage();
        return;
    }

    int opt;
    int option_index = 0;
    optind = 0;
    opterr = 0;

    int pid = -1;
    int topn = 0;
    bool sort_pss = false;
    bool with_attach = false;
    bool list_all = false;

    static struct option long_options[] = {
        {"pid",     required_argument, 0, 'p'},
        {"top",     required_argument, 0, 't'},
        {"sort",    required_argument, 0, 's'},
        {"attach",  no_argument,       0, 1000},
        {0, 0, 0, 0}
    };

    int local_argc = argcnt - 1;
    char *local_argv[MAXARGS];
    if (local_argc < 1)
        local_argc = 1;
    if (local_argc > MAXARGS - 1)
        local_argc = MAXARGS - 1;
    for (int i = 0; i < local_argc; i++)
        local_argv[i] = args[i + 1];
    local_argv[local_argc] = NULL;

    while ((opt = getopt_long(local_argc, local_argv, "+abp:t:s:",
                              long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a':
                break;
            case 'b':
                list_all = true;
                break;
            case 'p':
                pid = (int)strtol(optarg, NULL, 0);
                break;
            case 't':
                topn = (int)strtol(optarg, NULL, 0);
                break;
            case 's':
                if (optarg && !strcmp(optarg, "pss"))
                    sort_pss = true;
                break;
            case 1000:
                with_attach = true;
                break;
            default:
                break;
        }
    }

    struct dmabuf_obj *dmabufs = NULL;
    int dmabuf_count = 0;
    struct pid_entry *pids = NULL;
    int pid_count = 0;
    int ret;

    /*
     * Try approach 1: walk kernel global db_list.
     * If db_list symbol is not available, fall back to approach 2.
     */
    ret = dmabuf_enumerate_db_list(&dmabufs, &dmabuf_count);
    if (ret > 0) {
        /* db_list succeeded, now map to processes */
        ret = dmabuf_map_to_processes(dmabufs, dmabuf_count, &pids, &pid_count);
        if (ret < 0)
            goto out;
    } else if (ret == 0) {
        /*
         * Fallback: walk all process fdtables and identify dma_buf files
         * using circular reference: file->private_data->file == file
         */
        ret = dmabuf_enumerate_fdtable(&dmabufs, &dmabuf_count, &pids, &pid_count);
        if (ret <= 0)
            goto out;
    } else {
        goto out;
    }

    if (list_all)
        dmabuf_print_all_bufs(dmabufs, dmabuf_count, with_attach);
    else if (pid >= 0)
        dmabuf_print_pid_detail(pid, dmabufs, dmabuf_count, pids, pid_count, with_attach);
    else
        dmabuf_print_summary(dmabufs, dmabuf_count, pids, pid_count, topn, sort_pss);

out:
    free_pids(pids, pid_count);
    free(dmabufs);
}
