// Copyright 2022 Valentin BRICE <dev@vbrice.fr>
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

// Based on: https://github.com/iovisor/bcc/blob/master/tools/zfsdist.py
// Based on: ../xfs/bpf.c

#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define OP_CODE_READ 0
#define OP_CODE_WRITE 1

#define ZFS_MAXNAMELEN 256

typedef struct dist_key {
    char zvol_name[ZFS_MAXNAMELEN];
    u64 slot;
} dist_key_t;

typedef struct hash_value {
    char zvol_name[ZFS_MAXNAMELEN];
    u64 ts;
} hash_value_t;

BPF_HASH(start, u32, hash_value_t);

// value_to_index2() gives us from 0-460 as the index
BPF_HISTOGRAM(read, histo_value_t, 461);
BPF_HISTOGRAM(write, histo_value_t, 461);

VALUE_TO_INDEX2_FUNC

int trace_entry(struct pt_regs *ctx, zv_request_t *zvr)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    struct hash_value value = {.ts = ts};

    err = BPF_CORE_READ_INTO(&value.zvol_name, zvr, zv.zvol_name);
    if (err){
        return 0;
    }

    start.update(&tid, &value);
    return 0;
}

static int trace_return(struct pt_regs *ctx, const char *op)
{
    hash_value_t *start_value;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // lookup start time
    hash_value_t *start_value = start.lookup(&tid);

    // skip events without start
    if (start_value == NULL) {
        return 0;
    }

    // calculate latency in microseconds
    u64 delta = (bpf_ktime_get_ns() - start_value->name) / 1000;

    struct dist_key key = {};
    __builtin_memcpy(&key.zvol_name, start_value->zvol_name, sizeof(key.zvol_name));
    key.slot = bpf_log2l(delta);

    // calculate index
    u64 index = value_to_index2(delta);

    // store into correct histogram for OP
    if (op == OP_CODE_READ) {
        read.atomic_increment(key);
    } else if (op == OP_CODE_WRITE) {
        write.atomic_increment(key);
    }

    // clear the start time
    start.delete(&tid);

    return 0;
}

int trace_read_return(struct pt_regs *ctx)
{
    return trace_return(ctx, OP_CODE_READ);
}

int trace_write_return(struct pt_regs *ctx)
{
    return trace_return(ctx, OP_CODE_WRITE);
}

