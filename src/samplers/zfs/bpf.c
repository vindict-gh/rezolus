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
#define OP_CODE_OPEN 2
#define OP_CODE_FSYNC 3

BPF_HASH(start, u32);

// value_to_index2() gives us from 0-460 as the index
BPF_HISTOGRAM(read, int, 461);
BPF_HISTOGRAM(write, int, 461);
BPF_HISTOGRAM(open, int, 461);
BPF_HISTOGRAM(fsync, int, 461);

VALUE_TO_INDEX2_FUNC

int trace_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

static int trace_return(struct pt_regs *ctx, const int op)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // lookup start time
    u64 *tsp = start.lookup(&tid);

    // skip events without start
    if (tsp == 0) {
        return 0;
    }

    // calculate latency in microseconds
    u64 delta = (bpf_ktime_get_ns() - *tsp) / 1000;

    // calculate index
    u64 index = value_to_index2(delta);

    // store into correct histogram for OP
    if (op == OP_CODE_READ) {
        read.increment(index);
    } else if (op == OP_CODE_WRITE) {
        write.increment(index);
    } else if (op == OP_CODE_OPEN) {
        open.increment(index);
    } else if (op == OP_CODE_FSYNC) {
        fsync.increment(index);
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

int trace_open_return(struct pt_regs *ctx)
{
    return trace_return(ctx, OP_CODE_OPEN);
}

int trace_fsync_return(struct pt_regs *ctx)
{
    return trace_return(ctx, OP_CODE_FSYNC);
}
