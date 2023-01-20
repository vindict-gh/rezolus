// Copyright 2022 Valentin BRICE <dev@vbrice.fr>
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

// Based on: https://github.com/iovisor/bcc/blob/master/tools/zfsdist.py
// Based on: ../xfs/bpf.c

#include <uapi/linux/ptrace.h>

#define OP_CODE_READ 0
#define OP_CODE_WRITE 1

#define ZFS_MAXNAMELEN 256

// XXX: Incomplete declaration of ZFS's internal zv_request_stack
// We only care here about the pointer to zvol_state_t to access to the zvol name
typedef struct zv_request_stack {
	zvol_state_t	*zv;
//	struct bio	*bio;
//	struct request *rq;
} zv_request_t;

// XXX: Incomplete declaration of ZFS's internal zvol_state
// We only care here about the pointer to zv_name to access to the zvol name
typedef struct zvol_state {
    char			zv_name[ZFS_MAXNAMELEN];
//	uint64_t		zv_volsize;
//	uint64_t		zv_volblocksize;
//	objset_t		*zv_objset;
//	uint32_t		zv_flags;
//	uint32_t		zv_open_count;
//	uint32_t		zv_changed;
//	uint32_t		zv_volmode;
//	zilog_t			*zv_zilog;
//	zfs_rangelock_t		zv_rangelock;
//	dnode_t			*zv_dn;
//	dataset_kstats_t	zv_kstat;
//	list_node_t		zv_next;
//	uint64_t		zv_hash;
//	struct hlist_node	zv_hlink;
//	kmutex_t		zv_state_lock;
//	atomic_t		zv_suspend_ref;
//	krwlock_t		zv_suspend_lock;
//	struct zvol_state_os	*zv_zso;
} zvol_state_t;

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
BPF_HISTOGRAM(read, dist_key_t, 461);
BPF_HISTOGRAM(write, dist_key_t, 461);

VALUE_TO_INDEX2_FUNC

int trace_entry(struct pt_regs *ctx, zv_request_t *zvr)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 ts = bpf_ktime_get_ns();
    struct hash_value value = {.ts = ts};

    // arguably we could also write zvr->zv.zv_name just as zvr->zv
    // per C standard definitions
    bpf_probe_read_kernel(&value.zvol_name, sizeof(value.zvol_name), zvr->zv->zv_name);

    start.update(&tid, &value);
    return 0;
}

static int trace_return(struct pt_regs *ctx, const int op)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u64 cur_ts = bpf_ktime_get_ns()

    // lookup start time
    hash_value_t *start_value = start.lookup(&tid);

    // skip events without start
    if (start_value == NULL) {
        return 0;
    }

    // calculate latency in microseconds
    u64 delta = (cur_ts - start_value->ts) / 1000;

    struct dist_key key = {};
    __builtin_memcpy(&key.zvol_name, start_value->zvol_name, sizeof(key.zvol_name));
    key.slot = bpf_log2l(delta);

    // calculate index
    u64 index = value_to_index2(delta);

    // store into correct histogram for OP
    if (op == OP_CODE_READ) {
        read.increment(key);
    } else if (op == OP_CODE_WRITE) {
        write.increment(key);
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

