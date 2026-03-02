// ebpf/exec.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "exec.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    e->pid = id >> 32;
    e->uid = (u32)uid_gid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read __data_loc filename correctly
    u32 fname_off = ctx->__data_loc_filename & 0xFFFF;
    char *fname = (char *)ctx + fname_off;

    bpf_probe_read_str(e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
