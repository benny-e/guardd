// ebpf/netconnect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netconnect.h"
#include "stats.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} net_events SEC(".maps");

#ifndef TCP_SYN_SENT
#define TCP_SYN_SENT 2
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    __u32 key;
    __u64 *val;

    if (ctx->protocol != 6)
        return 0;

    if (ctx->newstate != TCP_SYN_SENT)
        return 0;

    if (ctx->family != AF_INET)
        return 0;

    struct netconnect_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) {
	key = STAT_NET_RINGBUF_DROP;
	val = bpf_map_lookup_elem(&stats, &key);
	bump_stat(val);
	return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    e->pid = id >> 32;
    e->uid = (u32)uid_gid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // ctx->saddr and ctx->daddr are __u8[4] on your kernel
    __builtin_memcpy(e->saddr, ctx->saddr, 4);
    __builtin_memcpy(e->daddr, ctx->daddr, 4);

    e->sport = ctx->sport;
    e->dport = ctx->dport;

    bpf_ringbuf_submit(e, 0);

    key = STAT_NET_EMIT_OK;
    val = bpf_map_lookup_elem(&stats, &key);
    bump_stat(val);

    return 0;
}
