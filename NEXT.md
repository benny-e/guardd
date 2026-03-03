Next: add outbound TCP connect sensor in C (eBPF + ringbuf + userspace print).
Goal fields: pid, uid, comm, daddr, dport (IPv4 first).
Hook: start with tracepoint (if stable) or kprobe tcp_v4_connect (fallback).
