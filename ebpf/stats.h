#ifndef STATS_H
#define STATS_H

enum guard_stat_key {
    STAT_EXEC_EMIT_OK = 0,
    STAT_EXEC_RINGBUF_DROP = 1,
    STAT_NET_EMIT_OK = 2,
    STAT_NET_RINGBUF_DROP = 3,
    STAT_MAX
};

static __always_inline void bump_stat(__u64 *value)
{
    if (value)
        __sync_fetch_and_add(value, 1);
}

#endif
