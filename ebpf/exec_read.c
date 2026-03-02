// ebpf/exec_read.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "exec.h"
#include <bpf/libbpf.h>
#include "exec.skel.h"

static volatile sig_atomic_t stop = 0;

static void on_sigint(int signo)
{
    (void)signo;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;

    const struct exec_event *e = data;
    printf("exec: pid=%u comm=%.*s\n", e->pid, 16, e->comm);
    return 0;
}

int main(void)
{
    struct exec_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    skel = exec_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = exec_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = exec_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    printf("listening for exec events... (Ctrl+C to stop)\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 250 /* ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    exec_bpf__destroy(skel);
    return err != 0;
}
