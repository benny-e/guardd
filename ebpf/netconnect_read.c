// ebpf/netconnect_read.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>

#include "netconnect.h"
#include "netconnect.skel.h"

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

    const struct netconnect_event *e = data;

    struct in_addr s, d;
    memcpy(&s.s_addr, e->saddr, 4);
    memcpy(&d.s_addr, e->daddr, 4);

    char s_ip[INET_ADDRSTRLEN];
    char d_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &s, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &d, d_ip, sizeof(d_ip));

        printf("connect: pid=%u uid=%u comm=%.*s %s:%u -> %s:%u\n",
           e->pid, e->uid, 16, e->comm,
           s_ip, ntohs(e->sport), d_ip, ntohs(e->dport));

    return 0;
}

int main(void)
{
    struct netconnect_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    skel = netconnect_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = netconnect_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = netconnect_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.net_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    printf("listening for TCP IPv4 connect attempts... (Ctrl+C to stop)\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 250);
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
    netconnect_bpf__destroy(skel);
    return err != 0;
}
