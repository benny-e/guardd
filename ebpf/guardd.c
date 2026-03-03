// ebpf/guardd.c
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#include "exec.h"
#include "netconnect.h"
#include "exec.skel.h"
#include "netconnect.skel.h"

static volatile sig_atomic_t stop = 0;

static void on_sigint(int signo) {
    (void)signo;
    stop = 1;
}

static int json_mode = 0;

static unsigned long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (unsigned long long)ts.tv_sec * 1000ULL + (unsigned long long)(ts.tv_nsec / 1000000ULL);
}

// Minimal JSON string escape (handles \ and " and control chars)
static void json_print_escaped(const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '\\': fputs("\\\\", stdout); break;
            case '"':  fputs("\\\"", stdout); break;
            case '\b': fputs("\\b", stdout); break;
            case '\f': fputs("\\f", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (c < 0x20) {
                    // control char -> \u00XX
                    printf("\\u%04x", c);
                } else {
                    fputc(c, stdout);
                }
        }
    }
}

/* -------- exec events -------- */

static int handle_exec_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;

    const struct exec_event *e = (const struct exec_event *)data;

    if (!json_mode) {
	 printf("[EXEC] pid=%u ppid=%u uid=%u comm=%.*s file=%s\n",
           e->pid, e->ppid, e->uid, 16, e->comm, e->filename);
    } else {
	unsigned long long ts = now_ms();

	// comm: ensure null-terminated
	char comm_buf[17];
	memcpy(comm_buf, e->comm, 16);
	comm_buf[16] = '\0';

	printf("{\"ts_ms\":%llu,\"type\":\"exec\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"",
           ts, e->pid, e->ppid, e->uid);
	json_print_escaped(comm_buf);
	printf("\",\"file\":\"");
	json_print_escaped(e->filename);
	printf("\"}\n");
	fflush(stdout);
    }
    return 0;
}

/* -------- netconnect events -------- */

static int handle_net_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    (void)data_sz;

    const struct netconnect_event *e = (const struct netconnect_event *)data;

    struct in_addr s, d;
    memcpy(&s.s_addr, e->saddr, 4);
    memcpy(&d.s_addr, e->daddr, 4);

    char s_ip[INET_ADDRSTRLEN];
    char d_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &s, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &d, d_ip, sizeof(d_ip));

    if (!json_mode) {
	printf("[NET ] pid=%u uid=%u comm=%.*s %s:%u -> %s:%u\n",
           e->pid, e->uid, 16, e->comm,
           s_ip, ntohs(e->sport), d_ip, ntohs(e->dport));
    } else {
	unsigned long long ts = now_ms();

	char comm_buf[17];
	memcpy(comm_buf, e->comm, 16);
	comm_buf[16] = '\0';

	printf("{\"ts_ms\":%llu,\"type\":\"net\",\"pid\":%u,\"uid\":%u,\"comm\":\"",
           ts, e->pid, e->uid);
	json_print_escaped(comm_buf);
	printf("\",\"src_ip\":\"%s\",\"src_port\":%u,\"dst_ip\":\"%s\",\"dst_port\":%u}\n",
           s_ip, ntohs(e->sport), d_ip, ntohs(e->dport));
	fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct exec_bpf *exec_skel = NULL;
    struct netconnect_bpf *net_skel = NULL;
    struct ring_buffer *rb_exec = NULL;
    struct ring_buffer *rb_net = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    for (int i = 1; i < argc; i++) {
	if (strcmp(argv[i], "--json") == 0) {
	    json_mode = 1;
	} else if (strcmp(argv[i], "--help") == 0) {
	    printf("usage: %s [--json]\n", argv[0]);
	    return 0;
    }
}

    /* --- open --- */
    exec_skel = exec_bpf__open();
    if (!exec_skel) {
        fprintf(stderr, "guardd: failed to open exec skeleton\n");
        err = 1;
        goto cleanup;
    }

    net_skel = netconnect_bpf__open();
    if (!net_skel) {
        fprintf(stderr, "guardd: failed to open netconnect skeleton\n");
        err = 1;
        goto cleanup;
    }

    /* --- load --- */
    if ((err = exec_bpf__load(exec_skel))) {
        fprintf(stderr, "guardd: failed to load exec BPF: %d\n", err);
        goto cleanup;
    }

    if ((err = netconnect_bpf__load(net_skel))) {
        fprintf(stderr, "guardd: failed to load netconnect BPF: %d\n", err);
        goto cleanup;
    }

    /* --- attach --- */
    if ((err = exec_bpf__attach(exec_skel))) {
        fprintf(stderr, "guardd: failed to attach exec BPF: %d\n", err);
        goto cleanup;
    }

    if ((err = netconnect_bpf__attach(net_skel))) {
        fprintf(stderr, "guardd: failed to attach netconnect BPF: %d\n", err);
        goto cleanup;
    }

    /* --- ring buffers --- */
    rb_exec = ring_buffer__new(bpf_map__fd(exec_skel->maps.events), handle_exec_event, NULL, NULL);
    if (!rb_exec) {
        fprintf(stderr, "guardd: failed to create exec ringbuf: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    rb_net = ring_buffer__new(bpf_map__fd(net_skel->maps.net_events), handle_net_event, NULL, NULL);
    if (!rb_net) {
        fprintf(stderr, "guardd: failed to create net ringbuf: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    printf("guardd: listening for EXEC + NET events... (Ctrl+C to stop)\n");

    while (!stop) {
        int e1 = ring_buffer__poll(rb_exec, 100);
        if (e1 == -EINTR) break;
        if (e1 < 0) {
            fprintf(stderr, "guardd: exec ringbuf poll error: %d\n", e1);
            err = 1;
            break;
        }

        int e2 = ring_buffer__poll(rb_net, 100);
        if (e2 == -EINTR) break;
        if (e2 < 0) {
            fprintf(stderr, "guardd: net ringbuf poll error: %d\n", e2);
            err = 1;
            break;
        }
    }

cleanup:
    ring_buffer__free(rb_net);
    ring_buffer__free(rb_exec);

    netconnect_bpf__destroy(net_skel);
    exec_bpf__destroy(exec_skel);

    return err != 0;
}
