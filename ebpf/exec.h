// ebpf/exec.h
#ifndef EXEC_H
#define EXEC_H

#ifdef __BPF__
#else

#include <stdint.h>
typedef uint32_t u32;
#endif

struct exec_event {
    u32 pid;
    char comm[16];
};

#endif
