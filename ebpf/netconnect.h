// ebpf/netconnect.h
#ifndef NETCONNECT_H
#define NETCONNECT_H

#ifdef __BPF__
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
#else
#include <stdint.h>
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#endif

// IPv4 only
struct netconnect_event {
  u32 pid;
  u32 uid;
  u8 saddr[4];
  u8 daddr[4];
  u16 sport; // network byte order
  u16 dport; // network byte order
  char comm[16];
};

#endif
