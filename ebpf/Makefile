# ebpf/Makefile
BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__BPF__

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: exec_read

vmlinux.h:
	bpftool btf dump file $(VMLINUX_BTF) format c > vmlinux.h

exec.bpf.o: vmlinux.h exec.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c exec.bpf.c -o exec.bpf.o

exec.skel.h: exec.bpf.o
	bpftool gen skeleton exec.bpf.o > exec.skel.h

exec_read: exec_read.c exec.skel.h
	clang -O2 -g -Wall -Werror exec_read.c -o exec_read -lbpf

clean:
	rm -f vmlinux.h exec.bpf.o exec.skel.h exec_read
