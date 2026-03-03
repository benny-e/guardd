# ebpf/Makefile
BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__BPF__

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: exec_read netconnect_read guardd

vmlinux.h:
	bpftool btf dump file $(VMLINUX_BTF) format c > vmlinux.h

# --- exec ---
exec.bpf.o: vmlinux.h exec.bpf.c exec.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c exec.bpf.c -o exec.bpf.o

exec.skel.h: exec.bpf.o
	bpftool gen skeleton exec.bpf.o > exec.skel.h

exec_read: exec_read.c exec.skel.h exec.h
	clang -O2 -g -Wall -Werror exec_read.c -o exec_read -lbpf

# --- netconnect ---
netconnect.bpf.o: vmlinux.h netconnect.bpf.c netconnect.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c netconnect.bpf.c -o netconnect.bpf.o

netconnect.skel.h: netconnect.bpf.o
	bpftool gen skeleton netconnect.bpf.o > netconnect.skel.h

netconnect_read: netconnect_read.c netconnect.skel.h netconnect.h
	clang -O2 -g -Wall -Werror netconnect_read.c -o netconnect_read -lbpf

# --- guardd ---
guardd: guardd.c exec.skel.h netconnect.skel.h exec.h netconnect.h
	clang -O2 -g -Wall -Werror guardd.c -o guardd -lbpf

clean:
	rm -f vmlinux.h *.o *.skel.h exec_read netconnect_read guardd
