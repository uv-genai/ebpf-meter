# Makefile for eBPF traffic meter

BPF_SRC = traffic_meter.bpf.c
BPF_OBJ = traffic_meter.bpf.o
USER_SRC = traffic_meter_user.c
USER_BIN = traffic_meter_user
SKEL_HDR = traffic_meter.skel.h

CLANG ?= clang
CPPFLAGS ?= -I/usr/include -I.
CFLAGS ?= -O2 -g -Wall
LIBS ?= -lbpf -lelf -lz

all: $(BPF_OBJ) $(USER_BIN)

# Build BPF object file
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_X86 -c $< -o $@

# Build user‑space loader (no skeleton needed)
$(USER_BIN): $(USER_SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)

.PHONY: all clean
