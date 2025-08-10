package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -cc clang -cflags "-O2 -g -Wall -I../../bpf -I../../bpf/include" -no-global-types -type event -target amd64,arm64 Bpf ../../bpf/tracer.bpf.c
