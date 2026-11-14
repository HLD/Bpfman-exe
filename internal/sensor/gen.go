// Package sensor loads and attaches the warden eBPF programs.
package sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target amd64 -type hdr -type ev_exec -type ev_exit -type ev_file -type ev_net -type ev_creds -type ev_target -type ev_dns -type ev_shellcmd -type policy -type lpm_v4 -type lpm_v6 warden ../../bpf/warden.bpf.c -- -I../../bpf
