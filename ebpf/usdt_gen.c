// Combined BPF source for bpf2go code generation.
//
// bpf2go compiles a single .c file, so we merge the specs map definition
// (usdt.ebpf.c) with the test programs (usdt_test.ebpf.c) here.
//
// For parca-prof's linked build, use the individual .c files instead.

//go:build ignore

#include "usdt.ebpf.c"
#include "usdt_test.ebpf.c"
