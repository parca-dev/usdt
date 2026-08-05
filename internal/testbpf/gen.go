// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package testbpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -tags linux UsdtTest ../../ebpf/usdt_gen.c -- -I../../ebpf
