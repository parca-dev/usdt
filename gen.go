// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

//go:generate sh -c "go tool cgo -godefs types_def.go > types.go && rm -rf _obj"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -tags linux bpfUsdt ebpf/usdt_gen.c -- -Iebpf
