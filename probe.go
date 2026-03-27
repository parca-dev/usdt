// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "github.com/parca-dev/usdt"

// Probe represents a USDT probe found in an ELF binary with
// file-offset-adjusted addresses suitable for uprobe attachment.
type Probe struct {
	Provider        string
	Name            string
	Location        uint64 // File offset for uprobe attachment
	Base            uint64 // Original base address from note
	SemaphoreOffset uint64 // File offset for semaphore
	Arguments       string
}
