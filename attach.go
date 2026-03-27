// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package usdt

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ProbeLinks manages the lifecycle of attached USDT uprobes and their
// corresponding spec map entries.
type ProbeLinks struct {
	Links   []link.Link
	SpecIDs []uint32
	SpecMap *ebpf.Map
}

// Close detaches all probes and removes their spec map entries.
func (pl *ProbeLinks) Close() error { return pl.Unload() }

// Unload detaches all probes and removes their spec map entries.
func (pl *ProbeLinks) Unload() error {
	var errs []error
	for _, l := range pl.Links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if pl.SpecMap != nil {
		for _, id := range pl.SpecIDs {
			if id != 0 {
				if err := pl.SpecMap.Delete(unsafe.Pointer(&id)); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// PopulateSpecMap parses USDT probe arguments and stores the resulting specs
// in the BPF map.  Each probe with parseable arguments is assigned a spec ID
// starting from startID.  Probes with empty or unparseable arguments receive
// spec ID 0 (the BPF side treats 0 as "no spec").
func PopulateSpecMap(specMap *ebpf.Map, probes []Probe, startID uint32) ([]uint32, error) {
	specIDs := make([]uint32, len(probes))
	nextID := startID

	for i, p := range probes {
		if p.Arguments == "" {
			continue
		}
		spec, err := ParseUSDTArguments(p.Arguments)
		if err != nil {
			// Non-fatal: probe just won't have argument extraction.
			continue
		}
		id := nextID
		nextID++
		specIDs[i] = id
		if err := specMap.Put(unsafe.Pointer(&id), SpecToBytes(spec)); err != nil {
			return nil, fmt.Errorf("store spec for %s:%s: %w", p.Provider, p.Name, err)
		}
	}
	return specIDs, nil
}

// MergeCookies combines spec IDs (high 32 bits) with user cookies (low 32
// bits) into the format expected by the BPF USDT argument extraction code.
func MergeCookies(specIDs []uint32, userCookies []uint64) []uint64 {
	n := len(specIDs)
	if len(userCookies) > n {
		n = len(userCookies)
	}
	out := make([]uint64, n)
	for i := range out {
		if i < len(specIDs) {
			out[i] = uint64(specIDs[i]) << 32
		}
		if i < len(userCookies) {
			out[i] |= userCookies[i] & 0xFFFFFFFF
		}
	}
	return out
}

// AttachUprobes attaches one BPF program per probe as a uprobe.  The caller
// provides a slice of programs parallel to probes (one program per probe) and
// optional cookies.  Returns ProbeLinks that must be closed to detach and
// clean up spec map entries.
func AttachUprobes(exe *link.Executable, specMap *ebpf.Map, probes []Probe,
	progs []*ebpf.Program, cookies []uint64) (*ProbeLinks, error) {

	if len(progs) != len(probes) {
		return nil, fmt.Errorf("len(progs)=%d != len(probes)=%d", len(progs), len(probes))
	}

	var links []link.Link
	for i, p := range probes {
		opts := &link.UprobeOptions{
			Address:      p.Location,
			RefCtrOffset: p.SemaphoreOffset,
		}
		if cookies != nil && i < len(cookies) {
			opts.Cookie = cookies[i]
		}
		l, err := exe.Uprobe(p.Name, progs[i], opts)
		if err != nil {
			// Clean up already-attached links.
			for _, lnk := range links {
				lnk.Close()
			}
			return nil, fmt.Errorf("attach probe %s at 0x%x: %w", p.Name, p.Location, err)
		}
		links = append(links, l)
	}
	return &ProbeLinks{Links: links, SpecMap: specMap}, nil
}
