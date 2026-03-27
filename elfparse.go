// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "github.com/parca-dev/usdt"

import (
	"encoding/binary"
	"strings"
)

// ELFSection represents a minimal ELF section header with its data.
type ELFSection struct {
	Name string
	Addr uint64
	Data []byte
}

// ELFProg represents a minimal ELF program header (PT_LOAD segment).
type ELFProg struct {
	Vaddr uint64
	Memsz uint64
	Off   uint64
}

// ELFReader is the interface that USDT probe parsing requires from an ELF file.
// Implementers provide section and program header data; the usdt package handles
// the .note.stapsdt parsing logic.
type ELFReader interface {
	// Sections returns all ELF section headers with their data.
	// Only .note.stapsdt and .stapsdt.base sections need to have Data populated;
	// other sections may have nil Data.
	Sections() ([]ELFSection, error)

	// LoadSegments returns all PT_LOAD program headers.
	LoadSegments() []ELFProg
}

// findLoadSegment finds the PT_LOAD segment containing the given virtual address.
func findLoadSegment(segs []ELFProg, addr uint64) *ELFProg {
	for i := range segs {
		if addr >= segs[i].Vaddr && addr < segs[i].Vaddr+segs[i].Memsz {
			return &segs[i]
		}
	}
	return nil
}

// ParseProbes reads USDT probe information from an ELF file via the ELFReader
// interface. It parses .note.stapsdt sections, applies prelink adjustments,
// and converts virtual addresses to file offsets suitable for uprobe attachment.
func ParseProbes(r ELFReader) ([]Probe, error) {
	sections, err := r.Sections()
	if err != nil {
		return nil, err
	}

	// Find .note.stapsdt section
	var stapsdtData []byte
	var baseAddr uint64
	for i := range sections {
		switch sections[i].Name {
		case ".note.stapsdt":
			stapsdtData = sections[i].Data
		case ".stapsdt.base":
			baseAddr = sections[i].Addr
		}
	}

	if stapsdtData == nil {
		return nil, nil // No USDT probes in this binary
	}

	loadSegs := r.LoadSegments()

	var probes []Probe

	// Parse note entries
	offset := 0
	for offset < len(stapsdtData) {
		if offset+12 > len(stapsdtData) {
			break
		}

		// Note header: namesz(4) + descsz(4) + type(4)
		namesz := binary.LittleEndian.Uint32(stapsdtData[offset : offset+4])
		descsz := binary.LittleEndian.Uint32(stapsdtData[offset+4 : offset+8])
		noteType := binary.LittleEndian.Uint32(stapsdtData[offset+8 : offset+12])
		offset += 12

		if noteType != 3 { // NT_STAPSDT
			// Skip this note
			nameEnd := offset + int((namesz+3)&^3) // align to 4 bytes
			descEnd := nameEnd + int((descsz+3)&^3)
			offset = descEnd
			continue
		}

		// Skip owner name (should be "stapsdt")
		nameEnd := offset + int((namesz+3)&^3)

		if nameEnd+int(descsz) > len(stapsdtData) {
			break
		}

		// Parse descriptor
		desc := stapsdtData[nameEnd : nameEnd+int(descsz)]
		if len(desc) < 24 { // 3 uint64 values
			offset = nameEnd + int((descsz+3)&^3)
			continue
		}

		location := binary.LittleEndian.Uint64(desc[0:8])
		noteBase := binary.LittleEndian.Uint64(desc[8:16])
		semaphore := binary.LittleEndian.Uint64(desc[16:24])

		// Apply prelink adjustment if .stapsdt.base section exists
		// See: https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
		if baseAddr != 0 && noteBase != 0 {
			diff := baseAddr - noteBase
			location += diff
			if semaphore != 0 {
				semaphore += diff
			}
		}

		// Convert virtual address to file offset for uprobe attachment
		prog := findLoadSegment(loadSegs, location)
		if prog != nil {
			location = location - prog.Vaddr + prog.Off
		}

		// Convert semaphore virtual address to file offset
		var semaphoreFileOffset uint64
		if semaphore != 0 {
			semaProg := findLoadSegment(loadSegs, semaphore)
			if semaProg != nil {
				semaphoreFileOffset = semaphore - semaProg.Vaddr + semaProg.Off
			}
		}

		// Parse strings: provider\0probe\0arguments\0
		stringData := desc[24:]
		parts := strings.Split(string(stringData), "\x00")
		if len(parts) >= 3 {
			probe := Probe{
				Provider:        parts[0],
				Name:            parts[1],
				Location:        location,
				Base:            noteBase,
				SemaphoreOffset: semaphoreFileOffset,
				Arguments:       parts[2],
			}
			probes = append(probes, probe)
		}

		offset = nameEnd + int((descsz+3)&^3)
	}

	return probes, nil
}
