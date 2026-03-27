// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"encoding/binary"
	"testing"
)

// buildStapsdtNote constructs a minimal .note.stapsdt entry for testing.
func buildStapsdtNote(location, base, semaphore uint64, provider, name, args string) []byte {
	owner := "stapsdt\x00"
	// Build the descriptor: 3 uint64 + null-terminated strings
	desc := make([]byte, 24)
	binary.LittleEndian.PutUint64(desc[0:8], location)
	binary.LittleEndian.PutUint64(desc[8:16], base)
	binary.LittleEndian.PutUint64(desc[16:24], semaphore)
	desc = append(desc, []byte(provider+"\x00"+name+"\x00"+args+"\x00")...)

	// Note header
	namesz := uint32(len(owner))
	descsz := uint32(len(desc))
	noteType := uint32(3) // NT_STAPSDT

	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint32(hdr[0:4], namesz)
	binary.LittleEndian.PutUint32(hdr[4:8], descsz)
	binary.LittleEndian.PutUint32(hdr[8:12], noteType)

	note := append(hdr, []byte(owner)...)
	// Align name to 4 bytes (owner is 8 bytes, already aligned)
	note = append(note, desc...)
	// Align desc to 4 bytes
	for len(note)%4 != 0 {
		note = append(note, 0)
	}
	return note
}

type mockELFReader struct {
	sections []ELFSection
	loadSegs []ELFProg
}

func (m *mockELFReader) Sections() ([]ELFSection, error) {
	return m.sections, nil
}

func (m *mockELFReader) LoadSegments() []ELFProg {
	return m.loadSegs
}

func TestParseProbes_Basic(t *testing.T) {
	// Build a .note.stapsdt section with one probe
	noteData := buildStapsdtNote(
		0x401000, // location (vaddr)
		0x400000, // base
		0,        // no semaphore
		"myprov",
		"myprobe",
		"-4@%esi 8@%rdi",
	)

	reader := &mockELFReader{
		sections: []ELFSection{
			{Name: ".note.stapsdt", Data: noteData},
		},
		loadSegs: []ELFProg{
			{Vaddr: 0x400000, Memsz: 0x10000, Off: 0x0},
		},
	}

	probes, err := ParseProbes(reader)
	if err != nil {
		t.Fatalf("ParseProbes() error = %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("got %d probes, want 1", len(probes))
	}

	p := probes[0]
	if p.Provider != "myprov" {
		t.Errorf("Provider = %q, want %q", p.Provider, "myprov")
	}
	if p.Name != "myprobe" {
		t.Errorf("Name = %q, want %q", p.Name, "myprobe")
	}
	if p.Arguments != "-4@%esi 8@%rdi" {
		t.Errorf("Arguments = %q, want %q", p.Arguments, "-4@%esi 8@%rdi")
	}
	// Location should be file offset: 0x401000 - 0x400000 + 0x0 = 0x1000
	if p.Location != 0x1000 {
		t.Errorf("Location = 0x%x, want 0x1000", p.Location)
	}
}

func TestParseProbes_NoProbes(t *testing.T) {
	reader := &mockELFReader{
		sections: []ELFSection{
			{Name: ".text"},
		},
	}

	probes, err := ParseProbes(reader)
	if err != nil {
		t.Fatalf("ParseProbes() error = %v", err)
	}
	if probes != nil {
		t.Errorf("got %d probes, want nil", len(probes))
	}
}

func TestParseProbes_PrelinkAdjust(t *testing.T) {
	noteData := buildStapsdtNote(
		0x201000, // location (original vaddr)
		0x200000, // noteBase
		0,
		"prov",
		"probe",
		"",
	)

	reader := &mockELFReader{
		sections: []ELFSection{
			{Name: ".note.stapsdt", Data: noteData},
			{Name: ".stapsdt.base", Addr: 0x400000}, // relocated base
		},
		loadSegs: []ELFProg{
			{Vaddr: 0x400000, Memsz: 0x10000, Off: 0x1000},
		},
	}

	probes, err := ParseProbes(reader)
	if err != nil {
		t.Fatalf("ParseProbes() error = %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("got %d probes, want 1", len(probes))
	}

	// After prelink: location = 0x201000 + (0x400000 - 0x200000) = 0x401000
	// File offset = 0x401000 - 0x400000 + 0x1000 = 0x2000
	if probes[0].Location != 0x2000 {
		t.Errorf("Location = 0x%x, want 0x2000", probes[0].Location)
	}
}
