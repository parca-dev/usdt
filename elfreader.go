// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "github.com/parca-dev/usdt"

import (
	"debug/elf"
	"io"
	"os"
)

// StdlibELFReader implements ELFReader using Go's debug/elf package.
type StdlibELFReader struct {
	f      *elf.File
	closer io.Closer // non-nil when opened from a path
}

// NewStdlibELFReader creates an ELFReader from an io.ReaderAt.
func NewStdlibELFReader(r io.ReaderAt) (*StdlibELFReader, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &StdlibELFReader{f: f}, nil
}

// OpenELF opens an ELF file by path and returns a StdlibELFReader.
// The caller must call Close() when done.
func OpenELF(path string) (*StdlibELFReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	f, err := elf.NewFile(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	return &StdlibELFReader{f: f, closer: file}, nil
}

// Sections returns all ELF section headers with their data.
func (r *StdlibELFReader) Sections() ([]ELFSection, error) {
	sections := make([]ELFSection, 0, len(r.f.Sections))
	for _, s := range r.f.Sections {
		sec := ELFSection{
			Name: s.Name,
			Addr: s.Addr,
		}
		// Only read data for the sections we actually need
		if s.Name == ".note.stapsdt" || s.Name == ".stapsdt.base" {
			data, err := io.ReadAll(s.Open())
			if err != nil {
				return nil, err
			}
			sec.Data = data
		}
		sections = append(sections, sec)
	}
	return sections, nil
}

// LoadSegments returns all PT_LOAD program headers.
func (r *StdlibELFReader) LoadSegments() []ELFProg {
	var segs []ELFProg
	for _, p := range r.f.Progs {
		if p.Type == elf.PT_LOAD {
			segs = append(segs, ELFProg{
				Vaddr: p.Vaddr,
				Memsz: p.Memsz,
				Off:   p.Off,
			})
		}
	}
	return segs
}

// Close closes the underlying file.
func (r *StdlibELFReader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// ParseProbesFromFile is a convenience function that opens an ELF file,
// parses its USDT probes, and closes it.
func ParseProbesFromFile(path string) ([]Probe, error) {
	r, err := OpenELF(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ParseProbes(r)
}
