// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package test

import (
	"os"
	"runtime"
	"testing"

	"github.com/parca-dev/usdt"
)

// TestParseSelfProbes parses USDT probes from the test binary itself.
// The binary has USDT probes embedded via the DTRACE_PROBE macros in
// probes_linux.go. This validates the full pipeline: ELF parsing,
// note section parsing, and argument extraction.
func TestParseSelfProbes(t *testing.T) {
	// Call the probes so the linker doesn't strip them
	CallTestProbes()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	probes, err := usdt.ParseProbesFromFile(exe)
	if err != nil {
		t.Fatalf("ParseProbesFromFile(%s): %v", exe, err)
	}

	if len(probes) == 0 {
		t.Fatal("expected USDT probes in test binary, got 0")
	}

	// Build a map of probe names for lookup
	probeMap := make(map[string]*usdt.Probe, len(probes))
	for i := range probes {
		p := &probes[i]
		if p.Provider == "testprov" {
			probeMap[p.Name] = p
		}
	}

	// Expected probes from probes_linux.go
	expectedProbes := []struct {
		name    string
		minArgs int // minimum expected arguments (0 for const_probe which may vary)
	}{
		{"simple_probe", 3},
		{"memory_probe", 2},
		{"const_probe", 0},
		{"mixed_probe", 4},
		{"int32_args", 3},
		{"int64_args", 2},
		{"mixed_refs", 3},
		{"uint8_args", 2},
	}

	for _, ep := range expectedProbes {
		t.Run(ep.name, func(t *testing.T) {
			p, ok := probeMap[ep.name]
			if !ok {
				t.Fatalf("probe %q not found in binary", ep.name)
			}

			if p.Provider != "testprov" {
				t.Errorf("Provider = %q, want %q", p.Provider, "testprov")
			}

			if p.Location == 0 {
				t.Error("Location is 0, expected a valid file offset")
			}

			t.Logf("  location=0x%x args=%q", p.Location, p.Arguments)

			// Parse the arguments
			if p.Arguments != "" {
				spec, err := usdt.ParseUSDTArguments(p.Arguments)
				if err != nil {
					t.Errorf("ParseUSDTArguments(%q): %v", p.Arguments, err)
					return
				}
				if ep.minArgs > 0 && int(spec.Arg_cnt) < ep.minArgs {
					t.Errorf("Arg_cnt = %d, want >= %d", spec.Arg_cnt, ep.minArgs)
				}
				t.Logf("  parsed %d arguments", spec.Arg_cnt)

				// Validate SpecToBytes produces correct-sized output
				b := usdt.SpecToBytes(spec)
				if len(b) == 0 {
					t.Error("SpecToBytes produced empty output")
				}
			}
		})
	}
}

// TestOpenELF_BadPath verifies error handling for non-existent files.
func TestOpenELF_BadPath(t *testing.T) {
	_, err := usdt.ParseProbesFromFile("/nonexistent/binary")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

// TestParseSelfProbes_Architecture validates architecture-specific argument parsing.
func TestParseSelfProbes_Architecture(t *testing.T) {
	CallTestProbes()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	probes, err := usdt.ParseProbesFromFile(exe)
	if err != nil {
		t.Fatalf("ParseProbesFromFile: %v", err)
	}

	for _, p := range probes {
		if p.Provider != "testprov" || p.Arguments == "" {
			continue
		}

		spec, err := usdt.ParseUSDTArguments(p.Arguments)
		if err != nil {
			t.Errorf("probe %s: ParseUSDTArguments(%q): %v", p.Name, p.Arguments, err)
			continue
		}

		// Verify each parsed argument has valid type and register info
		for i := 0; i < int(spec.Arg_cnt); i++ {
			arg := spec.Args[i]
			switch arg.Arg_type {
			case usdt.ArgConst:
				// Constants should have no register
			case usdt.ArgReg:
				if arg.Reg_id == usdt.RegNone {
					t.Errorf("probe %s arg %d: ArgReg with RegNone", p.Name, i)
				}
			case usdt.ArgRegDeref:
				if arg.Reg_id == usdt.RegNone {
					t.Errorf("probe %s arg %d: ArgRegDeref with RegNone", p.Name, i)
				}
			default:
				t.Errorf("probe %s arg %d: unknown arg_type %d", p.Name, i, arg.Arg_type)
			}

			// Validate bitshift is sensible (0, 24, 32, 48, or 56)
			switch arg.Arg_bitshift {
			case 0, 24, 32, 48, 56:
				// OK
			default:
				t.Errorf("probe %s arg %d: unexpected bitshift %d", p.Name, i, arg.Arg_bitshift)
			}
		}

		t.Logf("probe %s: %d args parsed on %s", p.Name, spec.Arg_cnt, runtime.GOARCH)
	}
}
