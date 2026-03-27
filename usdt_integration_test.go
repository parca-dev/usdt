// Copyright The Parca Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package usdt

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	usdttest "github.com/parca-dev/usdt/test"
)

// TestUSDTProbeLifecycleSingle is a full end-to-end test:
// parse probes from self, load BPF, populate spec map, attach individual
// programs, fire probes, verify results via BPF map.
func TestUSDTProbeLifecycleSingle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}

	setup := newIntegrationSetup(t)
	defer setup.close()

	// Attach each probe with its own dedicated BPF program.
	progs := make([]*ebpf.Program, len(setup.probes))
	for i, p := range setup.probes {
		prog := setup.progByName(t, p.Name)
		if prog == nil {
			t.Fatalf("no BPF program for probe %s", p.Name)
		}
		progs[i] = prog
	}

	// Cookies carry the probe_id (1-8) that the BPF programs use to key
	// into the results map.  Spec IDs go in the high 32 bits.
	userCookies := make([]uint64, len(setup.probes))
	for i := range userCookies {
		userCookies[i] = uint64(i + 1)
	}
	cookies := MergeCookies(setup.specIDs, userCookies)

	pl, err := AttachUprobes(setup.exe, setup.objs.BpfUsdtSpecs, setup.probes, progs, cookies)
	if err != nil {
		t.Fatalf("AttachUprobes: %v", err)
	}
	defer pl.Close()

	setup.fireAndVerify(t)
}

// TestUSDTProbeLifecycleMulti tests multi-probe attachment where a single
// dispatcher program handles all probes, using the cookie for dispatch.
func TestUSDTProbeLifecycleMulti(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load BPF programs")
	}

	setup := newIntegrationSetup(t)
	defer setup.close()

	// All probes share the multi-probe dispatcher program.
	progs := make([]*ebpf.Program, len(setup.probes))
	for i := range progs {
		progs[i] = setup.objs.UsdtTestMulti
	}

	userCookies := make([]uint64, len(setup.probes))
	for i := range userCookies {
		userCookies[i] = uint64(i + 1)
	}
	cookies := MergeCookies(setup.specIDs, userCookies)

	pl, err := AttachUprobes(setup.exe, setup.objs.BpfUsdtSpecs, setup.probes, progs, cookies)
	if err != nil {
		t.Fatalf("AttachUprobes: %v", err)
	}
	defer pl.Close()

	setup.fireAndVerify(t)
}

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

type integrationSetup struct {
	objs    bpfUsdtObjects
	exe     *link.Executable
	probes  []Probe
	specIDs []uint32
}

func newIntegrationSetup(t *testing.T) *integrationSetup {
	t.Helper()

	// Ensure probes are compiled into the binary.
	usdttest.CallTestProbes()

	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	allProbes, err := ParseProbesFromFile(exePath)
	if err != nil {
		t.Fatalf("ParseProbesFromFile: %v", err)
	}

	// Keep only testprov probes, in the order the BPF test programs expect.
	probeOrder := []string{
		"simple_probe", "memory_probe", "const_probe", "mixed_probe",
		"int32_args", "int64_args", "mixed_refs", "uint8_args",
	}
	byName := make(map[string]Probe, len(allProbes))
	for _, p := range allProbes {
		if p.Provider == "testprov" {
			byName[p.Name] = p
		}
	}
	var probes []Probe
	for _, name := range probeOrder {
		p, ok := byName[name]
		if !ok {
			t.Fatalf("probe %q not found in binary", name)
		}
		probes = append(probes, p)
		t.Logf("probe %s: location=0x%x args=%q", p.Name, p.Location, p.Arguments)
	}

	// Load BPF objects.
	var objs bpfUsdtObjects
	if err := loadBpfUsdtObjects(&objs, nil); err != nil {
		t.Fatalf("loadBpfUsdtObjects: %v", err)
	}

	// Populate the spec map with argument metadata.
	specIDs, err := PopulateSpecMap(objs.BpfUsdtSpecs, probes, 1)
	if err != nil {
		objs.Close()
		t.Fatalf("PopulateSpecMap: %v", err)
	}

	exe, err := link.OpenExecutable(exePath)
	if err != nil {
		objs.Close()
		t.Fatalf("OpenExecutable: %v", err)
	}

	return &integrationSetup{
		objs:    objs,
		exe:     exe,
		probes:  probes,
		specIDs: specIDs,
	}
}

func (s *integrationSetup) close() {
	s.objs.Close()
}

func (s *integrationSetup) progByName(t *testing.T, name string) *ebpf.Program {
	t.Helper()
	switch name {
	case "simple_probe":
		return s.objs.SimpleProbe
	case "memory_probe":
		return s.objs.MemoryProbe
	case "const_probe":
		return s.objs.ConstProbe
	case "mixed_probe":
		return s.objs.MixedProbe
	case "int32_args":
		return s.objs.Int32Args
	case "int64_args":
		return s.objs.Int64Args
	case "mixed_refs":
		return s.objs.MixedRefs
	case "uint8_args":
		return s.objs.Uint8Args
	default:
		return nil
	}
}

func (s *integrationSetup) fireAndVerify(t *testing.T) {
	t.Helper()

	// Fire probes several times.
	for range 10 {
		usdttest.CallTestProbes()
		time.Sleep(10 * time.Millisecond)
	}

	passed, failed := 0, 0
	for i, p := range s.probes {
		probeID := uint32(i + 1)
		var val uint64
		if err := s.objs.UsdtTestResults.Lookup(&probeID, &val); err != nil {
			t.Logf("probe %s (id=%d): no result (may not have fired)", p.Name, probeID)
			continue
		}
		if val == 1 {
			t.Logf("probe %s: PASS", p.Name)
			passed++
		} else {
			t.Errorf("probe %s: FAIL (arguments did not match)", p.Name)
			failed++
		}
	}
	t.Logf("%d passed, %d failed out of %d probes", passed, failed, len(s.probes))
	if passed == 0 {
		t.Fatal("no probes fired")
	}
}
