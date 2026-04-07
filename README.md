# usdt - USDT Probe Support for Go and eBPF

A standalone Go library for working with [User Statically-Defined Tracepoints (USDTs)](https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation).
Parse USDT probes from ELF binaries, extract argument specifications, and attach eBPF programs to probes at runtime.

## Features

- **ELF probe parsing**: Read `.note.stapsdt` sections, apply prelink adjustments, convert virtual addresses to file offsets for uprobe attachment
- **Argument spec parsing**: Decode USDT argument specifications (registers, memory dereferences, constants) for x86_64 and ARM64
- **eBPF headers**: BPF-side helpers for extracting USDT arguments at runtime (`BPF_USDT()` macro, `bpf_usdt_arg()`)
- **bpf2go integration**: Pre-compiled eBPF objects with generated Go bindings via `go generate`
- **Pluggable ELF reader**: Interface-based design lets you use `debug/elf` (included) or bring your own optimized reader

## Installation

```bash
go get github.com/parca-dev/usdt
```

## Usage

### Parse USDT probes from a binary

```go
probes, err := usdt.ParseProbesFromFile("/usr/lib/libc.so.6")
if err != nil {
    log.Fatal(err)
}
for _, p := range probes {
    fmt.Printf("%s:%s at offset 0x%x args=%q\n",
        p.Provider, p.Name, p.Location, p.Arguments)
}
```

### Parse argument specifications

```go
// Parse a USDT argument string like "-4@%esi 8@%rdi"
spec, err := usdt.ParseUSDTArguments("-4@%esi 8@%rdi")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("%d arguments\n", spec.Arg_cnt)
```

### Custom ELF reader

Implement the `ELFReader` interface to use your own ELF parser:

```go
type ELFReader interface {
    Sections() ([]usdt.ELFSection, error)
    LoadSegments() []usdt.ELFProg
}

probes, err := usdt.ParseProbes(myCustomReader)
```

### eBPF headers

Include in your BPF programs for USDT argument extraction. The headers
intentionally pull in nothing — your own prelude (providing `u8`/`u64`/
`bool`/`pt_regs`/`EBPF_INLINE` and the BPF helper declarations) must be
included first. The bundled `ebpf/kernel.h` is one such prelude:

```c
#include "kernel.h"     // or your own equivalent
#include "usdt_args.h"

SEC("usdt/myprovider/myprobe")
int BPF_USDT(myprobe, s64 arg0, u64 arg1)
{
    // arg0 and arg1 are automatically extracted
    return 0;
}
```

`usdt_defs.h` (struct/enum definitions only) can be included on its own
when you just need the userspace-visible layouts without the BPF helpers.

## Building

```bash
# Generate eBPF objects and run tests
make

# Regenerate after modifying BPF sources
make generate

# Run tests only
make test
```

### Requirements

- Go 1.25+
- clang (for `go generate` / bpf2go BPF compilation)
- `systemtap-sdt-dev` (for test probes, provides `sys/sdt.h`)
- Requires Linux 5.15+ for bpf_get_attach_cookie

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
