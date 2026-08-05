default: all

.PHONY: all build generate test clean lint fmt

generate:
	GOARCH=amd64 go generate ./...
	GOARCH=arm64 go generate ./...

build:
	go build -o bin/usdt ./cmd/usdt

test:
	go test -v ./...

all: generate test

lint:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -f bin/usdt
	rm -f internal/testbpf/bpfusdt_*.go internal/testbpf/bpfusdt_*.o
	rm -f _obj/ ebpf/*.o ebpf/*.ebpf.amd64 ebpf/*.ebpf.arm64
