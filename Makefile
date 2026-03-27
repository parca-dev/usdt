default: all

.PHONY: all generate test clean lint fmt

generate:
	GOARCH=amd64 go generate ./...
	GOARCH=arm64 go generate ./...

test:
	go test -v ./...

all: generate test

lint:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -f bpfusdt_*.go bpfusdt_*.o _obj/ ebpf/*.o ebpf/*.ebpf.amd64 ebpf/*.ebpf.arm64
