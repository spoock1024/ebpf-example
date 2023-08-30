all: build-ebpf build

.PHONY: build-ebpf
build-ebpf:
	export BPF_CLANG=clang; \
	export BPF_CFLAGS="-O2 -g -Wall -Werror"; \
	go generate ./...



build:
	go build -o bin/main .



run:
	sudo bin/main
