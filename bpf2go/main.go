package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel bpf ebpf/main.c -- -I ./ebpf/bpf -I ./ebpf/coreheaders

func trigger() error {
	fmt.Println("Generating events to trigger the probes ...")
	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	fmt.Printf("creating %v\n", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Sleep a bit to give time to the perf event
	time.Sleep(500 * time.Millisecond)

	// Removing a tmp directory to trigger the probes
	fmt.Printf("removing %s\n", tmpDir)
	err = os.RemoveAll(tmpDir)
	if err != nil {
		return err
	}

	// Sleep a bit to give time to the perf event
	time.Sleep(500 * time.Millisecond)
	return nil
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Println("loading objects: %s", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("vfs_mkdir", objs.bpfPrograms.KprobeVfsMkdir, nil)
	if err != nil {
		fmt.Println("opening Kprobe: %s", err)
	}
	defer kp.Close()

	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	trigger()
	fmt.Println("exiting program..")
}
