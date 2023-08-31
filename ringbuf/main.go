package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	manager "github.com/gojue/ebpfmanager"
	"os"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

// trigger - Creates and then removes a tmp folder to trigger the probes
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
	m := &manager.Manager{
		Probes: []*manager.Probe{
			&manager.Probe{
				UID:              "MyFirstHook",
				Section:          "kprobe/vfs_mkdir",
				AttachToFuncName: "vfs_mkdir",
				EbpfFuncName:     "kprobe_vfs_mkdir",
			},
		},
		RingbufMaps: []*manager.RingbufMap{
			&manager.RingbufMap{
				Map: manager.Map{
					Name: "events",
				},
				RingbufMapOptions: manager.RingbufMapOptions{
					DataHandler: myDataHandler,
				},
			},
		},
	}

	err := m.Init(bytes.NewReader(_bytecode))
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := m.Start(); err != nil {
		fmt.Println(err)
	}
	fmt.Println("successfully started, head over to /sys/kernel/debug/tracing/trace_pipe")

	// Create a folder to trigger the probes
	if err := trigger(); err != nil {
		fmt.Println(err)
	}

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		fmt.Println(err)
	}
}

func myDataHandler(cpu int, data []byte, ringbufmap *manager.RingbufMap, manager *manager.Manager) {
	pid := binary.LittleEndian.Uint32(data[0:4])
	comm := string(data[4:])
	fmt.Printf("received: pid:%d,comm:%s\n", pid, comm)
}
