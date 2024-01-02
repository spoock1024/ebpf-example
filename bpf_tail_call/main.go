package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed ebpf/bin/probe.o
var _bytecode []byte

func main() {
	specs, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_bytecode))
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(specs)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	defer coll.Close()

	// Load XDP programs from the collection
	icmpProg := coll.Programs["handle_icmp"]
	tcpProg := coll.Programs["handle_tcp"]
	udpProg := coll.Programs["handle_udp"]
	//
	// Get the packet_processing_progs map
	packetProgsMap := coll.Maps["packet_processing_progs"]

	// Update map entries with the program file descriptors
	keysAndProgs := map[uint32]*ebpf.Program{
		0: icmpProg,
		1: tcpProg,
		2: udpProg,
	}

	for key, prog := range keysAndProgs {
		if prog == nil {
			log.Fatalf("program with key %d not found", key)
		}
		fmt.Println(fmt.Sprintf("key: %d, prog: %v", key, prog))
		if err := packetProgsMap.Update(key, uint32(prog.FD()), ebpf.UpdateAny); err != nil {
			log.Fatalf("updating packet_processing_progs map: %v", err)
		}
	}

	// Attach the XDP program to the interface
	xdpProg := coll.Programs["packet_classifier"]
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: 2,
	})
	if err != nil {
		log.Fatalf("attaching xdp: %v", err)
	}
	defer xdpLink.Close()

	log.Println("eBPF program successfully attached. Press CTRL+C to stop.")

	// Wait for an interrupt or a timeout
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		// Interrupt signal received, close the collection
		coll.Close()
		log.Println("Detaching program and closing link")
	case <-time.After(10 * time.Minute):
		// Timeout after 10 minutes, close the collection
		coll.Close()
	}

}
