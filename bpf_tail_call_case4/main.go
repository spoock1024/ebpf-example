package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
	"os"
	"os/signal"
	"syscall"
)

//go:embed ebpf/bin/probe.o
var bytecode []byte

func main() {
	// 加载 eBPF 程序的集合
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bytecode))
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading collection spec: %s\n", err)
		os.Exit(1)
	}

	// 根据集合规范创建集合实例
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating collection: %s\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	// 从集合中获取 XDP 程序
	xdpProg, found := coll.Programs["packet_classifier"]
	if !found {
		fmt.Fprintf(os.Stderr, "program packet_classifier not found\n")
		os.Exit(1)
	}

	// 获取要附加 XDP 程序的网络接口
	iface, err := net.InterfaceByName("eno1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "getting network interface: %s\n", err)
		os.Exit(1)
	}

	// 将 XDP 程序附加到网络接口
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "attaching xdp: %s\n", err)
		os.Exit(1)
	}
	defer xdpLink.Close()

	fmt.Println("XDP program successfully attached, head over to /sys/kernel/debug/tracing/trace_pipe")
	fmt.Println("Press Ctrl+C to exit and detach the program")

	// 等待程序退出（例如，通过信号）
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals

	// 程序退出时，xdpLink 会自动关闭并卸载 XDP 程序
	fmt.Println("Detaching XDP program and exiting")
}
