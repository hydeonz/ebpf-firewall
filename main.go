package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	TYPE_ENTER = 1
	TYPE_DROP  = 2
	TYPE_PASS  = 3
)

func main() {
	spec, err := ebpf.LoadCollectionSpec("xdp_block.o")
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	defer coll.Close()

	// Записываем индекс интерфейса в карту
	ifaceName := "wlp3s0" // Укажите нужный интерфейс
	targetIface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(fmt.Sprintf("Interface %s not found: %v", ifaceName, err))
	}

	blockedMap := coll.Maps["blocked_iface_map"]
	key := uint32(0)
	value := uint32(targetIface.Index)
	if err := blockedMap.Put(key, value); err != nil {
		panic(fmt.Sprintf("Failed to update map: %v", err))
	}

	// Прикрепляем XDP программу
	opts := link.XDPOptions{
		Program:   coll.Programs["xdp_dilih"],
		Interface: targetIface.Index,
	}
	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(err)
	}
	defer lnk.Close()

	fmt.Printf("Blocking all traffic on interface %s (index %d)\n", 
		targetIface.Name, targetIface.Index)

	// Ожидание сигнала
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
