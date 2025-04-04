package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Загрузка eBPF программы
	spec, err := ebpf.LoadCollectionSpec("xdp_block.o")
	if err != nil {
		panic(fmt.Sprintf("Failed to load spec: %v", err))
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create collection: %v", err))
	}
	defer coll.Close()

	// Получаем карту для блокировки IP
	blockedIPs := coll.Maps["blocked_ips"]
	if blockedIPs == nil {
		panic("blocked_ips map not found")
	}

	// Записываем IP для блокировки
	ipToBlock := net.ParseIP("1.1.1.1").To4()
	if ipToBlock == nil {
		panic("invalid IP address")
	}

	// Конвертируем IP в be32 (network byte order)
	var ipBytes [4]byte
	copy(ipBytes[:], ipToBlock)
	ipValue := binary.BigEndian.Uint32(ipBytes[:])

	key := uint32(0)
	if err := blockedIPs.Put(key, ipValue); err != nil {
		panic(fmt.Sprintf("Failed to update map: %v", err))
	}

	// Прикрепляем XDP программу
	ifaceName := "wlp3s0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(fmt.Sprintf("Interface %s not found: %v", ifaceName, err))
	}

	opts := link.XDPOptions{
		Program:   coll.Programs["xdp_block_ip"],
		Interface: iface.Index,
	}

	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(fmt.Sprintf("Failed to attach XDP: %v", err))
	}
	defer lnk.Close()

	fmt.Printf("Blocking traffic for IP: %s on interface %s\n", 
		ipToBlock.String(), ifaceName)

	// Ожидание сигнала
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
