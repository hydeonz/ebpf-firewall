package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BlockRequest struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
}

var (
	coll        *ebpf.Collection
	blockedIPs  *ebpf.Map
	currentLink link.Link
)

func main() {
	spec, err := ebpf.LoadCollectionSpec("bpf/xdp_block.o")
	if err != nil {
		log.Fatalf("Failed to load spec: %v", err)
	}

	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	blockedIPs = coll.Maps["blocked_ips"]
	if blockedIPs == nil {
		log.Fatal("blocked_ips map not found")
	}

	http.HandleFunc("/block", handleBlockRequest)
	http.HandleFunc("/unblock", handleUnblockRequest)

	go func() {
		log.Println("Starting server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	if currentLink != nil {
		currentLink.Close()
	}
}

func handleBlockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ifaceName := r.FormValue("interface")
	ipToBlock := r.FormValue("ip")

	if ifaceName == "" || ipToBlock == "" {
		http.Error(w, "Both interface and ip parameters are required", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(ipToBlock).To4()
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	var ipBytes [4]byte
	copy(ipBytes[:], ip)
	ipValue := binary.BigEndian.Uint32(ipBytes[:])

	key := uint32(0)
	if err := blockedIPs.Put(key, ipValue); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update map: %v", err), http.StatusInternalServerError)
		return
	}

	if currentLink != nil {
		currentLink.Close()
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Interface %s not found: %v", ifaceName, err), http.StatusBadRequest)
		return
	}

	opts := link.XDPOptions{
		Program:   coll.Programs["xdp_block_ip"],
		Interface: iface.Index,
	}

	lnk, err := link.AttachXDP(opts)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to attach XDP: %v", err), http.StatusInternalServerError)
		return
	}
	currentLink = lnk

	fmt.Fprintf(w, "Successfully blocking traffic for IP: %s on interface %s\n", ip, ifaceName)
}

func handleUnblockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if currentLink != nil {
		currentLink.Close()
		currentLink = nil
	}

	key := uint32(0)
	if err := blockedIPs.Delete(key); err != nil && !os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("Failed to clear blocked IP: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully unblocked all traffic and detached XDP program\n")
}
