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
	Direction string `json:"direction"` // "src" или "dst"
}

var (
	coll         *ebpf.Collection
	blockedSrc   *ebpf.Map
	blockedDst   *ebpf.Map
	currentLinks map[string]link.Link // Храним ссылки для каждого интерфейса
)

func main() {
	currentLinks = make(map[string]link.Link)

	spec, err := ebpf.LoadCollectionSpec("bpf/xdp_block.o")
	if err != nil {
		log.Fatalf("Failed to load spec: %v", err)
	}

	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	blockedSrc = coll.Maps["blocked_src"]
	blockedDst = coll.Maps["blocked_dst"]
	if blockedSrc == nil || blockedDst == nil {
		log.Fatal("Required maps not found in BPF program")
	}

	http.HandleFunc("/block", handleBlockRequest)
	http.HandleFunc("/unblock", handleUnblockRequest)
	http.HandleFunc("/list", handleListRequest)

	go func() {
		log.Println("Starting server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	for _, lnk := range currentLinks {
		lnk.Close()
	}
}

func handleBlockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ifaceName := r.FormValue("interface")
	ipToBlock := r.FormValue("ip")
	direction := r.FormValue("direction")

	if ifaceName == "" || ipToBlock == "" || direction == "" {
		http.Error(w, "interface, ip and direction parameters are required", http.StatusBadRequest)
		return
	}

	if direction != "src" && direction != "dst" {
		http.Error(w, "direction must be either 'src' or 'dst'", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(ipToBlock).To4()
	if ip == nil {
		http.Error(w, "Invalid IPv4 address", http.StatusBadRequest)
		return
	}

	var ipBytes [4]byte
	copy(ipBytes[:], ip)
	ipValue := binary.BigEndian.Uint32(ipBytes[:])

	// Выбираем карту в зависимости от направления
	var targetMap *ebpf.Map
	if direction == "src" {
		targetMap = blockedSrc
	} else {
		targetMap = blockedDst
	}

	// Добавляем IP в соответствующую карту
	if err := targetMap.Put(ipValue, uint8(1)); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update map: %v", err), http.StatusInternalServerError)
		return
	}

	// Прикрепляем XDP программу, если еще не сделано
	if _, exists := currentLinks[ifaceName]; !exists {
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
		currentLinks[ifaceName] = lnk
	}

	fmt.Fprintf(w, "Successfully blocked %s traffic for IP: %s on interface %s\n", direction, ip, ifaceName)
}

func handleUnblockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipToUnblock := r.FormValue("ip")
	direction := r.FormValue("direction")

	if ipToUnblock == "" || direction == "" {
		http.Error(w, "ip and direction parameters are required", http.StatusBadRequest)
		return
	}

	if direction != "src" && direction != "dst" {
		http.Error(w, "direction must be either 'src' or 'dst'", http.StatusBadRequest)
		return
	}

	ip := net.ParseIP(ipToUnblock).To4()
	if ip == nil {
		http.Error(w, "Invalid IPv4 address", http.StatusBadRequest)
		return
	}

	var ipBytes [4]byte
	copy(ipBytes[:], ip)
	ipValue := binary.BigEndian.Uint32(ipBytes[:])

	var targetMap *ebpf.Map
	if direction == "src" {
		targetMap = blockedSrc
	} else {
		targetMap = blockedDst
	}

	if err := targetMap.Delete(ipValue); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock IP: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully unblocked %s traffic for IP: %s\n", direction, ip)
}

func handleListRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprintln(w, "Blocked source IPs (outgoing traffic):")
	iter := blockedSrc.Iterate()
	var key uint32
	var value uint8
	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		fmt.Fprintf(w, "- %s\n", ip)
	}

	fmt.Fprintln(w, "\nBlocked destination IPs (incoming traffic):")
	iter = blockedDst.Iterate()
	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		fmt.Fprintf(w, "- %s\n", ip)
	}
}
