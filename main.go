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
	Protocol  string `json:"protocol"`  // "icmp", "tcp", "udp", "all"
	Direction string `json:"direction"` // "src" или "dst"
}

type RuleKey struct {
	IP        uint32 `ebpf:"ip"`
	Proto     uint8  `ebpf:"proto"`
	Direction uint8  `ebpf:"direction"`
	Pad       uint16 `ebpf:"pad"`
}

var (
	coll         *ebpf.Collection
	blockedRules *ebpf.Map
	currentLinks map[string]link.Link
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

	blockedRules = coll.Maps["blocked_rules"]
	if blockedRules == nil {
		log.Fatal("blocked_rules map not found in BPF program")
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
	protocol := r.FormValue("protocol")
	direction := r.FormValue("direction")

	if ifaceName == "" || ipToBlock == "" || protocol == "" || direction == "" {
		http.Error(w, "interface, ip, protocol and direction parameters are required", http.StatusBadRequest)
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

	protoNum, err := protocolToNumber(protocol)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var ipBytes [4]byte
	copy(ipBytes[:], ip)
	ipValue := binary.BigEndian.Uint32(ipBytes[:])

	var dirNum uint8
	if direction == "src" {
		dirNum = 0
	} else {
		dirNum = 1
	}

	key := RuleKey{
		IP:        ipValue,
		Proto:     protoNum,
		Direction: dirNum,
		Pad:       0,
	}

	if err := blockedRules.Put(key, uint8(1)); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update map: %v", err), http.StatusInternalServerError)
		return
	}

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

	fmt.Fprintf(w, "Successfully blocked %s %s traffic for IP: %s on interface %s\n",
		direction, protocol, ip, ifaceName)
}

func handleUnblockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ipToUnblock := r.FormValue("ip")
	protocol := r.FormValue("protocol")
	direction := r.FormValue("direction")

	if ipToUnblock == "" || protocol == "" || direction == "" {
		http.Error(w, "ip, protocol and direction parameters are required", http.StatusBadRequest)
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

	protoNum, err := protocolToNumber(protocol)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var ipBytes [4]byte
	copy(ipBytes[:], ip)
	ipValue := binary.BigEndian.Uint32(ipBytes[:])

	var dirNum uint8
	if direction == "src" {
		dirNum = 0
	} else {
		dirNum = 1
	}

	key := RuleKey{
		IP:        ipValue,
		Proto:     protoNum,
		Direction: dirNum,
		Pad:       0,
	}

	if err := blockedRules.Delete(key); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock IP: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully unblocked %s %s traffic for IP: %s\n",
		direction, protocol, ip)
}

func handleListRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprintln(w, "Blocked rules:")
	var key RuleKey
	var value uint8
	iter := blockedRules.Iterate()
	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key.IP)
		protoName := numberToProtocol(key.Proto)
		dirName := "src"
		if key.Direction == 1 {
			dirName = "dst"
		}
		fmt.Fprintf(w, "- IP: %s, Protocol: %s, Direction: %s\n", ip, protoName, dirName)
	}
}

func protocolToNumber(protocol string) (uint8, error) {
	switch protocol {
	case "icmp":
		return 1, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "all":
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid protocol, must be icmp, tcp, udp or all")
	}
}

func numberToProtocol(num uint8) string {
	switch num {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 0:
		return "all"
	default:
		return fmt.Sprintf("%d", num)
	}
}
