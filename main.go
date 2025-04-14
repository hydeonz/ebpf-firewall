package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type BlockRequest struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`  // "icmp", "tcp", "udp", "all"
	Direction string `json:"direction"` // "src" или "dst"
	Port      string `json:"port"`      // номер порта или "any"
}

type RuleKey struct {
	IP        uint32 `json:"ip"`
	Proto     uint8  `json:"proto"`
	Direction uint8  `json:"direction"`
	Port      uint16 `json:"port"` // 0 означает любой порт
}

type SavedRule struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Port      string `json:"port"`
}

var (
	coll         *ebpf.Collection
	blockedRules *ebpf.Map
	currentLinks = make(map[string]link.Link)
	rulesFile    = "rules.json"
	rulesMutex   sync.Mutex
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

	blockedRules = coll.Maps["blocked_rules"]
	if blockedRules == nil {
		log.Fatal("blocked_rules map not found in BPF program")
	}

	rules, err := loadRulesFromFile()
	if err != nil {
		log.Printf("Warning: could not load rules from file: %v", err)
	}

	for _, rule := range rules {
		if err := applyRule(rule); err != nil {
			log.Printf("Failed to apply rule: %v", err)
		}
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

	br := BlockRequest{
		Interface: r.FormValue("interface"),
		IP:        r.FormValue("ip"),
		Protocol:  r.FormValue("protocol"),
		Direction: r.FormValue("direction"),
		Port:      r.FormValue("port"),
	}

	if br.Interface == "" || br.IP == "" || br.Protocol == "" || br.Direction == "" {
		http.Error(w, "interface, ip, protocol and direction parameters are required", http.StatusBadRequest)
		return
	}

	// Если порт не указан, используем "any"
	if br.Port == "" {
		br.Port = "any"
	}

	rule := SavedRule(br)

	if err := applyRule(rule); err != nil {
		http.Error(w, fmt.Sprintf("Failed to apply rule: %v", err), http.StatusInternalServerError)
		return
	}

	if err := saveRulesToFile(); err != nil {
		http.Error(w, fmt.Sprintf("Rule applied but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully blocked %s %s traffic for IP: %s, port: %s on interface %s\n",
		rule.Direction, rule.Protocol, rule.IP, rule.Port, rule.Interface)
}

func handleUnblockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	br := BlockRequest{
		Interface: r.FormValue("interface"),
		IP:        r.FormValue("ip"),
		Protocol:  r.FormValue("protocol"),
		Direction: r.FormValue("direction"),
		Port:      r.FormValue("port"),
	}

	if br.Interface == "" || br.IP == "" || br.Protocol == "" || br.Direction == "" {
		http.Error(w, "interface, ip, protocol and direction parameters are required", http.StatusBadRequest)
		return
	}

	// Если порт не указан, используем "any"
	if br.Port == "" {
		br.Port = "any"
	}

	ip := net.ParseIP(br.IP).To4()
	if ip == nil {
		http.Error(w, "Invalid IPv4 address", http.StatusBadRequest)
		return
	}

	protoNum, err := protocolToNumber(br.Protocol)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	portNum, err := portToNumber(br.Port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dirNum := directionToNumber(br.Direction)
	ipVal := binary.BigEndian.Uint32(ip)

	key := RuleKey{IP: ipVal, Proto: protoNum, Direction: dirNum, Port: portNum}

	if err := blockedRules.Delete(key); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock IP: %v", err), http.StatusInternalServerError)
		return
	}

	rulesMutex.Lock()
	rules, err := loadRulesFromFile()
	if err == nil {
		newRules := make([]SavedRule, 0)
		for _, rule := range rules {
			if rule.IP == br.IP && rule.Protocol == br.Protocol &&
				rule.Direction == br.Direction && rule.Interface == br.Interface &&
				rule.Port == br.Port {
				continue
			}
			newRules = append(newRules, rule)
		}
		writeRulesToFile(newRules)
	}
	rulesMutex.Unlock()

	fmt.Fprintf(w, "Successfully unblocked %s %s traffic for IP: %s, port: %s\n",
		br.Direction, br.Protocol, br.IP, br.Port)
}

func handleListRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules, err := loadRulesFromFile()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load rules: %v", err), http.StatusInternalServerError)
		return
	}

	if len(rules) == 0 {
		fmt.Fprintln(w, "No blocked rules")
		return
	}

	fmt.Fprintln(w, "Blocked rules:")
	for _, rule := range rules {
		fmt.Fprintf(w, "- Interface: %s, IP: %s, Protocol: %s, Direction: %s, Port: %s\n",
			rule.Interface, rule.IP, rule.Protocol, rule.Direction, rule.Port)
	}
}

func applyRule(rule SavedRule) error {
	ip := net.ParseIP(rule.IP).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", rule.IP)
	}

	protoNum, err := protocolToNumber(rule.Protocol)
	if err != nil {
		return err
	}

	portNum, err := portToNumber(rule.Port)
	if err != nil {
		return err
	}

	dirNum := directionToNumber(rule.Direction)
	ipVal := binary.BigEndian.Uint32(ip)

	key := RuleKey{IP: ipVal, Proto: protoNum, Direction: dirNum, Port: portNum}

	if err := blockedRules.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("failed to insert into BPF map: %v", err)
	}

	if _, exists := currentLinks[rule.Interface]; !exists {
		iface, err := net.InterfaceByName(rule.Interface)
		if err != nil {
			return fmt.Errorf("interface not found: %s", rule.Interface)
		}
		opts := link.XDPOptions{
			Program:   coll.Programs["xdp_block_ip"],
			Interface: iface.Index,
		}
		lnk, err := link.AttachXDP(opts)
		if err != nil {
			return fmt.Errorf("failed to attach XDP: %v", err)
		}
		currentLinks[rule.Interface] = lnk
	}

	return nil
}

func directionToNumber(direction string) uint8 {
	if direction == "src" {
		return 0
	}
	return 1
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

func portToNumber(port string) (uint16, error) {
	if port == "any" {
		return 0, nil
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", port)
	}
	return uint16(p), nil
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

func loadRulesFromFile() ([]SavedRule, error) {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %v", err)
	}

	var rules []SavedRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %v", err)
	}

	return rules, nil
}

func saveRulesToFile() error {
	rulesMutex.Lock()
	defer rulesMutex.Unlock()

	var rules []SavedRule
	iter := blockedRules.Iterate()
	var key RuleKey
	var value uint8

	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key.IP)
		rule := SavedRule{
			IP:        ip.String(),
			Protocol:  numberToProtocol(key.Proto),
			Direction: "src",
			Port:      "any",
		}
		if key.Direction == 1 {
			rule.Direction = "dst"
		}
		if key.Port != 0 {
			rule.Port = strconv.Itoa(int(key.Port))
		}

		for ifaceName := range currentLinks {
			rule.Interface = ifaceName
			break
		}

		rules = append(rules, rule)
	}

	return writeRulesToFile(rules)
}

func writeRulesToFile(rules []SavedRule) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %v", err)
	}

	tmpFile := rulesFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp rules file: %v", err)
	}

	if err := os.Rename(tmpFile, rulesFile); err != nil {
		return fmt.Errorf("failed to rename temp file: %v", err)
	}

	return nil
}
