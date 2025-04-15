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

// Constants
const (
	RulesFile      = "rules.json"
	ServerPort     = ":8080"
	AnyPort        = "any"
	DirectionSrc   = "src"
	DirectionDst   = "dst"
	ProtocolICMP   = "icmp"
	ProtocolTCP    = "tcp"
	ProtocolUDP    = "udp"
	ProtocolAll    = "all"
	HTTPMethodPost = http.MethodPost
	HTTPMethodGet  = http.MethodGet
)

// Types
type (
	BlockRequest struct {
		Interface string `json:"interface"`
		IP        string `json:"ip"`
		Protocol  string `json:"protocol"`  // "icmp", "tcp", "udp", "all"
		Direction string `json:"direction"` // "src" или "dst"
		Port      string `json:"port"`      // номер порта или "any"
	}

	RuleKey struct {
		IP        uint32 `json:"ip"`
		Proto     uint8  `json:"proto"`
		Direction uint8  `json:"direction"`
		Port      uint16 `json:"port"` // 0 означает любой порт
	}

	SavedRule struct {
		Interface string `json:"interface"`
		IP        string `json:"ip"`
		Protocol  string `json:"protocol"`
		Direction string `json:"direction"`
		Port      string `json:"port"`
	}

	Firewall struct {
		collection   *ebpf.Collection
		blockedRules *ebpf.Map
		currentLinks map[string]link.Link
		rulesMutex   sync.Mutex
	}
)

var (
	firewall *Firewall
)

func main() {
	// Initialize firewall
	var err error
	firewall, err = NewFirewall()
	if err != nil {
		log.Fatalf("Failed to initialize firewall: %v", err)
	}
	defer firewall.Close()

	// Load saved rules
	if err := firewall.LoadAndApplyRules(); err != nil {
		log.Printf("Warning: could not load rules from file: %v", err)
	}

	// Setup HTTP server
	setupHTTPServer()

	// Wait for termination signal
	waitForTermination()
}

// NewFirewall creates and initializes a new Firewall instance
func NewFirewall() (*Firewall, error) {
	spec, err := ebpf.LoadCollectionSpec("bpf/xdp_block.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	blockedRules := coll.Maps["blocked_rules"]
	if blockedRules == nil {
		coll.Close()
		return nil, fmt.Errorf("blocked_rules map not found in BPF program")
	}

	return &Firewall{
		collection:   coll,
		blockedRules: blockedRules,
		currentLinks: make(map[string]link.Link),
	}, nil
}

// Close cleans up firewall resources
func (fw *Firewall) Close() {
	for _, lnk := range fw.currentLinks {
		lnk.Close()
	}
	fw.collection.Close()
}

// LoadAndApplyRules loads rules from file and applies them
func (fw *Firewall) LoadAndApplyRules() error {
	rules, err := fw.loadRulesFromFile()
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if err := fw.ApplyRule(rule); err != nil {
			log.Printf("Failed to apply rule: %v", err)
		}
	}

	return nil
}

// ApplyRule applies a single firewall rule
func (fw *Firewall) ApplyRule(rule SavedRule) error {
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
	ipVal := binary.LittleEndian.Uint32(ip)

	key := RuleKey{IP: ipVal, Proto: protoNum, Direction: dirNum, Port: portNum}

	if err := fw.blockedRules.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("failed to insert into BPF map: %v", err)
	}

	if _, exists := fw.currentLinks[rule.Interface]; !exists {
		iface, err := net.InterfaceByName(rule.Interface)
		if err != nil {
			return fmt.Errorf("interface not found: %s", rule.Interface)
		}
		opts := link.XDPOptions{
			Program:   fw.collection.Programs["xdp_block_ip"],
			Interface: iface.Index,
		}
		lnk, err := link.AttachXDP(opts)
		if err != nil {
			return fmt.Errorf("failed to attach XDP: %v", err)
		}
		fw.currentLinks[rule.Interface] = lnk
	}

	return nil
}

// RemoveRule removes a firewall rule
func (fw *Firewall) RemoveRule(br BlockRequest) error {
	ip := net.ParseIP(br.IP).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	protoNum, err := protocolToNumber(br.Protocol)
	if err != nil {
		return err
	}

	portNum, err := portToNumber(br.Port)
	if err != nil {
		return err
	}

	dirNum := directionToNumber(br.Direction)
	ipVal := binary.LittleEndian.Uint32(ip)

	key := RuleKey{IP: ipVal, Proto: protoNum, Direction: dirNum, Port: portNum}

	if err := fw.blockedRules.Delete(key); err != nil {
		return fmt.Errorf("failed to unblock IP: %v", err)
	}

	return nil
}

// loadRulesFromFile loads rules from JSON file
func (fw *Firewall) loadRulesFromFile() ([]SavedRule, error) {
	fw.rulesMutex.Lock()
	defer fw.rulesMutex.Unlock()

	if _, err := os.Stat(RulesFile); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(RulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %v", err)
	}

	var rules []SavedRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %v", err)
	}

	return rules, nil
}

// saveRulesToFile saves current rules to JSON file
func (fw *Firewall) saveRulesToFile() error {
	fw.rulesMutex.Lock()
	defer fw.rulesMutex.Unlock()

	var rules []SavedRule
	iter := fw.blockedRules.Iterate()
	var key RuleKey
	var value uint8

	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key.IP)
		rule := SavedRule{
			IP:        ip.String(),
			Protocol:  numberToProtocol(key.Proto),
			Direction: DirectionSrc,
			Port:      AnyPort,
		}
		if key.Direction == 1 {
			rule.Direction = DirectionDst
		}
		if key.Port != 0 {
			rule.Port = strconv.Itoa(int(key.Port))
		}

		for ifaceName := range fw.currentLinks {
			rule.Interface = ifaceName
			break
		}

		rules = append(rules, rule)
	}

	return fw.writeRulesToFile(rules)
}

// writeRulesToFile writes rules to file with atomic replace
func (fw *Firewall) writeRulesToFile(rules []SavedRule) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %v", err)
	}

	tmpFile := RulesFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp rules file: %v", err)
	}

	if err := os.Rename(tmpFile, RulesFile); err != nil {
		return fmt.Errorf("failed to rename temp file: %v", err)
	}

	return nil
}

// HTTP Handlers
func handleBlockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
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

	if br.Port == "" {
		br.Port = AnyPort
	}

	rule := SavedRule(br)

	if err := firewall.ApplyRule(rule); err != nil {
		http.Error(w, fmt.Sprintf("Failed to apply rule: %v", err), http.StatusInternalServerError)
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		http.Error(w, fmt.Sprintf("Rule applied but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully blocked %s %s traffic for IP: %s, port: %s on interface %s\n",
		rule.Direction, rule.Protocol, rule.IP, rule.Port, rule.Interface)
}

func handleUnblockRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
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

	if br.Port == "" {
		br.Port = AnyPort
	}

	if err := firewall.RemoveRule(br); err != nil {
		http.Error(w, fmt.Sprintf("Failed to unblock IP: %v", err), http.StatusInternalServerError)
		return
	}

	// Update rules file
	rules, err := firewall.loadRulesFromFile()
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
		firewall.writeRulesToFile(newRules)
	}

	fmt.Fprintf(w, "Successfully unblocked %s %s traffic for IP: %s, port: %s\n",
		br.Direction, br.Protocol, br.IP, br.Port)
}

func handleListRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules, err := firewall.loadRulesFromFile()
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

// Helper functions
func directionToNumber(direction string) uint8 {
	if direction == DirectionSrc {
		return 0
	}
	return 1
}

func protocolToNumber(protocol string) (uint8, error) {
	switch protocol {
	case ProtocolICMP:
		return 1, nil
	case ProtocolTCP:
		return 6, nil
	case ProtocolUDP:
		return 17, nil
	case ProtocolAll:
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid protocol, must be icmp, tcp, udp or all")
	}
}

func portToNumber(port string) (uint16, error) {
	if port == AnyPort {
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
		return ProtocolICMP
	case 6:
		return ProtocolTCP
	case 17:
		return ProtocolUDP
	case 0:
		return ProtocolAll
	default:
		return fmt.Sprintf("%d", num)
	}
}

func setupHTTPServer() {
	http.HandleFunc("/block", handleBlockRequest)
	http.HandleFunc("/unblock", handleUnblockRequest)
	http.HandleFunc("/list", handleListRequest)

	go func() {
		log.Printf("Starting server on %s", ServerPort)
		if err := http.ListenAndServe(ServerPort, nil); err != nil {
			log.Fatal(err)
		}
	}()
}

func waitForTermination() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
}
