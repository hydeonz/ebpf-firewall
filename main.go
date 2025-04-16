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
	ActionBlock    = "block"
	ActionAllow    = "allow"
	HTTPMethodPost = http.MethodPost
	HTTPMethodGet  = http.MethodGet
)

// Types
type (
	RuleRequest struct {
		Interface string `json:"interface"`
		IP        string `json:"ip"`
		Protocol  string `json:"protocol"`  // "icmp", "tcp", "udp", "all"
		Direction string `json:"direction"` // "src" или "dst"
		Port      string `json:"port"`      // номер порта или "any"
		Action    string `json:"action"`    // "block" или "allow"
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
		Action    string `json:"action"`
	}

	Firewall struct {
		collection   *ebpf.Collection
		blockedRules *ebpf.Map
		allowedRules *ebpf.Map
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
	spec, err := ebpf.LoadCollectionSpec("bpf/xdp_block.o") // Обновленное имя файла
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

	allowedRules := coll.Maps["allowed_rules"]
	if allowedRules == nil {
		coll.Close()
		return nil, fmt.Errorf("allowed_rules map not found in BPF program")
	}

	return &Firewall{
		collection:   coll,
		blockedRules: blockedRules,
		allowedRules: allowedRules,
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

	// Выбираем карту в зависимости от действия
	var targetMap *ebpf.Map
	switch rule.Action {
	case ActionBlock:
		targetMap = fw.blockedRules
	case ActionAllow:
		targetMap = fw.allowedRules
	default:
		return fmt.Errorf("invalid action: %s", rule.Action)
	}

	if err := targetMap.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("failed to insert into BPF map: %v", err)
	}

	if _, exists := fw.currentLinks[rule.Interface]; !exists {
		iface, err := net.InterfaceByName(rule.Interface)
		if err != nil {
			return fmt.Errorf("interface not found: %s", rule.Interface)
		}
		opts := link.XDPOptions{
			Program:   fw.collection.Programs["xdp_filter_ip"], // Обновленное имя программы
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
func (fw *Firewall) RemoveRule(rr RuleRequest) error {
	ip := net.ParseIP(rr.IP).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	protoNum, err := protocolToNumber(rr.Protocol)
	if err != nil {
		return err
	}

	portNum, err := portToNumber(rr.Port)
	if err != nil {
		return err
	}

	dirNum := directionToNumber(rr.Direction)
	ipVal := binary.LittleEndian.Uint32(ip)

	key := RuleKey{IP: ipVal, Proto: protoNum, Direction: dirNum, Port: portNum}

	// Пытаемся удалить из обеих карт
	if err := fw.blockedRules.Delete(key); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove from blocked rules: %v", err)
	}

	if err := fw.allowedRules.Delete(key); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove from allowed rules: %v", err)
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

	// Собираем блокирующие правила
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
			Action:    ActionBlock,
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

	// Собираем разрешающие правила
	iter = fw.allowedRules.Iterate()
	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key.IP)
		rule := SavedRule{
			IP:        ip.String(),
			Protocol:  numberToProtocol(key.Proto),
			Direction: DirectionSrc,
			Port:      AnyPort,
			Action:    ActionAllow,
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
func handleAddRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rr := RuleRequest{
		Interface: r.FormValue("interface"),
		IP:        r.FormValue("ip"),
		Protocol:  r.FormValue("protocol"),
		Direction: r.FormValue("direction"),
		Port:      r.FormValue("port"),
		Action:    r.FormValue("action"),
	}

	if rr.Interface == "" || rr.IP == "" || rr.Protocol == "" || rr.Direction == "" || rr.Action == "" {
		http.Error(w, "interface, ip, protocol, direction and action parameters are required", http.StatusBadRequest)
		return
	}

	if rr.Port == "" {
		rr.Port = AnyPort
	}

	if rr.Action != ActionBlock && rr.Action != ActionAllow {
		http.Error(w, "action must be either 'block' or 'allow'", http.StatusBadRequest)
		return
	}

	rule := SavedRule{
		Interface: rr.Interface,
		IP:        rr.IP,
		Protocol:  rr.Protocol,
		Direction: rr.Direction,
		Port:      rr.Port,
		Action:    rr.Action,
	}

	if err := firewall.ApplyRule(rule); err != nil {
		http.Error(w, fmt.Sprintf("Failed to apply rule: %v", err), http.StatusInternalServerError)
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		http.Error(w, fmt.Sprintf("Rule applied but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully %sed %s %s traffic for IP: %s, port: %s on interface %s\n",
		rr.Action, rr.Direction, rr.Protocol, rr.IP, rr.Port, rr.Interface)
}

func handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rr := RuleRequest{
		Interface: r.FormValue("interface"),
		IP:        r.FormValue("ip"),
		Protocol:  r.FormValue("protocol"),
		Direction: r.FormValue("direction"),
		Port:      r.FormValue("port"),
		Action:    r.FormValue("action"),
	}

	if rr.IP == "" || rr.Protocol == "" || rr.Direction == "" {
		http.Error(w, "ip, protocol and direction parameters are required", http.StatusBadRequest)
		return
	}

	if rr.Port == "" {
		rr.Port = AnyPort
	}

	if err := firewall.RemoveRule(rr); err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove rule: %v", err), http.StatusInternalServerError)
		return
	}

	// Update rules file
	rules, err := firewall.loadRulesFromFile()
	if err == nil {
		newRules := make([]SavedRule, 0)
		for _, rule := range rules {
			if rule.IP == rr.IP && rule.Protocol == rr.Protocol &&
				rule.Direction == rr.Direction && rule.Port == rr.Port {
				continue
			}
			newRules = append(newRules, rule)
		}
		firewall.writeRulesToFile(newRules)
	}

	fmt.Fprintf(w, "Successfully removed rule for %s %s traffic for IP: %s, port: %s\n",
		rr.Direction, rr.Protocol, rr.IP, rr.Port)
}

func handleListRules(w http.ResponseWriter, r *http.Request) {
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
		fmt.Fprintln(w, "No rules defined")
		return
	}

	fmt.Fprintln(w, "Current rules:")
	for _, rule := range rules {
		fmt.Fprintf(w, "- Action: %s, Interface: %s, IP: %s, Protocol: %s, Direction: %s, Port: %s\n",
			rule.Action, rule.Interface, rule.IP, rule.Protocol, rule.Direction, rule.Port)
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
	http.HandleFunc("/add-rule", handleAddRule)
	http.HandleFunc("/remove-rule", handleRemoveRule)
	http.HandleFunc("/list-rules", handleListRules)

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
