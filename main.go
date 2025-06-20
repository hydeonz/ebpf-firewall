package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	RulesFile    = "rules.json"
	AnyPort      = "any"
	ProtocolICMP = "icmp"
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolAll  = "all"
	ActionBlock  = "block"
	ActionAllow  = "allow"
)

// RuleKey matches the C struct rule_key
type RuleKey struct {
	SrcIP   uint32  `json:"src_ip"`   // Source IP in network byte order
	DstIP   uint32  `json:"dst_ip"`   // Destination IP in network byte order
	SrcPort uint16  `json:"src_port"` // Source port in host byte order
	DstPort uint16  `json:"dst_port"` // Destination port in host byte order
	Proto   uint8   `json:"proto"`    // IP protocol number
	Padding [3]byte // padding to match C struct
}

// SavedRule represents a rule as saved in JSON
type SavedRule struct {
	Interface string `json:"interface"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	SrcPort   string `json:"src_port"`
	DstPort   string `json:"dst_port"`
	Action    string `json:"action"`
}

// RulesFileFormat represents the structure of the rules file
type RulesFileFormat struct {
	Rules []SavedRule `json:"rules"`
}

// Firewall holds the eBPF programs and maps
type Firewall struct {
	collection   *ebpf.Collection
	allowRules   *ebpf.Map
	blockRules   *ebpf.Map
	currentLinks map[string]link.Link
	rulesMutex   sync.Mutex
}

var firewall *Firewall

func main() {
	var err error
	firewall, err = NewFirewall()
	if err != nil {
		log.Fatalf("Failed to initialize firewall: %v", err)
	}
	defer firewall.Close()

	if err := firewall.LoadAndApplyRules(); err != nil {
		log.Printf("Warning: could not load rules from file: %v", err)
	}

	waitForTermination()
}

func NewFirewall() (*Firewall, error) {
	// Load the compiled eBPF ELF file
	spec, err := ebpf.LoadCollectionSpec("bpf/filter.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	// Get the maps
	allowRules := coll.Maps["allow_rules"]
	blockRules := coll.Maps["block_rules"]

	if allowRules == nil || blockRules == nil {
		coll.Close()
		return nil, fmt.Errorf("required maps not found")
	}

	return &Firewall{
		collection:   coll,
		allowRules:   allowRules,
		blockRules:   blockRules,
		currentLinks: make(map[string]link.Link),
	}, nil
}

func (fw *Firewall) Close() {
	// Close all XDP links
	for iface, lnk := range fw.currentLinks {
		if err := lnk.Close(); err != nil {
			log.Printf("Failed to close XDP link for interface %s: %v", iface, err)
		}
	}

	// Close the eBPF collection
	fw.collection.Close()
}

func (fw *Firewall) ApplyRule(rule SavedRule) error {
	// Parse source IP
	var srcIP uint32
	if rule.SrcIP != "" {
		ip := net.ParseIP(rule.SrcIP).To4()
		if ip == nil {
			return fmt.Errorf("invalid source IP: %s", rule.SrcIP)
		}
		srcIP = binary.BigEndian.Uint32(ip)
	} else {
		srcIP = 0
	}

	// Parse destination IP
	var dstIP uint32
	if rule.DstIP != "" {
		ip := net.ParseIP(rule.DstIP).To4()
		if ip == nil {
			return fmt.Errorf("invalid destination IP: %s", rule.DstIP)
		}
		dstIP = binary.BigEndian.Uint32(ip)
	} else {
		dstIP = 0
	}

	protoNum, err := protocolToNumber(rule.Protocol)
	if err != nil {
		return err
	}

	srcPort, err := portToNumber(rule.SrcPort)
	if err != nil {
		return err
	}

	dstPort, err := portToNumber(rule.DstPort)
	if err != nil {
		return err
	}
	padding := [3]uint8{0, 0, 0}

	// Create rule key
	key := RuleKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Proto:   protoNum,
		SrcPort: srcPort,
		DstPort: dstPort,
		Padding: padding,
	}

	// Set value in the appropriate map
	var targetMap *ebpf.Map
	if rule.Action == ActionAllow {
		targetMap = fw.allowRules
	} else {
		targetMap = fw.blockRules
	}

	// Use 1 as value (the actual value doesn't matter, just the presence in the map)
	value := uint8(1)
	if err := targetMap.Put(key, value); err != nil {
		return fmt.Errorf("failed to insert into BPF map: %v", err)
	}

	// Attach XDP program if not already attached
	if _, exists := fw.currentLinks[rule.Interface]; !exists {
		iface, err := net.InterfaceByName(rule.Interface)
		if err != nil {
			return fmt.Errorf("interface not found: %s", rule.Interface)
		}

		opts := link.XDPOptions{
			Program:   fw.collection.Programs["xdp_firewall"],
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

func (fw *Firewall) RemoveRule(rule SavedRule) error {
	// Parse source IP
	var srcIP uint32
	if rule.SrcIP != "" {
		ip := net.ParseIP(rule.SrcIP).To4()
		if ip == nil {
			return fmt.Errorf("invalid source IP: %s", rule.SrcIP)
		}
		srcIP = binary.BigEndian.Uint32(ip)
	}

	// Parse destination IP
	var dstIP uint32
	if rule.DstIP != "" {
		ip := net.ParseIP(rule.DstIP).To4()
		if ip == nil {
			return fmt.Errorf("invalid destination IP: %s", rule.DstIP)
		}
		dstIP = binary.BigEndian.Uint32(ip)
	}

	protoNum, err := protocolToNumber(rule.Protocol)
	if err != nil {
		return err
	}

	srcPort, err := portToNumber(rule.SrcPort)
	if err != nil {
		return err
	}

	dstPort, err := portToNumber(rule.DstPort)
	if err != nil {
		return err
	}

	// Create rule key
	key := RuleKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Proto:   protoNum,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Try to remove from both maps
	var targetMaps []*ebpf.Map
	if rule.Action == ActionAllow {
		targetMaps = []*ebpf.Map{fw.allowRules}
	} else {
		targetMaps = []*ebpf.Map{fw.blockRules}
	}

	var lastErr error
	for _, m := range targetMaps {
		if err := m.Delete(key); err != nil {
			if !os.IsNotExist(err) {
				lastErr = fmt.Errorf("failed to remove rule from map: %v", err)
			}
		}
	}

	return lastErr
}

func (fw *Firewall) LoadAndApplyRules() error {
	rulesFile, err := fw.loadRulesFromFile()
	if err != nil {
		return err
	}

	// Apply all rules from the file
	for _, rule := range rulesFile.Rules {
		if err := fw.ApplyRule(rule); err != nil {
			log.Printf("Failed to apply rule: %v", err)
		}
	}

	return nil
}

func (fw *Firewall) loadRulesFromFile() (*RulesFileFormat, error) {
	fw.rulesMutex.Lock()
	defer fw.rulesMutex.Unlock()

	if _, err := os.Stat(RulesFile); os.IsNotExist(err) {
		return &RulesFileFormat{Rules: []SavedRule{}}, nil
	}

	data, err := os.ReadFile(RulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %v", err)
	}

	var rulesFile RulesFileFormat
	if err := json.Unmarshal(data, &rulesFile); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %v", err)
	}

	return &rulesFile, nil
}

func (fw *Firewall) saveRulesToFile() error {
	fw.rulesMutex.Lock()
	defer fw.rulesMutex.Unlock()

	var rules []SavedRule

	// Iterate through all rules in the BPF maps
	iterAllow := fw.allowRules.Iterate()
	var key RuleKey
	var value uint8

	for iterAllow.Next(&key, &value) {
		srcIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(srcIP, key.SrcIP)

		dstIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(dstIP, key.DstIP)

		rule := SavedRule{
			SrcIP:    srcIP.String(),
			DstIP:    dstIP.String(),
			Protocol: numberToProtocol(key.Proto),
			SrcPort:  AnyPort,
			DstPort:  AnyPort,
			Action:   ActionAllow,
		}

		if key.SrcPort != 0 {
			rule.SrcPort = strconv.Itoa(int(key.SrcPort))
		}
		if key.DstPort != 0 {
			rule.DstPort = strconv.Itoa(int(key.DstPort))
		}

		// Find the interface for this rule
		for ifaceName := range fw.currentLinks {
			rule.Interface = ifaceName
			break
		}

		rules = append(rules, rule)
	}

	// Iterate through block rules
	iterBlock := fw.blockRules.Iterate()
	for iterBlock.Next(&key, &value) {
		srcIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(srcIP, key.SrcIP)

		dstIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(dstIP, key.DstIP)

		rule := SavedRule{
			SrcIP:    srcIP.String(),
			DstIP:    dstIP.String(),
			Protocol: numberToProtocol(key.Proto),
			SrcPort:  AnyPort,
			DstPort:  AnyPort,
			Action:   ActionBlock,
		}

		if key.SrcPort != 0 {
			rule.SrcPort = strconv.Itoa(int(key.SrcPort))
		}
		if key.DstPort != 0 {
			rule.DstPort = strconv.Itoa(int(key.DstPort))
		}

		// Find the interface for this rule
		for ifaceName := range fw.currentLinks {
			rule.Interface = ifaceName
			break
		}

		rules = append(rules, rule)
	}

	rulesFile := RulesFileFormat{
		Rules: rules,
	}

	data, err := json.MarshalIndent(rulesFile, "", "  ")
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

func waitForTermination() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")

	// Save rules before exiting
	if err := firewall.saveRulesToFile(); err != nil {
		log.Printf("Failed to save rules: %v", err)
	}
}
