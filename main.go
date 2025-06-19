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
	SrcIP   uint32  `json:"src_ip"`
	DstIP   uint32  `json:"dst_ip"`
	Proto   uint8   `json:"proto"`
	_       byte    // padding
	SrcPort uint16  `json:"src_port"`
	DstPort uint16  `json:"dst_port"`
	_       [2]byte // дополнительный padding для выравнивания до 16 байт
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
	Rules       []SavedRule `json:"rules"`
	GlobalBlock bool        `json:"global_block"`
	GlobalAllow bool        `json:"global_allow"`
}

// Firewall holds the eBPF programs and maps
type Firewall struct {
	collection    *ebpf.Collection
	firewallRules *ebpf.Map
	globalBlock   *ebpf.Map
	globalAllow   *ebpf.Map
	debugSrcIP    *ebpf.Map
	debugDstIP    *ebpf.Map
	debugProto    *ebpf.Map
	debugSrcPort  *ebpf.Map
	debugDstPort  *ebpf.Map
	currentLinks  map[string]link.Link
	rulesMutex    sync.Mutex
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
	firewallRules := coll.Maps["firewall_rules"]
	globalBlock := coll.Maps["global_block"]
	globalAllow := coll.Maps["global_allow"]
	debugSrcIP := coll.Maps["debug_src_ip"]
	debugDstIP := coll.Maps["debug_dst_ip"]
	debugProto := coll.Maps["debug_proto"]
	debugSrcPort := coll.Maps["debug_src_port"]
	debugDstPort := coll.Maps["debug_dst_port"]

	if firewallRules == nil || globalBlock == nil || globalAllow == nil {
		coll.Close()
		return nil, fmt.Errorf("required maps not found")
	}

	return &Firewall{
		collection:    coll,
		firewallRules: firewallRules,
		globalBlock:   globalBlock,
		globalAllow:   globalAllow,
		debugSrcIP:    debugSrcIP,
		debugDstIP:    debugDstIP,
		debugProto:    debugProto,
		debugSrcPort:  debugSrcPort,
		debugDstPort:  debugDstPort,
		currentLinks:  make(map[string]link.Link),
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

func (fw *Firewall) AddDebugValues(rule SavedRule) error {
	// Parse source IP
	srcIP := net.ParseIP(rule.SrcIP).To4()
	if srcIP == nil && rule.SrcIP != "" {
		return fmt.Errorf("invalid source IP: %s", rule.SrcIP)
	}

	// Parse destination IP
	dstIP := net.ParseIP(rule.DstIP).To4()
	if dstIP == nil && rule.DstIP != "" {
		return fmt.Errorf("invalid destination IP: %s", rule.DstIP)
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

	// Add values to debug maps
	if srcIP != nil {
		srcIPVal := binary.BigEndian.Uint32(srcIP)
		if err := fw.debugSrcIP.Put(srcIPVal, uint8(1)); err != nil {
			return fmt.Errorf("failed to add src_ip to debug map: %v", err)
		}
	}

	if dstIP != nil {
		dstIPVal := binary.BigEndian.Uint32(dstIP)
		if err := fw.debugDstIP.Put(dstIPVal, uint8(1)); err != nil {
			return fmt.Errorf("failed to add dst_ip to debug map: %v", err)
		}
	}

	if protoNum != 0 {
		if err := fw.debugProto.Put(protoNum, uint8(1)); err != nil {
			return fmt.Errorf("failed to add proto to debug map: %v", err)
		}
	}

	if srcPort != 0 {
		if err := fw.debugSrcPort.Put(srcPort, uint8(1)); err != nil {
			return fmt.Errorf("failed to add src_port to debug map: %v", err)
		}
	}

	if dstPort != 0 {
		if err := fw.debugDstPort.Put(dstPort, uint8(1)); err != nil {
			return fmt.Errorf("failed to add dst_port to debug map: %v", err)
		}
	}

	return nil
}

func (fw *Firewall) SetGlobalBlock(enabled bool) error {
	key := uint8(0)
	value := uint8(0)
	if enabled {
		value = 1
	}
	// If enabling global block, disable global allow
	if enabled {
		if err := fw.globalAllow.Put(key, uint8(0)); err != nil {
			return err
		}
	}
	return fw.globalBlock.Put(key, value)
}

func (fw *Firewall) SetGlobalAllow(enabled bool) error {
	key := uint8(0)
	value := uint8(0)
	if enabled {
		value = 1
	}
	// If enabling global allow, disable global block
	if enabled {
		if err := fw.globalBlock.Put(key, uint8(0)); err != nil {
			return err
		}
	}
	return fw.globalAllow.Put(key, value)
}

func (fw *Firewall) ApplyRule(rule SavedRule) error {
	// Parse source IP
	srcIP := net.ParseIP(rule.SrcIP).To4()
	if srcIP == nil && rule.SrcIP != "" {
		return fmt.Errorf("invalid source IP: %s", rule.SrcIP)
	}

	// Parse destination IP
	dstIP := net.ParseIP(rule.DstIP).To4()
	if dstIP == nil && rule.DstIP != "" {
		return fmt.Errorf("invalid destination IP: %s", rule.DstIP)
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
		SrcIP:   binary.BigEndian.Uint32(srcIP),
		DstIP:   binary.BigEndian.Uint32(dstIP),
		Proto:   protoNum,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Set value in the map (1 = allow, 0 = block)
	var value uint8
	if rule.Action == ActionAllow {
		value = 1
	}

	if err := fw.firewallRules.Put(key, value); err != nil {
		return fmt.Errorf("failed to insert into BPF map: %v", err)
	}

	// Add debug values
	if err := fw.AddDebugValues(rule); err != nil {
		log.Printf("Warning: failed to add debug values: %v", err)
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
	srcIP := net.ParseIP(rule.SrcIP).To4()
	if srcIP == nil && rule.SrcIP != "" {
		return fmt.Errorf("invalid source IP: %s", rule.SrcIP)
	}

	// Parse destination IP
	dstIP := net.ParseIP(rule.DstIP).To4()
	if dstIP == nil && rule.DstIP != "" {
		return fmt.Errorf("invalid destination IP: %s", rule.DstIP)
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
		SrcIP:   binary.BigEndian.Uint32(srcIP),
		DstIP:   binary.BigEndian.Uint32(dstIP),
		Proto:   protoNum,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	if err := fw.firewallRules.Delete(key); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rule not found")
		}
		return fmt.Errorf("failed to remove rule: %v", err)
	}

	return nil
}

func (fw *Firewall) LoadAndApplyRules() error {
	rulesFile, err := fw.loadRulesFromFile()
	if err != nil {
		return err
	}

	// Apply global settings from the file
	if err := fw.SetGlobalBlock(rulesFile.GlobalBlock); err != nil {
		log.Printf("Failed to apply global block: %v", err)
	}
	if err := fw.SetGlobalAllow(rulesFile.GlobalAllow); err != nil {
		log.Printf("Failed to apply global allow: %v", err)
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

	// Iterate through all rules in the BPF map
	iter := fw.firewallRules.Iterate()
	var key RuleKey
	var value uint8

	for iter.Next(&key, &value) {
		srcIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(srcIP, key.SrcIP)

		dstIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(dstIP, key.DstIP)

		action := ActionBlock
		if value == 1 {
			action = ActionAllow
		}

		rule := SavedRule{
			SrcIP:    srcIP.String(),
			DstIP:    dstIP.String(),
			Protocol: numberToProtocol(key.Proto),
			SrcPort:  AnyPort,
			DstPort:  AnyPort,
			Action:   action,
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

	// Get current global settings
	var globalBlockVal, globalAllowVal uint8
	if err := fw.globalBlock.Lookup(uint8(0), &globalBlockVal); err != nil {
		return fmt.Errorf("failed to get global block status: %v", err)
	}
	if err := fw.globalAllow.Lookup(uint8(0), &globalAllowVal); err != nil {
		return fmt.Errorf("failed to get global allow status: %v", err)
	}

	rulesFile := RulesFileFormat{
		Rules:       rules,
		GlobalBlock: globalBlockVal == 1,
		GlobalAllow: globalAllowVal == 1,
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
}
