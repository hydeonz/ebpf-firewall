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
	ProtocolICMP   = "icmp"
	ProtocolTCP    = "tcp"
	ProtocolUDP    = "udp"
	ProtocolAll    = "all"
	ActionBlock    = "block"
	ActionAllow    = "allow"
	HTTPMethodPost = "POST"
	HTTPMethodGet  = "GET"
)

// RuleKey matches the C struct rule_key
type RuleKey struct {
	SrcIP   uint32 `json:"src_ip"`
	DstIP   uint32 `json:"dst_ip"`
	Proto   uint8  `json:"proto"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
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

// ApiResponse is the standard API response structure
type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ListRulesResponse is the response for listing rules
type ListRulesResponse struct {
	GlobalBlock bool        `json:"global_block"`
	GlobalAllow bool        `json:"global_allow"`
	Rules       []SavedRule `json:"rules"`
}

// GlobalStatusResponse shows global rule status
type GlobalStatusResponse struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
}

// Firewall holds the eBPF programs and maps
type Firewall struct {
	collection    *ebpf.Collection
	firewallRules *ebpf.Map
	globalBlock   *ebpf.Map
	globalAllow   *ebpf.Map
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

	setupHTTPServer()
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

	if firewallRules == nil || globalBlock == nil || globalAllow == nil {
		coll.Close()
		return nil, fmt.Errorf("required maps not found")
	}

	return &Firewall{
		collection:    coll,
		firewallRules: firewallRules,
		globalBlock:   globalBlock,
		globalAllow:   globalAllow,
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
		SrcIP:   binary.LittleEndian.Uint32(srcIP),
		DstIP:   binary.LittleEndian.Uint32(dstIP),
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
		SrcIP:   binary.LittleEndian.Uint32(srcIP),
		DstIP:   binary.LittleEndian.Uint32(dstIP),
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
		binary.LittleEndian.PutUint32(srcIP, key.SrcIP)

		dstIP := make(net.IP, 4)
		binary.LittleEndian.PutUint32(dstIP, key.DstIP)

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

// Helper functions for API responses
func sendJSONResponse(w http.ResponseWriter, status int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func parseJSONRequest(r *http.Request, v interface{}) error {
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		decoder := json.NewDecoder(r.Body)
		defer r.Body.Close()
		if err := decoder.Decode(v); err != nil {
			return fmt.Errorf("invalid JSON: %v", err)
		}
		return nil
	}
	return fmt.Errorf("content-type must be application/json")
}

// HTTP handlers
func handleAddRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var rule SavedRule
	if err := parseJSONRequest(r, &rule); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Error parsing request: %v", err),
		})
		return
	}

	// Validate required fields
	if rule.Interface == "" || rule.SrcIP == "" || rule.DstIP == "" || rule.Protocol == "" || rule.Action == "" {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "interface, src_ip, dst_ip, protocol and action parameters are required",
		})
		return
	}

	if rule.SrcPort == "" {
		rule.SrcPort = AnyPort
	}
	if rule.DstPort == "" {
		rule.DstPort = AnyPort
	}

	if rule.Action != ActionBlock && rule.Action != ActionAllow {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "action must be either 'block' or 'allow'",
		})
		return
	}

	if err := firewall.ApplyRule(rule); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to apply rule: %v", err),
		})
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Rule applied but failed to save: %v", err),
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully %sed traffic from %s:%s to %s:%s (%s) on interface %s",
			rule.Action, rule.SrcIP, rule.SrcPort, rule.DstIP, rule.DstPort, rule.Protocol, rule.Interface),
		Data: rule,
	})
}

func handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var rule SavedRule
	if err := parseJSONRequest(r, &rule); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Error parsing request: %v", err),
		})
		return
	}

	if rule.SrcIP == "" || rule.DstIP == "" || rule.Protocol == "" {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "src_ip, dst_ip and protocol parameters are required",
		})
		return
	}

	if rule.SrcPort == "" {
		rule.SrcPort = AnyPort
	}
	if rule.DstPort == "" {
		rule.DstPort = AnyPort
	}

	if err := firewall.RemoveRule(rule); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to remove rule: %v", err),
		})
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Rule removed but failed to save: %v", err),
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully removed rule for traffic from %s:%s to %s:%s (%s)",
			rule.SrcIP, rule.SrcPort, rule.DstIP, rule.DstPort, rule.Protocol),
	})
}

func handleGlobalBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var request struct {
		Enable bool `json:"enable"`
	}
	if err := parseJSONRequest(r, &request); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Error parsing request: %v", err),
		})
		return
	}

	if err := firewall.SetGlobalBlock(request.Enable); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to set global block: %v", err),
		})
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Global block set but failed to save: %v", err),
		})
		return
	}

	status := "disabled"
	if request.Enable {
		status = "enabled"
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Global block %s", status),
		Data: GlobalStatusResponse{
			Enabled: request.Enable,
			Type:    "block",
		},
	})
}

func handleGlobalAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var request struct {
		Enable bool `json:"enable"`
	}
	if err := parseJSONRequest(r, &request); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Error parsing request: %v", err),
		})
		return
	}

	if err := firewall.SetGlobalAllow(request.Enable); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to set global allow: %v", err),
		})
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Global allow set but failed to save: %v", err),
		})
		return
	}

	status := "disabled"
	if request.Enable {
		status = "enabled"
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: fmt.Sprintf("Global allow %s", status),
		Data: GlobalStatusResponse{
			Enabled: request.Enable,
			Type:    "allow",
		},
	})
}

func handleGetInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodGet {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to get network interfaces: %v", err),
		})
		return
	}

	var result []map[string]interface{}
	for _, iface := range interfaces {
		result = append(result, map[string]interface{}{
			"name":  iface.Name,
			"is_up": iface.Flags&net.FlagUp != 0,
		})
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Network interfaces retrieved successfully",
		Data:    result,
	})
}

func handleListRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodGet {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	rulesFile, err := firewall.loadRulesFromFile()
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to load rules: %v", err),
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Rules loaded successfully",
		Data: ListRulesResponse{
			GlobalBlock: rulesFile.GlobalBlock,
			GlobalAllow: rulesFile.GlobalAllow,
			Rules:       rulesFile.Rules,
		},
	})
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
	http.HandleFunc("/global-block", handleGlobalBlock)
	http.HandleFunc("/global-allow", handleGlobalAllow)
	http.HandleFunc("/interfaces", handleGetInterfaces)

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
