package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/vishvananda/netlink"
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
	HTTPMethodPost = "POST"
	HTTPMethodGet  = "GET"
)

type RuleRequest struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Port      string `json:"port"`
	Action    string `json:"action"`
}

type RuleKey struct {
	IP        uint32 `json:"ip"`
	Proto     uint8  `json:"proto"`
	Direction uint8  `json:"direction"`
	Port      uint16 `json:"port"`
}

type SavedRule struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Port      string `json:"port"`
	Action    string `json:"action"`
}

type RulesFileFormat struct {
	Rules       []SavedRule `json:"rules"`
	GlobalBlock bool        `json:"global_block"`
	GlobalAllow bool        `json:"global_allow"`
}

type Firewall struct {
	collection     *ebpf.Collection
	blockedRules   *ebpf.Map
	allowedRules   *ebpf.Map
	globalBlock    *ebpf.Map
	globalAllow    *ebpf.Map
	currentLinks   map[string]link.Link     // XDP
	currentTcLinks map[string]netlink.Qdisc // TC
	rulesMutex     sync.Mutex
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
	spec, err := ebpf.LoadCollectionSpec("bpf/xdp_filter.o")
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
		return nil, fmt.Errorf("blocked_rules map not found")
	}

	allowedRules := coll.Maps["allowed_rules"]
	if allowedRules == nil {
		coll.Close()
		return nil, fmt.Errorf("allowed_rules map not found")
	}

	globalBlock := coll.Maps["global_block"]
	if globalBlock == nil {
		coll.Close()
		return nil, fmt.Errorf("global_block map not found")
	}

	globalAllow := coll.Maps["global_allow"]
	if globalAllow == nil {
		coll.Close()
		return nil, fmt.Errorf("global_allow map not found")
	}

	return &Firewall{
		collection:     coll,
		blockedRules:   blockedRules,
		allowedRules:   allowedRules,
		globalBlock:    globalBlock,
		globalAllow:    globalAllow,
		currentLinks:   make(map[string]link.Link),
		currentTcLinks: make(map[string]netlink.Qdisc),
	}, nil
}

func (fw *Firewall) Close() {
	// Закрываем все XDP линки
	for iface, lnk := range fw.currentLinks {
		if err := lnk.Close(); err != nil {
			log.Printf("Failed to close XDP link for interface %s: %v", iface, err)
		}
	}

	// Удаляем все TC фильтры и qdisc
	for iface := range fw.currentTcLinks {
		ifaceObj, err := net.InterfaceByName(iface)
		if err != nil {
			log.Printf("Failed to get interface %s: %v", iface, err)
			continue
		}

		// Сначала удаляем фильтры
		filters, err := netlink.FilterList(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Index: ifaceObj.Index,
		}}, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			log.Printf("Failed to list filters for interface %s: %v", iface, err)
			continue
		}

		for _, filter := range filters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if err := netlink.FilterDel(bpfFilter); err != nil {
					log.Printf("Failed to delete BPF filter on interface %s: %v", iface, err)
				}
			}
		}

		// Затем удаляем qdisc clsact
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: ifaceObj.Index,
				Handle:    netlink.MakeHandle(0xffff, 0), // Исправленный handle
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		// Пробуем удалить с разными родительскими handles
		if err := netlink.QdiscDel(qdisc); err != nil {
			// Пробуем альтернативный вариант
			qdisc.Parent = netlink.HANDLE_INGRESS
			if err := netlink.QdiscDel(qdisc); err != nil {
				log.Printf("Failed to delete qdisc on interface %s: %v", iface, err)
			}
		}
	}

	// Закрываем коллекцию eBPF
	fw.collection.Close()
}

func (fw *Firewall) SetGlobalBlock(enabled bool) error {
	key := uint8(0)
	value := uint8(0)
	if enabled {
		value = 1
	}
	// Если включаем глобальную блокировку, выключаем глобальное разрешение
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
	// Если включаем глобальное разрешение, выключаем глобальную блокировку
	if enabled {
		if err := fw.globalBlock.Put(key, uint8(0)); err != nil {
			return err
		}
	}
	return fw.globalAllow.Put(key, value)
}

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

	iface, err := net.InterfaceByName(rule.Interface)
	if err != nil {
		return fmt.Errorf("interface not found: %s", rule.Interface)
	}

	// Attach XDP (ingress) only once
	if rule.Direction == DirectionSrc {
		if _, exists := fw.currentLinks[rule.Interface]; !exists {
			opts := link.XDPOptions{
				Program:   fw.collection.Programs["xdp_filter_ip"],
				Interface: iface.Index,
			}
			lnk, err := link.AttachXDP(opts)
			if err != nil {
				return fmt.Errorf("failed to attach XDP: %v", err)
			}
			fw.currentLinks[rule.Interface] = lnk
		}
	} else if rule.Direction == DirectionDst {
		if _, exists := fw.currentTcLinks[rule.Interface]; !exists {
			qdisc := &netlink.GenericQdisc{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: iface.Index,
					Handle:    netlink.MakeHandle(1, 0),
					Parent:    netlink.HANDLE_CLSACT,
				},
				QdiscType: "clsact",
			}
			if err := netlink.QdiscAdd(qdisc); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to add qdisc: %v", err)
			}

			prog := fw.collection.Programs["tc_egress_filter"]
			if prog == nil {
				return fmt.Errorf("TC program not found in collection")
			}

			filter := &netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: iface.Index,
					Parent:    netlink.HANDLE_MIN_EGRESS,
					Handle:    netlink.MakeHandle(1, 0),
					Priority:  1,
					Protocol:  syscall.ETH_P_ALL,
				},
				Fd:           prog.FD(),
				Name:         "tc_egress_filter",
				DirectAction: true,
			}

			if err := netlink.FilterAdd(filter); err != nil {
				return fmt.Errorf("failed to attach BPF filter with netlink: %v", err)
			}

			fw.currentTcLinks[rule.Interface] = qdisc
		}
	}
	return nil
}

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

	var targetMap *ebpf.Map
	switch rr.Action {
	case ActionBlock:
		targetMap = fw.blockedRules
	case ActionAllow:
		targetMap = fw.allowedRules
	default:
		return fmt.Errorf("invalid action: %s", rr.Action)
	}

	if err := targetMap.Delete(key); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rule not found in %s rules", rr.Action)
		}
		return fmt.Errorf("failed to remove from %s rules: %v", rr.Action, err)
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

	// Сохраняем блокирующие правила
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

		// Находим интерфейс для этого правила
		for ifaceName, lnk := range fw.currentLinks {
			if lnk != nil {
				rule.Interface = ifaceName
				break
			}
		}
		if rule.Interface == "" {
			for ifaceName := range fw.currentTcLinks {
				rule.Interface = ifaceName
				break
			}
		}

		rules = append(rules, rule)
	}

	// Сохраняем разрешающие правила
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

		for ifaceName, lnk := range fw.currentLinks {
			if lnk != nil {
				rule.Interface = ifaceName
				break
			}
		}
		if rule.Interface == "" {
			for ifaceName := range fw.currentTcLinks {
				rule.Interface = ifaceName
				break
			}
		}

		rules = append(rules, rule)
	}

	// Получаем текущие глобальные настройки
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

	if err := firewall.saveRulesToFile(); err != nil {
		http.Error(w, fmt.Sprintf("Rule removed but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Successfully removed rule for %s %s traffic for IP: %s, port: %s\n",
		rr.Direction, rr.Protocol, rr.IP, rr.Port)
}

func handleGlobalBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enable := r.FormValue("enable")
	if enable == "" {
		http.Error(w, "enable parameter is required (true/false)", http.StatusBadRequest)
		return
	}

	enabled := enable == "true"
	if err := firewall.SetGlobalBlock(enabled); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set global block: %v", err), http.StatusInternalServerError)
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		http.Error(w, fmt.Sprintf("Global block set but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	status := "disabled"
	if enabled {
		status = "enabled"
	}
	fmt.Fprintf(w, "Global block %s\n", status)
}

func handleGlobalAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enable := r.FormValue("enable")
	if enable == "" {
		http.Error(w, "enable parameter is required (true/false)", http.StatusBadRequest)
		return
	}

	enabled := enable == "true"
	if err := firewall.SetGlobalAllow(enabled); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set global allow: %v", err), http.StatusInternalServerError)
		return
	}

	if err := firewall.saveRulesToFile(); err != nil {
		http.Error(w, fmt.Sprintf("Global allow set but failed to save: %v", err), http.StatusInternalServerError)
		return
	}

	status := "disabled"
	if enabled {
		status = "enabled"
	}
	fmt.Fprintf(w, "Global allow %s\n", status)
}

func handleListRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rulesFile, err := firewall.loadRulesFromFile()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load rules: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Current rules:")
	fmt.Fprintf(w, "Global block: %t\n", rulesFile.GlobalBlock)
	fmt.Fprintf(w, "Global allow: %t\n", rulesFile.GlobalAllow)

	if len(rulesFile.Rules) == 0 {
		fmt.Fprintln(w, "No rules defined")
		return
	}

	for _, rule := range rulesFile.Rules {
		fmt.Fprintf(w, "- Action: %s, Interface: %s, IP: %s, Protocol: %s, Direction: %s, Port: %s\n",
			rule.Action, rule.Interface, rule.IP, rule.Protocol, rule.Direction, rule.Port)
	}
}

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
	http.HandleFunc("/global-block", handleGlobalBlock)
	http.HandleFunc("/global-allow", handleGlobalAllow)

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
