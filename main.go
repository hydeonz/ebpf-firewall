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
	"time"

	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Константы
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

type ConnStats struct {
	Count uint32
	Bytes uint32
}

type ConnectionStats struct {
	SourceIP   string    `json:"source_ip"`
	Packets    uint32    `json:"packets"`
	Bytes      uint32    `json:"bytes"`
	LastUpdate time.Time `json:"last_update"`
}

type TCPStats struct {
	SYNCount uint64 `json:"syn_count"`
	ACKCount uint64 `json:"ack_count"`
}

type ConnectionsResponse struct {
	Connections      []ConnectionStats `json:"connections"`
	TotalConnections int               `json:"total_connections"`
	TotalBytes       uint64            `json:"total_bytes"`
	TCPStats         TCPStats          `json:"tcp_stats"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// Структуры запросов и ответов
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

// Структуры ответов API
type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ListRulesResponse struct {
	GlobalBlock bool        `json:"global_block"`
	GlobalAllow bool        `json:"global_allow"`
	Rules       []SavedRule `json:"rules"`
}

type GlobalStatusResponse struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
}

type Firewall struct {
	collection        *ebpf.Collection
	analyzeCollection *ebpf.Collection
	blockedRules      *ebpf.Map
	allowedRules      *ebpf.Map
	globalBlock       *ebpf.Map
	globalAllow       *ebpf.Map
	currentLinks      map[string]link.Link
	currentTcLinks    map[string]netlink.Qdisc
	rulesMutex        sync.Mutex
	connectionMap     *ebpf.Map
	totalBytes        *ebpf.Map
	tcpSynCount       *ebpf.Map // Добавляем карту для TCP SYN
	tcpAckCount       *ebpf.Map // Добавляем карту для TCP ACK
	analyzeLinks      map[string]link.Link
	statsMutex        sync.RWMutex
}

var firewall *Firewall

func main() {
	var err error
	firewall, err = NewFirewall()
	if err != nil {
		log.Fatalf("Failed to initialize firewall: %v", err)
	}
	defer firewall.Close()

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: could not get network interfaces: %v", err)
	}

	// Прикрепляем анализатор ко всем активным интерфейсам (кроме loopback)
	for _, iface := range interfaces {
		// Пропускаем неактивные и loopback интерфейсы
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if err := firewall.AttachAnalyzer(iface.Name); err != nil {
			log.Printf("Warning: could not attach analyzer to %s: %v", iface.Name, err)
		} else {
			log.Printf("Successfully attached analyzer to interface: %s", iface.Name)
		}
	}

	if err := firewall.LoadAndApplyRules(); err != nil {
		log.Printf("Warning: could not load rules from file: %v", err)
	}

	setupHTTPServer()
	waitForTermination()
}

func NewFirewall() (*Firewall, error) {
	// Загружаем фильтр
	filterSpec, err := ebpf.LoadCollectionSpec("bpf/filter.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load filter spec: %v", err)
	}

	// Загружаем анализатор
	analyzeSpec, err := ebpf.LoadCollectionSpec("bpf/analyze.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load analyze spec: %v", err)
	}

	filterColl, err := ebpf.NewCollection(filterSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter collection: %v", err)
	}

	analyzeColl, err := ebpf.NewCollection(analyzeSpec)
	if err != nil {
		filterColl.Close()
		return nil, fmt.Errorf("failed to create analyze collection: %v", err)
	}

	// Получаем карты
	blockedRules := filterColl.Maps["blocked_rules"]
	allowedRules := filterColl.Maps["allowed_rules"]
	globalBlock := filterColl.Maps["global_block"]
	globalAllow := filterColl.Maps["global_allow"]
	connectionMap := analyzeColl.Maps["connection_map"]
	totalBytes := analyzeColl.Maps["total_bytes"]
	tcpSynCount := analyzeColl.Maps["tcp_syn_count"] // Получаем карту для TCP SYN
	tcpAckCount := analyzeColl.Maps["tcp_ack_count"] // Получаем карту для TCP ACK

	if blockedRules == nil || allowedRules == nil || globalBlock == nil ||
		globalAllow == nil || connectionMap == nil || totalBytes == nil ||
		tcpSynCount == nil || tcpAckCount == nil {
		filterColl.Close()
		analyzeColl.Close()
		return nil, fmt.Errorf("required maps not found")
	}

	return &Firewall{
		collection:        filterColl,
		analyzeCollection: analyzeColl,
		blockedRules:      blockedRules,
		allowedRules:      allowedRules,
		globalBlock:       globalBlock,
		globalAllow:       globalAllow,
		connectionMap:     connectionMap,
		totalBytes:        totalBytes,
		tcpSynCount:       tcpSynCount,
		tcpAckCount:       tcpAckCount,
		currentLinks:      make(map[string]link.Link),
		currentTcLinks:    make(map[string]netlink.Qdisc),
		analyzeLinks:      make(map[string]link.Link),
	}, nil
}

func (fw *Firewall) AttachAnalyzer(ifaceName string) error {
	fw.statsMutex.Lock()
	defer fw.statsMutex.Unlock()

	if _, exists := fw.analyzeLinks[ifaceName]; exists {
		return nil
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %s", err)
	}

	// Изменить эту строку: использовать analyzeColl вместо collection
	// на:
	prog := fw.analyzeCollection.Programs["analyze_connections"]

	if prog == nil {
		return fmt.Errorf("analyze_connections program not found")
	}

	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	}

	lnk, err := link.AttachXDP(opts)
	if err != nil {
		return fmt.Errorf("failed to attach analyzer: %v", err)
	}

	fw.analyzeLinks[ifaceName] = lnk
	return nil
}

func (fw *Firewall) GetConnectionStats() (*ConnectionsResponse, error) {
	fw.statsMutex.RLock()
	defer fw.statsMutex.RUnlock()

	stats := &ConnectionsResponse{
		Connections: make([]ConnectionStats, 0),
		UpdatedAt:   time.Now(),
	}

	// Читаем статистику соединений
	var key uint32
	var value ConnStats
	iter := fw.connectionMap.Iterate()
	for iter.Next(&key, &value) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key)

		stats.Connections = append(stats.Connections, ConnectionStats{
			SourceIP:   ip.String(),
			Packets:    value.Count,
			Bytes:      value.Bytes,
			LastUpdate: time.Now(),
		})
	}

	// Читаем общее количество байт
	var totalKey uint32 = 0
	var total uint64
	if err := fw.totalBytes.Lookup(&totalKey, &total); err == nil {
		stats.TotalBytes = total
	}

	// Читаем количество TCP SYN пакетов
	var synCount uint64
	if err := fw.tcpSynCount.Lookup(&totalKey, &synCount); err == nil {
		stats.TCPStats.SYNCount = synCount
	}

	// Читаем количество TCP ACK пакетов
	var ackCount uint64
	if err := fw.tcpAckCount.Lookup(&totalKey, &ackCount); err == nil {
		stats.TCPStats.ACKCount = ackCount
	}

	stats.TotalConnections = len(stats.Connections)
	return stats, nil
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
				Handle:    netlink.MakeHandle(0xffff, 0),
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

// Вспомогательная функция для отправки JSON-ответов
func sendJSONResponse(w http.ResponseWriter, status int, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// Функция для обработки запросов в формате JSON
func parseJSONRequest(r *http.Request, v interface{}) error {
	contentType := r.Header.Get("Content-Type")

	// Проверяем, что запрос в формате JSON
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

func handleGetConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodGet {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	stats, err := firewall.GetConnectionStats()
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, ApiResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to get connection stats: %v", err),
		})
		return
	}

	sendJSONResponse(w, http.StatusOK, ApiResponse{
		Success: true,
		Message: "Connection statistics retrieved successfully",
		Data:    stats,
	})
}

func handleAddRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != HTTPMethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, ApiResponse{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	var rr RuleRequest

	// Проверяем, является ли запрос JSON-запросом
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		if err := parseJSONRequest(r, &rr); err != nil {
			sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: fmt.Sprintf("Error parsing request: %v", err),
			})
			return
		}
	} else {
		// Обработка form-data запросов для обратной совместимости
		rr = RuleRequest{
			Interface: r.FormValue("interface"),
			IP:        r.FormValue("ip"),
			Protocol:  r.FormValue("protocol"),
			Direction: r.FormValue("direction"),
			Port:      r.FormValue("port"),
			Action:    r.FormValue("action"),
		}
	}

	if rr.Interface == "" || rr.IP == "" || rr.Protocol == "" || rr.Direction == "" || rr.Action == "" {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "interface, ip, protocol, direction and action parameters are required",
		})
		return
	}

	if rr.Port == "" {
		rr.Port = AnyPort
	}

	if rr.Action != ActionBlock && rr.Action != ActionAllow {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "action must be either 'block' or 'allow'",
		})
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
		Message: fmt.Sprintf("Successfully %sed %s %s traffic for IP: %s, port: %s on interface %s",
			rr.Action, rr.Direction, rr.Protocol, rr.IP, rr.Port, rr.Interface),
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

	var rr RuleRequest

	// Проверяем, является ли запрос JSON-запросом
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		if err := parseJSONRequest(r, &rr); err != nil {
			sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: fmt.Sprintf("Error parsing request: %v", err),
			})
			return
		}
	} else {
		// Обработка form-data запросов для обратной совместимости
		rr = RuleRequest{
			Interface: r.FormValue("interface"),
			IP:        r.FormValue("ip"),
			Protocol:  r.FormValue("protocol"),
			Direction: r.FormValue("direction"),
			Port:      r.FormValue("port"),
			Action:    r.FormValue("action"),
		}
	}

	if rr.IP == "" || rr.Protocol == "" || rr.Direction == "" || rr.Action == "" {
		sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
			Success: false,
			Message: "ip, protocol, direction and action parameters are required",
		})
		return
	}

	if rr.Port == "" {
		rr.Port = AnyPort
	}

	if err := firewall.RemoveRule(rr); err != nil {
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
		Message: fmt.Sprintf("Successfully removed %s rule for %s %s traffic for IP: %s, port: %s",
			rr.Action, rr.Direction, rr.Protocol, rr.IP, rr.Port),
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

	// Проверяем, является ли запрос JSON-запросом
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		if err := parseJSONRequest(r, &request); err != nil {
			sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: fmt.Sprintf("Error parsing request: %v", err),
			})
			return
		}
	} else {
		// Обработка form-data запросов для обратной совместимости
		enable := r.FormValue("enable")
		if enable == "" {
			sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: "enable parameter is required (true/false)",
			})
			return
		}
		request.Enable = enable == "true"
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

	// Проверяем, является ли запрос JSON-запросом
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		if err := parseJSONRequest(r, &request); err != nil {
			sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: fmt.Sprintf("Error parsing request: %v", err),
			})
			return
		}
	} else {
		// Обработка form-data запросов для обратной совместимости
		enable := r.FormValue("enable")
		if enable == "" {
			sendJSONResponse(w, http.StatusBadRequest, ApiResponse{
				Success: false,
				Message: "enable parameter is required (true/false)",
			})
			return
		}
		request.Enable = enable == "true"
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
	// Существующие обработчики
	http.HandleFunc("/add-rule", handleAddRule)
	http.HandleFunc("/remove-rule", handleRemoveRule)
	http.HandleFunc("/list-rules", handleListRules)
	http.HandleFunc("/global-block", handleGlobalBlock)
	http.HandleFunc("/global-allow", handleGlobalAllow)
	http.HandleFunc("/interfaces", handleGetInterfaces)
	http.HandleFunc("/connections", handleGetConnections)

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
