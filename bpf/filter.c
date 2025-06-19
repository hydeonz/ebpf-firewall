#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define MAX_RULES 1024
#define IP_ANY 0

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

struct rule_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 proto;
    __u16 src_port;
    __u16 dst_port;
};

// Основная мапа с правилами
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct rule_key);
    __type(value, __u8);
} firewall_rules SEC(".maps");

// Мапы для дебага каждого поля
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __be32); // src_ip
    __type(value, __u8);
} debug_src_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __be32); // dst_ip
    __type(value, __u8);
} debug_dst_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u8); // proto
    __type(value, __u8);
} debug_proto SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u16); // src_port
    __type(value, __u8);
} debug_src_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u16); // dst_port
    __type(value, __u8);
} debug_dst_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
} global_block SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u8);
    __type(value, __u8);
} global_allow SEC(".maps");

static __always_inline void log_ip_port(__be32 saddr, __be32 daddr,
                                      __u16 sport, __u16 dport) {
    bpf_printk("IP SRC: 0x%x", saddr);
    bpf_printk("IP DST: 0x%x", daddr);
    bpf_printk("PORT SRC: %u", sport);
    bpf_printk("PORT DST: %u", dport);
}

static __always_inline void log_proto(__u8 proto) {
    switch (proto) {
        case IPPROTO_TCP: bpf_printk("PROTO: TCP"); break;
        case IPPROTO_UDP: bpf_printk("PROTO: UDP"); break;
        case IPPROTO_ICMP: bpf_printk("PROTO: ICMP"); break;
        default: bpf_printk("PROTO: UNKNOWN(%u)", proto); break;
    }
}

static __always_inline void log_rule_match(const struct rule_key *rule, __u8 action) {
    bpf_printk("MATCHED RULE:");
    bpf_printk("SRC IP: 0x%x", rule->src_ip);
    bpf_printk("DST IP: 0x%x", rule->dst_ip);
    bpf_printk("PROTO: %u", rule->proto);
    bpf_printk("SRC PORT: %u", rule->src_port);
    bpf_printk("DST PORT: %u", rule->dst_port);
    bpf_printk("ACTION: %s", action ? "ALLOW" : "BLOCK");
}

static __always_inline void debug_check_fields(__be32 saddr, __be32 daddr,
                                             __u8 proto, __u16 sport, __u16 dport) {
    // Проверяем каждое поле по отдельности
    __u8 *found;

    found = bpf_map_lookup_elem(&debug_src_ip, &saddr);
    bpf_printk("DEBUG SRC_IP: 0x%x %s", saddr, found ? "FOUND" : "NOT FOUND");

    found = bpf_map_lookup_elem(&debug_dst_ip, &daddr);
    bpf_printk("DEBUG DST_IP: 0x%x %s", daddr, found ? "FOUND" : "NOT FOUND");

    found = bpf_map_lookup_elem(&debug_proto, &proto);
    bpf_printk("DEBUG PROTO: %u %s", proto, found ? "FOUND" : "NOT FOUND");

    if (sport != 0) {
        found = bpf_map_lookup_elem(&debug_src_port, &sport);
        bpf_printk("DEBUG SRC_PORT: %u %s", sport, found ? "FOUND" : "NOT FOUND");
    }

    if (dport != 0) {
        found = bpf_map_lookup_elem(&debug_dst_port, &dport);
        bpf_printk("DEBUG DST_PORT: %u %s", dport, found ? "FOUND" : "NOT FOUND");
    }
}

static __always_inline int process_packet(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        struct udphdr *udp = (void *)ip + sizeof(*ip);

        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            src_port = bpf_ntohs(ip->protocol == IPPROTO_TCP ? tcp->source : udp->source);
            dst_port = bpf_ntohs(ip->protocol == IPPROTO_TCP ? tcp->dest : udp->dest);
        }
    }

    __be32 saddr = ip->saddr;
    __be32 daddr = ip->daddr;

    // Log packet details
    bpf_printk("--- NEW PACKET ---");
    log_ip_port(saddr, daddr, src_port, dst_port);
    log_proto(ip->protocol);

    // Дебаг: проверяем каждое поле отдельно
    debug_check_fields(saddr, daddr, ip->protocol, src_port, dst_port);

    // Check global policies
    __u8 key = 0;
    __u8 *global_allow_enabled = bpf_map_lookup_elem(&global_allow, &key);
    if (global_allow_enabled && *global_allow_enabled) {
        bpf_printk("GLOBAL POLICY: ALLOW");
        return XDP_PASS;
    }

    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        bpf_printk("GLOBAL POLICY: BLOCK");
        return XDP_DROP;
    }

    // Prepare rule keys
    struct rule_key exact_key = {
        .src_ip = saddr,
        .dst_ip = daddr,
        .proto = ip->protocol,
        .src_port = src_port,
        .dst_port = dst_port
    };

    struct rule_key wildcard_src_ip = {
        .src_ip = IP_ANY,
        .dst_ip = daddr,
        .proto = ip->protocol,
        .src_port = src_port,
        .dst_port = dst_port
    };

    struct rule_key wildcard_dst_ip = {
        .src_ip = saddr,
        .dst_ip = IP_ANY,
        .proto = ip->protocol,
        .src_port = src_port,
        .dst_port = dst_port
    };

    struct rule_key wildcard_src_port = {
        .src_ip = saddr,
        .dst_ip = daddr,
        .proto = ip->protocol,
        .src_port = 0,
        .dst_port = dst_port
    };

    struct rule_key wildcard_dst_port = {
        .src_ip = saddr,
        .dst_ip = daddr,
        .proto = ip->protocol,
        .src_port = src_port,
        .dst_port = 0
    };

    struct rule_key wildcard_both_ips = {
        .src_ip = IP_ANY,
        .dst_ip = IP_ANY,
        .proto = ip->protocol,
        .src_port = src_port,
        .dst_port = dst_port
    };

    struct rule_key wildcard_both_ports = {
        .src_ip = saddr,
        .dst_ip = daddr,
        .proto = ip->protocol,
        .src_port = 0,
        .dst_port = 0
    };

    struct rule_key wildcard_all = {
        .src_ip = IP_ANY,
        .dst_ip = IP_ANY,
        .proto = ip->protocol,
        .src_port = 0,
        .dst_port = 0
    };

    // Check rules in order of specificity
    __u8 *rule_action;

    #define CHECK_RULE(rule, name) \
        rule_action = bpf_map_lookup_elem(&firewall_rules, &rule); \
        if (rule_action) { \
            log_rule_match(&rule, *rule_action); \
            return *rule_action ? XDP_PASS : XDP_DROP; \
        } else { \
            bpf_printk("RULE NOT FOUND: " name); \
        }

    CHECK_RULE(exact_key, "exact");
    CHECK_RULE(wildcard_src_ip, "wildcard_src_ip");
    CHECK_RULE(wildcard_dst_ip, "wildcard_dst_ip");
    CHECK_RULE(wildcard_src_port, "wildcard_src_port");
    CHECK_RULE(wildcard_dst_port, "wildcard_dst_port");
    CHECK_RULE(wildcard_both_ips, "wildcard_both_ips");
    CHECK_RULE(wildcard_both_ports, "wildcard_both_ports");
    CHECK_RULE(wildcard_all, "wildcard_all");

    bpf_printk("NO RULE MATCHED - DEFAULT ALLOW");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    return process_packet(data, data_end);
}

char _license[] SEC("license") = "GPL";