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

// New rule structure to match the JSON format
struct rule_key {
    __be32 src_ip;    // 0 means any source IP
    __be32 dst_ip;    // 0 means any destination IP
    __u8 proto;       // protocol
    __u16 src_port;   // 0 means any source port
    __u16 dst_port;   // 0 means any destination port
};

// Maps for filtering
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct rule_key);
    __type(value, __u8); // 1 = allow, 0 = block
} firewall_rules SEC(".maps");

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

static __always_inline void log_packet(__be32 saddr, __be32 daddr, __u8 proto,
                                     __u16 sport, __u16 dport, int action, const char *reason) {
    // Разбиваем вывод на несколько вызовов bpf_printk
    char proto_str[8] = {0};
    switch (proto) {
        case IPPROTO_TCP: __builtin_memcpy(proto_str, "TCP", 4); break;
        case IPPROTO_UDP: __builtin_memcpy(proto_str, "UDP", 4); break;
        case IPPROTO_ICMP: __builtin_memcpy(proto_str, "ICMP", 5); break;
        default: __builtin_memcpy(proto_str, "UNKN", 5); break;
    }

    // Первая строка: протокол и адреса
    bpf_printk("FIREWALL: %s %pI4 -> %pI4", proto_str, &saddr, &daddr);

    // Вторая строка: порты
    bpf_printk("PORTS: %d -> %d", sport, dport);

    // Третья строка: действие и причина
    bpf_printk("ACTION: %s, REASON: %s",
              action == XDP_PASS ? "ALLOW" : "BLOCK",
              reason);
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

    // Initialize ports (0 means any port)
    __u16 src_port = 0;
    __u16 dst_port = 0;

    // Check transport header only for TCP/UDP
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

    // Check global allow (highest priority)
    __u8 key = 0;
    __u8 *global_allow_enabled = bpf_map_lookup_elem(&global_allow, &key);
    if (global_allow_enabled && *global_allow_enabled) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port, XDP_PASS, "global allow");
        return XDP_PASS;
    }

    // Check global block
    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port, XDP_DROP, "global block");
        return XDP_DROP;
    }

    // Create rule keys with different combinations of wildcards
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

    rule_action = bpf_map_lookup_elem(&firewall_rules, &exact_key);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "exact match rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_src_ip);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard src_ip rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_dst_ip);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard dst_ip rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_src_port);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard src_port rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_dst_port);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard dst_port rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_both_ips);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard both IPs rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_both_ports);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard both ports rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    rule_action = bpf_map_lookup_elem(&firewall_rules, &wildcard_all);
    if (rule_action) {
        log_packet(saddr, daddr, ip->protocol, src_port, dst_port,
                 *rule_action ? XDP_PASS : XDP_DROP, "wildcard all rule");
        return *rule_action ? XDP_PASS : XDP_DROP;
    }

    // If no rules matched, default action is to pass
    log_packet(saddr, daddr, ip->protocol, src_port, dst_port, XDP_PASS, "default pass");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    return process_packet(data, data_end);
}

char _license[] SEC("license") = "GPL";