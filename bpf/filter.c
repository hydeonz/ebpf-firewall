/**
 * @file simple_firewall.c
 * @brief Simplified eBPF firewall with allow/block rules
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_RULES 1024

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define WILDCARD 0

struct rule_key {
    __le32 src_ip;
    __le32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 padding[3];  // Explicit padding to avoid implicit padding
};

// Common map definition structure
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct rule_key);
    __type(value, __u8);
} allow_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, struct rule_key);
    __type(value, __u8);
} block_rules SEC(".maps");

static __always_inline int match_rule(__be32 src_ip, __be32 dst_ip,
                                     __u16 src_port, __u16 dst_port,
                                     __u8 proto, void *rules_map) {
    // Check exact match first
    struct rule_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = proto,
        .padding = {0, 0, 0}
    };

    if (bpf_map_lookup_elem(rules_map, &key))
        return 1;

    // Generate all possible wildcard combinations
    struct rule_key wildcards[] = {
        // Full wildcard (only protocol)
        { .src_ip = WILDCARD, .dst_ip = WILDCARD, .src_port = WILDCARD, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },

        // Single field wildcards
        { .src_ip = src_ip, .dst_ip = WILDCARD, .src_port = WILDCARD, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = WILDCARD, .dst_ip = dst_ip, .src_port = WILDCARD, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = WILDCARD, .dst_ip = WILDCARD, .src_port = src_port, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = WILDCARD, .dst_ip = WILDCARD, .src_port = WILDCARD, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },

        // Two field wildcards
        // IP pairs
        { .src_ip = src_ip, .dst_ip = dst_ip, .src_port = WILDCARD, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = src_ip, .dst_ip = WILDCARD, .src_port = src_port, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = src_ip, .dst_ip = WILDCARD, .src_port = WILDCARD, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = WILDCARD, .dst_ip = dst_ip, .src_port = src_port, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = WILDCARD, .dst_ip = dst_ip, .src_port = WILDCARD, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },
        // Port pairs
        { .src_ip = WILDCARD, .dst_ip = WILDCARD, .src_port = src_port, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },

        // Three field wildcards
        { .src_ip = src_ip, .dst_ip = dst_ip, .src_port = src_port, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = src_ip, .dst_ip = dst_ip, .src_port = WILDCARD, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = src_ip, .dst_ip = WILDCARD, .src_port = src_port, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },
        { .src_ip = WILDCARD, .dst_ip = dst_ip, .src_port = src_port, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },

        // All combinations with one specific field and rest wildcards
        // Specific src_ip only
        { .src_ip = src_ip, .dst_ip = WILDCARD, .src_port = WILDCARD, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        // Specific dst_ip only
        { .src_ip = WILDCARD, .dst_ip = dst_ip, .src_port = WILDCARD, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        // Specific src_port only
        { .src_ip = WILDCARD, .dst_ip = WILDCARD, .src_port = src_port, .dst_port = WILDCARD, .proto = proto, .padding = {0, 0, 0} },
        // Specific dst_port only
        { .src_ip = WILDCARD, .dst_ip = WILDCARD, .src_port = WILDCARD, .dst_port = dst_port, .proto = proto, .padding = {0, 0, 0} },
    };

    for (int i = 0; i < sizeof(wildcards)/sizeof(wildcards[0]); i++) {
        if (bpf_map_lookup_elem(rules_map, &wildcards[i]))
            return 1;
    }

    return 0;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

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

    // Check allow rules first (higher priority)
    if (match_rule(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol, &allow_rules)) {
        return XDP_PASS;
    }

    // Check block rules
    if (match_rule(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol, &block_rules)) {
        return XDP_DROP;
    }

    // Default action if no rules matched
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";