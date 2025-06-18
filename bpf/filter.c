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

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

struct rule_key {
    __le32 src_ip;
    __le32 dst_ip;
    __u8 proto;
    __u16 src_port;
    __u16 dst_port;
} __attribute__((packed));

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

    // Check global allow (highest priority)
    __u8 key = 0;
    __u8 *global_allow_enabled = bpf_map_lookup_elem(&global_allow, &key);
    if (global_allow_enabled && *global_allow_enabled) {
        return XDP_PASS;
    }

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

    // Create rule key
    struct rule_key rule = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .proto = ip->protocol,
        .src_port = src_port,
        .dst_port = dst_port
    };

    // Check for exact match first
    __u8 *action = bpf_map_lookup_elem(&firewall_rules, &rule);
    if (action) {
        return *action ? XDP_PASS : XDP_DROP;
    }

    // Check for rules with wildcard ports
    struct rule_key rule_src_any = rule;
    rule_src_any.src_port = 0;
    action = bpf_map_lookup_elem(&firewall_rules, &rule_src_any);
    if (action) {
        return *action ? XDP_PASS : XDP_DROP;
    }

    struct rule_key rule_dst_any = rule;
    rule_dst_any.dst_port = 0;
    action = bpf_map_lookup_elem(&firewall_rules, &rule_dst_any);
    if (action) {
        return *action ? XDP_PASS : XDP_DROP;
    }

    struct rule_key rule_both_any = rule;
    rule_both_any.src_port = 0;
    rule_both_any.dst_port = 0;
    action = bpf_map_lookup_elem(&firewall_rules, &rule_both_any);
    if (action) {
        return *action ? XDP_PASS : XDP_DROP;
    }

    // Check global block
    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";