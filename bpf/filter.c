/**
 * @file filter_analyze.c
 * @brief Combined eBPF program for packet filtering and connection analysis
 *
 * This program combines:
 * 1. XDP/TC-based packet filtering
 * 2. Connection statistics tracking
 * 3. TCP flag analysis
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define MAX_BLOCKED_IPS 256
#define MAX_BLOCKED_PORTS 1024
#define MAX_ALLOWED_IPS 256
#define MAX_ALLOWED_PORTS 1024

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

// Filtering structures
struct rule_key {
    __le32 ip;
    __u8 proto;
    __u8 direction; // 0 = src, 1 = dst
    __u16 port;     // 0 means any port
};

// Maps for filtering
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS * 10);
    __type(key, struct rule_key);
    __type(value, __u8);
} blocked_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_IPS * 10);
    __type(key, struct rule_key);
    __type(value, __u8);
} allowed_rules SEC(".maps");

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

// Statistics structures
struct conn_stats {
    __u32 count;
    __u32 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct conn_stats));
    __uint(max_entries, 10000);
} connection_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} total_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} tcp_syn_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} tcp_ack_count SEC(".maps");

static __always_inline void update_stats(__be32 saddr, __u32 packet_length) {
    // Update total bytes
    __u32 key = 0;
    __u64 *total = bpf_map_lookup_elem(&total_bytes, &key);
    if (total) {
        __sync_fetch_and_add(total, packet_length);
    } else {
        __u64 init_val = packet_length;
        bpf_map_update_elem(&total_bytes, &key, &init_val, BPF_NOEXIST);
    }

    // Update connection stats
    __u32 src_ip = saddr;
    struct conn_stats *stats = bpf_map_lookup_elem(&connection_map, &src_ip);
    struct conn_stats new_stats = {
        .count = 1,
        .bytes = packet_length
    };

    if (stats) {
        new_stats.count = stats->count + 1;
        new_stats.bytes = stats->bytes + packet_length;
    }

    bpf_map_update_elem(&connection_map, &src_ip, &new_stats, BPF_ANY);
}

static __always_inline void update_tcp_flags(struct tcphdr *tcp) {
    __u32 key = 0;

    if (tcp->syn) {
        __u64 *syn_count = bpf_map_lookup_elem(&tcp_syn_count, &key);
        if (syn_count) {
            __sync_fetch_and_add(syn_count, 1);
        } else {
            __u64 init_val = 1;
            bpf_map_update_elem(&tcp_syn_count, &key, &init_val, BPF_NOEXIST);
        }
    }

    if (tcp->ack) {
        __u64 *ack_count = bpf_map_lookup_elem(&tcp_ack_count, &key);
        if (ack_count) {
            __sync_fetch_and_add(ack_count, 1);
        } else {
            __u64 init_val = 1;
            bpf_map_update_elem(&tcp_ack_count, &key, &init_val, BPF_NOEXIST);
        }
    }
}

SEC("xdp")
int xdp_filter_analyze(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 packet_length = data_end - data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    // Update statistics for all packets
    update_stats(ip->saddr, packet_length);

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

            // Update TCP flags if TCP
            if (ip->protocol == IPPROTO_TCP) {
                update_tcp_flags(tcp);
            }
        }
    }

    // Convert IP addresses to host order
    __be32 saddr = ip->saddr;
    __be32 daddr = ip->daddr;

    // Create rule keys
    struct rule_key src_key = { .ip = saddr, .proto = ip->protocol, .direction = 0, .port = 0 };
    struct rule_key dst_key = { .ip = daddr, .proto = ip->protocol, .direction = 1, .port = 0 };
    struct rule_key src_port_key = { .ip = saddr, .proto = ip->protocol, .direction = 0, .port = src_port };
    struct rule_key dst_port_key = { .ip = daddr, .proto = ip->protocol, .direction = 1, .port = dst_port };

    // Check allow rules first (high priority)
    if (bpf_map_lookup_elem(&allowed_rules, &src_port_key) ||
        bpf_map_lookup_elem(&allowed_rules, &dst_port_key) ||
        bpf_map_lookup_elem(&allowed_rules, &src_key) ||
        bpf_map_lookup_elem(&allowed_rules, &dst_key)) {
        return XDP_PASS;
    }

    // Check global block
    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        return XDP_DROP;
    }

    // Check block rules
    if (bpf_map_lookup_elem(&blocked_rules, &src_port_key) ||
        bpf_map_lookup_elem(&blocked_rules, &dst_port_key) ||
        bpf_map_lookup_elem(&blocked_rules, &src_key) ||
        bpf_map_lookup_elem(&blocked_rules, &dst_key)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("classifier/egress")
int tc_egress_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 packet_length = data_end - data;

    // Check global allow (highest priority)
    __u8 key = 0;
    __u8 *global_allow_enabled = bpf_map_lookup_elem(&global_allow, &key);
    if (global_allow_enabled && *global_allow_enabled) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // Get destination IP and port
    __be32 daddr = ip->daddr;
    __u16 dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        struct udphdr *udp = (void *)ip + sizeof(*ip);

        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            dst_port = bpf_ntohs(ip->protocol == IPPROTO_TCP ? tcp->dest : udp->dest);
        }
    }
    update_stats(ip->saddr, packet_length);
    // Create rule keys
    struct rule_key dst_key = { .ip = daddr, .proto = ip->protocol, .direction = 1, .port = 0 };
    struct rule_key dst_port_key = { .ip = daddr, .proto = ip->protocol, .direction = 1, .port = dst_port };

    // Check allow rules first
    if (bpf_map_lookup_elem(&allowed_rules, &dst_port_key) ||
        bpf_map_lookup_elem(&allowed_rules, &dst_key)) {
        return TC_ACT_OK;
    }

    // Check global block
    __u8 *global_block_enabled = bpf_map_lookup_elem(&global_block, &key);
    if (global_block_enabled && *global_block_enabled) {
        return TC_ACT_SHOT;
    }

    // Check block rules
    if (bpf_map_lookup_elem(&blocked_rules, &dst_port_key) ||
        bpf_map_lookup_elem(&blocked_rules, &dst_key)) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";