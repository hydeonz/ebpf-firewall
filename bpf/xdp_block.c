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

struct rule_key {
    __be32 ip;
    __u8 proto;
    __u8 direction; // 0 = src, 1 = dst
    __u16 pad;     // для выравнивания
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS * 10);
    __type(key, struct rule_key);
    __type(value, __u8);
} blocked_rules SEC(".maps");

SEC("xdp")
int xdp_block_ip(struct xdp_md *ctx) {
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

    // Проверка для исходящего трафика (direction=0)
    struct rule_key src_key = {
        .ip = ip->saddr,
        .proto = ip->protocol,
        .direction = 0,
        .pad = 0
    };

    // Проверка для входящего трафика (direction=1)
    struct rule_key dst_key = {
        .ip = ip->daddr,
        .proto = ip->protocol,
        .direction = 1,
        .pad = 0
    };

    if (bpf_map_lookup_elem(&blocked_rules, &src_key)) {
        bpf_printk("BLOCKED OUTGOING: Src %pI4 Proto %d", &ip->saddr, ip->protocol);
        return XDP_DROP;
    }

    if (bpf_map_lookup_elem(&blocked_rules, &dst_key)) {
        bpf_printk("BLOCKED INCOMING: Dst %pI4 Proto %d", &ip->daddr, ip->protocol);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";