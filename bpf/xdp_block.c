#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#define MAX_BLOCKED_IPS 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __be32);  // IP-адрес источника для блокировки исходящего трафика
    __type(value, __u8);  // Флаг
} blocked_src SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS);
    __type(key, __be32);  // IP-адрес назначения для блокировки входящего трафика
    __type(value, __u8);  // Флаг
} blocked_dst SEC(".maps");

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

    // Проверяем исходящий трафик (по source IP)
    __u8 *src_blocked = bpf_map_lookup_elem(&blocked_src, &ip->saddr);
    if (src_blocked) {
        bpf_printk("BLOCKED OUTGOING: Source IP %pI4", &ip->saddr);
        return XDP_DROP;
    }

    // Проверяем входящий трафик (по destination IP)
    __u8 *dst_blocked = bpf_map_lookup_elem(&blocked_dst, &ip->daddr);
    if (dst_blocked) {
        bpf_printk("BLOCKED INCOMING: Destination IP %pI4", &ip->daddr);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";