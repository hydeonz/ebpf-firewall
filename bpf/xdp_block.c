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

// Структура для ключа в карте - IP + протокол
struct ip_proto_key {
    __be32 ip;
    __u8 proto;  // IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP и т.д.
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_IPS * 3);  // Умножаем на 3 (ICMP, TCP, UDP)
    __type(key, struct ip_proto_key);
    __type(value, __u8);  // Флаг
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

    // Проверяем блокировку для исходного IP (исходящий трафик)
    struct ip_proto_key src_key = {.ip = ip->saddr, .proto = ip->protocol};
    __u8 *src_blocked = bpf_map_lookup_elem(&blocked_rules, &src_key);
    if (src_blocked) {
        bpf_printk("BLOCKED OUTGOING: Src IP %pI4 Proto %d", &ip->saddr, ip->protocol);
        return XDP_DROP;
    }

    // Проверяем блокировку для IP назначения (входящий трафик)
    struct ip_proto_key dst_key = {.ip = ip->daddr, .proto = ip->protocol};
    __u8 *dst_blocked = bpf_map_lookup_elem(&blocked_rules, &dst_key);
    if (dst_blocked) {
        bpf_printk("BLOCKED INCOMING: Dst IP %pI4 Proto %d", &ip->daddr, ip->protocol);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";