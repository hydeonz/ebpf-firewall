#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // Добавляем для работы с endianness
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be32);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_block_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Используем правильное преобразование endianness
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __be32 *blocked_ip = bpf_map_lookup_elem(&blocked_ips, &key);
    if (!blocked_ip)
        return XDP_PASS;

    if (ip->saddr == *blocked_ip || ip->daddr == *blocked_ip) {
        bpf_printk("Blocking packet for IP: %pI4", blocked_ip);
        return XDP_DROP;
    }
    bpf_printk("Checking IP packet: src %pI4, dst %pI4", &ip->saddr, &ip->daddr);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
