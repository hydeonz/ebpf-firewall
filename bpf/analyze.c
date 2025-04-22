#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 10000);
} connection_map SEC(".maps");

SEC("xdp")
int analyze_connections(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void*)(ip + 1);
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 *count = bpf_map_lookup_elem(&connection_map, &src_ip);
    __u32 new_count = 1;

    if (count) {
        new_count = *count + 1;
    }

    bpf_map_update_elem(&connection_map, &src_ip, &new_count, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";